//! Capture mode: mail is accepted, signed and stored as ever, and
//! each transaction the scheduler dispatches is written to a directory in
//! place of being sent. Nothing is looked up in the DNS and nothing reaches
//! a receiver; each delivery finishes captured, never delivered.
//!
//! Each transaction is two files, its owner's alone: `<name>.eml`, its
//! content exactly as it would have gone, signed, and `<name>.json`, its
//! envelope (the return path, the recipients, the deliveries) and when it
//! was captured, written last, so one listed is whole. While its body is
//! sealed, both are sealed under the body's key, so a tenant's
//! captures are erased with its key. The inspector, on the operator
//! endpoint's `/capture`, shows them, newest first, each with its headers,
//! its text and its message's lifecycle.

use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use engine_core::attempt::Evidence;
use engine_core::command::{Answer, Command, Inspect};
use engine_core::id::{Id, MessageId};
use engine_feedback::token;
use engine_scheduler::{Attempted, Dispatch, Route, Tls};
use http_body_util::Full;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

use crate::clock::SystemClock;
use crate::config;
use crate::delivery::{self, Deliverer};
use crate::log::Hex;
use crate::sealing::Sealer;
use crate::simulator::Simulator;
use crate::store::Store;

/// Where the scheduler's attempts go: out by SMTP, but for SES's mailbox
/// simulator's addresses, which it ends itself; or, in capture mode, into
/// the capture directory. Chosen once, at start.
pub enum Transport {
    Smtp {
        deliverer: Deliverer,
        simulator: Arc<Simulator>,
    },
    Capture(Capturer),
}

impl Transport {
    pub fn resolve(&self, domain: Box<str>) {
        match self {
            Self::Smtp {
                deliverer,
                simulator,
            } => {
                if !simulator.resolve(&domain) {
                    deliverer.resolve(domain);
                }
            }
            Self::Capture(capturer) => capturer.resolve(domain),
        }
    }

    pub fn dispatch(&self, dispatch: Dispatch) {
        match self {
            Self::Smtp { simulator, .. } if Simulator::takes(&dispatch) => {
                simulator.dispatch(dispatch);
            }
            Self::Smtp { deliverer, .. } => deliverer.dispatch(dispatch),
            Self::Capture(capturer) => capturer.dispatch(dispatch),
        }
    }
}

/// The one route every domain has in capture mode, which names no host.
const CAPTURED: &str = "capture.invalid";

/// The capture transport.
pub struct Capturer {
    inner: Arc<Inner>,
}

struct Inner {
    directory: PathBuf,
    return_path_key: token::Key,
    return_path_domain: String,
    scheduler: UnboundedSender<engine_scheduler::Input>,
    clock: Arc<SystemClock>,
    /// The deliveries captured before the engine started, by ID, each with
    /// its capture's name, until each is reported again.
    found: Mutex<BTreeMap<u64, String>>,
    /// Opens a body sealed under any key.
    sealer: Arc<Sealer>,
}

/// A capture's files, as they are sealed.
const CONTENT: u32 = 0;
const ENVELOPE: u32 = 1;

/// A transaction's envelope, as `<name>.json` keeps it.
#[derive(Serialize, Deserialize)]
struct Envelope {
    message: String,
    from: String,
    to: Vec<String>,
    deliveries: Vec<String>,
    captured: String,
}

impl Capturer {
    /// The capture transport into `capture`'s directory, made its owner's
    /// alone if it is not there.
    pub fn new(
        capture: &config::Capture,
        delivery: &config::Delivery,
        scheduler: UnboundedSender<engine_scheduler::Input>,
        clock: Arc<SystemClock>,
        sealer: Arc<Sealer>,
    ) -> Result<Self, String> {
        let directory = &capture.directory;
        let failed =
            |error: &dyn std::fmt::Display| format!("capture: {}: {error}", directory.display());
        // Each directory made here is kept in its parent before anything is
        // captured into it.
        let made: Vec<PathBuf> = directory
            .ancestors()
            .take_while(|ancestor| !ancestor.as_os_str().is_empty() && !ancestor.exists())
            .map(Path::to_path_buf)
            .collect();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .map_err(|error| failed(&error))?;
        for made in &made {
            let parent = match made.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            sync_directory(parent).map_err(|error| failed(&error))?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                directory: directory.clone(),
                return_path_key: delivery::return_path_key(delivery)?,
                return_path_domain: delivery.return_path_domain.clone(),
                scheduler,
                clock,
                found: Mutex::new(found(directory, &sealer)?),
                sealer,
            }),
        })
    }

    /// Every domain goes to the one local route, without a lookup.
    pub fn resolve(&self, domain: Box<str>) {
        let _ = self
            .inner
            .scheduler
            .send(engine_scheduler::Input::Resolved {
                domain,
                route: Route::Exchanges(vec![CAPTURED.to_owned()], Tls::default()),
                ttl: Duration::from_secs(86_400),
            });
    }

    /// Captures a transaction, off the runtime's threads, and reports each
    /// of its deliveries captured, or not sent if it could not be written.
    pub fn dispatch(&self, dispatch: Dispatch) {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let written = inner.write(&dispatch);
            for ((permit, _), written) in dispatch.recipients.into_iter().zip(written) {
                let (result, said) = match written {
                    Ok(name) => (Attempted::Captured, format!("captured as {name}")),
                    Err(why) => {
                        tracing::warn!(why = %why, "a delivery could not be captured");
                        (Attempted::NotSent, format!("not captured: {why}"))
                    }
                };
                let _ = inner.scheduler.send(engine_scheduler::Input::Finished {
                    permit,
                    result,
                    evidence: Some(Evidence::local(&said)),
                    verdict: None,
                    feedback: None,
                    replied: None,
                });
            }
        });
    }
}

/// The deliveries the captures in `directory` hold, each with its
/// capture's name, the directory kept as it is found. One whose key is gone
/// holds none: its mail can no longer be sent.
fn found(directory: &Path, sealer: &Sealer) -> Result<BTreeMap<u64, String>, String> {
    let failed =
        |error: &dyn std::fmt::Display| format!("capture: {}: {error}", directory.display());
    let mut found = BTreeMap::new();
    for entry in std::fs::read_dir(directory).map_err(|error| failed(&error))? {
        let entry = entry.map_err(|error| failed(&error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(name) = name.strip_suffix(".json") else {
            continue;
        };
        // Whole only with its content beside it, a file of its own that
        // opens as this capture's: the two are published one after the
        // other.
        let Some(envelope) = envelope(directory, sealer, name)
            .filter(|_| opened(directory, sealer, name, CONTENT).is_some())
        else {
            continue;
        };
        for delivery in &envelope.deliveries {
            if let Ok(delivery) = u64::from_str_radix(delivery, 16) {
                found.insert(delivery, name.to_owned());
            }
        }
    }
    // Written before the engine stopped, perhaps not yet kept.
    sync_directory(directory).map_err(|error| failed(&error))?;
    Ok(found)
}

/// The capture `name`'s ID, which its files are sealed in the place of: its
/// first delivery's.
fn capture_id(name: &str) -> Option<u64> {
    let (_, delivery) = name.split_once('-')?;
    u64::from_str_radix(delivery, 16).ok()
}

/// `file` of the capture `name`, read and opened.
fn opened(directory: &Path, sealer: &Sealer, name: &str, file: u32) -> Option<Vec<u8>> {
    let suffix = if file == CONTENT { "eml" } else { "json" };
    let kept = read(directory, &format!("{name}.{suffix}")).ok()?;
    sealer.open_capture(kept, capture_id(name)?, file).ok()
}

/// The capture `name`'s envelope, read and opened.
fn envelope(directory: &Path, sealer: &Sealer, name: &str) -> Option<Envelope> {
    serde_json::from_slice(&opened(directory, sealer, name, ENVELOPE)?).ok()
}

impl Inner {
    /// Captures the transaction's deliveries: those captured before the
    /// engine stopped, their outcomes not yet kept, are found, never written
    /// twice; the rest are written, the content then the envelope, as one
    /// capture named by its message and its first delivery, every file kept
    /// before this returns. Gives each delivery's capture's name, or why it
    /// was not captured.
    fn write(&self, dispatch: &Dispatch) -> Vec<Result<String, String>> {
        let mut written: Vec<Option<Result<String, String>>> = {
            let mut found = self.found.lock().unwrap_or_else(PoisonError::into_inner);
            dispatch
                .recipients
                .iter()
                .map(|(permit, _)| found.remove(&permit.delivery().0.as_u64()).map(Ok))
                .collect()
        };
        let left: Vec<usize> = (0..written.len())
            .filter(|&index| written[index].is_none())
            .collect();
        if let Some(&first) = left.first() {
            let name = format!(
                "{}-{}",
                Hex(dispatch.message.0),
                Hex(dispatch.recipients[first].0.delivery().0)
            );
            let published = self.publish(&name, dispatch, &left).and_then(|()| {
                sync_directory(&self.directory)
                    .map_err(|error| format!("{}: {error}", self.directory.display()))
            });
            for &index in &left {
                written[index] = Some(published.clone().map(|()| name.clone()));
            }
        }
        written.into_iter().flatten().collect()
    }

    /// Writes the transaction's content, then its envelope naming the
    /// recipients at `recipients`, as `name`.
    fn publish(&self, name: &str, dispatch: &Dispatch, recipients: &[usize]) -> Result<(), String> {
        let envelope = Envelope {
            message: Hex(dispatch.message.0).to_string(),
            from: delivery::return_path(
                &self.return_path_key,
                dispatch
                    .return_domain
                    .as_deref()
                    .unwrap_or(&self.return_path_domain),
                dispatch.message,
            ),
            to: recipients
                .iter()
                .map(|&index| dispatch.recipients[index].1.as_str().to_owned())
                .collect(),
            deliveries: recipients
                .iter()
                .map(|&index| Hex(dispatch.recipients[index].0.delivery().0).to_string())
                .collect(),
            captured: engine_api::inspect::rfc3339(self.clock.now().wall),
        };
        let envelope = serde_json::to_vec_pretty(&envelope).map_err(|error| error.to_string())?;
        // Captured as it is sent, opened if it was sealed, and each file
        // sealed again as its body was.
        let opened = self
            .sealer
            .open_body(&dispatch.content)
            .map_err(delivery::unopened_body)?;
        let content = opened.as_deref().unwrap_or(&dispatch.content);
        let capture = dispatch.recipients[recipients[0]].0.delivery().0.as_u64();
        let sealed = |file, bytes| {
            self.sealer
                .seal_capture(&dispatch.content, capture, file, bytes)
        };
        write_whole(
            &self.directory.join(format!("{name}.eml")),
            &sealed(CONTENT, content),
        )?;
        // The content's name kept before the envelope's, so an envelope
        // found never names content that is not there.
        sync_directory(&self.directory)
            .map_err(|error| format!("{}: {error}", self.directory.display()))?;
        write_whole(
            &self.directory.join(format!("{name}.json")),
            &sealed(ENVELOPE, &envelope),
        )
    }
}

/// Writes `bytes` to a file of its own beside `path`, its owner's alone,
/// kept, then puts it at `path`, so it is never seen in part.
fn write_whole(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    let partial = PathBuf::from(format!("{}.partial", path.display()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&partial)
        .map_err(|error| failed(&error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| failed(&error))?;
    std::fs::rename(&partial, path).map_err(|error| failed(&error))
}

/// The file `name` in `directory`, read only where it is a file there of
/// its own: never through a link, and never anything but a regular file.
fn read(directory: &Path, name: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut file = open_regular(directory, name)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The file `name` in `directory`, opened only where it is a regular file
/// there of its own, never through a link.
fn open_regular(directory: &Path, name: &str) -> std::io::Result<std::fs::File> {
    // Not blocking on a pipe, whose opening would wait for a writer.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(directory.join(name))?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// Keeps `directory`'s entries: what was made or renamed in it.
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory).and_then(|directory| directory.sync_all())
}

/// The capture directory's inspector, on the operator endpoint: a capture
/// whose key is gone is not there.
pub struct Inspector {
    pub directory: PathBuf,
    pub store: Store,
    pub sealer: Arc<Sealer>,
}

/// The most transactions the index lists.
const LISTED: usize = 500;

impl Inspector {
    /// The page at `path`, under `/capture`: the index, a transaction, or a
    /// transaction's raw message.
    pub async fn page(&self, path: &str) -> http::Response<Full<Bytes>> {
        let rest = path.strip_prefix("/capture").unwrap_or_default();
        match rest.trim_start_matches('/') {
            "" => html(200, &self.index()),
            name => {
                let (name, raw) = match name.strip_suffix(".eml") {
                    Some(name) => (name, true),
                    None => (name, false),
                };
                // A name is the engine's own, in hex: nothing else is read.
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
                    return html(404, "<p>No such capture.</p>");
                }
                if raw {
                    match opened(&self.directory, &self.sealer, name, CONTENT) {
                        Some(content) => http::Response::builder()
                            .status(200)
                            .header(http::header::CONTENT_TYPE, "message/rfc822")
                            .header(
                                http::header::CONTENT_DISPOSITION,
                                format!("attachment; filename=\"{name}.eml\""),
                            )
                            .body(Full::new(Bytes::from(content)))
                            .expect("a valid response"),
                        None => html(404, "<p>No such capture.</p>"),
                    }
                } else {
                    match self.transaction(name).await {
                        Some(page) => html(200, &page),
                        None => html(404, "<p>No such capture.</p>"),
                    }
                }
            }
        }
    }

    /// Every transaction captured, newest first, at most [`LISTED`].
    fn index(&self) -> String {
        let mut captured: Vec<(Envelope, String)> = std::fs::read_dir(&self.directory)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let name = name.strip_suffix(".json")?.to_owned();
                let envelope = envelope(&self.directory, &self.sealer, &name)?;
                Some((envelope, name))
            })
            .collect();
        captured.sort_by(|(left, _), (right, _)| right.captured.cmp(&left.captured));
        let rows: String = captured
            .iter()
            .take(LISTED)
            .map(|(envelope, name)| {
                let (from, subject) = self
                    .headers(name)
                    .unwrap_or_else(|| (String::new(), String::new()));
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td><a href=\"/capture/{name}\">{}</a></td></tr>",
                    escape(&envelope.captured),
                    escape(&from),
                    escape(&envelope.to.join(", ")),
                    escape(if subject.is_empty() { "(no subject)" } else { &subject }),
                )
            })
            .collect();
        let shown = if captured.is_empty() {
            "<p>Nothing captured yet. Mail submitted to the engine is captured here in place of being sent.</p>".to_owned()
        } else {
            format!(
                "<p>{} captured, newest first.</p><table><tr><th>Captured</th><th>From</th><th>To</th><th>Subject</th></tr>{rows}</table>",
                captured.len()
            )
        };
        page("Captured mail", &shown)
    }

    /// A transaction's message's From and Subject.
    fn headers(&self, name: &str) -> Option<(String, String)> {
        let content = opened(&self.directory, &self.sealer, name, CONTENT)?;
        let message = mail_parser::MessageParser::default().parse(&content)?;
        let from = message
            .from()
            .and_then(|from| from.first())
            .and_then(|from| from.address())
            .unwrap_or_default()
            .to_owned();
        Some((from, message.subject().unwrap_or_default().to_owned()))
    }

    /// A transaction's page: its envelope, its message's headers and text,
    /// and the lifecycle of its message's deliveries.
    async fn transaction(&self, name: &str) -> Option<String> {
        let envelope = envelope(&self.directory, &self.sealer, name)?;
        let content = opened(&self.directory, &self.sealer, name, CONTENT)?;
        let message = mail_parser::MessageParser::default().parse(&content);
        let (headers, text) = match &message {
            Some(message) => {
                let end = message.root_part().offset_body() as usize;
                (
                    String::from_utf8_lossy(&content[..end.min(content.len())]).into_owned(),
                    message
                        .body_text(0)
                        .map(|text| text.into_owned())
                        .unwrap_or_default(),
                )
            }
            None => (String::new(), String::new()),
        };
        let lifecycle = match u64::from_str_radix(&envelope.message, 16)
            .ok()
            .and_then(Id::from_u64)
        {
            Some(id) => self.lifecycle(MessageId(id)).await,
            None => String::new(),
        };
        let body = format!(
            "<p><a href=\"/capture\">All captured mail</a> · <a href=\"/capture/{name}.eml\">The raw message</a></p>
<h2>Envelope</h2><table>
<tr><th>Message</th><td>{message}</td></tr>
<tr><th>Return path</th><td>{from}</td></tr>
<tr><th>Recipients</th><td>{to}</td></tr>
<tr><th>Captured</th><td>{captured}</td></tr></table>
<h2>Lifecycle</h2>{lifecycle}
<h2>Headers</h2><pre>{headers}</pre>
<h2>Text</h2><pre>{text}</pre>",
            message = escape(&envelope.message),
            from = escape(&envelope.from),
            to = escape(&envelope.to.join(", ")),
            captured = escape(&envelope.captured),
            headers = escape(&headers),
            text = escape(&text),
        );
        Some(page("A captured message", &body))
    }

    /// Each of a message's deliveries as the store holds it, as `explain`
    /// gives it.
    async fn lifecycle(&self, message: MessageId) -> String {
        let Some(Answer::Inspected(Ok(deliveries))) = self
            .store
            .ask(Command::Inspect(Inspect::Message(message)))
            .await
        else {
            return "<p>The store did not answer.</p>".to_owned();
        };
        let explained = engine_api::inspect::explained(
            &deliveries,
            &engine_scheduler::Report::Holds(Vec::new()),
        );
        let rows: String = serde_json::from_slice::<serde_json::Value>(&explained)
            .ok()
            .and_then(|answer| answer["ok"]["deliveries"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .map(|delivery| {
                let text = |name: &str| delivery[name].as_str().unwrap_or_default().to_owned();
                let state = match delivery["completion"].as_str() {
                    Some(completion) => format!("{}, {completion}", text("state")),
                    None => text("state"),
                };
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape(&text("recipient")),
                    escape(&state),
                    escape(&text("at")),
                    delivery["attempts"],
                )
            })
            .collect();
        format!(
            "<table><tr><th>Recipient</th><th>State</th><th>Since</th><th>Attempts</th></tr>{rows}</table>"
        )
    }
}

/// An HTML page, whole.
fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title} · NitroMTA</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;margin:2rem;max-width:72rem}}table{{border-collapse:collapse}}th,td{{text-align:left;padding:.3rem .8rem;border-bottom:1px solid #ddd;vertical-align:top}}pre{{white-space:pre-wrap;background:#f6f6f6;padding:1rem}}</style>
</head><body><h1>{title}</h1>{body}</body></html>"
    )
}

fn html(status: u16, body: &str) -> http::Response<Full<Bytes>> {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("a valid response")
}

/// `text` safe inside HTML.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_escaped_for_html() {
        assert_eq!(
            escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }
}
