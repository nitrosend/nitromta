//! The feedback listener: SMTP, without a login, for the return
//! paths the engine issued and its complaint loops' addresses. Each
//! recipient is put to the intake, which refuses relay at once. A report is
//! answered only once the store has recorded it, so a reporter whose
//! report was lost sends it again.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use engine_core::command::{Answer, Command, Commit};
use engine_core::component::Component;
use engine_core::feedback::Trust;
use engine_core::id::{IdGenerator, ReportId};
use engine_feedback::intake::Intake;
use engine_smtp::reply::Reply;
use engine_smtp::server::{Config, Input, Output, Session, Transaction};
use mail_auth::{DkimResult, MessageAuthenticator};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::clock::SystemClock;
use crate::config;
use crate::log::Hex;
use crate::operator::{Listener, Operations};
use crate::stop::Stop;
use crate::store::Store;
use crate::stream::{self, Read};

pub struct Feedback {
    pub session: Arc<Config>,
    /// Its certificate, which a reload replaces.
    pub tls: Arc<crate::tls::Certified>,
    pub intake: Intake,
    /// Who may authenticate a report.
    pub reporters: Reporters,
    pub store: Store,
    pub ids: Mutex<IdGenerator>,
    pub clock: Arc<SystemClock>,
    /// The engine's stop, which counts the reports under way.
    pub stop: Arc<Stop>,
    pub operations: Arc<Operations>,
}

impl Feedback {
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<(), String> {
        let operations = Arc::clone(&self.operations);
        let most = crate::listen::MOST_OPEN;
        crate::listen::accept(listener, Listener::Feedback, most, &operations, |tcp| {
            Arc::clone(&self).connection(tcp)
        })
        .await
    }

    async fn connection(self: Arc<Self>, tcp: TcpStream) {
        let mut session = Session::new(Arc::clone(&self.session));
        let Ok(Some(tcp)) = self.drive(&mut session, tcp).await else {
            return;
        };
        let Some(tls) = self.tls.accept(tcp).await else {
            return;
        };
        session.handle(self.clock.now(), Input::TlsStarted);
        let _ = self.drive(&mut session, tls).await;
    }

    /// Runs the session over `stream` until it closes, or until it asks for
    /// TLS, when the stream comes back for the handshake.
    async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        session: &mut Session,
        mut stream: S,
    ) -> io::Result<Option<S>> {
        let mut out = Vec::new();
        let mut pending: Vec<Bytes> = Vec::new();
        let mut buffer = Vec::new();
        // A report is counted until its reply is written, so a stop lets it
        // finish.
        let mut _under_way = None;
        loop {
            let deadline = session.poll(self.clock.now(), &mut out);
            let mut answered = false;
            for output in out.drain(..) {
                match output {
                    Output::Send(bytes) => pending.push(Bytes::from(bytes)),
                    Output::StartTls => {
                        stream::write(&mut stream, &mut pending).await?;
                        return Ok(Some(stream));
                    }
                    Output::Close => {
                        stream::write(&mut stream, &mut pending).await?;
                        stream::close(&mut stream).await;
                        return Ok(None);
                    }
                    Output::Recipient => {
                        let taken = session
                            .asked()
                            .is_some_and(|address| self.intake.takes(address));
                        let verdict = if taken {
                            Ok(())
                        } else {
                            Err(engine_smtp::server::no_such_recipient())
                        };
                        session.handle(self.clock.now(), Input::Recipient(verdict));
                        answered = true;
                    }
                    // A receiver asks for no login.
                    Output::Authenticate { .. } => {
                        session.handle(self.clock.now(), Input::Authenticated(false));
                        answered = true;
                    }
                    Output::Submit(transaction) => {
                        stream::write(&mut stream, &mut pending).await?;
                        let reply = match self.stop.begin() {
                            Some(report_under_way) => {
                                _under_way = Some(report_under_way);
                                self.record(transaction).await
                            }
                            None => Reply::new(451, "4.3.2 Service shutting down, try again later"),
                        };
                        session.handle(self.clock.now(), Input::Answered(reply));
                        answered = true;
                    }
                }
            }
            // An answer given at once needs no write of its own: what is
            // pending goes out together before the next read.
            if answered {
                continue;
            }
            stream::write(&mut stream, &mut pending).await?;
            _under_way = None;
            match stream::read(&mut stream, &mut buffer, deadline, &self.clock).await? {
                Read::Bytes(bytes) => session.handle(self.clock.now(), Input::Received(bytes)),
                Read::Deadline => {}
                Read::Closed => return Ok(None),
            }
        }
    }

    /// Records a report, and returns its reply.
    async fn record(&self, transaction: Transaction) -> Reply {
        let now = self.clock.now().wall;
        let id = ReportId(
            self.ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .next(now),
        );
        let signed = self.reporters.signed(&transaction.content).await;
        // Trusting only authenticated reports, one whose enrolled reporter's
        // signature could not be checked for now is sent again later, when
        // it may be, rather than taken as unauthenticated for good.
        if signed == Signed::Unknown && self.intake.trusts() == Trust::Authenticated {
            return Reply::new(
                451,
                "4.4.3 Its signature could not be checked; try again later",
            );
        }
        let report = self.intake.report(
            id,
            &transaction.recipients,
            &transaction.content,
            now,
            signed == Signed::Authenticated,
        );
        let message = report.message;
        match self.store.ask(Command::RecordFeedback(report)).await {
            Some(Answer::Feedback(Commit::Committed(recorded))) => {
                self.operations.recorded(&recorded);
                // Past the quarantine's bound a report about none of the
                // engine's mail is taken, and says it was not kept.
                if recorded.unkept {
                    tracing::debug!(
                        report = %Hex(id.0),
                        "took a report about none of the engine's mail, and kept none of it: the quarantine is full"
                    );
                    return Reply::new(250, "2.0.0 Report taken, not kept");
                }
                tracing::debug!(
                    report = %Hex(id.0),
                    message_id = message.map(|message| tracing::field::display(Hex(message.0))),
                    duplicate = recorded.duplicate,
                    deliveries = recorded.deliveries,
                    suppressed = recorded.suppressed,
                    "recorded a report"
                );
                Reply::new(250, "2.0.0 Report recorded")
            }
            _ => Reply::new(451, "4.3.0 Try again later"),
        }
    }
}

/// The reporters the operator enrolled with, by the domains
/// that sign their reports, and the resolver their keys are read through:
/// none when none is enrolled, when nothing is looked up.
pub struct Reporters {
    domains: Vec<String>,
    authenticator: Option<MessageAuthenticator>,
}

impl Reporters {
    pub fn new(domains: &[String], delivery: &config::Delivery) -> Result<Self, String> {
        let domains: Vec<String> = domains
            .iter()
            .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        if let Some(bad) = domains
            .iter()
            .find(|domain| engine_core::address::domain(domain).is_err())
        {
            return Err(format!("feedback: reporters: {bad:?} is not a domain"));
        }
        let authenticator = if domains.is_empty() {
            None
        } else {
            // Keys are read as receivers read records: never from the
            // host's own files.
            let mut options = hickory_resolver::config::ResolverOpts::default();
            options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
            Some(
                MessageAuthenticator::new(crate::delivery::resolver_config(delivery)?, options)
                    .map_err(|error| {
                        format!("feedback: the resolver for reporters' keys: {error}")
                    })?,
            )
        };
        Ok(Self {
            domains,
            authenticator,
        })
    }

    /// Whether `content` carries a DKIM signature that verifies, by an
    /// enrolled reporter's domain or one under it. Only those signatures
    /// are checked, at most [`MOST_SIGNATURES`], one at a time, each within
    /// [`VERIFY_WITHIN`], and the first that verifies authenticates it: a
    /// signature by any other domain authenticates nothing, so it costs no
    /// lookup unless an enrolled one signs it. None verified, but one could
    /// not be checked for now, and whether it is authenticated is not known.
    async fn signed(&self, content: &[u8]) -> Signed {
        let Some(authenticator) = &self.authenticator else {
            return Signed::Not;
        };
        let mut unknown = false;
        for candidate in candidates(content, |domain| self.enrolled(domain)) {
            let Some(message) = mail_auth::AuthenticatedMessage::parse(&candidate) else {
                continue;
            };
            let Ok(outputs) =
                tokio::time::timeout(VERIFY_WITHIN, authenticator.verify_dkim(&message)).await
            else {
                unknown = true;
                continue;
            };
            let enrolled = outputs.iter().filter(|output| {
                output
                    .signature()
                    .is_some_and(|signature| self.enrolled(&signature.d))
            });
            for output in enrolled {
                match output.result() {
                    DkimResult::Pass => return Signed::Authenticated,
                    DkimResult::TempError(_) => unknown = true,
                    _ => {}
                }
            }
        }
        if unknown {
            Signed::Unknown
        } else {
            Signed::Not
        }
    }

    /// Whether `domain` is an enrolled reporter's, or under one.
    fn enrolled(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.domains.iter().any(|enrolled| {
            domain == *enrolled
                || domain
                    .strip_suffix(enrolled.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }
}

/// The most of a report's signatures by enrolled reporters checked, and
/// the most a message may carry for one that signs the others to be.
const MOST_SIGNATURES: usize = 4;
/// How long one signature is checked for, at most.
const VERIFY_WITHIN: Duration = Duration::from_secs(5);

/// Whether a report is signed by an enrolled reporter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signed {
    Authenticated,
    Not,
    /// A signature by an enrolled reporter could not be checked for now:
    /// its key's lookup failed or took too long.
    Unknown,
}

/// A DKIM signature field's parts: the domain it names, if it names one
/// once, and whether its `h=` signs other signatures.
struct Signature {
    domain: Option<String>,
    signs_signatures: bool,
}

/// The messages to check `content`'s enrolled signatures in, one for each
/// of the first [`MOST_SIGNATURES`] whose `d=` is `enrolled`: its fields as
/// they were, with that signature and no other, unless it signs other
/// signatures, when they stay as they were, if the message carries at most
/// [`MOST_SIGNATURES`], so what it signed is unchanged.
fn candidates(content: &[u8], enrolled: impl Fn(&str) -> bool) -> Vec<Vec<u8>> {
    let end = header_end(content);
    let (header, body) = content.split_at(end);
    let fields: Vec<&[u8]> = header_fields(header).collect();
    let parsed: Vec<Option<Signature>> = fields.iter().map(|field| signature(field)).collect();
    let signatures = parsed.iter().flatten().count();
    let mut candidates = Vec::new();
    for (index, found) in parsed.iter().enumerate() {
        let Some(found) = found else {
            continue;
        };
        if candidates.len() == MOST_SIGNATURES {
            break;
        }
        if !found.domain.as_deref().is_some_and(&enrolled) {
            continue;
        }
        let keep_others = found.signs_signatures;
        if keep_others && signatures > MOST_SIGNATURES {
            continue;
        }
        let mut message = Vec::with_capacity(content.len());
        for (at, field) in fields.iter().enumerate() {
            if at == index || keep_others || parsed[at].is_none() {
                message.extend_from_slice(field);
            }
        }
        message.extend_from_slice(body);
        candidates.push(message);
    }
    candidates
}

/// `field`'s parts, if it is a DKIM signature.
fn signature(field: &[u8]) -> Option<Signature> {
    let colon = field.iter().position(|byte| *byte == b':')?;
    if !field[..colon]
        .trim_ascii()
        .eq_ignore_ascii_case(b"dkim-signature")
    {
        return None;
    }
    let text = String::from_utf8_lossy(&field[colon + 1..]);
    let tags: Vec<(String, String)> = text
        .split(';')
        .filter_map(|tag| {
            let (name, value) = tag.split_once('=')?;
            let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
            Some((name.trim().to_owned(), value))
        })
        .collect();
    // A tag named twice makes the whole list invalid (RFC 6376, 3.2).
    let named = |name: &str| tags.iter().filter(|(tag, _)| tag == name).count();
    let domain = (named("d") == 1)
        .then(|| tags.iter().find(|(tag, _)| tag == "d"))
        .flatten()
        .map(|(_, value)| value.to_ascii_lowercase());
    let signs_signatures = tags.iter().any(|(tag, value)| {
        tag == "h"
            && value
                .split(':')
                .any(|name| name.eq_ignore_ascii_case("dkim-signature"))
    });
    Some(Signature {
        domain,
        signs_signatures,
    })
}

/// Where a message's header ends: after the empty line that closes it, or
/// at its end.
fn header_end(content: &[u8]) -> usize {
    let mut at = 0;
    while at < content.len() {
        let line_end = content[at..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(content.len(), |end| at + end + 1);
        let line = &content[at..line_end];
        if line == b"\r\n" || line == b"\n" {
            return at;
        }
        at = line_end;
    }
    content.len()
}

/// A header's fields, each with its folded lines and line ends.
fn header_fields(header: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut at = 0;
    std::iter::from_fn(move || {
        if at >= header.len() {
            return None;
        }
        let start = at;
        loop {
            let line_end = header[at..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(header.len(), |end| at + end + 1);
            at = line_end;
            if at >= header.len() || !matches!(header[at], b' ' | b'\t') {
                break;
            }
        }
        Some(&header[start..at])
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use engine_core::address::Address;
    use engine_core::id::{Id, Lane, MessageId, Shard};
    use engine_feedback::token::{self, Key};
    use engine_store::store::StoreOptions;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;
    use crate::tls;

    /// A certificate and key made for this test alone.
    const CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nMIIBizCCATGgAwIBAgIUPAn4y9GY9xOFjYZEPcImxP8m/iMwCgYIKoZIzj0EAwIw\nGjEYMBYGA1UEAwwPbXguYm91bmNlcy50ZXN0MCAXDTI2MTAyODA0NTMxM1oYDzIx\nMjYxMDA0MDQ1MzEzWjAaMRgwFgYDVQQDDA9teC5ib3VuY2VzLnRlc3QwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASPaUc/VaLjHIzgNSvb2BH9Ps42fGOwrbfDmplT\n5yFwN1pZHMNTlQbXTJQLuNaSMVUZyOjid845FGOpt3Y4ZvZao1MwUTAdBgNVHQ4E\nFgQUfmKikznPdTcZVfj/ZTfkrpYWtIwwHwYDVR0jBBgwFoAUfmKikznPdTcZVfj/\nZTfkrpYWtIwwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBx28vg\nHKxVvJ8T7HhchrFXB/rBZJ57Ok43agkhoNzTJwIhAKrAB/wgrVXXUkR8GdGFpOk2\n+B0ccQ6/GEby5pM0T+dG\n-----END CERTIFICATE-----";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVyInjvCtsGX89Nw\n3NEJRuoWpBJvpv0t7BLkYPeeN8ChRANCAASPaUc/VaLjHIzgNSvb2BH9Ps42fGOw\nrbfDmplT5yFwN1pZHMNTlQbXTJQLuNaSMVUZyOjid845FGOpt3Y4ZvZa\n-----END PRIVATE KEY-----";

    const SECRET: &[u8] = b"a secret of the installation for tests";

    async fn reply(reader: &mut BufReader<TcpStream>) -> String {
        let mut text = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            text.push_str(&line);
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return text;
            }
        }
    }

    async fn say(reader: &mut BufReader<TcpStream>, line: &str) -> String {
        reader.get_mut().write_all(line.as_bytes()).await.unwrap();
        reply(reader).await
    }

    #[test]
    fn each_enrolled_signature_is_checked_alone_unless_it_signs_the_others() {
        let signature = |domain: &str, signed: &str| {
            format!(
                "DKIM-Signature: v=1; a=rsa-sha256;\r\n\td = {domain} ; s=s1; h={signed}; b=x\r\n"
            )
        };
        let enrolled = |domain: &str| domain == "reporter.test";
        let tail = "From: <fbl@reporter.test>\r\nSubject: x\r\n\r\nbody\r\n";
        let mut header = signature("stranger.test", "from");
        for _ in 0..6 {
            header.push_str(&signature("Reporter.Test", "from"));
        }
        let content = format!("{header}{tail}");
        let checked = candidates(content.as_bytes(), enrolled);
        assert_eq!(checked.len(), MOST_SIGNATURES);
        for candidate in &checked {
            let text = String::from_utf8_lossy(candidate);
            assert_eq!(text.matches("DKIM-Signature").count(), 1, "{text}");
            assert!(!text.contains("stranger.test"));
            assert!(text.ends_with(tail));
        }
        // One that signs the others keeps them as they were.
        let content = format!(
            "{}{}{tail}",
            signature("stranger.test", "from"),
            signature("reporter.test", "from:dkim-signature")
        );
        let checked = candidates(content.as_bytes(), enrolled);
        assert_eq!(checked, [content.as_bytes().to_vec()]);
        // A domain named twice names none.
        let twice = format!("DKIM-Signature: d=reporter.test; d=slow.test; b=x\r\n{tail}");
        assert!(candidates(twice.as_bytes(), enrolled).is_empty());
        let unsigned = "From: <fbl@reporter.test>\r\n\r\nDKIM-Signature: d=reporter.test\r\n";
        assert!(
            candidates(unsigned.as_bytes(), enrolled).is_empty(),
            "a body is no header"
        );
    }

    #[tokio::test]
    async fn a_report_is_taken_for_a_return_path_recorded_and_relay_is_refused() {
        let directory =
            std::env::temp_dir().join(format!("nitromta-feedback-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let (certificate, key) = (directory.join("cert.pem"), directory.join("key.pem"));
        std::fs::write(&certificate, CERTIFICATE).unwrap();
        std::fs::write(&key, KEY).unwrap();
        let clock = Arc::new(SystemClock::new());
        let (scheduler, _scheduled) = tokio::sync::mpsc::unbounded_channel();
        let ring = Arc::new(engine_store::keys::Keyring::new(&[(1, [1; 32])]).unwrap());
        // No keys file here: a file of the test's own stands for it, and for
        // its hold.
        let held = directory.join("held");
        let hold = std::fs::File::create(&held).unwrap();
        let sealer =
            crate::sealing::Sealer::load(crate::config::Encryption::Off, Arc::clone(&ring), &held)
                .unwrap();
        let crate::store::Started { store, after, .. } = crate::store::start(
            &directory.join("store.db"),
            StoreOptions::default(),
            crate::store::Keys {
                ring,
                held: hold,
                sealer: Arc::new(sealer),
            },
            0,
            Arc::clone(&clock),
            scheduler,
            Arc::default(),
        )
        .unwrap();
        let rules = Arc::new(engine_rules::Rules::new(&std::collections::BTreeMap::new()).unwrap());
        let intake = || {
            Intake::new(
                vec![Key::new(SECRET)],
                "bounces.test",
                &[],
                Arc::clone(&rules),
            )
        };
        let feedback = Arc::new(Feedback {
            session: Arc::new(Config {
                role: engine_smtp::server::Role::Receiver,
                hostname: "mx.bounces.test".to_owned(),
                max_message_bytes: 1 << 20,
                max_recipients: 4,
                idle: Duration::from_secs(10),
            }),
            tls: tls::Certified::load(Path::new(&certificate), Path::new(&key)).unwrap(),
            intake: intake(),
            reporters: Reporters {
                domains: Vec::new(),
                authenticator: None,
            },
            store: store.clone(),
            ids: Mutex::new(IdGenerator::new(
                Shard::new(0),
                Lane::new(3).unwrap(),
                after,
            )),
            clock: Arc::clone(&clock),
            stop: Arc::default(),
            operations: Arc::default(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(Arc::clone(&feedback).serve(listener));

        let message = MessageId(Id::from_u64(1 << 40).unwrap());
        let return_path = format!(
            "{}@bounces.test",
            token::local_part(&Key::new(SECRET), message)
        );
        let report = "Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\r\n--b\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.example.net\r\n\r\nFinal-Recipient: rfc822; gone@example.net\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n--b--\r\n";

        let mut reader = BufReader::new(TcpStream::connect(address).await.unwrap());
        assert!(reply(&mut reader).await.starts_with("220 mx.bounces.test"));
        assert!(
            say(&mut reader, "EHLO mx.example.net\r\n")
                .await
                .contains("250 STARTTLS")
        );
        assert!(
            say(&mut reader, "MAIL FROM:<>\r\n")
                .await
                .starts_with("250")
        );
        assert!(
            say(&mut reader, "RCPT TO:<someone@elsewhere.test>\r\n")
                .await
                .starts_with("550 5.1.1"),
            "relay is refused"
        );
        let taken = say(&mut reader, &format!("RCPT TO:<{return_path}>\r\n")).await;
        assert!(taken.starts_with("250"), "{taken}");
        assert!(say(&mut reader, "DATA\r\n").await.starts_with("354"));
        let recorded = say(&mut reader, &format!("{report}.\r\n")).await;
        assert_eq!(recorded, "250 2.0.0 Report recorded\r\n");
        assert!(say(&mut reader, "QUIT\r\n").await.starts_with("221"));

        // The store holds it: the same report again is one it has.
        let recipients = [Address::parse(&return_path).unwrap()];
        let again = intake().report(
            ReportId(Id::from_u64((2 << 40) | 3 << 9).unwrap()),
            &recipients,
            report.as_bytes(),
            clock.now().wall,
            false,
        );
        match store.ask(Command::RecordFeedback(again)).await {
            Some(Answer::Feedback(Commit::Committed(recorded))) => assert!(recorded.duplicate),
            other => panic!("expected the report recorded before, got {other:?}"),
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
