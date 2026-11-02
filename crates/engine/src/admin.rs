//! The admin service: the native API on a local socket. Only the
//! engine's own user, or root, may use it: the socket is readable by its
//! owner alone, and every connection's peer is checked as well, since a
//! client could connect between the bind and the change of mode.
//!
//! A connection's requests go to the store as they are read, without
//! waiting for the one before, and are answered in the order they came.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::future::Future;
use std::pin::Pin;

use engine_api::inspect::{self, Asked};
use engine_api::native::{self, Entropy, Issued, MAX_REQUEST_BYTES, Refusal};
use engine_api::{backup, drain, list, parked, sealing};
use engine_core::command::{Answer, Command, Commit, FenceDecision};
use engine_core::id::{Id, IdGenerator};
use engine_scheduler::{Inspection, Report};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedReadHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use crate::clock::SystemClock;
use crate::events::Replays;
use crate::operator::Operations;
use crate::policy::Current;
use crate::scheduler::Inspections;
use crate::store::Store;

pub struct Admin {
    pub store: Store,
    pub clock: Arc<SystemClock>,
    /// The IDs of the records requests create.
    pub ids: Mutex<IdGenerator>,
    /// Where `explain` and `queue` ask the scheduler.
    pub scheduler: tokio::sync::mpsc::UnboundedSender<engine_scheduler::Input>,
    pub inspections: Arc<Inspections>,
    /// Where `replay` asks event delivery.
    pub replays: Arc<Replays>,
    /// The policy `list` shows.
    pub policy: Arc<Current>,
    /// The counts and the drain flag `drain` reads and sets.
    pub operations: Arc<Operations>,
    /// The installation key every secret is sealed under, and
    /// the full paths of the keys file the engine holds and the store it
    /// seals, so `key retire` knows it asked the engine using them.
    pub sealing: u8,
    pub keys_file: String,
    pub store_file: String,
    /// Makes a tenant's key before it is created.
    pub sealer: Arc<crate::sealing::Sealer>,
}

/// The bound socket, and the user who owns it.
pub struct Listener {
    listener: UnixListener,
    owner: u32,
}

/// Binds the admin socket at `path`, replacing one left by an engine that
/// has stopped, and makes it its owner's alone.
pub fn bind(path: &Path) -> Result<Listener, String> {
    let failed =
        |error: &dyn std::fmt::Display| format!("the admin socket {}: {error}", path.display());
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(failed(&"another engine is serving it"));
            }
            std::fs::remove_file(path).map_err(|error| failed(&error))?;
        }
        Ok(_) => return Err(failed(&"something other than a socket is there")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(failed(&error)),
    }
    let listener = UnixListener::bind(path).map_err(|error| failed(&error))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| failed(&error))?;
    let owner = std::fs::metadata(path)
        .map_err(|error| failed(&error))?
        .uid();
    Ok(Listener { listener, owner })
}

/// Requests a session may have sent to the store and not yet answered:
/// enough that a bulk load shares commit groups, few enough to bound what a
/// session holds.
const IN_FLIGHT: usize = 1024;

/// A request's answer, in the order the requests came.
enum Pending {
    /// Answered before it reached the store.
    Ready(Vec<u8>),
    /// Sent to the store, with the secret it issued.
    Sent(oneshot::Receiver<Answer>, Option<Issued>),
    /// An inspection under way, which makes its own line.
    Inspecting(Pin<Box<dyn Future<Output = Vec<u8>> + Send>>),
    /// A listing of policy, made as its turn to be written comes, so it
    /// shows what the session's earlier changes made: policy is published
    /// before a change is answered.
    Listing(list::Asked),
}

impl Admin {
    pub async fn serve(self: Arc<Self>, listener: Listener) -> Result<(), String> {
        let owner = listener.owner;
        loop {
            match listener.listener.accept().await {
                Ok((stream, _)) => {
                    let permitted = stream
                        .peer_cred()
                        .is_ok_and(|peer| peer.uid() == owner || peer.uid() == 0);
                    if permitted {
                        tokio::spawn(Arc::clone(&self).session(stream));
                    }
                }
                // Out of descriptors, for one: the next connection may fare
                // better.
                Err(error) => {
                    tracing::warn!(%error, "accepting an admin connection");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Reads requests and sends each to the store without waiting for the
    /// one before, while their answers are written in the order the
    /// requests came.
    async fn session(self: Arc<Self>, stream: UnixStream) {
        let (read, mut write) = stream.into_split();
        let (pending, mut answers) = mpsc::channel(IN_FLIGHT);
        let policy = Arc::clone(&self.policy);
        let writer = async move {
            while let Some(answer) = answers.recv().await {
                let line = match answer {
                    Pending::Ready(line) => line,
                    Pending::Listing(asked) => list::listed(policy.load().policy(), asked),
                    Pending::Sent(answer, issued) => {
                        native::reply(answer.await.ok(), issued.as_ref())
                    }
                    Pending::Inspecting(inspection) => inspection.await,
                };
                if write.write_all(&line).await.is_err() {
                    return;
                }
            }
        };
        tokio::join!(self.read(read, pending), writer);
    }

    async fn read(&self, read: OwnedReadHalf, pending: mpsc::Sender<Pending>) {
        let mut read = BufReader::new(read);
        let mut line = Vec::new();
        loop {
            line.clear();
            let limit = MAX_REQUEST_BYTES as u64 + 1;
            match (&mut read).take(limit).read_until(b'\n', &mut line).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let ended = line.last() == Some(&b'\n');
            if !ended && line.len() > MAX_REQUEST_BYTES {
                let refused = native::refused(&Refusal::TooLarge);
                let _ = pending.send(Pending::Ready(refused)).await;
                return;
            }
            if let Some(asked) = inspect::asked(&line) {
                let answer = match asked {
                    Ok(asked) => Pending::Inspecting(Box::pin(self.inspection(asked))),
                    Err(refused) => Pending::Ready(refused),
                };
                if pending.send(answer).await.is_err() {
                    return;
                }
                continue;
            }
            if let Some(asked) = sealing::asked(&line) {
                let answer = match asked {
                    Ok(sealing::Asked::Keys) => {
                        sealing::answered(self.sealing, &self.keys_file, &self.store_file)
                    }
                    Ok(sealing::Asked::KeyHeld { key, from }) => {
                        match self.store.ask(Command::KeyHeld { key, from }).await {
                            Some(Answer::KeyHeld(Ok(page))) => sealing::held(&page),
                            _ => native::reply(None, None),
                        }
                    }
                    Err(refused) => refused,
                };
                if pending.send(Pending::Ready(answer)).await.is_err() {
                    return;
                }
                continue;
            }
            if let Some(asked) = drain::asked(&line) {
                let answer = match asked {
                    Ok(asked) => {
                        let draining = asked == drain::Asked::Drain;
                        if draining {
                            tracing::info!(
                                "draining: no new mail is taken while the queue is delivered"
                            );
                        } else {
                            tracing::info!("taking new mail again");
                        }
                        // The flag is set as the line is read; the answer
                        // waits for the acceptances already past it.
                        self.operations.drain(draining);
                        let operations = Arc::clone(&self.operations);
                        Pending::Inspecting(Box::pin(async move {
                            if draining {
                                operations.settled().await;
                            }
                            drain::answered(&operations.outstanding())
                        }))
                    }
                    Err(refused) => Pending::Ready(refused),
                };
                if pending.send(answer).await.is_err() {
                    return;
                }
                continue;
            }
            if let Some(asked) = backup::asked(&line) {
                let answer = match asked {
                    Ok(asked) => Pending::Inspecting(Box::pin(self.copying(asked))),
                    Err(refused) => Pending::Ready(refused),
                };
                if pending.send(answer).await.is_err() {
                    return;
                }
                continue;
            }
            if let Some(asked) = list::asked(&line) {
                let answer = match asked {
                    Ok(asked) => Pending::Listing(asked),
                    Err(refused) => Pending::Ready(refused),
                };
                if pending.send(answer).await.is_err() {
                    return;
                }
                continue;
            }
            if let Some(asked) = parked::asked(&line) {
                let answer = match asked {
                    Ok(asked) => Pending::Inspecting(Box::pin(self.parked(asked))),
                    Err(refused) => Pending::Ready(refused),
                };
                if pending.send(answer).await.is_err() {
                    return;
                }
                continue;
            }
            let now = self.clock.now().wall;
            let parsed = native::command(&line, now, || self.new_id(), entropy);
            let answer = match parsed {
                // A tenant's key is made before the change creating it is
                // asked, and kept while it is.
                Ok(parsed) if self.sealer.creates(&parsed.command).is_some() => {
                    match self
                        .sealer
                        .ask(&self.store, &self.policy, parsed.command)
                        .await
                    {
                        Ok(answer) => Pending::Ready(native::reply(answer, parsed.issued.as_ref())),
                        Err(why) => {
                            tracing::error!(why = %why, "a tenant's key could not be made");
                            Pending::Ready(native::reply(None, None))
                        }
                    }
                }
                Ok(parsed) => match self.store.submit(parsed.command) {
                    Some(answer) => Pending::Sent(answer, parsed.issued),
                    None => Pending::Ready(native::reply(None, None)),
                },
                Err(refusal) => Pending::Ready(native::refused(&refusal)),
            };
            if pending.send(answer).await.is_err() {
                return;
            }
        }
    }

    /// Carries an inspection out: `explain` reads the store's records and
    /// then asks the scheduler where it holds them; `queue` asks the
    /// scheduler, beside the store's counts.
    fn inspection(&self, asked: Asked) -> impl Future<Output = Vec<u8>> + Send + 'static {
        let (store, scheduler) = (self.store.clone(), self.scheduler.clone());
        let inspections = Arc::clone(&self.inspections);
        let operations = Arc::clone(&self.operations);
        async move {
            let ask = |inspection| inspections.ask(&scheduler, inspection);
            let stopped = || native::reply(None, None);
            match asked {
                Asked::Explain(inspect) => {
                    let Some(Answer::Inspected(Ok(deliveries))) =
                        store.ask(Command::Inspect(inspect)).await
                    else {
                        return stopped();
                    };
                    let ids = deliveries
                        .iter()
                        .map(|inspected| inspected.delivery.id())
                        .collect();
                    let report = ask(Inspection::Explain(ids))
                        .await
                        .unwrap_or(Report::Holds(Vec::new()));
                    inspect::explained(&deliveries, &report)
                }
                Asked::Queue { most } => match ask(Inspection::Queues { most }).await {
                    Ok(report) => {
                        // One snapshot, so a delivery between states is
                        // counted in one of them.
                        let queued = *operations
                            .queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let stored = inspect::Stored {
                            waiting: queued.waiting,
                            in_flight: queued.in_flight,
                            held: queued.held,
                        };
                        inspect::queued(&report, stored)
                    }
                    Err(_) => stopped(),
                },
            }
        }
    }

    /// Carries a parked-events request out: `parked` reads the store, and
    /// `replay` asks event delivery.
    fn parked(&self, asked: parked::Asked) -> impl Future<Output = Vec<u8>> + Send + 'static {
        let (store, replays) = (self.store.clone(), Arc::clone(&self.replays));
        async move {
            match asked {
                parked::Asked::Parked {
                    account,
                    subscription,
                    from,
                } => {
                    let read = Command::ParkedEvents {
                        account,
                        subscription,
                        from,
                        limit: parked::PAGE + 1,
                    };
                    parked::listed(store.ask(read).await)
                }
                parked::Asked::Replay {
                    account,
                    subscription,
                    batch,
                } => parked::replaying(replays.ask(account, subscription, batch).await.ok()),
            }
        }
    }

    /// A backup, or the store's fence or a decision on it, and
    /// its answer: a decision is answered with the fence it leaves.
    fn copying(&self, asked: backup::Asked) -> impl Future<Output = Vec<u8>> + Send + 'static {
        let store = self.store.clone();
        async move {
            let fenced = async |store: &Store| match store.ask(Command::Fenced).await {
                Some(Answer::Fenced(Ok(fence))) => backup::fenced(fence),
                _ => native::reply(None, None),
            };
            let decision = match asked {
                backup::Asked::Backup { to } => {
                    return match store.backup(std::path::PathBuf::from(&to)).await {
                        Ok(copied) => backup::copied(&to, copied.bytes, copied.taken),
                        Err(why) => backup::not_copied(&why),
                    };
                }
                backup::Asked::Fence => return fenced(&store).await,
                backup::Asked::Release => FenceDecision::Release,
                backup::Asked::Discard => FenceDecision::Discard,
            };
            match store.ask(Command::DecideFence(decision)).await {
                Some(Answer::FenceDecided(Commit::Committed(_))) => {
                    tracing::warn!(decision = ?decision, "the operator decided on the store's fence");
                    fenced(&store).await
                }
                Some(Answer::FenceDecided(Commit::Refused(_))) => backup::unfenced(),
                _ => native::reply(None, None),
            }
        }
    }

    fn new_id(&self) -> Id {
        let now = self.clock.now().wall;
        self.ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next(now)
    }
}

/// Randomness for a secret, from the operating system.
fn entropy() -> Option<Entropy> {
    let mut bytes = [0; 32];
    aws_lc_rs::rand::fill(&mut bytes).ok()?;
    Some(bytes)
}

/// How long a command waits for the engine's answers, in all, and the most
/// bytes they may come to: a listing of a large policy's every identity,
/// each with its DKIM key, is a few megabytes.
const ASK_PATIENCE: Duration = Duration::from_secs(60);
const ASK_MOST_BYTES: usize = 256 << 20;

/// Sends `requests` to the admin socket at `socket`, one a line, and returns
/// their answers, in the order sent: within a minute, and 256 MiB, so a
/// stalled engine or a runaway answer ends the command rather than holding
/// it.
pub fn ask(
    socket: &Path,
    requests: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, String> {
    ask_within(socket, requests, ASK_PATIENCE, ASK_MOST_BYTES)
}

/// How long a backup is waited for: a large store's copy takes minutes.
const BACKUP_PATIENCE: Duration = Duration::from_secs(6 * 3600);

/// Asks the running engine for a backup, which takes as long as its store
/// takes to copy.
pub fn ask_backup(socket: &Path, request: &serde_json::Value) -> Result<serde_json::Value, String> {
    let mut answers = ask_within(
        socket,
        std::slice::from_ref(request),
        BACKUP_PATIENCE,
        ASK_MOST_BYTES,
    )?;
    Ok(answers.remove(0))
}

fn ask_within(
    socket: &Path,
    requests: &[serde_json::Value],
    patience: Duration,
    most: usize,
) -> Result<Vec<serde_json::Value>, String> {
    let failed =
        |error: &dyn std::fmt::Display| format!("the admin socket {}: {error}", socket.display());
    let mut lines = Vec::new();
    for request in requests {
        lines.extend_from_slice(request.to_string().as_bytes());
        lines.push(b'\n');
    }
    // The exchange on a thread of its own, which the patience bounds from
    // the connection on, whatever blocks: a connection waiting on a full
    // backlog, a write the engine does not read, or an answer that never
    // ends. A thread left blocked ends with the command.
    let (answered, answer) = std::sync::mpsc::channel();
    let path = socket.to_owned();
    std::thread::spawn(move || {
        let _ = answered.send(exchange(&path, &lines, most));
    });
    let answered = match answer.recv_timeout(patience) {
        Ok(answered) => answered.map_err(|error| failed(&error))?,
        Err(_) => return Err(failed(&"the engine did not answer in time")),
    };
    if answered.last().is_some_and(|last| *last != b'\n') {
        return Err(failed(
            &"the engine ended the session part way through an answer",
        ));
    }
    let answers: Vec<serde_json::Value> = answered
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|error| failed(&error)))
        .collect::<Result<_, _>>()?;
    if answers.len() != requests.len() {
        return Err(failed(&"the engine ended the session before it answered"));
    }
    Ok(answers)
}

/// Sends `lines` to the socket at `path` and reads its answers to their end:
/// at most `most` bytes of them.
fn exchange(path: &Path, lines: &[u8], most: usize) -> Result<Vec<u8>, String> {
    use std::io::{Read as _, Write as _};
    let mut stream =
        std::os::unix::net::UnixStream::connect(path).map_err(|error| error.to_string())?;
    stream.write_all(lines).map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut answered = Vec::new();
    // One byte past the bound shows the answer is past it.
    (&mut stream)
        .take(u64::try_from(most).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut answered)
        .map_err(|error| error.to_string())?;
    if answered.len() > most {
        return Err(format!(
            "the engine's answer is too large for a command, past {most} bytes"
        ));
    }
    Ok(answered)
}

/// `nitromta admin`: sends each line of standard input to the admin socket
/// and writes each answer to standard output, as they come.
pub fn client(socket: &Path) -> Result<(), String> {
    let failed =
        |error: &dyn std::fmt::Display| format!("the admin socket {}: {error}", socket.display());
    let stream = std::os::unix::net::UnixStream::connect(socket).map_err(|error| failed(&error))?;
    let mut to = stream.try_clone().map_err(|error| failed(&error))?;
    let (sent, sending) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = std::io::copy(&mut std::io::stdin().lock(), &mut to);
        let _ = to.shutdown(std::net::Shutdown::Write);
        let _ = sent.send(result);
    });
    std::io::copy(&mut &stream, &mut std::io::stdout().lock()).map_err(|error| failed(&error))?;
    // The engine closes the session only once it has read the end of the
    // input, so the input is all sent unless the engine ended the session
    // first, while the input was still being read.
    match sending.recv_timeout(Duration::from_secs(1)) {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(failed(&error)),
        Err(_) => Err(failed(&"the engine ended the session before the input did")),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;

    use serde_json::json;

    use super::*;

    /// A peer on a socket of its own that reads the requests to their end
    /// and answers with `answer`, then waits `then` before it closes.
    fn peer(name: &str, answer: &'static [u8], then: Duration) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("nitromta-ask-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut requests = Vec::new();
            let _ = stream.read_to_end(&mut requests);
            let _ = stream.write_all(answer);
            std::thread::sleep(then);
        });
        path
    }

    #[test]
    fn an_answer_stalled_cut_short_or_too_large_ends_the_command() {
        let requests = [json!({"op": "keys"})];
        let patience = Duration::from_millis(300);
        let answered = peer("answered", b"{\"ok\":{\"sealing\":1}}\n", Duration::ZERO);
        assert_eq!(
            ask_within(&answered, &requests, patience, 1024),
            Ok(vec![json!({"ok": {"sealing": 1}})])
        );
        let stalled = peer("stalled", b"", Duration::from_secs(5));
        assert!(
            ask_within(&stalled, &requests, patience, 1024)
                .is_err_and(|why| why.contains("did not answer in time"))
        );
        let cut = peer("cut", b"{\"ok\":", Duration::ZERO);
        assert!(
            ask_within(&cut, &requests, patience, 1024)
                .is_err_and(|why| why.contains("part way through an answer"))
        );
        let large = peer("large", &[b' '; 4096], Duration::ZERO);
        assert!(
            ask_within(&large, &requests, patience, 1024)
                .is_err_and(|why| why.contains("too large for a command"))
        );
        let none = peer("none", b"", Duration::ZERO);
        assert!(
            ask_within(&none, &requests, patience, 1024)
                .is_err_and(|why| why.contains("before it answered"))
        );
        for path in [answered, stalled, cut, large, none] {
            let _ = std::fs::remove_file(path);
        }
    }
}
