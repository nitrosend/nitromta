//! The commit owner on a thread of its own, over the store's SQLite file.
//!
//! Commands arrive on a channel from every part of the engine. Whatever has
//! arrived when the commit owner is free goes to it together, so while one
//! group's sync is under way the next group gathers: group commit with no
//! timer. Each answer goes back the way its command came, once
//! any policy the group changed is published to the adapters.
//!
//! Once a second the thread reads the store's size and its disk's free
//! space; below the reserve, new mail is refused until space is free again.
//! A store left by a stop that did not close it is checked at
//! start, and the engine does not start on one that is damaged.
//!
//! A backup runs on the thread too: a step of pages between
//! turns, each of which commits what came meanwhile, so commits go first.
//! The store's connection is opened on the thread, and shared there alone
//! between the commit owner and a backup.

use std::collections::BTreeMap;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;

use engine_core::command::{Answer, Command, Request, Response};
use engine_core::component::{Component, Ticket};
use engine_core::id::Id;
use engine_core::time::{Monotonic, Timestamp};
use engine_store::commit_owner::{CommitOwner, GroupLimits};
use engine_store::keys::Keyring;
use engine_store::store::{Store as SqliteStore, StoreOptions};
use rusqlite::Connection;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};

use crate::backup::{self, Copied};
use crate::clock::SystemClock;
use crate::operator::Operations;
use crate::policy::Current;

/// How often the store's size and its disk's free space are read.
const MEASURE_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// A group slower than this is reported: it holds up every command behind
/// it.
const SLOW_GROUP: std::time::Duration = std::time::Duration::from_millis(200);

enum Route {
    Caller(oneshot::Sender<Answer>),
    /// The scheduler's request, under its own ticket.
    Scheduler(Ticket),
}

struct Envelope {
    command: Command,
    route: Route,
    /// An acceptance's bytes, counted as waiting for their commit, kept
    /// until the command is answered.
    waiting: Option<Waiting>,
}

/// An acceptance counted as waiting for its commit, with its bytes,
/// from before it reads the drain's flag until the commit owner
/// answers it, whether or not anyone still waits for the answer.
struct Waiting {
    operations: Arc<Operations>,
    bytes: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.operations
            .pending_bytes
            .fetch_sub(self.bytes, Ordering::Relaxed);
        self.operations.accepting.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A drain began before an acceptance was sent, so it was not.
pub struct Draining;

/// What the thread takes: a command, or a backup to make. A command is the
/// size its envelope always was; boxing it would allocate for each.
#[allow(clippy::large_enum_variant)]
enum Work {
    Command(Envelope),
    Backup(BackupRequest),
}

struct BackupRequest {
    to: PathBuf,
    reply: oneshot::Sender<Result<Copied, String>>,
}

/// A handle on the store, for any part of the engine.
#[derive(Clone)]
pub struct Store {
    sender: mpsc::Sender<Work>,
    operations: Arc<Operations>,
}

impl Store {
    /// Sends a command and waits for its answer. `None` when the store has
    /// stopped.
    pub async fn ask(&self, command: Command) -> Option<Answer> {
        self.submit(command)?.await.ok()
    }

    /// As [`Store::ask`], for an acceptance: counted, with its `bytes`, as
    /// waiting for its commit until the commit owner answers, past which
    /// new mail is refused; and not sent once a drain has begun,
    /// which it reads only once it is counted.
    pub async fn ask_accepting(
        &self,
        command: Command,
        bytes: u64,
    ) -> Result<Option<Answer>, Draining> {
        self.operations
            .pending_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        self.operations.accepting.fetch_add(1, Ordering::SeqCst);
        let waiting = Waiting {
            operations: Arc::clone(&self.operations),
            bytes,
        };
        if self.operations.draining.load(Ordering::SeqCst) {
            return Err(Draining);
        }
        Ok(match self.send(command, Some(waiting)) {
            Some(answer) => answer.await.ok(),
            None => None,
        })
    }

    /// Sends a command now, in order with every command sent before it, and
    /// returns where its answer will arrive. `None` when the store has
    /// stopped.
    pub fn submit(&self, command: Command) -> Option<oneshot::Receiver<Answer>> {
        self.send(command, None)
    }

    fn send(
        &self,
        command: Command,
        waiting: Option<Waiting>,
    ) -> Option<oneshot::Receiver<Answer>> {
        let (reply, answer) = oneshot::channel();
        let envelope = Envelope {
            command,
            route: Route::Caller(reply),
            waiting,
        };
        self.sender.send(Work::Command(envelope)).ok()?;
        Some(answer)
    }

    /// Copies the store to `to`, a step between commit groups, and answers
    /// once the copy is in place.
    pub async fn backup(&self, to: PathBuf) -> Result<Copied, String> {
        let (reply, copied) = oneshot::channel();
        self.sender
            .send(Work::Backup(BackupRequest { to, reply }))
            .map_err(|_| "the store has stopped".to_owned())?;
        copied
            .await
            .map_err(|_| "the store stopped before the copy was complete".to_owned())?
    }

    /// Sends the scheduler's request; its answer goes to the scheduler.
    pub fn send_for_scheduler(&self, request: Request) {
        let _ = self.sender.send(Work::Command(Envelope {
            command: request.command,
            route: Route::Scheduler(request.ticket),
            waiting: None,
        }));
    }
}

/// Opens the store, recovers attempts that were in flight, and starts the
/// commit owner's thread. Returns the handle, the policy the adapters read,
/// and the highest ID the store holds, after which new IDs must start.
pub fn start(
    path: &Path,
    options: StoreOptions,
    keys: Keys,
    reserve: u64,
    clock: Arc<SystemClock>,
    scheduler: tokio_mpsc::UnboundedSender<engine_scheduler::Input>,
    operations: Arc<Operations>,
) -> Result<Started, String> {
    let Keys {
        ring: keys,
        held,
        sealer,
    } = keys;
    let failed =
        |error: &dyn std::fmt::Display| format!("the store at {}: {error}", path.display());
    protect(path).map_err(|error| failed(&error))?;
    // SQLite opens the file a link names: its log, and the disk measured,
    // are beside that file.
    let path = &std::fs::canonicalize(path).map_err(|error| failed(&error))?;
    // The sidecars SQLite uses are the target's, which an earlier run may
    // have left readable.
    protect(path).map_err(|error| failed(&error))?;
    // A clean stop closes the store, which takes its write-ahead log away:
    // one left behind means the last stop did not.
    let mut log = path.as_os_str().to_owned();
    log.push("-wal");
    if std::fs::metadata(&log).is_ok_and(|log| log.len() > 0) {
        // On a connection of its own, which never checkpoints as it closes,
        // so a damaged store keeps its log, and the next start checks it
        // again.
        let started = std::time::Instant::now();
        let checking = Connection::open(path).map_err(|error| failed(&error))?;
        checking
            .set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .map_err(|error| failed(&error))?;
        engine_store::store::quick_check(&checking).map_err(|error| {
            failed(&format!(
                "{error}; it is damaged, and the engine does not start on it: restore it from a backup, or keep it as evidence"
            ))
        })?;
        drop(checking);
        tracing::info!(
            ms = started.elapsed().as_millis(),
            "the store was not closed at the last stop; its check found nothing wrong"
        );
    }
    let (sender, receiver) = mpsc::channel();
    let disk = Disk {
        directory: path
            .parent()
            .filter(|directory| !directory.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned(),
        reserve,
    };
    // Measured before anything is accepted.
    measure(&disk, &operations);
    let handle = Store {
        sender,
        operations: Arc::clone(&operations),
    };
    // Opened on the thread that keeps it, which shares its connection with
    // a backup, and says what it found.
    let (opened, opening) = mpsc::sync_channel(1);
    let shown = path.display().to_string();
    let path = path.clone();
    let thread = std::thread::Builder::new()
        .name("commit-owner".to_owned())
        .spawn(move || {
            let failed = |error: &dyn std::fmt::Display| format!("the store at {shown}: {error}");
            let started = (|| {
                let connection = Rc::new(Connection::open(&path).map_err(|error| failed(&error))?);
                let source = Rc::clone(&connection);
                let mut store =
                    SqliteStore::open(connection, options, keys).map_err(|error| failed(&error))?;
                // Every tenant's key, in step with the policy it opened with,
                // before recovery or any command reads or writes a record of
                // its mail: one written for a tenant with no key
                // would keep nothing.
                let present = store.policy().tenants().map(|tenant| tenant.id).collect();
                let fenced = store.policy().fence().is_some();
                for (tenant, key) in &sealer
                    .settle(&present, fenced)
                    .map_err(|why| failed(&why))?
                {
                    store.add_tenant_key(*tenant, key);
                }
                let after = store.highest_id().map_err(|error| failed(&error))?;
                let policy = Arc::new(
                    Current::new(Arc::clone(store.policy())).map_err(|error| failed(&error))?,
                );
                let (owner, abandoned) =
                    CommitOwner::start(store, GroupLimits::default(), clock.now().wall)
                        .map_err(|error| failed(&error))?;
                Ok::<_, String>((owner, source, policy, after, abandoned.len()))
            })();
            match started {
                Ok((owner, source, policy, after, abandoned)) => {
                    let _ = opened.send(Ok((Arc::clone(&policy), after, abandoned)));
                    run(
                        owner,
                        &source,
                        &receiver,
                        &clock,
                        &scheduler,
                        &policy,
                        &operations,
                        &disk,
                    );
                    // The store closes with the last handle on its
                    // connection, and only then does the keys' hold go.
                    drop(source);
                    drop(held);
                }
                Err(why) => {
                    let _ = opened.send(Err(why));
                }
            }
        })
        .map_err(|error| failed(&error))?;
    let (policy, after, abandoned) = opening
        .recv()
        .map_err(|_| failed(&"its thread stopped as it opened it"))??;
    if abandoned > 0 {
        tracing::warn!(
            attempts = abandoned,
            "attempts were in flight when the store last stopped; they are recorded as abandoned and retried"
        );
    }
    Ok(Started {
        store: handle,
        policy,
        after,
        thread,
    })
}

/// The installation's keys, and the hold on their file, which the
/// store's thread keeps until the store is closed.
pub struct Keys {
    pub ring: Arc<Keyring>,
    pub held: std::fs::File,
    /// Tenants' keys, settled with the store's policy and given
    /// to it before it reads any record.
    pub sealer: Arc<crate::sealing::Sealer>,
}

/// The store, started: the handle every part of the engine uses, the policy
/// the adapters read, the highest ID the store holds, after which new IDs
/// must start, and the commit owner's thread, which ends, closing the store,
/// once every handle is gone.
pub struct Started {
    pub store: Store,
    pub policy: Arc<Current>,
    pub after: Option<Id>,
    pub thread: std::thread::JoinHandle<()>,
}

/// The disk the store is on: its directory, and the space kept free on it.
struct Disk {
    directory: std::path::PathBuf,
    reserve: u64,
}

impl Disk {
    /// The space free to the engine, if the system says.
    fn free(&self) -> Option<u64> {
        let stats = rustix::fs::statvfs(&self.directory).ok()?;
        Some(stats.f_bavail.saturating_mul(stats.f_frsize))
    }
}

/// Reads the disk's free space, and refuses new mail below the reserve, or
/// while the space cannot be read (fail closed). Each crossing is logged
/// once.
/// The queue's depth, by state, and its age and lag, and how far behind
/// the furthest-behind subscription is: counts the store keeps,
/// and a few index seeks.
/// The unfinished deliveries by state, as the store counts them: for the
/// metrics each alone, and for a drain together.
fn queued(store: &SqliteStore<Rc<Connection>>, operations: &Operations) {
    let queued = store.queued();
    *operations
        .queue
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = crate::operator::Queued {
        waiting: queued.waiting,
        in_flight: queued.in_flight,
        held: queued.held,
    };
    operations
        .queue_waiting
        .store(queued.waiting, Ordering::Relaxed);
    operations
        .queue_in_flight
        .store(queued.in_flight, Ordering::Relaxed);
    operations.queue_held.store(queued.held, Ordering::Relaxed);
}

fn queue_and_lag(store: &SqliteStore<Rc<Connection>>, now: Timestamp, operations: &Operations) {
    let set = |gauge: &AtomicU64, value: u64| gauge.store(value, Ordering::Relaxed);
    let age =
        |at: Option<Timestamp>| at.map_or(0, |at| now.saturating_duration_since(at).as_secs());
    if let Ok((oldest, due)) = store.queue_times() {
        set(&operations.queue_oldest_seconds, age(oldest));
        set(&operations.queue_due_lag_seconds, age(due));
    }
    if let Ok(lag) = store.event_lag() {
        set(
            &operations.event_lag_entries,
            lag.map_or(0, |lag| lag.entries),
        );
        set(
            &operations.event_lag_seconds,
            age(lag.and_then(|lag| lag.since)),
        );
    }
}

fn measure(disk: &Disk, operations: &Operations) {
    let free = disk.free();
    operations
        .store_free_bytes
        .store(free.unwrap_or(0), Ordering::Relaxed);
    let low = free.is_none_or(|free| free < disk.reserve);
    if operations.disk_low.swap(low, Ordering::Relaxed) == low {
        return;
    }
    let reserve_mib = disk.reserve >> 20;
    match free {
        None => tracing::error!(
            directory = %disk.directory.display(),
            "the store's disk does not say how much space is free: new mail is refused until it does"
        ),
        Some(free) if low => tracing::warn!(
            free_mib = free >> 20,
            reserve_mib,
            "the store's disk is below its reserve: new mail is refused until space is free"
        ),
        Some(free) => tracing::info!(
            free_mib = free >> 20,
            reserve_mib,
            "the store's disk has its reserve again"
        ),
    }
}

/// Runs SQLite's quick check on the stopped store at `path`.
pub fn quick_check(path: &Path) -> Result<(), String> {
    let failed = |error: &dyn std::fmt::Display| format!("store: {}: {error}", path.display());
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| failed(&error))?;
    engine_store::store::quick_check(&connection).map_err(|error| failed(&error))
}

/// Brings the stopped store at `path` up to the schema this release
/// writes, as its next start would, and says from which version to which.
pub fn migrate(path: &Path) -> Result<(), String> {
    let failed =
        |error: &dyn std::fmt::Display| format!("the store at {}: {error}", path.display());
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|error| failed(&error))?;
    match engine_store::store::migrate(&connection) {
        Ok((from, to)) if from == to => {
            println!(
                "the store at {} is at schema version {to}, this release's",
                path.display()
            );
            Ok(())
        }
        Ok((from, to)) => {
            println!(
                "the store at {} is at schema version {to}, from {from}",
                path.display()
            );
            Ok(())
        }
        Err(engine_store::store::StoreError::Sqlite(error))
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) =>
        {
            Err(failed(&"the engine holds it; stop the engine first"))
        }
        Err(error) => Err(failed(&error)),
    }
}

/// Checks the store at `path` with SQLite's full integrity check, while the
/// engine is stopped: it holds the store alone while it runs.
pub fn check(path: &Path) -> Result<(), String> {
    let failed =
        |error: &dyn std::fmt::Display| format!("the store at {}: {error}", path.display());
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| failed(&error))?;
    let started = std::time::Instant::now();
    match engine_store::store::verify(&connection) {
        Ok(()) => {
            println!(
                "the store at {} is sound ({} ms)",
                path.display(),
                started.elapsed().as_millis()
            );
            Ok(())
        }
        Err(engine_store::store::StoreError::Sqlite(error))
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) =>
        {
            Err(failed(&"the engine holds it; stop the engine first"))
        }
        Err(error) => Err(failed(&error)),
    }
}

/// Makes the store its owner's alone, since it holds access keys' secrets
/// and signing keys: created so if it is new, and made so if it is not.
/// SQLite creates its log and the log's index with the database's own
/// mode, and any left by an earlier run are made its owner's too.
fn protect(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        match std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

/// The store's thread: turn after turn, and a backup when one is asked for,
/// a step of it between turns.
#[allow(clippy::too_many_arguments)]
fn run(
    owner: CommitOwner<Rc<Connection>>,
    source: &Connection,
    receiver: &mpsc::Receiver<Work>,
    clock: &SystemClock,
    scheduler: &tokio_mpsc::UnboundedSender<engine_scheduler::Input>,
    policy: &Current,
    operations: &Operations,
    disk: &Disk,
) {
    // The scheduler places mail on the egresses policy names.
    let told = owner.store().policy().revision();
    let _ = scheduler.send(engine_scheduler::Input::Policy(Arc::clone(
        owner.store().policy(),
    )));
    let mut turns = Turns {
        owner,
        receiver,
        clock,
        scheduler,
        policy,
        operations,
        disk,
        routes: BTreeMap::new(),
        measured: None,
        next_ticket: 0,
        responses: Vec::new(),
        wake: None,
        reported: false,
        told,
        backup: None,
        copying: false,
    };
    while turns.turn() {
        if let Some(request) = turns.backup.take() {
            turns.copying = true;
            let started = std::time::Instant::now();
            let copied = backup::copy(source, &request.to, || clock.now().wall, || turns.turn());
            turns.copying = false;
            match &copied {
                Ok(copied) => tracing::info!(
                    to = %request.to.display(),
                    bytes = copied.bytes,
                    ms = started.elapsed().as_millis(),
                    "backed up the store"
                ),
                Err(why) => tracing::warn!(why = %why, "a backup failed"),
            }
            let _ = request.reply.send(copied);
        }
    }
}

/// What the store's thread keeps from one turn to the next.
struct Turns<'a> {
    owner: CommitOwner<Rc<Connection>>,
    receiver: &'a mpsc::Receiver<Work>,
    clock: &'a SystemClock,
    scheduler: &'a tokio_mpsc::UnboundedSender<engine_scheduler::Input>,
    policy: &'a Current,
    operations: &'a Operations,
    disk: &'a Disk,
    routes: BTreeMap<Ticket, (Route, Option<Waiting>)>,
    // The store's size and free space are read once a second.
    measured: Option<std::time::Instant>,
    next_ticket: u64,
    responses: Vec<Response>,
    // When the commit owner asked to be polled again: at once while it has
    // work, later for a trim that is due then, never if neither.
    wake: Option<Monotonic>,
    reported: bool,
    told: engine_core::message::PolicyRevision,
    /// A backup asked for, to start after this turn, and whether one is
    /// under way, when a turn never waits.
    backup: Option<BackupRequest>,
    copying: bool,
}

impl Turns<'_> {
    /// Takes what has come, commits it, and answers it: false once every
    /// handle on the store is gone.
    fn turn(&mut self) -> bool {
        // Wait only when nothing is left to commit and no backup is under
        // way, and only until the wake the commit owner asked for, or the
        // next measurement of the disk, a second on.
        let wait = if self.copying {
            std::time::Duration::ZERO
        } else {
            self.wake.map_or(MEASURE_EVERY, |at| {
                at.saturating_duration_since(self.clock.now().monotonic)
                    .min(MEASURE_EVERY)
            })
        };
        let first = if wait.is_zero() {
            match self.receiver.try_recv() {
                Ok(work) => Some(work),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => return false,
            }
        } else {
            match self.receiver.recv_timeout(wait) {
                Ok(work) => Some(work),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return false,
            }
        };
        let now = self.clock.now();
        for work in first
            .into_iter()
            .chain(std::iter::from_fn(|| self.receiver.try_recv().ok()))
        {
            let envelope = match work {
                Work::Command(envelope) => envelope,
                Work::Backup(request) => {
                    if self.copying || self.backup.is_some() {
                        let _ = request.reply.send(Err("a backup is under way".to_owned()));
                    } else {
                        self.backup = Some(request);
                    }
                    continue;
                }
            };
            let ticket = Ticket(self.next_ticket);
            self.next_ticket += 1;
            self.routes
                .insert(ticket, (envelope.route, envelope.waiting));
            self.owner.handle(
                now,
                Request {
                    ticket,
                    command: envelope.command,
                },
            );
        }
        let started = std::time::Instant::now();
        self.wake = self.owner.poll(self.clock.now(), &mut self.responses);
        let took = started.elapsed();
        let operations = self.operations;
        // The queue as this group left it, before any of its answers goes,
        // so a drain that waited for an acceptance's answer counts it:
        // from counts the store keeps.
        queued(self.owner.store(), operations);
        if !self.responses.is_empty() {
            operations.commit_groups.fetch_add(1, Ordering::Relaxed);
            let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
            operations
                .commit_micros
                .fetch_add(micros, Ordering::Relaxed);
        }
        if self.measured.is_none_or(|at| at.elapsed() >= MEASURE_EVERY) {
            self.measured = Some(std::time::Instant::now());
            let store = self.owner.store();
            if let Ok(bytes) = store.bytes() {
                operations.store_bytes.store(bytes, Ordering::Relaxed);
            }
            if let Ok(Some(parked)) = store.parked_batches() {
                operations
                    .events_parked_now
                    .store(parked, Ordering::Relaxed);
            }
            queue_and_lag(store, self.clock.now().wall, operations);
            measure(self.disk, operations);
        }
        if took > SLOW_GROUP {
            tracing::warn!(
                answers = self.responses.len(),
                ms = took.as_millis(),
                "a commit group was slow"
            );
        }
        // What the group committed is durable, so a policy it changed is
        // published before anyone hears of the change.
        if !self.owner.has_failed() {
            let committed = self.owner.store().policy();
            self.policy.publish(committed);
            if committed.revision() != self.told {
                self.told = committed.revision();
                let _ = self
                    .scheduler
                    .send(engine_scheduler::Input::Policy(Arc::clone(committed)));
            }
        }
        for Response { ticket, answer } in self.responses.drain(..) {
            // A count of bytes waiting goes with its command's route, as
            // the command is answered.
            match self.routes.remove(&ticket).map(|(route, _waiting)| route) {
                Some(Route::Caller(reply)) => {
                    let _ = reply.send(answer);
                }
                Some(Route::Scheduler(theirs)) => {
                    let response = Response {
                        ticket: theirs,
                        answer,
                    };
                    let _ = self
                        .scheduler
                        .send(engine_scheduler::Input::Answer(response));
                }
                None => {}
            }
        }
        if self.owner.has_failed() && !self.reported {
            self.reported = true;
            operations.store_failed.store(true, Ordering::Relaxed);
            tracing::error!(
                "the store failed; every command is answered as unavailable until the engine restarts"
            );
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_store_and_its_log_are_their_owners_alone() {
        let directory = std::env::temp_dir().join(format!("nitromta-store-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        // Left readable by an earlier run.
        let old = directory.join("old.db");
        let old_log = directory.join("old.db-wal");
        let old_index = directory.join("old.db-shm");
        for file in [&old, &old_log, &old_index] {
            std::fs::write(file, b"").unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        protect(&old).unwrap();
        for file in [&old, &old_log, &old_index] {
            assert_eq!(mode(file), 0o600, "{}", file.display());
        }
        // New, with the log and its index SQLite creates.
        let new = directory.join("new.db");
        protect(&new).unwrap();
        let connection = Connection::open(&new).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL; CREATE TABLE t (x); INSERT INTO t VALUES (1);",
            )
            .unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let file = directory.join(format!("new.db{suffix}"));
            assert_eq!(mode(&file), 0o600, "{}", file.display());
        }
        drop(connection);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
