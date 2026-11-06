//! The store: one SQLite database in WAL mode with synchronous commits,
//! holding every authoritative record.
//!
//! Records are stored in their encoded form, and the columns that indexes
//! need are derived from each record as it is written, so the two cannot
//! disagree. Reads are open to anyone holding the store; changes are made
//! only by the [`CommitOwner`](crate::commit_owner::CommitOwner), inside
//! the transactions it opens.
//!
//! One connection owns the database, in exclusive locking mode.

use std::borrow::Borrow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use engine_core::address::Address;
use engine_core::attempt::{Attempt, AttemptEnd, AttemptResult, Evidence};
use engine_core::budget::{self, Counts, Signal, Tally, Window};
use engine_core::command::{
    Accept, AcceptRefusal, CooldownChange, DayEvidence, DispatchLedger, DuePosition, Expire,
    FeedbackRecorded, FenceDecision, Inspect, Inspected, KeyHeld, MAX_RECIPIENTS, Mailed, Owed,
    Park, ParkedEvents, Postpone, RecordOutcome, Release, Reported, Reservation, Reserve,
    SiteCooldown, Suppress, Unfenced, Unsuppress,
};
use engine_core::delivery::{Delivery, Disposition, QueueState, Refusal};
use engine_core::feedback::{Claim, Effect, Kind, Report};
use engine_core::id::{
    AccountId, AttemptId, BodyId, DeliveryId, EgressId, Id, MessageId, ReportId, SubscriptionId,
    TenantId, TopicId,
};
use engine_core::journal::Entry;
use engine_core::message::{Message, PolicyRevision};
use engine_core::policy::{Capping, Change, Feed, Fence, Policy, PolicyRefusal, Record};
use engine_core::quota::Ledger;
use engine_core::sts;
use engine_core::suppression::{self, List, Page, Reason, Suppressed};
use engine_core::time::Timestamp;
use rusqlite::{Connection, ErrorCode, OptionalExtension, Params};

use crate::codec::CodecError;
use crate::keys::{self, Keyring, Keys, NO_KEY, TenantKey};
use crate::records;
use crate::schema;

/// A store's file: its size, without its write-ahead log, and how much of
/// that is free pages, which new pages take before the file grows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    pub bytes: u64,
    pub reusable: u64,
}

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    /// A record could not be read. The store stops rather than guess.
    Corrupt {
        table: &'static str,
        id: i64,
        problem: String,
    },
    /// The store was written by a newer release.
    Newer {
        version: u32,
        known: u32,
    },
    /// SQLite would not run the database in WAL mode.
    JournalMode(String),
    /// SQLite's integrity check found damage.
    Damaged(Vec<String>),
    /// A restore was given a store `nitromta backup` did not copy, which
    /// says nothing of when it was taken.
    NotACopy,
}

impl StoreError {
    /// Whether this says the store itself is damaged, not that it could not
    /// be read just now, as on a disk with no room left.
    pub fn is_damage(&self) -> bool {
        match self {
            Self::Damaged(_) | Self::Corrupt { .. } => true,
            Self::Sqlite(error) => matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase)
            ),
            Self::Newer { .. } | Self::JournalMode(_) | Self::NotACopy => false,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite failed: {error}"),
            Self::Corrupt { table, id, problem } => {
                write!(formatter, "{table} row {id} cannot be read: {problem}")
            }
            Self::Newer { version, known } => write!(
                formatter,
                "the store is at schema version {version}, newer than this release's {known}"
            ),
            Self::JournalMode(mode) => {
                write!(formatter, "SQLite chose journal mode {mode}, not WAL")
            }
            Self::Damaged(problems) => write!(
                formatter,
                "the integrity check failed: {}",
                problems.join("; ")
            ),
            Self::NotACopy => write!(
                formatter,
                "it is not a copy `nitromta backup` made, which notes when it was taken"
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// A journal entry as it was read: its position, the entry, and the topics
/// it was published to, if they were kept as it was written.
type Journaled = (u64, Entry, Vec<TopicId>);

/// An (egress, site)'s row of the dispatch ledger: its window of
/// reservations, and warmup's evidence beside it.
#[derive(Clone, Debug, Default)]
struct Dispatched {
    window: Window,
    tally: Tally,
}

pub struct Store<C> {
    connection: C,
    /// The policy as committed so far, which reservations and stale
    /// acceptances are checked against.
    policy: Arc<Policy>,
    /// The recipients each account accepted over the last 24 hours.
    ledger: Ledger,
    /// The dispatch ledger: each (egress, site)'s reservations
    /// over the last 24 hours and warmup's evidence, for egresses capped
    /// there, and those this commit group changed.
    dispatched: BTreeMap<(EgressId, Arc<str>), Dispatched>,
    dispatched_changed: BTreeSet<(EgressId, Arc<str>)>,
    /// How long finished mail is kept: while bounces and complaints about
    /// it can still arrive.
    feedback_window: Duration,
    /// The most reports kept in quarantine at once.
    quarantine: u64,
    encryption: Encryption,
    /// Where the last trim's searches of deliveries and of messages
    /// stopped, which the next goes on from.
    trim_resume: (i64, i64),
    /// The installation's keys, which seal policy's secrets.
    keys: Arc<Keyring>,
    /// The keys personal data is sealed under: the
    /// installation's, and each tenant's while per-tenant keys are on.
    data: Keys,
    /// Whether parked batches of events may have come or gone since they
    /// were last counted.
    parked_changed: Cell<bool>,
    /// Unfinished deliveries by state, counted at open, then kept as each
    /// moves.
    moves: Cell<Moves>,
}

/// Unfinished deliveries by state, indexed as their rows' `state`: those
/// counted, what the unit under way has moved, apart until the unit is
/// kept, as a refusal undoes it, and what the group's kept units moved,
/// apart until the group commits. Finished ones are not counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Moves {
    queued: [i64; 4],
    moving: [i64; 4],
    grouped: [i64; 4],
}

impl Moves {
    /// A delivery moved into `to` from `from`, or came.
    fn moved(&mut self, from: Option<i64>, to: i64) {
        let mut add = |state: i64, by: i64| {
            if let Some(count) = usize::try_from(state)
                .ok()
                .and_then(|index| self.moving.get_mut(index))
            {
                *count += by;
            }
        };
        if let Some(from) = from {
            add(from, -1);
        }
        add(to, 1);
        self.moving[2] = 0;
    }

    /// The unit's moves, kept with its group or undone with the unit.
    fn settle(&mut self, kept: bool) {
        let moving = std::mem::take(&mut self.moving);
        if kept {
            self.grouped = added(self.grouped, moving);
        }
    }

    /// The group's moves, counted once it has committed or undone with it.
    fn commit(&mut self, committed: bool) {
        let grouped = std::mem::take(&mut self.grouped);
        if committed {
            self.queued = added(self.queued, grouped);
        }
    }
}

/// Unfinished deliveries by their state, as the store keeps them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Queued {
    pub waiting: u64,
    pub in_flight: u64,
    pub held: u64,
}

impl Queued {
    fn from_states(states: [i64; 4]) -> Self {
        let count = |state: i64| u64::try_from(state).unwrap_or_default();
        Self {
            waiting: count(states[0]),
            in_flight: count(states[1]),
            held: count(states[3]),
        }
    }
}

/// The furthest-behind subscription: the journal's entries past
/// its cursor, and when the first of them happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventLag {
    pub entries: u64,
    pub since: Option<Timestamp>,
}

/// A delivery that finished: its message, and when.
pub(crate) type Finished = (MessageId, Timestamp);

/// Deliveries finished in a commit group, by message: how many, and when
/// the last of them finished.
pub(crate) type Finishing = BTreeMap<MessageId, (u32, Timestamp)>;

/// Counts a finished delivery against its message.
pub(crate) fn count_finished(finishing: &mut Finishing, (message, at): Finished) {
    let (count, last) = finishing.entry(message).or_insert((0, at));
    *count += 1;
    *last = (*last).max(at);
}

/// What one trim did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Trimmed {
    pub deliveries: usize,
    pub messages: usize,
    pub entries: usize,
    /// Reports, and the records of their effects.
    pub reports: usize,
    /// MTA-STS policies that ran out.
    pub policies: usize,
    /// Parked batches of events whose entries are gone.
    pub parked: usize,
    /// A search left rows unread, or a table had a full batch to delete.
    pub more: bool,
    /// When the journal's oldest remaining entry happened: nothing that
    /// remains finished much before it.
    pub oldest: Option<Timestamp>,
}

impl Trimmed {
    pub fn changed(&self) -> bool {
        self.deliveries + self.messages + self.entries + self.reports + self.policies + self.parked
            > 0
    }
}

/// How a store runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreOptions {
    /// Pages the write-ahead log may hold before SQLite checkpoints it into
    /// the database. The checkpoint runs inside a commit, so every command
    /// behind it waits for it.
    ///
    /// Measured on 27 October 2026. The store alone completed half again as
    /// many deliveries a second at 16,000 pages (a 64 MiB log). But the whole
    /// engine, in the harness, stalled for over five seconds on some of those
    /// checkpoints, and at SQLite's default of 1,000 it never stalled for
    /// 200 ms, with the same rate and CPU per message: the engine's limit is
    /// its CPU, not the store's syncs.
    pub checkpoint_pages: u32,
    /// How long finished mail is kept, for the bounces and complaints that
    /// arrive after it: 7 days by default.
    pub feedback_window: Duration,
    /// The most reports naming no message the engine sent that are kept at
    /// once, in quarantine, each until retention takes it:
    /// 10,000 by default.
    pub quarantine: u64,
    /// Whether personal data is sealed: off by default.
    pub encryption: Encryption,
}

impl StoreOptions {
    pub const DEFAULT: Self = Self {
        checkpoint_pages: 1000,
        feedback_window: Duration::from_secs(7 * 86_400),
        quarantine: 10_000,
        encryption: Encryption::Off,
    };
}

/// The tenant whose message a report is about, and the deliveries it is
/// about, each with its claim.
type About = (Option<TenantId>, Vec<(Delivery, Claim)>);

/// The tables holding personal data, as a key's scan reads them, in turn.
const SEALED: [&str; 7] = [
    "bodies",
    "messages",
    "deliveries",
    "journal",
    "feedback",
    "cooldowns",
    "suppressions",
];

/// The rows a page of a key's scan reads.
const KEY_PAGE: i64 = 1_000;

/// A row a key's scan reads: its key, and two of its columns.
type Row = (i64, Vec<u8>, Vec<u8>);

/// Whether, and under what, the store seals personal data:
/// bodies, addresses, what receivers said, header copies and report
/// evidence. Data sealed under any mode, or none, still reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Encryption {
    /// Nothing is sealed: operators use full-disk encryption.
    #[default]
    Off,
    /// Sealed under the installation's keys, the newest sealing.
    Installation,
    /// Each tenant's mail sealed under its own key, given to the store,
    /// and the rest under the installation's, so erasing a tenant's key
    /// erases its mail wherever it is kept. Once a tenant has a key, the
    /// engine starts in no other mode until every tenant with one is gone.
    Tenant,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl<C: Borrow<Connection>> Store<C> {
    /// Opens the store on `connection`, which recovers SQLite's write-ahead
    /// log, and brings its schema up to date. Its secrets are sealed under
    /// `keys`: any it finds under an older key are sealed again under the
    /// newest, so a key's rotation needs only a restart.
    pub fn open(
        connection: C,
        options: StoreOptions,
        keys: Arc<Keyring>,
    ) -> Result<Self, StoreError> {
        let mut store = Self {
            connection,
            policy: Arc::default(),
            ledger: Ledger::default(),
            dispatched: BTreeMap::new(),
            dispatched_changed: BTreeSet::new(),
            feedback_window: options.feedback_window,
            quarantine: options.quarantine,
            encryption: options.encryption,
            trim_resume: (0, 0),
            data: Keys::new(Arc::clone(&keys)),
            keys,
            parked_changed: Cell::new(true),
            moves: Cell::new(Moves::default()),
        };
        let db = store.db();
        db.execute_batch("PRAGMA locking_mode = EXCLUSIVE")?;
        let mode: String = db.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if mode != "wal" {
            return Err(StoreError::JournalMode(mode));
        }
        // fullfsync matters where F_FULLFSYNC exists (macOS), and is
        // ignored elsewhere. A write to policy zeroes what it replaces and
        // the pages it frees (`zeroing`).
        db.execute_batch(&format!(
            "PRAGMA synchronous = FULL;
             PRAGMA fullfsync = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA wal_autocheckpoint = {};",
            options.checkpoint_pages
        ))?;
        schema::migrate(db)?;
        let Queued {
            waiting,
            in_flight,
            held,
        } = store.count_queued()?;
        let count = |count: u64| i64::try_from(count).unwrap_or(i64::MAX);
        store.moves.set(Moves {
            queued: [count(waiting), count(in_flight), 0, count(held)],
            ..Moves::default()
        });
        store.policy = Arc::new(store.read_policy()?);
        store.seal_again()?;
        // Its old keys and records zeroed as they go, and the log's frames
        // truncated below, so none is left in the clear.
        store.zeroing(|| store.rekey_suppressions())?;
        // The log's frames go once they are in the database, those of a run
        // before a rotation's with them, whether or not this start sealed
        // anything again. A log this start found is then written afresh by
        // one commit, which syncs it, so a power cut cannot bring its older
        // frames back. The commit leaves the revision as it was, but SQLite
        // writes a page only if its bytes change, so it changes it and back.
        // The frames are counted before the truncation, which reports none.
        let frames: i64 = store
            .db()
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| row.get(1))?;
        let busy: i64 = store
            .db()
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        if busy != 0 {
            return Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                Some("the write-ahead log could not be checkpointed at open".to_owned()),
            )));
        }
        if frames > 0 {
            store.db().execute_batch(
                "BEGIN IMMEDIATE;
                 UPDATE policy_revision SET revision = revision + 1;
                 UPDATE policy_revision SET revision = revision - 1;
                 COMMIT;",
            )?;
        }
        store.ledger = store.read_ledger()?;
        store.dispatched = store.read_dispatched()?;
        Ok(store)
    }

    fn read_dispatched(&self) -> Result<BTreeMap<(EgressId, Arc<str>), Dispatched>, StoreError> {
        let mut statement = self
            .db()
            .prepare("SELECT egress, site, record FROM dispatched")?;
        let rows: Vec<(i64, String, Vec<u8>)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(egress, site, record)| {
                let id = id_from_key(egress)
                    .ok_or_else(|| corrupt("dispatched", egress)(CodecError::Invalid("egress")))?;
                let (window, tally) =
                    records::decode_dispatched(&record).map_err(corrupt("dispatched", egress))?;
                Ok((
                    (EgressId(id), Arc::from(site)),
                    Dispatched { window, tally },
                ))
            })
            .collect()
    }

    /// The dispatch ledger's windows, as the scheduler starts from them.
    pub fn dispatched(&self) -> Vec<(EgressId, Arc<str>, Window)> {
        self.dispatched
            .iter()
            .map(|((egress, site), dispatched)| {
                (*egress, Arc::clone(site), dispatched.window.clone())
            })
            .collect()
    }

    /// Whether each of `cappings` was judged on its egress's evidence as it
    /// is now, on the day it judged: the ledger read once, in order, its
    /// rows for each egress together.
    fn evidence_kept(&self, cappings: &[Capping]) -> bool {
        let mut now: BTreeMap<EgressId, Vec<(Arc<str>, Counts)>> = cappings
            .iter()
            .map(|capping| (capping.egress, Vec::new()))
            .collect();
        let days: BTreeMap<EgressId, u64> = cappings
            .iter()
            .filter_map(|capping| Some((capping.egress, capping.to.warmed.as_ref()?.day)))
            .collect();
        for ((egress, site), dispatched) in &self.dispatched {
            if let (Some(rows), Some(day)) = (now.get_mut(egress), days.get(egress)) {
                let counts = dispatched.tally.on(*day);
                if !counts.is_empty() {
                    rows.push((Arc::clone(site), counts));
                }
            }
        }
        cappings.iter().all(|capping| {
            !days.contains_key(&capping.egress) || now[&capping.egress] == capping.evidence
        })
    }

    /// Warmup's evidence of the UTC day `day`: each (egress,
    /// site)'s counts, those that counted anything, and the attempts from a
    /// capped egress reserved before the day ended that are still in
    /// flight, their outcomes not yet recorded.
    pub fn evidence(&self, day: u64) -> Result<DayEvidence, StoreError> {
        let counts = self
            .dispatched
            .iter()
            .map(|((egress, site), dispatched)| (*egress, site, dispatched.tally.on(day)))
            .filter(|(_, _, counts)| !counts.is_empty())
            .map(|(egress, site, counts)| (egress, Arc::clone(site), counts))
            .collect();
        let ended = budget::day_start(day.saturating_add(1));
        let in_flight = self.deliveries("SELECT id, record FROM deliveries WHERE state = 1", [])?;
        let unrecorded = in_flight
            .iter()
            .filter(|delivery| {
                matches!(delivery.state(), QueueState::InFlight { since, .. } if since < ended)
                    && delivery
                        .egress()
                        .and_then(|egress| self.policy.egress(egress))
                        .is_some_and(|egress| egress.caps.any())
            })
            .count();
        Ok(DayEvidence {
            counts,
            unrecorded: u64::try_from(unrecorded).unwrap_or(u64::MAX),
        })
    }

    /// Counts what an outcome or a report showed at an (egress, site) the
    /// policy caps, toward warmup's evidence. Whether it did.
    fn tally(
        &mut self,
        egress: Option<EgressId>,
        site: &Arc<str>,
        signal: Signal,
        at: Timestamp,
    ) -> bool {
        let Some(egress) = egress.filter(|egress| {
            self.policy
                .egress(*egress)
                .is_some_and(|held| held.caps.at(site).is_some())
        }) else {
            return false;
        };
        let counted = (egress, Arc::clone(site));
        self.dispatched
            .entry(counted.clone())
            .or_default()
            .tally
            .count(signal, at);
        self.dispatched_changed.insert(counted);
        true
    }

    /// Forgets the rows that count nothing as of `now`, which no budget or
    /// judgment needs.
    pub(crate) fn expire_dispatched(&mut self, now: Timestamp) -> Result<(), StoreError> {
        let empty: Vec<(EgressId, Arc<str>)> = self
            .dispatched
            .iter()
            .filter(|(_, dispatched)| {
                dispatched.window.is_empty(now) && dispatched.tally.is_empty(now)
            })
            .map(|(key, _)| key.clone())
            .collect();
        let db = self.db();
        let mut delete =
            db.prepare_cached("DELETE FROM dispatched WHERE egress = ?1 AND site = ?2")?;
        for (egress, site) in &empty {
            delete.execute((key(egress.0), site.as_ref()))?;
        }
        drop(delete);
        for key in &empty {
            self.dispatched.remove(key);
        }
        Ok(())
    }

    /// Writes each window of the dispatch ledger this group changed, once.
    pub(crate) fn flush_dispatched(&mut self) -> Result<(), StoreError> {
        let changed = std::mem::take(&mut self.dispatched_changed);
        let db = self.db();
        let mut write = db.prepare_cached(
            "INSERT INTO dispatched (egress, site, record) VALUES (?1, ?2, ?3)
             ON CONFLICT (egress, site) DO UPDATE SET record = excluded.record",
        )?;
        for (egress, site) in changed {
            if let Some(dispatched) = self.dispatched.get(&(egress, Arc::clone(&site))) {
                let record = records::encode_dispatched(&dispatched.window, &dispatched.tally);
                write.execute((key(egress.0), site.as_ref(), record))?;
            }
        }
        Ok(())
    }

    fn read_ledger(&self) -> Result<Ledger, StoreError> {
        let mut statement = self
            .db()
            .prepare("SELECT account, minute, recipients FROM sent")?;
        let rows: Vec<(i64, i64, i64)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?;
        let counts = rows
            .into_iter()
            .map(|(account, minute, recipients)| {
                let invalid = || corrupt("sent", account)(CodecError::Invalid("count"));
                let account = id_from_key(account).ok_or_else(invalid)?;
                let minute = u64::try_from(minute).map_err(|_| invalid())?;
                let recipients = u64::try_from(recipients).map_err(|_| invalid())?;
                Ok(((AccountId(account), minute), recipients))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(Ledger::from_counts(counts))
    }

    /// The recipients the stored ledger holds for `account`, in every
    /// minute it has not yet deleted.
    pub fn sent_stored(&self, account: AccountId) -> Result<u64, StoreError> {
        let total: i64 = self
            .db()
            .prepare_cached("SELECT COALESCE(SUM(recipients), 0) FROM sent WHERE account = ?1")?
            .query_row([key(account.0)], |row| row.get(0))?;
        Ok(u64::try_from(total).unwrap_or_default())
    }

    /// The recipients `account` accepted in the 24 hours up to `at`.
    pub fn sent(&mut self, account: AccountId, at: Timestamp) -> u64 {
        self.ledger.sent(account, at)
    }

    /// Forgets the ledger's minutes that have left the window as of `now`.
    pub(crate) fn expire_sent(&mut self, now: Timestamp) {
        self.ledger.expire_all(now);
    }

    /// Writes each minute of the ledger this group changed, once, and
    /// deletes those that left the window.
    pub(crate) fn flush_sent(&mut self) -> Result<(), StoreError> {
        let flushed = self.ledger.flush();
        let db = self.db();
        let mut write = db.prepare_cached(
            "INSERT INTO sent (account, minute, recipients) VALUES (?1, ?2, ?3)
             ON CONFLICT (account, minute) DO UPDATE SET recipients = excluded.recipients",
        )?;
        for ((account, minute), recipients) in flushed.counts {
            write.execute((
                key(account.0),
                i64::try_from(minute).unwrap_or(i64::MAX),
                i64::try_from(recipients).unwrap_or(i64::MAX),
            ))?;
        }
        let mut delete =
            db.prepare_cached("DELETE FROM sent WHERE account = ?1 AND minute = ?2")?;
        for (account, minute) in flushed.gone {
            delete.execute((key(account.0), i64::try_from(minute).unwrap_or(i64::MAX)))?;
        }
        Ok(())
    }

    /// The policy as committed.
    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }

    /// Seals again, under the newest key, every secret in policy sealed
    /// under another: each record whose form under the newest key differs
    /// from the one kept is written again, in one transaction, zeroing what
    /// it frees. A crash before its commit leaves them all to the next
    /// start.
    fn seal_again(&self) -> Result<(), StoreError> {
        let db = self.db();
        let kept: Vec<(i64, Vec<u8>)> = db
            .prepare("SELECT id, record FROM policy")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut stale = Vec::new();
        for (key, record) in kept {
            let id = id_from_key(key)
                .ok_or_else(|| corrupt("policy", key)(CodecError::Invalid("ID")))?;
            let decoded =
                records::decode_policy(id, &record, &self.keys).map_err(corrupt("policy", key))?;
            let sealed = records::encode_policy(&decoded, &self.keys);
            if sealed != record {
                stale.push((key, sealed));
            }
        }
        if stale.is_empty() {
            return Ok(());
        }
        db.execute_batch("BEGIN IMMEDIATE")?;
        let written = self.zeroing(|| {
            let mut write = db.prepare_cached("UPDATE policy SET record = ?2 WHERE id = ?1")?;
            for (key, sealed) in &stale {
                write.execute((key, sealed))?;
            }
            Ok(())
        });
        match written.and_then(|()| Ok(db.execute_batch("COMMIT")?)) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Runs `write`, a write to policy, zeroing what it replaces or removes
    /// and every page it frees as it goes (`secure_delete`), so no form of
    /// a secret outlives its write, in its page or on the free list, where
    /// another table could take the page with the secret still in it. Only
    /// policy holds secrets, and its changes are rare; other writes zero
    /// nothing, as they cost a write more for each page they free.
    fn zeroing<T>(&self, write: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
        self.db().execute_batch("PRAGMA secure_delete = ON")?;
        let written = write();
        self.db().execute_batch("PRAGMA secure_delete = OFF")?;
        written
    }

    fn read_policy(&self) -> Result<Policy, StoreError> {
        let revision: i64 =
            self.db()
                .query_row("SELECT revision FROM policy_revision", [], |row| row.get(0))?;
        let mut statement = self.db().prepare("SELECT id, record FROM policy")?;
        let rows: Vec<(i64, Vec<u8>)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let records = rows
            .into_iter()
            .map(|(key, record)| {
                let id = id_from_key(key)
                    .ok_or_else(|| corrupt("policy", key)(CodecError::Invalid("ID")))?;
                records::decode_policy(id, &record, &self.keys).map_err(corrupt("policy", key))
            })
            .collect::<Result<_, _>>()?;
        let revision = u64::try_from(revision)
            .map_err(|_| corrupt("policy_revision", 0)(CodecError::Invalid("revision")))?;
        let mut policy = Policy::from_records(PolicyRevision(revision), records).map_err(|_| {
            StoreError::Corrupt {
                table: "policy",
                id: 0,
                problem: "the records are not a policy any sequence of changes makes".to_owned(),
            }
        })?;
        policy.set_fence(read_fence(self.db())?, false);
        Ok(policy)
    }

    /// The operator's decision on the store's fence, in policy
    /// at the next revision, which is written with it: refused if the
    /// store has none.
    pub(crate) fn decide_fence(
        &mut self,
        decision: FenceDecision,
    ) -> Result<Result<PolicyRevision, Unfenced>, StoreError> {
        let Some(fence) = self.policy.fence().copied() else {
            return Ok(Err(Unfenced));
        };
        let decided = match decision {
            FenceDecision::Release => {
                self.db().prepare_cached("DELETE FROM fence")?.execute([])?;
                None
            }
            FenceDecision::Discard => {
                self.db()
                    .prepare_cached("UPDATE fence SET discarding = 1")?
                    .execute([])?;
                Some(Fence {
                    discarding: true,
                    ..fence
                })
            }
        };
        let policy = Arc::make_mut(&mut self.policy);
        policy.set_fence(decided, true);
        let revision = policy.revision();
        self.db()
            .prepare_cached("UPDATE policy_revision SET revision = ?1")?
            .execute([i64::try_from(revision.0).unwrap_or(i64::MAX)])?;
        Ok(Ok(revision))
    }

    /// The store's fence, if it has one, and how many deliveries it covers
    /// that are not finished: waiting, in flight or held.
    pub fn fenced(&self) -> Result<Option<(Fence, u64)>, StoreError> {
        let Some(fence) = self.policy.fence().copied() else {
            return Ok(None);
        };
        let unfinished: i64 = self.db().query_row(
            "SELECT count(*) FROM deliveries WHERE state IN (0, 1, 3) AND id <= ?1",
            [key(fence.below)],
            |row| row.get(0),
        )?;
        Ok(Some((fence, u64::try_from(unfinished).unwrap_or_default())))
    }

    /// Fences this store, restored at `restored` from a copy `nitromta
    /// backup` made: every ID the copy issued is at or below its
    /// high-water mark. Refused unless the copy says when it was taken.
    pub fn fence_restored(&mut self, restored: Timestamp) -> Result<Fence, StoreError> {
        let taken: Option<i64> =
            self.db()
                .query_row("SELECT max(taken_at) FROM copied", [], |row| row.get(0))?;
        let Some(taken) = taken else {
            return Err(StoreError::NotACopy);
        };
        let fence = Fence {
            below: self
                .highest_id()?
                .unwrap_or_else(|| Id::from_u64(1).expect("one is an ID")),
            taken: Timestamp::from_micros(u64::try_from(taken).unwrap_or_default()),
            restored,
            discarding: false,
        };
        let mut revision = self.policy.revision();
        revision.0 += 1;
        // The fence and the revision that publishes it, in one commit.
        let db = self.db();
        db.execute_batch("BEGIN IMMEDIATE; DELETE FROM fence;")?;
        let written = db
            .execute(
                "INSERT INTO fence (below, taken_at, restored_at, discarding) VALUES (?1, ?2, ?3, 0)",
                (key(fence.below), column(fence.taken), column(restored)),
            )
            .and_then(|_| {
                db.execute(
                    "UPDATE policy_revision SET revision = ?1",
                    [i64::try_from(revision.0).unwrap_or(i64::MAX)],
                )
            })
            .and_then(|_| db.execute_batch("COMMIT"));
        if let Err(error) = written {
            let _ = db.execute_batch("ROLLBACK");
            return Err(error.into());
        }
        Arc::make_mut(&mut self.policy).set_fence(Some(fence), true);
        Ok(fence)
    }

    /// Applies a policy change, writing the records it changed and the
    /// revision, and answers that revision. Later commands in the group see
    /// it already. The policy is copied only while a published snapshot
    /// shares it, so a group's changes share one copy.
    pub(crate) fn change_policy(
        &mut self,
        change: Change,
    ) -> Result<Result<PolicyRevision, PolicyRefusal>, StoreError> {
        // While per-tenant keys are on, a tenant is created only with its
        // key given: one decided from a snapshot a change ahead
        // of it outdated, which still held a tenant of its name, was never
        // given one, and none of its mail would be kept.
        if self.encryption == Encryption::Tenant && self.creates_unkeyed(&change) {
            return Ok(Err(PolicyRefusal::Outdated));
        }
        // Warmup's judgment holds only on the evidence it read: one counted
        // since, as an outcome or report that waited its turn, is judged
        // again.
        if let Change::Caps(cappings) = &change
            && !self.evidence_kept(cappings)
        {
            return Ok(Err(PolicyRefusal::Outdated));
        }
        let policy = Arc::make_mut(&mut self.policy);
        let changed = match policy.apply(change) {
            Ok(changed) => changed,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let revision = policy.revision();
        self.zeroing(|| {
            let db = self.db();
            let mut write =
                db.prepare_cached("INSERT OR REPLACE INTO policy (id, record) VALUES (?1, ?2)")?;
            for record in &changed.written {
                write.execute((key(record.id()), records::encode_policy(record, &self.keys)))?;
            }
            let mut remove = db.prepare_cached("DELETE FROM policy WHERE id = ?1")?;
            for id in &changed.removed {
                let removed = remove.execute([key(*id)])?;
                expect_one_row(removed, "policy", key(*id))?;
            }
            Ok(())
        })?;
        {
            let db = self.db();
            // A new subscription owes what is committed from now on, and a
            // removed one owes nothing.
            let mut start = db.prepare_cached(
                "INSERT OR IGNORE INTO cursors (subscription, position)
                 SELECT ?1, COALESCE(MAX(position), 0) FROM journal",
            )?;
            // A topic subscriber owes what is committed from when it
            // confirms.
            for record in &changed.written {
                match record {
                    Record::Subscription(subscription) => {
                        start.execute([key(subscription.id.0)])?;
                    }
                    Record::Subscriber(subscriber) if subscriber.confirmed => {
                        start.execute([key(subscriber.id.0)])?;
                    }
                    _ => {}
                }
            }
            let mut forget = db.prepare_cached("DELETE FROM cursors WHERE subscription = ?1")?;
            let mut unpark =
                db.prepare_cached("DELETE FROM parked_events WHERE subscription = ?1")?;
            for id in &changed.removed {
                forget.execute([key(*id)])?;
                if unpark.execute([key(*id)])? > 0 {
                    self.parked_changed.set(true);
                }
            }
            db.prepare_cached("UPDATE policy_revision SET revision = ?1")?
                .execute([i64::try_from(revision.0).unwrap_or(i64::MAX)])?;
        }
        Ok(Ok(revision))
    }

    /// Every ID the shard has ever stored is at or below this.
    pub fn highest_id(&self) -> Result<Option<Id>, StoreError> {
        let highest: i64 = self
            .db()
            .query_row("SELECT id FROM highest_id", [], |row| row.get(0))?;
        Ok(id_from_key(highest))
    }

    /// Runs SQLite's full integrity check.
    pub fn verify(&self) -> Result<(), StoreError> {
        self.check("integrity_check")
    }

    fn check(&self, pragma: &str) -> Result<(), StoreError> {
        checked(self.db(), pragma)
    }

    pub fn message(&self, id: MessageId) -> Result<Option<Message>, StoreError> {
        let key = key(id.0);
        let record: Option<Vec<u8>> = self
            .db()
            .prepare_cached("SELECT record FROM messages WHERE id = ?1")?
            .query_row([key], |row| row.get(0))
            .optional()?;
        record
            .map(|record| records::decode_message(id, &record).map_err(corrupt("messages", key)))
            .transpose()
    }

    /// What SES-shaped events say of message `id`, while it is kept: when
    /// it was accepted, and its copy, if one was kept.
    fn mailed(&self, id: MessageId) -> Result<Option<Mailed>, StoreError> {
        let key = key(id.0);
        let row: Option<(Vec<u8>, Option<Vec<u8>>)> = self
            .db()
            .prepare_cached("SELECT record, mail FROM messages WHERE id = ?1")?
            .query_row([key], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let Some((record, mail)) = row else {
            return Ok(None);
        };
        let message = records::decode_message(id, &record).map_err(corrupt("messages", key))?;
        let mail = mail
            .map(|mail| records::decode_mail(&mail, id, self.open_keys()))
            .transpose()
            .map_err(corrupt("messages", key))?;
        Ok(Some(Mailed {
            accepted_at: message.accepted_at,
            mail,
        }))
    }

    pub fn delivery(&self, id: DeliveryId) -> Result<Option<Delivery>, StoreError> {
        let key = key(id.0);
        let record: Option<Vec<u8>> = self
            .db()
            .prepare_cached("SELECT record FROM deliveries WHERE id = ?1")?
            .query_row([key], |row| row.get(0))
            .optional()?;
        record
            .map(|record| {
                records::decode_delivery(id, &record, self.open_keys())
                    .map_err(corrupt("deliveries", key))
            })
            .transpose()
    }

    /// The journal's entries after `position`, oldest first, with their
    /// positions: how a reader that has read up to `position` reads on.
    pub fn entries(&self, position: u64, limit: usize) -> Result<Vec<(u64, Entry)>, StoreError> {
        Ok(self
            .entries_until(position, u64::MAX, limit)?
            .into_iter()
            .map(|(position, entry, _)| (position, entry))
            .collect())
    }

    /// As `entries`, none past `until`, each with the topics it was
    /// published to, or `None` if it was written before they were kept.
    fn entries_until(
        &self,
        position: u64,
        until: u64,
        limit: usize,
    ) -> Result<Vec<Journaled>, StoreError> {
        let mut statement = self.db().prepare_cached(
            "SELECT position, record, topics FROM journal WHERE position > ?1 AND position <= ?2
             ORDER BY position LIMIT ?3",
        )?;
        let at_most = |position: u64| i64::try_from(position).unwrap_or(i64::MAX);
        let rows: Vec<(i64, Vec<u8>, Option<Vec<u8>>)> = statement
            .query_map((at_most(position), at_most(until), count(limit)), |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(position, record, topics)| {
                let entry = records::decode_entry(&record, self.open_keys())
                    .map_err(corrupt("journal", position))?;
                let topics = records::decode_topics(topics.as_deref())
                    .map_err(corrupt("journal", position))?;
                Ok((u64::try_from(position).unwrap_or_default(), entry, topics))
            })
            .collect()
    }

    /// The events `subscription` owes from the journal past `after`, or
    /// past its cursor, reading at most `limit` entries and none past
    /// `until`. None if there is no such subscription.
    pub fn owed(
        &self,
        subscription: SubscriptionId,
        after: Option<u64>,
        until: Option<u64>,
        limit: usize,
    ) -> Result<Option<Owed>, StoreError> {
        let Some(feed) = self.policy.feed(subscription) else {
            return Ok(None);
        };
        let after_given = after;
        let after = match after {
            Some(after) => after,
            None => match self.cursor(subscription)? {
                Some(cursor) => cursor,
                None => return Ok(None),
            },
        };
        let read = self.entries_until(after, until.unwrap_or(u64::MAX), limit)?;
        let through = read.last().map_or(after, |(position, ..)| *position);
        let entries: Vec<(u64, Entry)> = read
            .into_iter()
            .filter(|(_, entry, published)| Policy::owes(feed, entry, published))
            .map(|(position, entry, _)| (position, entry))
            .collect();
        let failing_since = match (after_given, entries.first()) {
            (None, Some((first, _))) => self.failing_since(subscription, *first)?,
            _ => None,
        };
        let mut deliveries = BTreeMap::new();
        for id in entries.iter().flat_map(|(_, entry)| entry.deliveries()) {
            if let Some(delivery) = self.delivery(id)? {
                deliveries.insert(id, (delivery.message(), delivery.recipient().clone()));
            }
        }
        // A topic's subscriber is posted SES's shape, which says what was
        // kept of each message.
        let mut mailed = BTreeMap::new();
        if matches!(feed, Feed::Topic(_)) {
            let messages = entries
                .iter()
                .filter_map(|(_, entry)| match entry {
                    Entry::Accepted { message, .. } => Some(*message),
                    _ => None,
                })
                .chain(deliveries.values().map(|(message, _)| *message));
            for message in messages {
                if !mailed.contains_key(&message)
                    && let Some(found) = self.mailed(message)?
                {
                    mailed.insert(message, found);
                }
            }
        }
        Ok(Some(Owed {
            entries,
            deliveries,
            mailed,
            through,
            failing_since,
        }))
    }

    /// When `subscription`'s batch whose first event is at `first` first
    /// failed, if it is failing.
    fn failing_since(
        &self,
        subscription: SubscriptionId,
        first: u64,
    ) -> Result<Option<Timestamp>, StoreError> {
        let since: Option<Option<i64>> = self
            .db()
            .prepare_cached(
                "SELECT failing_since FROM cursors WHERE subscription = ?1 AND failing_first = ?2",
            )?
            .query_row((key(subscription.0), position(first)), |row| row.get(0))
            .optional()?;
        Ok(since
            .flatten()
            .map(|since| Timestamp::from_micros(u64::try_from(since).unwrap_or_default())))
    }

    /// `subscription`'s batch whose first event is at `first` first failed
    /// at `since`, unless an earlier failure of that batch is kept. Nothing
    /// if its cursor is already past the batch.
    pub(crate) fn events_failing(
        &self,
        subscription: SubscriptionId,
        first: u64,
        since: Timestamp,
    ) -> Result<Result<(), Refusal>, StoreError> {
        let db = self.db();
        let changed = db
            .prepare_cached(
                "UPDATE cursors SET
                 failing_since = CASE WHEN failing_first = ?2 THEN IFNULL(failing_since, ?3) ELSE ?3 END,
                 failing_first = ?2
                 WHERE subscription = ?1 AND position < ?2",
            )?
            .execute((key(subscription.0), position(first), column(since)))?;
        if changed == 1 {
            return Ok(Ok(()));
        }
        let cursor: Option<i64> = db
            .prepare_cached("SELECT position FROM cursors WHERE subscription = ?1")?
            .query_row([key(subscription.0)], |row| row.get(0))
            .optional()?;
        Ok(cursor.map(|_| ()).ok_or(Refusal::Gone))
    }

    /// Parked batches of events, in every subscription, for the gauge: a
    /// count once they may have changed since the last, and none else, so
    /// the count costs nothing while none comes or goes.
    pub fn parked_batches(&self) -> Result<Option<u64>, StoreError> {
        if !self.parked_changed.replace(false) {
            return Ok(None);
        }
        let counted = self
            .db()
            .query_row("SELECT count(*) FROM parked_events", [], |row| {
                row.get::<_, i64>(0)
            });
        match counted {
            Ok(count) => Ok(Some(u64::try_from(count).unwrap_or_default())),
            Err(error) => {
                self.parked_changed.set(true);
                Err(error.into())
            }
        }
    }

    /// Where `subscription`'s cursor stands, if it has one.
    pub fn cursor(&self, subscription: SubscriptionId) -> Result<Option<u64>, StoreError> {
        let position: Option<i64> = self
            .db()
            .prepare_cached("SELECT position FROM cursors WHERE subscription = ?1")?
            .query_row([key(subscription.0)], |row| row.get(0))
            .optional()?;
        Ok(position.map(|position| u64::try_from(position).unwrap_or_default()))
    }

    /// The store's size on disk and what it holds free.
    pub fn space(&self) -> Result<Space, StoreError> {
        space(self.db())
    }

    /// How long finished mail is kept.
    pub(crate) fn feedback_window(&self) -> Duration {
        self.feedback_window
    }

    /// The journal positions `subscription` skipped because they were
    /// trimmed before it was given them, if it has a cursor.
    pub fn skipped(&self, subscription: SubscriptionId) -> Result<Option<u64>, StoreError> {
        let skipped: Option<i64> = self
            .db()
            .prepare_cached("SELECT skipped FROM cursors WHERE subscription = ?1")?
            .query_row([key(subscription.0)], |row| row.get(0))
            .optional()?;
        Ok(skipped.map(|skipped| u64::try_from(skipped).unwrap_or_default()))
    }

    /// Parks a batch of `parked.subscription`'s events: its row,
    /// and its cursor moved past it, never back.
    pub(crate) fn park_events(
        &self,
        parked: &ParkedEvents,
    ) -> Result<Result<(), Refusal>, StoreError> {
        if let Err(refusal) = self.acknowledge(parked.subscription, parked.through)? {
            return Ok(Err(refusal));
        }
        // A span the trim has taken leaves nothing to replay, and no row.
        let oldest: Option<i64> = self
            .db()
            .prepare_cached("SELECT MIN(position) FROM journal")?
            .query_row([], |row| row.get(0))?;
        let at_most = |position: u64| i64::try_from(position).unwrap_or(i64::MAX);
        if oldest.is_none_or(|oldest| at_most(parked.through) < oldest) {
            return Ok(Ok(()));
        }
        self.db()
            .prepare_cached(
                "INSERT OR REPLACE INTO parked_events
                 (subscription, first, through, parked_at, attempts, failure)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute((
                key(parked.subscription.0),
                at_most(parked.first),
                at_most(parked.through),
                column(parked.at),
                i64::from(parked.attempts),
                &parked.failure,
            ))?;
        self.parked_changed.set(true);
        Ok(Ok(()))
    }

    /// The feed `name` names in `account`, a subscription or a topic's
    /// subscriber, and its parked batches, oldest first: at most `limit`,
    /// from the one whose first event is at `from` or the next after it.
    /// None if there is no such feed.
    pub fn parked_events(
        &self,
        account: AccountId,
        name: &str,
        from: Option<u64>,
        limit: usize,
    ) -> Result<Option<(SubscriptionId, Vec<ParkedEvents>)>, StoreError> {
        let Some(subscription) = self.policy.feed_named(account, name) else {
            return Ok(None);
        };
        let mut statement = self.db().prepare_cached(
            "SELECT first, through, parked_at, attempts, failure FROM parked_events
             WHERE subscription = ?1 AND first >= ?2 ORDER BY first LIMIT ?3",
        )?;
        let from = i64::try_from(from.unwrap_or_default()).unwrap_or(i64::MAX);
        let parked = statement
            .query_map((key(subscription.0), from, count(limit)), |row| {
                let position = |value: i64| u64::try_from(value).unwrap_or_default();
                Ok(ParkedEvents {
                    subscription,
                    first: position(row.get(0)?),
                    through: position(row.get(1)?),
                    at: Timestamp::from_micros(position(row.get(2)?)),
                    attempts: u32::try_from(row.get::<_, i64>(3)?).unwrap_or(u32::MAX),
                    failure: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(Some((subscription, parked)))
    }

    /// Removes a parked batch, a replay of which was taken.
    pub(crate) fn unpark_events(
        &self,
        subscription: SubscriptionId,
        first: u64,
    ) -> Result<Result<(), Refusal>, StoreError> {
        let removed = self
            .db()
            .prepare_cached("DELETE FROM parked_events WHERE subscription = ?1 AND first = ?2")?
            .execute((
                key(subscription.0),
                i64::try_from(first).unwrap_or(i64::MAX),
            ))?;
        Ok(if removed == 1 {
            self.parked_changed.set(true);
            Ok(())
        } else {
            Err(Refusal::Gone)
        })
    }

    /// Moves `subscription`'s cursor on to `through`, and never back. A
    /// cursor moved past its failing batch drops the batch's time.
    pub(crate) fn acknowledge(
        &self,
        subscription: SubscriptionId,
        through: u64,
    ) -> Result<Result<(), Refusal>, StoreError> {
        let changed = self
            .db()
            .prepare_cached(
                "UPDATE cursors SET position = MAX(position, ?2),
                 failing_since = CASE WHEN ?2 >= failing_first THEN NULL ELSE failing_since END,
                 failing_first = CASE WHEN ?2 >= failing_first THEN NULL ELSE failing_first END
                 WHERE subscription = ?1",
            )?
            .execute((
                key(subscription.0),
                i64::try_from(through).unwrap_or(i64::MAX),
            ))?;
        Ok(if changed == 1 {
            Ok(())
        } else {
            Err(Refusal::Gone)
        })
    }

    /// A message's prepared content, while any of its deliveries is
    /// unfinished.
    /// It is as it was kept: sealed, if it was sealed, for
    /// whoever sends it to open, so no cipher work runs on the store's
    /// thread.
    pub fn body(&self, id: BodyId) -> Result<Option<Bytes>, StoreError> {
        let content: Option<Vec<u8>> = self
            .db()
            .prepare_cached("SELECT content FROM bodies WHERE id = ?1")?
            .query_row([key(id.0)], |row| row.get(0))
            .optional()?;
        // A sealed body opens only in its own row: one moved from another's
        // is damage, never another message's content sent here.
        if let Some(content) = &content
            && !keys::body_in_place(content, id.0.as_u64())
        {
            return Err(corrupt("bodies", key(id.0))(CodecError::Invalid(
                "body's place",
            )));
        }
        Ok(content.map(Bytes::from))
    }

    /// A message's prepared content: its body, through its message record.
    pub fn content(&self, id: MessageId) -> Result<Option<Bytes>, StoreError> {
        match self.message(id)? {
            Some(message) => self.body(message.body),
            None => Ok(None),
        }
    }

    /// Waiting deliveries due by `now`, earliest first, from just past
    /// `after` in the order of due time, then ID.
    pub fn due(
        &self,
        now: Timestamp,
        after: Option<DuePosition>,
        limit: usize,
    ) -> Result<Vec<Delivery>, StoreError> {
        let (due_at, id) = after.map_or((i64::MIN, 0), |after| {
            (column(after.due_at), key(after.delivery.0))
        });
        self.deliveries(
            "SELECT id, record FROM deliveries
             WHERE state = 0 AND due_at <= ?1 AND (due_at, id) > (?2, ?3)
             ORDER BY due_at, id LIMIT ?4",
            (column(now), due_at, id, count(limit)),
        )
    }

    /// Waiting and held deliveries whose expiry has passed by `now`,
    /// earliest first: a hold never keeps mail past its expiry.
    pub fn expiring(&self, now: Timestamp, limit: usize) -> Result<Vec<Delivery>, StoreError> {
        self.deliveries(
            "SELECT id, record FROM deliveries WHERE state IN (0, 3) AND expires_at <= ?1
             ORDER BY expires_at LIMIT ?2",
            (column(now), count(limit)),
        )
    }

    /// Held deliveries by ID, from just past `after`.
    pub fn held(
        &self,
        after: Option<DeliveryId>,
        limit: usize,
    ) -> Result<Vec<Delivery>, StoreError> {
        let after = after.map_or(0, |after| key(after.0));
        self.deliveries(
            "SELECT id, record FROM deliveries WHERE state = 3 AND id > ?1
             ORDER BY id LIMIT ?2",
            (after, count(limit)),
        )
    }

    pub(crate) fn execute(&self, sql: &str) -> Result<(), StoreError> {
        Ok(self.db().execute_batch(sql)?)
    }

    /// Raises the ID high-water mark to at least `id`.
    pub(crate) fn raise_highest_id(&self, id: Id) -> Result<(), StoreError> {
        self.db()
            .prepare_cached("UPDATE highest_id SET id = max(id, ?1)")?
            .execute([key(id)])?;
        Ok(())
    }

    /// Accepts a submission: its bodies, messages and deliveries, counted
    /// against its account's quota.
    pub(crate) fn accept(
        &mut self,
        unit: &Accept,
    ) -> Result<Result<(), AcceptRefusal>, StoreError> {
        let Some(first) = unit.messages.first() else {
            return Ok(Err(AcceptRefusal::NoMessages));
        };
        if unit
            .messages
            .iter()
            .any(|message| message.recipients.is_empty())
        {
            return Ok(Err(AcceptRefusal::NoRecipients));
        }
        if unit
            .messages
            .iter()
            .any(|message| message.recipients.len() > MAX_RECIPIENTS)
        {
            return Ok(Err(AcceptRefusal::TooManyRecipients));
        }
        if unit.accepted_at >= unit.expires_at {
            return Ok(Err(AcceptRefusal::ExpiresAtAcceptance));
        }
        // A command applied again finds everything it creates already there.
        if self.message_exists(first.id)? {
            for message in &unit.messages {
                if !self.message_exists(message.id)? {
                    return Ok(Err(AcceptRefusal::Conflict));
                }
            }
            return Ok(Ok(()));
        }
        // Authorised under an older policy: the decision is taken again.
        let authority = &unit.authority;
        if authority.revision != self.policy.revision()
            && let Err(denial) = self
                .policy
                .admits(authority.credential, authority.account, &authority.origin)
                .and_then(|()| match authority.template {
                    Some(template) => {
                        self.policy
                            .uses(&authority.origin, authority.account, template)
                    }
                    None => Ok(()),
                })
        {
            return Ok(Err(AcceptRefusal::Unauthorised(denial)));
        }
        let recipients: u64 = unit
            .messages
            .iter()
            .map(|message| message.recipients.len() as u64)
            .sum();
        let quota = self
            .policy
            .account(authority.account)
            .and_then(|account| account.daily_quota);
        if let Some(quota) = quota
            && !self
                .ledger
                .admits(authority.account, unit.accepted_at, recipients, quota)
        {
            return Ok(Err(AcceptRefusal::QuotaExceeded));
        }
        {
            let db = self.db();
            let mut insert_body = db.prepare_cached(
                "INSERT INTO bodies (id, key, nonce, content) VALUES (?1, ?2, NULL, ?3)",
            )?;
            let mut insert_message = db.prepare_cached(
                "INSERT INTO messages (id, unfinished, record, mail) VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut insert_delivery = db.prepare_cached(
                "INSERT INTO deliveries (id, state, due_at, expires_at, record) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for accepted in &unit.messages {
                let message = Message {
                    id: accepted.id,
                    submission: unit.submission,
                    account: authority.account,
                    origin: authority.origin,
                    body: accepted.body,
                    accepted_at: unit.accepted_at,
                    policy_revision: authority.revision,
                    recipients: u32::try_from(accepted.recipients.len())
                        .expect("at most MAX_RECIPIENTS, checked above"),
                };
                let body = insert_body.execute((
                    key(accepted.body.0),
                    keys::body_key(&accepted.content),
                    &accepted.content[..],
                ));
                if !inserted_unless_taken(body)? {
                    return Ok(Err(AcceptRefusal::Conflict));
                }
                let record = records::encode_message(&message);
                let unfinished = count(accepted.recipients.len());
                // Nothing more for a message SES-shaped events say nothing
                // of.
                let mail = accepted.mail.as_ref().map(|mail| {
                    let tenant = self.sealed_as(message.origin.tenant);
                    records::encode_mail(mail, message.id, tenant, self.data_keys())
                });
                let message = insert_message.execute((key(message.id.0), unfinished, record, mail));
                if !inserted_unless_taken(message)? {
                    return Ok(Err(AcceptRefusal::Conflict));
                }
                for recipient in &accepted.recipients {
                    let delivery = unit
                        .delivery(accepted, recipient)
                        .expect("checked above: accepted before it expires");
                    let (state, due_at, until) = index_keys(&delivery);
                    let result = insert_delivery.execute((
                        key(delivery.id().0),
                        state,
                        due_at,
                        until,
                        records::encode_delivery(
                            &delivery,
                            self.sealed_as(delivery.origin().tenant),
                            self.data_keys(),
                        ),
                    ));
                    if !inserted_unless_taken(result)? {
                        return Ok(Err(AcceptRefusal::Conflict));
                    }
                    self.moved(None, state);
                }
                self.append(&Entry::Accepted {
                    message: accepted.id,
                    account: authority.account,
                    configuration: authority.origin.configuration,
                    deliveries: accepted
                        .recipients
                        .iter()
                        .map(|recipient| recipient.delivery)
                        .collect(),
                    at: unit.accepted_at,
                })?;
            }
        }
        self.ledger
            .count(authority.account, unit.accepted_at, recipients);
        Ok(Ok(()))
    }

    /// Reserves a delivery for an attempt. The delivery records the attempt
    /// in flight; the attempt's evidence is written when it ends.
    /// A delivery whose authority current policy withdrew, or whose
    /// recipient is suppressed when it falls due, is not sent: it finishes
    /// without an attempt, and its message is returned
    /// for `finish`. One a hold covers is parked.
    pub(crate) fn reserve(
        &mut self,
        reserve: &Reserve,
    ) -> Result<Result<(Reservation, Option<Finished>), Refusal>, StoreError> {
        let Some(delivery) = self.delivery(reserve.delivery)? else {
            return Ok(Err(Refusal::Gone));
        };
        let was = state_of(&delivery);
        let mut reserved = delivery.clone();
        let reservation =
            reserved.reserve(reserve.seen, reserve.attempt, reserve.egress, reserve.now);
        let permit = match reservation {
            Ok(permit) => permit,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // So is one a restored store's fence discards, and one
        // whose recipient is erased with its tenant's key, which
        // is nobody's to send to.
        let erased = delivery.recipient().as_str().as_bytes() == records::ERASED_ADDRESS;
        if erased
            || self
                .policy
                .allows(delivery.account(), delivery.origin())
                .is_err()
            || self.policy.discards(delivery.id())
        {
            let mut cancelled = delivery;
            cancelled
                .cancel(reserve.now)
                .expect("it could be reserved, so it is waiting");
            self.update_delivery(&cancelled, was)?;
            self.append(&Entry::Cancelled {
                delivery: cancelled.id(),
                account: cancelled.account(),
                configuration: cancelled.origin().configuration,
                at: reserve.now,
            })?;
            return Ok(Ok((
                Reservation::Cancelled,
                Some((cancelled.message(), reserve.now)),
            )));
        }
        if self.is_suppressed(delivery.account(), delivery.recipient())? {
            let mut suppressed = delivery;
            suppressed
                .suppress(reserve.now)
                .expect("it could be reserved, so it is waiting");
            self.update_delivery(&suppressed, was)?;
            self.append(&Entry::Suppressed {
                delivery: suppressed.id(),
                account: suppressed.account(),
                configuration: suppressed.origin().configuration,
                at: reserve.now,
            })?;
            return Ok(Ok((
                Reservation::Suppressed,
                Some((suppressed.message(), reserve.now)),
            )));
        }
        // An attempt goes out only from a source current policy gives its
        // mail: one placed under older policy is placed again. A
        // settlement, which has no site, sends nothing.
        if reserve.site.is_some()
            && !self.policy.sends_from(
                delivery.account(),
                delivery.origin().configuration,
                reserve.egress,
            )
        {
            return Ok(Err(Refusal::Unsourced));
        }
        // Paused by a hold, or held by a restored store's fence:
        // parked in this commit, keeping when it was due and where it
        // goes out from, with no journal entry, as nothing about its
        // delivery has happened.
        if self.policy.holds_back(
            delivery.id(),
            delivery.account(),
            delivery.origin(),
            reserve.egress,
        ) {
            let mut held = delivery;
            held.park(reserve.seen, reserve.egress, reserve.now)
                .expect("it could be reserved, so it is waiting and due");
            self.update_delivery(&held, was)?;
            return Ok(Ok((Reservation::Paused, None)));
        }
        self.update_delivery(&reserved, was)?;
        // An attempt from an egress with a cap at the site counts against
        // its budget there.
        if let (Some(egress), Some(site)) = (reserve.egress, &reserve.site)
            && self
                .policy
                .egress(egress)
                .is_some_and(|held| held.caps.at(site).is_some())
        {
            let counted = (egress, Arc::clone(site));
            self.dispatched
                .entry(counted.clone())
                .or_default()
                .window
                .add(reserve.now);
            self.dispatched_changed.insert(counted);
        }
        Ok(Ok((Reservation::Permit(permit), None)))
    }

    /// Whether `recipient` is on `account`'s suppression list.
    pub fn is_suppressed(
        &self,
        account: AccountId,
        recipient: &Address,
    ) -> Result<bool, StoreError> {
        Ok(self
            .db()
            .prepare_cached("SELECT 1 FROM suppressions WHERE account = ?1 AND key = ?2")?
            .exists((key(account.0), self.suppression_key(recipient).as_bytes()))?)
    }

    /// Adds addresses to `account`'s suppression list, or replaces their
    /// reason. Returns how many it wrote.
    pub(crate) fn suppress(&self, suppress: &Suppress) -> Result<u64, StoreError> {
        let mut statement = self.db().prepare_cached(
            "INSERT OR REPLACE INTO suppressions (account, key, record) VALUES (?1, ?2, ?3)",
        )?;
        for address in &suppress.addresses {
            let found_by = self.suppression_key(address);
            statement.execute((
                key(suppress.account.0),
                found_by.as_bytes(),
                records::encode_suppression(
                    suppress.account,
                    &found_by,
                    address,
                    suppress.reason,
                    suppress.now,
                    self.data_keys(),
                ),
            ))?;
        }
        Ok(suppress.addresses.len() as u64)
    }

    /// `address` on `account`'s suppression list, if it is.
    pub fn suppression(
        &self,
        account: AccountId,
        address: &Address,
    ) -> Result<Option<Suppressed>, StoreError> {
        let found_by = self.suppression_key(address);
        let record: Option<Vec<u8>> = self
            .db()
            .prepare_cached("SELECT record FROM suppressions WHERE account = ?1 AND key = ?2")?
            .query_row((key(account.0), found_by.as_bytes()), |row| row.get(0))
            .optional()?;
        record
            .map(|record| {
                records::decode_suppression(&record, account, found_by.as_bytes(), self.open_keys())
                    .map_err(corrupt("suppressions", key(account.0)))
            })
            .transpose()
    }

    /// A page of an account's suppression list, reading at most
    /// `List::MOST_READ` rows.
    pub fn suppressions(&self, list: &List) -> Result<Page, StoreError> {
        let mut statement = self.db().prepare_cached(
            "SELECT key, record FROM suppressions WHERE account = ?1 AND key > ?2 ORDER BY key LIMIT ?3",
        )?;
        let after = list.after.clone().unwrap_or_default();
        let read = i64::try_from(List::MOST_READ).unwrap_or(i64::MAX);
        let mut rows = statement.query((key(list.account.0), after.as_bytes(), read))?;
        let mut page = Page::default();
        let (mut count, mut last) = (0, None);
        while let Some(row) = rows.next()? {
            count += 1;
            let found_by: Vec<u8> = row.get(0)?;
            let found = records::decode_suppression(
                &row.get::<_, Vec<u8>>(1)?,
                list.account,
                &found_by,
                self.open_keys(),
            )
            .map_err(corrupt("suppressions", key(list.account.0)))?;
            last = Some(found_by);
            let wanted = (list.reasons.is_empty() || list.reasons.contains(&found.reason))
                && list.from.is_none_or(|from| found.at >= from)
                && list.to.is_none_or(|to| found.at < to);
            if wanted {
                page.suppressed.push(found);
                if page.suppressed.len() == list.limit {
                    break;
                }
            }
        }
        // More may follow the last row read, unless fewer were read than
        // the most and the page is not full.
        let full = page.suppressed.len() == list.limit;
        if full || count == List::MOST_READ {
            page.next = last.map(|key| String::from_utf8_lossy(&key).into_owned());
        }
        Ok(page)
    }

    /// Removes addresses from `account`'s suppression list. Returns how
    /// many it removed.
    pub(crate) fn unsuppress(&self, unsuppress: &Unsuppress) -> Result<u64, StoreError> {
        let mut statement = self
            .db()
            .prepare_cached("DELETE FROM suppressions WHERE account = ?1 AND key = ?2")?;
        let mut removed = 0;
        for address in &unsuppress.addresses {
            removed += statement.execute((
                key(unsuppress.account.0),
                self.suppression_key(address).as_bytes(),
            ))? as u64;
        }
        Ok(removed)
    }

    /// Records what an attempt did. Returns the delivery's message and when
    /// it finished, if this finished it, for the commit owner to count
    /// (`finish`).
    pub(crate) fn record_outcome(
        &mut self,
        outcome: RecordOutcome,
    ) -> Result<Result<Option<Finished>, Refusal>, StoreError> {
        let Some(mut delivery) = self.delivery(outcome.permit.delivery())? else {
            return Ok(Err(Refusal::Gone));
        };
        let was = state_of(&delivery);
        let reserved_at = match delivery.state() {
            QueueState::InFlight { since, .. } => Some(since),
            _ => None,
        };
        let attempt = outcome.permit.attempt();
        if let Err(refusal) =
            delivery.record_outcome(outcome.permit, outcome.disposition, outcome.now)
        {
            return Ok(Err(refusal));
        }
        let reserved_at =
            reserved_at.expect("an outcome is recorded only for an attempt in flight");
        let (_, entry) = self.end_attempt(
            &delivery,
            attempt,
            reserved_at,
            (outcome.disposition.into(), outcome.evidence.clone()),
            outcome.now,
        )?;
        // The delivery keeps where its reply is, not the reply.
        delivery.heard(outcome.evidence.as_ref(), entry);
        // What the reply showed counts toward warmup at a site its egress
        // is capped at, and a delivered recipient keeps the site, so a
        // report about it counts there too.
        let delivered_at = outcome.counted.as_ref().filter(|counted| {
            self.tally(delivery.egress(), &counted.site, counted.signal, counted.at)
                && counted.signal == Signal::Delivered
        });
        self.update_delivery_at(&delivery, was, delivered_at.map(|counted| &*counted.site))?;
        // A refusal of the address itself suppresses it, in this commit.
        if outcome.disposition == Disposition::Rejected && outcome.suppress {
            self.suppress(&Suppress {
                account: delivery.account(),
                addresses: vec![delivery.recipient().clone()],
                reason: Reason::Bounce,
                now: outcome.now,
            })?;
        }
        // How its site's cooldown changed is kept with it.
        if let Some(change) = &outcome.cooled {
            self.change_cooldown(change)?;
        }
        Ok(Ok(finished(&delivery)))
    }

    /// Keeps a change to a site's cooldown.
    pub(crate) fn change_cooldown(&self, change: &CooldownChange) -> Result<(), StoreError> {
        match change {
            CooldownChange::Kept(cooldown) => self.cool(cooldown),
            CooldownChange::Ended { egress, site } => self.uncool(*egress, site),
        }
    }

    /// Keeps `cooldown`, in place of one its site had from its source that
    /// ends sooner: whatever order cooldowns commit in, the latest end
    /// stands.
    fn cool(&self, cooldown: &SiteCooldown) -> Result<(), StoreError> {
        self.db()
            .prepare_cached(
                "INSERT INTO cooldowns (egress, site, until, record) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (egress, site) DO UPDATE
                 SET until = excluded.until, record = excluded.record
                 WHERE excluded.until > cooldowns.until",
            )?
            .execute((
                cooldown.egress.map_or(0, |egress| key(egress.0)),
                cooldown.site.as_ref(),
                column(cooldown.until),
                records::encode_cooldown(cooldown, self.data_keys()),
            ))?;
        Ok(())
    }

    /// Forgets the cooldown `site` had from `egress`.
    fn uncool(&self, egress: Option<EgressId>, site: &str) -> Result<(), StoreError> {
        self.db()
            .prepare_cached("DELETE FROM cooldowns WHERE egress = ?1 AND site = ?2")?
            .execute((egress.map_or(0, |egress| key(egress.0)), site))?;
        Ok(())
    }

    /// Keeps a domain's MTA-STS policy in place of the one an earlier fetch
    /// made: whatever order fetches commit in, the latest stands.
    pub(crate) fn keep_sts(&self, policy: &sts::Policy) -> Result<(), StoreError> {
        self.db()
            .prepare_cached(
                "INSERT INTO sts_policies (domain, fetched_at, expires_at, record)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (domain) DO UPDATE
                 SET fetched_at = excluded.fetched_at, expires_at = excluded.expires_at,
                     record = excluded.record
                 WHERE excluded.fetched_at >= sts_policies.fetched_at",
            )?
            .execute((
                policy.domain.as_ref(),
                column(policy.fetched_at),
                column(policy.expires_at()),
                records::encode_sts(policy),
            ))?;
        Ok(())
    }

    /// The MTA-STS policies kept that still hold at `now`: `domain`'s
    /// alone, if one is named; else those fetched last, at most `limit`.
    pub fn sts_policies(
        &self,
        now: Timestamp,
        domain: Option<&str>,
        limit: usize,
    ) -> Result<Vec<sts::Policy>, StoreError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        // A domain's alone by its key; the rest by when they were fetched.
        let mut statement = match domain {
            Some(_) => self.db().prepare_cached(
                "SELECT domain, fetched_at, record FROM sts_policies
                 WHERE domain = ?2 AND expires_at > ?1 LIMIT ?3",
            )?,
            None => self.db().prepare_cached(
                "SELECT domain, fetched_at, record FROM sts_policies
                 WHERE expires_at > ?1 AND ?2 IS NULL
                 ORDER BY fetched_at DESC LIMIT ?3",
            )?,
        };
        let mut rows = statement.query((column(now), domain, limit))?;
        let mut policies = Vec::new();
        while let Some(row) = rows.next()? {
            let domain: String = row.get(0)?;
            let fetched_at: i64 = row.get(1)?;
            let record: Vec<u8> = row.get(2)?;
            let fetched = Timestamp::from_micros(u64::try_from(fetched_at).unwrap_or_default());
            // The row has no number of its own: it is named by when it was
            // fetched.
            policies.push(
                records::decode_sts(&domain, fetched, &record)
                    .map_err(corrupt("sts_policies", fetched_at))?,
            );
        }
        Ok(policies)
    }

    /// What the scheduler starts from: the dispatch ledger's windows, and
    /// every cooldown kept.
    pub fn dispatch_ledger(&self) -> Result<DispatchLedger, StoreError> {
        let mut statement = self
            .db()
            .prepare_cached("SELECT egress, site, until, record FROM cooldowns")?;
        let mut rows = statement.query([])?;
        let mut cooldowns = Vec::new();
        while let Some(row) = rows.next()? {
            let egress_key: i64 = row.get(0)?;
            let site: String = row.get(1)?;
            let until: i64 = row.get(2)?;
            let record: Vec<u8> = row.get(3)?;
            let egress = match egress_key {
                0 => None,
                key => Some(EgressId(id_from_key(key).ok_or_else(|| {
                    corrupt("cooldowns", key)(CodecError::Invalid("egress"))
                })?)),
            };
            let until = Timestamp::from_micros(u64::try_from(until).unwrap_or_default());
            cooldowns.push(
                records::decode_cooldown(egress, site.into(), until, &record, self.open_keys())
                    .map_err(corrupt("cooldowns", egress_key))?,
            );
        }
        Ok(DispatchLedger {
            windows: self.dispatched(),
            cooldowns,
        })
    }

    /// Expires a waiting delivery, which finishes it. Returns its message,
    /// and when it finished.
    pub(crate) fn expire(&self, expire: &Expire) -> Result<Result<Finished, Refusal>, StoreError> {
        let Some(mut delivery) = self.delivery(expire.delivery)? else {
            return Ok(Err(Refusal::Gone));
        };
        let was = state_of(&delivery);
        if let Err(refusal) = delivery.expire(expire.now) {
            return Ok(Err(refusal));
        }
        self.update_delivery(&delivery, was)?;
        self.append(&Entry::Expired {
            delivery: delivery.id(),
            account: delivery.account(),
            configuration: delivery.origin().configuration,
            at: expire.now,
        })?;
        Ok(Ok((delivery.message(), expire.now)))
    }

    /// Parks a waiting delivery a hold covers, as it is to go
    /// out from `park.egress`, in its row, with no journal entry: nothing
    /// about its delivery has happened. Refused unless a hold in current
    /// policy covers it.
    pub(crate) fn park(&self, park: &Park) -> Result<Result<(), Refusal>, StoreError> {
        let Some(mut delivery) = self.delivery(park.delivery)? else {
            return Ok(Err(Refusal::Gone));
        };
        if !self.policy.holds_back(
            delivery.id(),
            delivery.account(),
            delivery.origin(),
            park.egress,
        ) {
            return Ok(Err(Refusal::NotHeld));
        }
        let was = state_of(&delivery);
        if let Err(refusal) = delivery.park(park.seen, park.egress, park.now) {
            return Ok(Err(refusal));
        }
        self.update_delivery(&delivery, was)?;
        Ok(Ok(()))
    }

    /// Releases a held delivery no hold covers any longer, in its row:
    /// refused while one in current policy does.
    pub(crate) fn release(&self, release: &Release) -> Result<Result<(), Refusal>, StoreError> {
        let Some(mut delivery) = self.delivery(release.delivery)? else {
            return Ok(Err(Refusal::Gone));
        };
        if self.policy.holds_back(
            delivery.id(),
            delivery.account(),
            delivery.origin(),
            delivery.egress(),
        ) {
            return Ok(Err(Refusal::Held));
        }
        let was = state_of(&delivery);
        if let Err(refusal) = delivery.release(release.seen) {
            return Ok(Err(refusal));
        }
        self.update_delivery(&delivery, was)?;
        Ok(Ok(()))
    }

    /// Puts off a waiting delivery whose egress has no room for it,
    /// as it is to go out from `postpone.egress`, in its row, with no
    /// journal entry: nothing about its delivery has happened.
    pub(crate) fn postpone(&self, postpone: &Postpone) -> Result<Result<(), Refusal>, StoreError> {
        let Some(mut delivery) = self.delivery(postpone.delivery)? else {
            return Ok(Err(Refusal::Gone));
        };
        let was = state_of(&delivery);
        if let Err(refusal) =
            delivery.postpone(postpone.seen, postpone.egress, postpone.until, postpone.now)
        {
            return Ok(Err(refusal));
        }
        self.update_delivery(&delivery, was)?;
        Ok(Ok(()))
    }

    /// Returns every delivery whose attempt was in flight when the store
    /// last stopped to the queue, due now, and marks those attempts
    /// abandoned: each may have reached its receiver. Returns them, and how
    /// many deliveries of each message this finished, for `finish`.
    pub(crate) fn recover_in_flight(
        &self,
        now: Timestamp,
    ) -> Result<(Vec<Attempt>, Finishing), StoreError> {
        let in_flight = self.deliveries("SELECT id, record FROM deliveries WHERE state = 1", [])?;
        let mut abandoned = Vec::with_capacity(in_flight.len());
        let mut finishing = Finishing::new();
        for mut delivery in in_flight {
            let QueueState::InFlight { since, .. } = delivery.state() else {
                unreachable!("selected in flight");
            };
            let was = state_of(&delivery);
            let attempt = delivery.recover(now, now).expect("selected in flight");
            self.update_delivery(&delivery, was)?;
            abandoned.push(
                self.end_attempt(
                    &delivery,
                    attempt,
                    since,
                    (AttemptResult::Abandoned, None),
                    now,
                )?
                .0,
            );
            if let Some(finished) = finished(&delivery) {
                count_finished(&mut finishing, finished);
            }
        }
        Ok((abandoned, finishing))
    }

    fn db(&self) -> &Connection {
        self.connection.borrow()
    }

    fn message_exists(&self, id: MessageId) -> Result<bool, StoreError> {
        Ok(self
            .db()
            .prepare_cached("SELECT 1 FROM messages WHERE id = ?1")?
            .exists([key(id.0)])?)
    }

    fn deliveries(&self, sql: &str, parameters: impl Params) -> Result<Vec<Delivery>, StoreError> {
        let mut statement = self.db().prepare_cached(sql)?;
        let rows: Vec<(i64, Vec<u8>)> = statement
            .query_map(parameters, |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(key, record)| {
                let id = id_from_key(key)
                    .ok_or_else(|| corrupt("deliveries", key)(CodecError::Invalid("ID")))?;
                records::decode_delivery(DeliveryId(id), &record, self.open_keys())
                    .map_err(corrupt("deliveries", key))
            })
            .collect()
    }

    /// Writes `delivery` again, which was in state `was` (`state_of`).
    fn update_delivery(&self, delivery: &Delivery, was: i64) -> Result<(), StoreError> {
        self.update_delivery_at(delivery, was, None)
    }

    /// Writes `delivery` as `update_delivery` does, and with `site`, the
    /// site its recipient was delivered at from a capped egress, which a
    /// report about it is counted at.
    fn update_delivery_at(
        &self,
        delivery: &Delivery,
        was: i64,
        site: Option<&str>,
    ) -> Result<(), StoreError> {
        let (state, due_at, until) = index_keys(delivery);
        self.moved(Some(was), state);
        let id = key(delivery.id().0);
        let record = records::encode_delivery(
            delivery,
            self.sealed_as(delivery.origin().tenant),
            self.data_keys(),
        );
        let db = self.db();
        let changed = match site {
            None => db
                .prepare_cached(
                    "UPDATE deliveries SET state = ?2, due_at = ?3, expires_at = ?4, record = ?5
                     WHERE id = ?1",
                )?
                .execute((id, state, due_at, until, record))?,
            Some(site) => db
                .prepare_cached(
                    "UPDATE deliveries
                     SET state = ?2, due_at = ?3, expires_at = ?4, record = ?5, site = ?6
                     WHERE id = ?1",
                )?
                .execute((id, state, due_at, until, record, site))?,
        };
        expect_one_row(changed, "deliveries", id)
    }

    /// The keys personal data is sealed under, while encryption is on.
    fn data_keys(&self) -> Option<&Keys> {
        match self.encryption {
            Encryption::Off => None,
            Encryption::Installation | Encryption::Tenant => Some(&self.data),
        }
    }

    /// The keys personal data opens under, whatever encryption is now: what
    /// was sealed while it was on still reads once it is off.
    fn open_keys(&self) -> Option<&Keys> {
        Some(&self.data)
    }

    /// Seals `tenant`'s mail under `key` from now on, while
    /// per-tenant keys are on, and opens what it sealed in any mode.
    pub fn add_tenant_key(&mut self, tenant: TenantId, key: &TenantKey) {
        self.data.add_tenant(tenant.0.as_u64(), key);
    }

    /// A page of the scan for what installation key `key` still seals:
    /// from `from`, where the last page left off, the records of
    /// one table holding personal data, each read as ever but with `key`
    /// refused, so those that still need it fail to open; then the next
    /// table's. A key may be retired once the whole scan finds none.
    pub fn key_held(&self, key: u8, from: Option<&[u8]>) -> Result<KeyHeld, StoreError> {
        let (table, after) = match from {
            Some([table, after @ ..]) => (usize::from(*table), after),
            _ => (0, &[][..]),
        };
        let Some(&name) = SEALED.get(table) else {
            return Ok(KeyHeld {
                table: "",
                held: 0,
                next: None,
            });
        };
        let probe = self.data.refusing(key);
        let probe = Some(&probe);
        let needs = |opened: Result<(), CodecError>, row: i64| match opened {
            Ok(()) | Err(CodecError::Erased) => Ok(0),
            Err(CodecError::NoKey(refused)) if refused == key => Ok(1),
            Err(error) => Err(corrupt(name, row)(error)),
        };
        let id = |row: i64| {
            id_from_key(row).ok_or_else(|| corrupt(name, row)(CodecError::Invalid("id")))
        };
        let row_after = after
            .first_chunk::<8>()
            .map_or(0, |row| i64::from_be_bytes(*row));
        // A page's rows, by their key: its column, then the record's.
        let page = |sql: &str| -> Result<Vec<Row>, StoreError> {
            let mut statement = self.db().prepare_cached(sql)?;
            let rows = statement
                .query_map((row_after, KEY_PAGE), |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .collect::<Result<_, _>>()?;
            Ok(rows)
        };
        let mut held = 0;
        // Where the next page of this table starts, if this one was full.
        let mut last: Option<Vec<u8>> = None;
        let full = |rows: usize| rows == usize::try_from(KEY_PAGE).unwrap_or(usize::MAX);
        match name {
            "bodies" => {
                let mut statement = self.db().prepare_cached(
                    "SELECT id, key FROM bodies WHERE id > ?1 ORDER BY id LIMIT ?2",
                )?;
                let rows: Vec<(i64, i64)> = statement
                    .query_map((row_after, KEY_PAGE), |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                let sealed = rows.iter().filter(|(_, sealed)| *sealed == i64::from(key));
                held = u64::try_from(sealed.count()).unwrap_or(u64::MAX);
                last = rows
                    .last()
                    .filter(|_| full(rows.len()))
                    .map(|(row, _)| row.to_be_bytes().to_vec());
            }
            "messages" | "deliveries" | "journal" | "feedback" => {
                let rows = page(match name {
                    "messages" => {
                        "SELECT id, mail, x'' FROM messages WHERE id > ?1 AND mail IS NOT NULL
                         ORDER BY id LIMIT ?2"
                    }
                    "deliveries" => {
                        "SELECT id, record, x'' FROM deliveries WHERE id > ?1 ORDER BY id LIMIT ?2"
                    }
                    "journal" => {
                        "SELECT position, record, x'' FROM journal WHERE position > ?1
                         ORDER BY position LIMIT ?2"
                    }
                    _ => {
                        "SELECT id, record, identity FROM feedback WHERE id > ?1 ORDER BY id LIMIT ?2"
                    }
                })?;
                for (row, record, identity) in &rows {
                    let opened = match name {
                        "messages" => {
                            records::decode_mail(record, MessageId(id(*row)?), probe).map(drop)
                        }
                        "deliveries" => {
                            records::decode_delivery(DeliveryId(id(*row)?), record, probe).map(drop)
                        }
                        "journal" => records::decode_entry(record, probe).map(drop),
                        _ => {
                            let identity: [u8; 32] =
                                identity.as_slice().try_into().map_err(|_| {
                                    corrupt(name, *row)(CodecError::Invalid("identity"))
                                })?;
                            records::decode_report(ReportId(id(*row)?), identity, record, probe)
                                .map(drop)
                        }
                    };
                    held += needs(opened, *row)?;
                }
                last = rows
                    .last()
                    .filter(|_| full(rows.len()))
                    .map(|(row, ..)| row.to_be_bytes().to_vec());
            }
            "cooldowns" => {
                // A row for each site a source is cooling at: few, read whole.
                let mut statement = self
                    .db()
                    .prepare_cached("SELECT egress, site, until, record FROM cooldowns")?;
                let rows: Vec<(i64, String, i64, Vec<u8>)> = statement
                    .query_map([], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    })?
                    .collect::<Result<_, _>>()?;
                for (egress, site, until, record) in rows {
                    let source = match egress {
                        0 => None,
                        egress => Some(EgressId(id(egress)?)),
                    };
                    let until = Timestamp::from_micros(u64::try_from(until).unwrap_or_default());
                    let opened =
                        records::decode_cooldown(source, site.into(), until, &record, probe);
                    held += needs(opened.map(drop), egress)?;
                }
            }
            _ => {
                let matching = after.get(8..).unwrap_or_default();
                let mut statement = self.db().prepare_cached(
                    "SELECT account, key, record FROM suppressions WHERE (account, key) > (?1, ?2)
                     ORDER BY account, key LIMIT ?3",
                )?;
                let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = statement
                    .query_map((row_after, matching, KEY_PAGE), |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })?
                    .collect::<Result<_, _>>()?;
                for (account, matching, record) in &rows {
                    let opened = records::decode_suppression(
                        record,
                        AccountId(id(*account)?),
                        matching,
                        probe,
                    );
                    held += needs(opened.map(drop), *account)?;
                }
                last = rows
                    .last()
                    .filter(|_| full(rows.len()))
                    .map(|(account, matching, _)| [&account.to_be_bytes()[..], matching].concat());
            }
        }
        let table = u8::try_from(table).expect("a few tables");
        let next = match last {
            Some(after) => Some([&[table][..], &after].concat()),
            None => (usize::from(table) + 1 < SEALED.len()).then(|| vec![table + 1]),
        };
        Ok(KeyHeld {
            table: name,
            held,
            next,
        })
    }

    /// Forgets `tenant`'s key: what it sealed reads as erased.
    pub fn forget_tenant_key(&mut self, tenant: TenantId) {
        self.data.forget_tenant(tenant.0.as_u64());
    }

    /// Whether `change` creates a tenant whose key the store does not hold.
    fn creates_unkeyed(&self, change: &Change) -> bool {
        match change {
            Change::Tenant {
                id, account, name, ..
            }
            | Change::NewTenant {
                id, account, name, ..
            } => {
                self.policy.tenant_named(*account, name).is_none()
                    && !self.data.has_tenant(id.0.as_u64())
            }
            _ => false,
        }
    }

    /// The tenant whose key `tenant`'s mail is sealed under: its own while
    /// per-tenant keys are on, none otherwise.
    fn sealed_as(&self, tenant: Option<TenantId>) -> Option<TenantId> {
        tenant.filter(|_| self.encryption == Encryption::Tenant)
    }

    /// What `address`'s suppression is found by: its matching
    /// key, or that hashed under the current key's index key while
    /// encryption is on, so the list holds no address in the clear.
    fn suppression_key(&self, address: &Address) -> String {
        let matching = suppression::key(address);
        match self.data_keys() {
            Some(keys) => keys.installation().index(&matching),
            None => matching,
        }
    }

    /// Rewrites the suppression list once, at start, when its keys were made
    /// otherwise than encryption now makes them: turned on or
    /// off, or under a key since rotated. Each record is sealed again as
    /// encryption now seals, and the whole list is replaced in one commit,
    /// which `zeroing` runs.
    fn rekey_suppressions(&self) -> Result<(), StoreError> {
        let wanted = i64::from(
            self.data_keys()
                .map_or(NO_KEY, |keys| keys.installation().current()),
        );
        let db = self.db();
        let made: i64 = db.query_row("SELECT key FROM suppression_index", [], |row| row.get(0))?;
        if made == wanted {
            return Ok(());
        }
        db.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE suppressions_rekeyed (
                 account INTEGER NOT NULL,
                 key BLOB NOT NULL,
                 record BLOB NOT NULL,
                 PRIMARY KEY (account, key)
             ) STRICT, WITHOUT ROWID;",
        )?;
        let rewritten = (|| -> Result<(), StoreError> {
            let mut read = db.prepare("SELECT account, key, record FROM suppressions")?;
            let mut write = db.prepare(
                "INSERT OR REPLACE INTO suppressions_rekeyed (account, key, record)
                 VALUES (?1, ?2, ?3)",
            )?;
            let mut rows = read.query([])?;
            while let Some(row) = rows.next()? {
                let account_key: i64 = row.get(0)?;
                let was_by: Vec<u8> = row.get(1)?;
                let record: Vec<u8> = row.get(2)?;
                let account = AccountId(id_from_key(account_key).ok_or_else(|| {
                    corrupt("suppressions", account_key)(CodecError::Invalid("account"))
                })?);
                let found =
                    records::decode_suppression(&record, account, &was_by, self.open_keys())
                        .map_err(corrupt("suppressions", account_key))?;
                let found_by = self.suppression_key(&found.address);
                write.execute((
                    account_key,
                    found_by.as_bytes(),
                    records::encode_suppression(
                        account,
                        &found_by,
                        &found.address,
                        found.reason,
                        found.at,
                        self.data_keys(),
                    ),
                ))?;
            }
            Ok(())
        })();
        if let Err(error) = rewritten {
            let _ = db.execute_batch("ROLLBACK");
            return Err(error);
        }
        db.execute_batch(
            "DROP TABLE suppressions;
             ALTER TABLE suppressions_rekeyed RENAME TO suppressions;",
        )?;
        db.execute("UPDATE suppression_index SET key = ?1", [wanted])?;
        db.execute_batch("COMMIT")?;
        Ok(())
    }

    /// The site `delivery` was delivered at from a capped egress, if it
    /// was.
    fn delivered_site(&self, delivery: DeliveryId) -> Result<Option<Arc<str>>, StoreError> {
        let site: Option<Option<String>> = self
            .db()
            .prepare_cached("SELECT site FROM deliveries WHERE id = ?1")?
            .query_row([key(delivery.0)], |row| row.get(0))
            .optional()?;
        Ok(site.flatten().map(Arc::from))
    }

    /// A delivery moved into `to` from `from`, or came, in the unit under
    /// way.
    fn moved(&self, from: Option<i64>, to: i64) {
        let mut moves = self.moves.get();
        moves.moved(from, to);
        self.moves.set(moves);
    }

    /// Ends the unit under way's moves: kept with its group, or undone with
    /// the unit.
    pub(crate) fn settle_moves(&self, kept: bool) {
        let mut moves = self.moves.get();
        moves.settle(kept);
        self.moves.set(moves);
    }

    /// Ends the group's moves: counted once it has committed, or undone
    /// with it.
    pub(crate) fn commit_moves(&self, committed: bool) {
        let mut moves = self.moves.get();
        moves.commit(committed);
        self.moves.set(moves);
    }

    /// Unfinished deliveries by state, as last kept.
    pub fn queued(&self) -> Queued {
        Queued::from_states(self.moves.get().queued)
    }

    /// Unfinished deliveries by state, counted from their rows' indexes: at
    /// open, and to check the counts kept.
    pub fn count_queued(&self) -> Result<Queued, StoreError> {
        let count = |sql: &str| -> Result<i64, StoreError> {
            Ok(self.db().query_row(sql, [], |row| row.get(0))?)
        };
        Ok(Queued::from_states([
            count("SELECT count(*) FROM deliveries WHERE state = 0")?,
            count("SELECT count(*) FROM deliveries WHERE state = 1")?,
            0,
            count("SELECT count(*) FROM deliveries WHERE state = 3")?,
        ]))
    }

    /// When the waiting or held delivery nearest its expiry was accepted,
    /// the oldest while every delivery has the same lifetime; and when the
    /// earliest waiting delivery was due. Each one seek of an index.
    pub fn queue_times(&self) -> Result<(Option<Timestamp>, Option<Timestamp>), StoreError> {
        let db = self.db();
        let oldest: Option<i64> = db
            .prepare_cached(
                "SELECT id FROM deliveries WHERE state IN (0, 3) ORDER BY expires_at LIMIT 1",
            )?
            .query_row([], |row| row.get(0))
            .optional()?;
        let due: Option<i64> = db
            .prepare_cached("SELECT MIN(due_at) FROM deliveries WHERE state = 0")?
            .query_row([], |row| row.get(0))?;
        let oldest = oldest.and_then(id_from_key).map(Id::issued_at);
        let due = due.map(|due| Timestamp::from_micros(u64::try_from(due).unwrap_or_default()));
        Ok((oldest, due))
    }

    /// How far behind the furthest-behind subscription is, if there is one.
    pub fn event_lag(&self) -> Result<Option<EventLag>, StoreError> {
        let db = self.db();
        let behind: Option<i64> = db
            .prepare_cached("SELECT MIN(position) FROM cursors")?
            .query_row([], |row| row.get(0))?;
        let Some(behind) = behind else {
            return Ok(None);
        };
        let head: Option<i64> = db
            .prepare_cached("SELECT MAX(position) FROM journal")?
            .query_row([], |row| row.get(0))?;
        let next: Option<(i64, Vec<u8>)> = db
            .prepare_cached(
                "SELECT position, record FROM journal WHERE position > ?1 ORDER BY position LIMIT 1",
            )?
            .query_row([behind], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let since = match next {
            Some((position, record)) => Some(
                records::decode_entry(&record, self.open_keys())
                    .map_err(corrupt("journal", position))?
                    .at(),
            ),
            None => None,
        };
        let entries = head.map_or(0, |head| u64::try_from(head - behind).unwrap_or_default());
        Ok(Some(EventLag { entries, since }))
    }

    /// Ends attempt `id`, with how it ended and what the receiver said.
    /// Returns it, and its entry's position in the journal.
    fn end_attempt(
        &self,
        delivery: &Delivery,
        id: AttemptId,
        reserved_at: Timestamp,
        (result, evidence): (AttemptResult, Option<Evidence>),
        at: Timestamp,
    ) -> Result<(Attempt, u64), StoreError> {
        let attempt = Attempt {
            id,
            delivery: delivery.id(),
            account: delivery.account(),
            reserved_at,
            ended: Some(AttemptEnd { result, at }),
        };
        let entry = self.append_of(
            &Entry::Attempted {
                attempt,
                configuration: delivery.origin().configuration,
                evidence,
            },
            delivery.origin().tenant,
        )?;
        Ok((attempt, entry))
    }

    /// Appends `entry` to the journal, after every entry before it, and
    /// returns its position.
    fn append(&self, entry: &Entry) -> Result<u64, StoreError> {
        self.append_of(entry, None)
    }

    /// Appends `entry` as `append` does, what it holds of `tenant`'s mail
    /// sealed as its tenant's.
    fn append_of(&self, entry: &Entry, tenant: Option<TenantId>) -> Result<u64, StoreError> {
        let db = self.db();
        // What it is published to, as policy stands as it is written: the
        // group's units are applied in order, so an entry before a policy
        // change in the group is published as policy was, and one after
        // as it is, as they would be committed one at a time.
        let topics = records::encode_topics(&self.policy.publishes(entry));
        db.prepare_cached("INSERT INTO journal (record, topics) VALUES (?1, ?2)")?
            .execute((
                records::encode_entry(entry, self.sealed_as(tenant), self.data_keys()),
                topics,
            ))?;
        Ok(u64::try_from(db.last_insert_rowid()).unwrap_or_default())
    }

    /// Deletes what finished before the feedback window that ends at `now`,
    /// oldest first: the deliveries, the messages whose
    /// deliveries all finished, the journal's entries and the reports. Each
    /// table's search reads at most `batch` rows, going on from where the
    /// last stopped, so a row not yet due costs a read once a round, not
    /// once a trim. A subscription still owed entries from before the
    /// window skips them, and counts the positions it skipped. Nothing
    /// unfinished is deleted, nor the journal's newest entry, so positions
    /// never start again.
    pub(crate) fn trim(&mut self, now: Timestamp, batch: usize) -> Result<Trimmed, StoreError> {
        let boundary = now.saturating_sub(self.feedback_window);
        let db: &Connection = self.connection.borrow();
        // Only rows issued before the boundary can have finished before it.
        let issued = key(Id::first_at(boundary));
        let (deliveries, more_deliveries) = trim_rows(
            db,
            "SELECT id, state = 2 AND expires_at < ?3 FROM deliveries
             WHERE id > ?1 AND id < ?2 ORDER BY id LIMIT ?4",
            "DELETE FROM deliveries WHERE id = ?1",
            &mut self.trim_resume.0,
            (issued, column(boundary)),
            batch,
        )?;
        let (messages, more_messages) = trim_rows(
            db,
            "SELECT id, unfinished = 0 AND IFNULL(finished_at < ?3, 0) FROM messages
             WHERE id > ?1 AND id < ?2 ORDER BY id LIMIT ?4",
            "DELETE FROM messages WHERE id = ?1",
            &mut self.trim_resume.1,
            (issued, seconds(boundary)),
            batch,
        )?;
        let reports = db
            .prepare_cached(
                "DELETE FROM feedback WHERE id IN (
                     SELECT id FROM feedback WHERE id < ?1 ORDER BY id LIMIT ?2)",
            )?
            .execute((issued, count(batch)))?;
        // A report's effects go once their deliveries have: deliveries are
        // trimmed oldest first, so every one below the oldest left is gone.
        let effects = db
            .prepare_cached(
                "DELETE FROM feedback_effects WHERE (delivery, report) IN (
                     SELECT delivery, report FROM feedback_effects
                     WHERE delivery < (SELECT IFNULL(MIN(id), ?1) FROM deliveries)
                     ORDER BY delivery, report LIMIT ?2)",
            )?
            .execute((issued, count(batch)))?;
        let (entries, more_entries, oldest) = trim_journal(db, boundary, batch, self.open_keys())?;
        // A parked batch lasts as long as the entries it names,
        // whatever this trim deleted.
        let parked = db
            .prepare_cached(
                "DELETE FROM parked_events WHERE through < (SELECT MIN(position) FROM journal)",
            )?
            .execute([])?;
        if parked > 0 {
            self.parked_changed.set(true);
        }
        // A policy is of no use once it runs out, window or no window.
        let policies = db
            .prepare_cached(
                "DELETE FROM sts_policies WHERE domain IN (
                     SELECT domain FROM sts_policies WHERE expires_at <= ?1 LIMIT ?2)",
            )?
            .execute((column(now), count(batch)))?;
        Ok(Trimmed {
            deliveries,
            messages,
            entries,
            reports: reports + effects,
            policies,
            parked,
            more: more_deliveries
                || more_messages
                || more_entries
                || reports == batch
                || effects == batch
                || policies == batch,
            oldest,
        })
    }

    /// Records `report` with what it proves: a bounce or a
    /// complaint for each delivery of the message it names whose recipient
    /// it names, and the suppressions those make. A report that names no
    /// recipient is about its message's delivery when there is only one,
    /// since only that recipient could have made it. Its first copy is
    /// kept as its evidence, and its effect on each delivery happens once,
    /// however often it comes.
    pub(crate) fn record_feedback(
        &mut self,
        report: &Report,
    ) -> Result<FeedbackRecorded, StoreError> {
        self.record_report(report, None)
    }

    /// Records `report`, which a transport made of its attempt of
    /// `delivery`, as [`Store::record_feedback`] records a report, for that
    /// delivery alone: another of its message's deliveries at the same
    /// address takes its own report with its own outcome.
    pub(crate) fn record_report_of(
        &mut self,
        report: &Report,
        delivery: DeliveryId,
    ) -> Result<FeedbackRecorded, StoreError> {
        self.record_report(report, Some(delivery))
    }

    fn record_report(
        &mut self,
        report: &Report,
        only: Option<DeliveryId>,
    ) -> Result<FeedbackRecorded, StoreError> {
        // The deliveries it is about, each with what it says of it: its
        // message's own recipients that it names, or the one recipient of a
        // message that had one when it names none.
        // A report about a tenant's message is that tenant's,
        // whatever recipients it names.
        let (tenant, about) = self.about(report, only)?;
        let tenant = self.sealed_as(tenant);
        let db = self.db();
        let kept: Option<i64> = db
            .prepare_cached("SELECT id FROM feedback WHERE identity = ?1")?
            .query_row([&report.identity[..]], |row| row.get(0))
            .optional()?;
        // A report about none of the engine's deliveries can change nothing:
        // it is kept in quarantine while that holds fewer than its bound.
        let quarantined = about.is_empty();
        if quarantined && kept.is_none() {
            let held: i64 = db
                .prepare_cached("SELECT COUNT(*) FROM feedback WHERE quarantined = 1")?
                .query_row([], |row| row.get(0))?;
            if u64::try_from(held).unwrap_or(u64::MAX) >= self.quarantine {
                return Ok(FeedbackRecorded {
                    unkept: true,
                    unmatched: true,
                    ..FeedbackRecorded::default()
                });
            }
        }
        // What it does is recorded under the copy kept as its evidence.
        let (id, duplicate) = match kept {
            Some(kept) => {
                let id = id_from_key(kept)
                    .ok_or_else(|| corrupt("feedback", kept)(CodecError::Invalid("ID")))?;
                (ReportId(id), true)
            }
            None => {
                let inserted = db
                    .prepare_cached(
                        "INSERT INTO feedback (id, identity, record, quarantined)
                         VALUES (?1, ?2, ?3, ?4)",
                    )?
                    .execute((
                        key(report.id.0),
                        &report.identity[..],
                        records::encode_report(report, tenant, self.data_keys()),
                        quarantined,
                    ));
                // Its ID is another report's, which no listener issues:
                // nothing it says is recorded or done.
                if !inserted_unless_taken(inserted)? {
                    return Ok(FeedbackRecorded {
                        duplicate: true,
                        ..FeedbackRecorded::default()
                    });
                }
                (report.id, false)
            }
        };
        let mut recorded = FeedbackRecorded {
            duplicate,
            unmatched: quarantined && !duplicate,
            ..FeedbackRecorded::default()
        };
        // Whether this copy, after one kept before, applied any effect.
        let mut replaces = false;
        for (delivery, claim) in &about {
            let effect = report.effect(claim);
            if effect == Effect::None {
                continue;
            }
            // Its first copy records its event, and its effects if it is
            // trusted. A trusted copy after copies that were not applies its
            // effects then, once, with an event of its own, so an untrusted
            // copy, a forged one among them, never stands in for it.
            let first = self
                .db()
                .prepare_cached(
                    "INSERT OR IGNORE INTO feedback_effects (delivery, report, trusted)
                     VALUES (?1, ?2, ?3)",
                )?
                .execute((key(delivery.id().0), &report.identity[..], report.trusted))?;
            let applies = if first == 1 {
                report.trusted
            } else if report.trusted {
                let promoted = self
                    .db()
                    .prepare_cached(
                        "UPDATE feedback_effects SET trusted = 1
                         WHERE delivery = ?1 AND report = ?2 AND trusted = 0",
                    )?
                    .execute((key(delivery.id().0), &report.identity[..]))?;
                if promoted == 0 {
                    continue;
                }
                true
            } else {
                continue;
            };
            replaces |= duplicate && applies;
            recorded.duplicate = false;
            recorded.deliveries += 1;
            let (entry, suppress) = match effect {
                Effect::Bounced { suppress } => (
                    Entry::Bounced {
                        delivery: delivery.id(),
                        account: delivery.account(),
                        configuration: delivery.origin().configuration,
                        report: id,
                        status: claim.status,
                        authenticated: report.authenticated,
                        at: report.received_at,
                    },
                    suppress.then_some(Reason::Bounce),
                ),
                Effect::Complained { suppress } => (
                    Entry::Complained {
                        delivery: delivery.id(),
                        account: delivery.account(),
                        configuration: delivery.origin().configuration,
                        report: id,
                        feedback_type: match &report.kind {
                            Kind::Feedback(feedback_type) => feedback_type.clone(),
                            Kind::DeliveryStatus | Kind::Unrecognised => String::new(),
                        },
                        authenticated: report.authenticated,
                        at: report.received_at,
                    },
                    suppress.then_some(Reason::Complaint),
                ),
                Effect::None => continue,
            };
            self.append(&entry)?;
            // Below the class the operator trusts, a report is its events
            // alone.
            if !applies {
                continue;
            }
            // A complaint, or a bounce after delivery, counts toward warmup
            // at the site its recipient was delivered at, from an egress
            // capped there; never the mailbox simulator's.
            let capped = delivery
                .egress()
                .and_then(|egress| self.policy.egress(egress))
                .is_some_and(|egress| egress.caps.any());
            if capped
                && !report.simulated
                && let Some(site) = self.delivered_site(delivery.id())?
            {
                let signal = match entry {
                    Entry::Complained { .. } => Signal::Complained,
                    _ => Signal::Failed,
                };
                self.tally(delivery.egress(), &site, signal, report.received_at);
            }
            recorded.effects.push(Reported {
                complaint: matches!(entry, Entry::Complained { .. }),
                egress: delivery.egress(),
                tenant: delivery.origin().tenant,
            });
            if let Some(reason) = suppress {
                self.suppress(&Suppress {
                    account: delivery.account(),
                    addresses: vec![delivery.recipient().clone()],
                    reason,
                    now: report.received_at,
                })?;
                recorded.suppressed += 1;
            }
        }
        // A trusted copy that applied what one kept before had not is the
        // one kept as the evidence.
        if replaces {
            // Under the kept copy's ID, which its sealed fields are in.
            let kept = Report {
                id,
                ..report.clone()
            };
            self.db()
                .prepare_cached("UPDATE feedback SET record = ?2 WHERE id = ?1")?
                .execute((
                    key(id.0),
                    records::encode_report(&kept, tenant, self.data_keys()),
                ))?;
        }
        Ok(recorded)
    }

    /// The tenant of the message `report`'s token names, and the deliveries
    /// it is about, each with its claim about it: of that message, those it
    /// names, or the one recipient of a message accepted for one when it
    /// names none, and only `only` when given.
    fn about(&self, report: &Report, only: Option<DeliveryId>) -> Result<About, StoreError> {
        let Some(message) = report
            .message
            .map(|id| self.message(id))
            .transpose()?
            .flatten()
        else {
            return Ok((None, Vec::new()));
        };
        let mut deliveries = self.deliveries_of(&message)?;
        if let Some(only) = only {
            deliveries.retain(|delivery| delivery.id() == only);
        }
        let sole =
            (message.recipients == 1 && deliveries.len() == 1 && report.recipients.is_empty())
                .then(|| Claim {
                    address: deliveries[0].recipient().clone(),
                    failed: false,
                    status: None,
                    rules_out_address: false,
                    diagnostic: None,
                });
        let about = deliveries
            .into_iter()
            .filter_map(|delivery| {
                let named = report.recipients.iter().find(|claim| {
                    suppression::key(&claim.address) == suppression::key(delivery.recipient())
                });
                let claim = named.cloned().or_else(|| sole.clone())?;
                Some((delivery, claim))
            })
            .collect();
        Ok((message.origin.tenant, about))
    }

    /// A delivery, or a message's deliveries, as they stand.
    pub fn inspect(&self, inspect: Inspect) -> Result<Vec<Inspected>, StoreError> {
        let deliveries = match inspect {
            Inspect::Delivery(id) => self.delivery(id)?.into_iter().collect(),
            Inspect::Message(id) => match self.message(id)? {
                Some(message) => self.deliveries_of(&message)?,
                None => Vec::new(),
            },
        };
        deliveries
            .into_iter()
            .map(|delivery| {
                let reply = match delivery.reply_entry() {
                    Some(position) => self.reply_at(position)?,
                    None => None,
                };
                let hold = match delivery.state() {
                    QueueState::Held { .. } => self
                        .policy
                        .hold(delivery.account(), delivery.origin(), delivery.egress())
                        .and_then(|hold| Some((hold.clone(), self.policy.held_by_name(hold)?))),
                    _ => None,
                };
                let fence = self
                    .policy
                    .fence()
                    .filter(|fence| fence.covers(delivery.id()))
                    .filter(|_| !matches!(delivery.state(), QueueState::Finished { .. }))
                    .copied();
                Ok(Inspected {
                    delivery,
                    reply,
                    hold,
                    fence,
                })
            })
            .collect()
    }

    /// The reply the journal's entry at `position` holds, unless retention
    /// has removed it.
    fn reply_at(&self, position: u64) -> Result<Option<Evidence>, StoreError> {
        let Ok(key) = i64::try_from(position) else {
            return Ok(None);
        };
        let record: Option<Vec<u8>> = self
            .db()
            .prepare_cached("SELECT record FROM journal WHERE position = ?1")?
            .query_row([key], |row| row.get(0))
            .optional()?;
        match record.map(|record| records::decode_entry(&record, self.open_keys())) {
            Some(Ok(Entry::Attempted { evidence, .. })) => Ok(evidence),
            Some(Ok(_)) | None => Ok(None),
            Some(Err(error)) => Err(corrupt("journal", key)(error)),
        }
    }

    /// The deliveries of `message`: the deliveries of its body's ID lane
    /// that follow its body's ID, which were issued with it (see
    /// `AcceptMessage::new`), up to the first of another message. They are
    /// read a millisecond's IDs of that lane at a time, so another lane's
    /// deliveries are never read.
    fn deliveries_of(&self, message: &Message) -> Result<Vec<Delivery>, StoreError> {
        // The milliseconds the most deliveries a message may have can take,
        // with the one its body ends and the one they may run into.
        const MOST_MILLISECONDS: usize = MAX_RECIPIENTS.div_ceil(Id::PER_MILLISECOND) + 2;
        let mut statement = self.db().prepare_cached(
            "SELECT id, record FROM deliveries WHERE id > ?1 AND id BETWEEN ?2 AND ?3 ORDER BY id",
        )?;
        let (mut first, mut last) = message.body.0.lane_millisecond();
        let mut found = Vec::new();
        // A millisecond may hold none of them, if its deliveries were
        // trimmed, or the body took its last ID, so every one is read.
        for _ in 0..MOST_MILLISECONDS {
            let mut rows = statement.query((key(message.body.0), key(first), key(last)))?;
            while let Some(row) = rows.next()? {
                let key: i64 = row.get(0)?;
                let id = id_from_key(key)
                    .ok_or_else(|| corrupt("deliveries", key)(CodecError::Invalid("ID")))?;
                let record: Vec<u8> = row.get(1)?;
                let delivery = records::decode_delivery(DeliveryId(id), &record, self.open_keys())
                    .map_err(corrupt("deliveries", key))?;
                if delivery.message() != message.id {
                    return Ok(found);
                }
                found.push(delivery);
            }
            (first, last) = (first.millisecond_after(), last.millisecond_after());
        }
        Ok(found)
    }

    /// The report recorded as `id`, if retention has not removed it.
    pub fn report(&self, id: ReportId) -> Result<Option<Report>, StoreError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .db()
            .prepare_cached("SELECT identity, record FROM feedback WHERE id = ?1")?
            .query_row([key(id.0)], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        row.map(|(identity, record)| {
            let identity: [u8; 32] = identity
                .try_into()
                .map_err(|_| corrupt("feedback", key(id.0))(CodecError::Invalid("identity")))?;
            records::decode_report(id, identity, &record, self.open_keys())
                .map_err(corrupt("feedback", key(id.0)))
        })
        .transpose()
    }

    /// Counts finished deliveries against their messages, once for each
    /// message however many of its deliveries finished, with when the last
    /// of them did. A message with none left has its body deleted.
    pub(crate) fn finish(&self, finished: &Finishing) -> Result<(), StoreError> {
        for (&message, &(count, at)) in finished {
            let message_key = key(message.0);
            let (unfinished, record): (i64, Vec<u8>) = self
                .db()
                .prepare_cached(
                    // The latest finish of any group, whichever finishes
                    // its last delivery.
                    "UPDATE messages SET unfinished = unfinished - ?2,
                         finished_at = MAX(IFNULL(finished_at, ?3), ?3)
                     WHERE id = ?1 RETURNING unfinished, record",
                )?
                .query_row((message_key, i64::from(count), seconds(at)), |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?
                .ok_or_else(|| corrupt("messages", message_key)(CodecError::Missing("message")))?;
            match unfinished {
                0 => {
                    let message = records::decode_message(message, &record)
                        .map_err(corrupt("messages", message_key))?;
                    let deleted = self
                        .db()
                        .prepare_cached("DELETE FROM bodies WHERE id = ?1")?
                        .execute([key(message.body.0)])?;
                    expect_one_row(deleted, "bodies", key(message.body.0))?;
                }
                1.. => {}
                _ => {
                    return Err(corrupt("messages", message_key)(CodecError::Invalid(
                        "unfinished count",
                    )));
                }
            }
        }
        Ok(())
    }
}

/// One table's part of a trim: reads at most `batch` rows issued before
/// `issued`, past `resume`, deletes those the search marks as due, and
/// moves `resume` on, back to the start once the search reaches `issued`.
/// Returns how many it deleted, and whether rows were left unread.
/// Runs SQLite's full integrity check on a store's connection, which
/// need not be open as a store: the operator's check reads a stopped
/// engine's store this way.
/// Brings a stopped store's schema up to date, as a start would, holding
/// the store alone while it does, and returns the schema version it was
/// at and the one it is at now.
pub fn migrate(db: &Connection) -> Result<(u32, u32), StoreError> {
    db.execute_batch("PRAGMA locking_mode = EXCLUSIVE")?;
    let mode: String = db.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if mode != "wal" {
        return Err(StoreError::JournalMode(mode));
    }
    let version = |db: &Connection| -> Result<u32, StoreError> {
        Ok(db.query_row("PRAGMA user_version", [], |row| row.get(0))?)
    };
    let from = version(db)?;
    schema::migrate(db)?;
    Ok((from, version(db)?))
}

/// Brings a copy `nitromta backup` made up to this release's schema, in
/// whatever journal mode it is.
pub fn migrate_copy(db: &Connection) -> Result<(), StoreError> {
    schema::migrate(db)
}

pub fn verify(db: &Connection) -> Result<(), StoreError> {
    checked(db, "integrity_check")
}

/// SQLite's quick check: every page read and its structure checked,
/// without comparing each index with its table, so quicker than
/// [`verify`]. A store left open at its last stop is checked this way
/// before it opens.
/// The size on disk of the store on `db` and what it holds free, a few
/// reads of its first page.
pub fn space(db: &Connection) -> Result<Space, StoreError> {
    let read = |pragma: &str| -> Result<u64, StoreError> {
        let value: i64 = db.query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))?;
        Ok(u64::try_from(value).unwrap_or_default())
    };
    let size = read("page_size")?;
    Ok(Space {
        bytes: read("page_count")?.saturating_mul(size),
        reusable: read("freelist_count")?.saturating_mul(size),
    })
}

pub fn quick_check(db: &Connection) -> Result<(), StoreError> {
    checked(db, "quick_check")
}

fn checked(db: &Connection, pragma: &str) -> Result<(), StoreError> {
    let mut statement = db.prepare(&format!("PRAGMA {pragma}"))?;
    let problems: Vec<String> = statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if problems == ["ok"] {
        Ok(())
    } else {
        Err(StoreError::Damaged(problems))
    }
}

fn trim_rows(
    db: &Connection,
    search: &str,
    delete: &str,
    resume: &mut i64,
    (issued, boundary): (i64, i64),
    batch: usize,
) -> Result<(usize, bool), StoreError> {
    let rows: Vec<(i64, bool)> = db
        .prepare_cached(search)?
        .query_map((*resume, issued, boundary, count(batch)), |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<Result<_, _>>()?;
    let mut statement = db.prepare_cached(delete)?;
    let mut deleted = 0;
    for &(id, due) in &rows {
        if due {
            deleted += statement.execute([id])?;
        }
    }
    let more = rows.len() == batch;
    *resume = match rows.last() {
        Some(&(id, _)) if more => id,
        _ => 0,
    };
    Ok((deleted, more))
}

/// Deletes up to `batch` of the journal's oldest entries from before
/// `boundary`, stopping at the first that is not. Entries are in commit
/// order, which is only nearly the order of their times, so an older entry
/// behind a newer one waits for it. The newest entry stays. Returns how
/// many it deleted, whether it stopped for the batch, and when the oldest
/// entry left happened.
fn trim_journal(
    db: &Connection,
    boundary: Timestamp,
    batch: usize,
    keys: Option<&Keys>,
) -> Result<(usize, bool, Option<Timestamp>), StoreError> {
    let last: Option<i64> = db
        .prepare_cached("SELECT MAX(position) FROM journal")?
        .query_row([], |row| row.get(0))?;
    let Some(last) = last else {
        return Ok((0, false, None));
    };
    let (mut through, mut oldest, mut read) = (None, None, 0);
    {
        let mut statement =
            db.prepare_cached("SELECT position, record FROM journal ORDER BY position LIMIT ?1")?;
        let mut rows = statement.query([count(batch.saturating_add(1))])?;
        while let Some(row) = rows.next()? {
            let position: i64 = row.get(0)?;
            let record: Vec<u8> = row.get(1)?;
            let at = records::decode_entry(&record, keys)
                .map_err(corrupt("journal", position))?
                .at();
            if at >= boundary || position == last || read == batch {
                oldest = Some(at);
                break;
            }
            through = Some(position);
            read += 1;
        }
    }
    let Some(through) = through else {
        return Ok((0, false, oldest));
    };
    // Whoever is still owed what goes skips it, and a failing batch the
    // trim takes no longer runs on its time.
    db.prepare_cached(
        "UPDATE cursors SET skipped = skipped + (?1 - position), position = ?1,
         failing_since = CASE WHEN ?1 >= failing_first THEN NULL ELSE failing_since END,
         failing_first = CASE WHEN ?1 >= failing_first THEN NULL ELSE failing_first END
         WHERE position < ?1",
    )?
    .execute([through])?;
    let deleted = db
        .prepare_cached("DELETE FROM journal WHERE position <= ?1")?
        .execute([through])?;
    Ok((deleted, read == batch, oldest))
}

/// The delivery's message, and when the delivery finished, if it has.
fn finished(delivery: &Delivery) -> Option<Finished> {
    match delivery.state() {
        QueueState::Finished { at, .. } => Some((delivery.message(), at)),
        _ => None,
    }
}

/// The index keys a delivery is stored under: its state, its due time
/// while it waits, and until when it lasts: its expiry until it finishes,
/// then when it finished, which retention reads.
/// `counts` with `moves` added, state by state.
fn added(mut counts: [i64; 4], moves: [i64; 4]) -> [i64; 4] {
    for (count, by) in counts.iter_mut().zip(moves) {
        *count += by;
    }
    counts
}

/// The state a delivery's row records it in.
fn state_of(delivery: &Delivery) -> i64 {
    index_keys(delivery).0
}

fn index_keys(delivery: &Delivery) -> (i64, Option<i64>, i64) {
    let expiry = column(delivery.expires_at());
    match delivery.state() {
        QueueState::Ready { due_at } => (0, Some(column(due_at)), expiry),
        QueueState::InFlight { .. } => (1, None, expiry),
        QueueState::Finished { at, .. } => (2, None, column(at)),
        QueueState::Held { .. } => (3, None, expiry),
    }
}

/// The fence a restored store keeps, if it has one.
fn read_fence(db: &Connection) -> Result<Option<Fence>, StoreError> {
    let row: Option<(i64, i64, i64, i64)> = db
        .query_row(
            "SELECT below, taken_at, restored_at, discarding FROM fence",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((below, taken, restored, discarding)) = row else {
        return Ok(None);
    };
    let micros = |at: i64| Timestamp::from_micros(u64::try_from(at).unwrap_or_default());
    Ok(Some(Fence {
        below: id_from_key(below)
            .ok_or_else(|| corrupt("fence", below)(CodecError::Invalid("ID")))?,
        taken: micros(taken),
        restored: micros(restored),
        discarding: discarding != 0,
    }))
}

/// Notes in a copy `nitromta backup` made that it was taken at `taken`,
/// in place of any note a copy it was restored from had.
pub fn mark_copied(db: &Connection, taken: Timestamp) -> Result<(), StoreError> {
    db.execute_batch("DELETE FROM copied")?;
    db.execute("INSERT INTO copied (taken_at) VALUES (?1)", [column(taken)])?;
    Ok(())
}

/// IDs fit in 63 bits, so they are stored as positive integer keys.
fn key(id: Id) -> i64 {
    i64::try_from(id.as_u64()).expect("an ID fits in 63 bits")
}

fn id_from_key(key: i64) -> Option<Id> {
    u64::try_from(key)
        .ok()
        .and_then(Id::from_u64)
        .filter(|id| id.as_u64() > 0)
}

/// A timestamp as an index column. Records keep the exact value; a time
/// past the end of the column's range sorts last.
fn column(time: Timestamp) -> i64 {
    i64::try_from(time.as_micros()).unwrap_or(i64::MAX)
}

/// A time as a column in whole seconds, which retention needs: half the
/// bytes of microseconds in every finished row. A row is past a boundary
/// only once its whole second is.
fn seconds(time: Timestamp) -> i64 {
    i64::try_from(time.as_micros() / 1_000_000).unwrap_or(i64::MAX)
}

fn count(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// A journal position as a column.
fn position(position: u64) -> i64 {
    i64::try_from(position).unwrap_or(i64::MAX)
}

fn inserted_unless_taken(result: rusqlite::Result<usize>) -> Result<bool, StoreError> {
    match result {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == ErrorCode::ConstraintViolation =>
        {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn expect_one_row(changed: usize, table: &'static str, id: i64) -> Result<(), StoreError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::Corrupt {
            table,
            id,
            problem: format!("expected one row, found {changed}"),
        })
    }
}

fn corrupt(table: &'static str, id: i64) -> impl Fn(CodecError) -> StoreError {
    move |error| StoreError::Corrupt {
        table,
        id,
        problem: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moves_count_once_their_unit_is_kept_and_their_group_commits() {
        let mut moves = Moves::default();
        // A unit kept, in a group that fails: nothing counted.
        moves.moved(None, 0);
        moves.settle(true);
        moves.commit(false);
        assert_eq!(moves.queued, [0; 4]);
        // A unit refused, in a group that commits: nothing counted.
        moves.moved(None, 0);
        moves.settle(false);
        moves.commit(true);
        assert_eq!(moves.queued, [0; 4]);
        // Kept, then committed: counted, not before.
        moves.moved(None, 0);
        moves.settle(true);
        assert_eq!(moves.queued, [0; 4], "not before its group commits");
        moves.commit(true);
        assert_eq!(moves.queued, [1, 0, 0, 0]);
        // A move into a finished state takes one away, and none goes in.
        moves.moved(Some(0), 2);
        moves.settle(true);
        moves.commit(true);
        assert_eq!(moves, Moves::default());
    }
}
