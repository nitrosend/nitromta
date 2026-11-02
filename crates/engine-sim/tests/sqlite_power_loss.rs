//! The simulation gate for SQLite. The real, unmodified SQLite, in WAL mode
//! with `synchronous=FULL`, on a disk whose power fails at any I/O
//! operation and tears or loses unsynced writes, never loses or corrupts a
//! commit it acknowledged. The same workload with weaker sync settings must
//! fail the same checks, which proves the disk really drops unsynced data.
//!
//! SQLite's random number generator is process-wide, so this binary holds
//! one test, which runs every seed in turn.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hasher};
use std::rc::Rc;
use std::time::Duration;

use engine_core::rng::Rng;
use engine_core::time::Timestamp;
use engine_sim::disk::Disk;
use engine_sim::simulation::{self, Config, Context, World};
use engine_sim::vfs::{SimConnection, SimVfs};

const DATABASE: &str = "ledger.db";
const WALL_START: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);

#[derive(Debug, Hash)]
enum Event {
    /// The machine starts, or restarts after a power failure.
    Recover,
    Commit,
    Checkpoint,
}

/// What a recovered database holds.
struct Recovered<'vfs> {
    connection: SimConnection<'vfs>,
    journal_mode: String,
    integrity: String,
    /// Every row, by its stored digest.
    rows: BTreeMap<i64, i64>,
    /// A row whose payload does not match its digest.
    mismatched: Option<i64>,
}

/// A table of rows written one commit at a time, checked after every
/// recovery against what SQLite acknowledged.
struct Ledger<'vfs> {
    vfs: &'vfs SimVfs,
    synchronous: &'static str,
    connection: Option<SimConnection<'vfs>>,
    next_id: i64,
    /// Every row ever written, acknowledged or not, by its payload digest.
    attempted: BTreeMap<i64, i64>,
    /// Rows that must survive: every acknowledged commit, and every row a
    /// recovery found.
    durable: BTreeMap<i64, i64>,
    violation: Option<String>,
    acknowledged: u64,
    /// Power failures, by what they interrupted.
    failures: BTreeMap<Phase, u64>,
}

/// What a power failure interrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Recovery,
    Commit,
    Checkpoint,
}

impl<'vfs> Ledger<'vfs> {
    fn new(vfs: &'vfs SimVfs, synchronous: &'static str) -> Self {
        Self {
            vfs,
            synchronous,
            connection: None,
            next_id: 1,
            attempted: BTreeMap::new(),
            durable: BTreeMap::new(),
            violation: None,
            acknowledged: 0,
            failures: BTreeMap::new(),
        }
    }

    fn violate(&mut self, violation: String) {
        self.violation.get_or_insert(violation);
    }

    /// An operation failed. With the power off, the process is gone: the
    /// disk takes the power failure and the machine restarts. With the
    /// power on, SQLite itself failed.
    fn failed(&mut self, phase: Phase, error: &rusqlite::Error, context: &mut Context<'_, Event>) {
        if self.power_failed() {
            *self.failures.entry(phase).or_default() += 1;
            self.restart(context);
        } else {
            self.violate(format!("SQLite failed with the power on: {error}"));
        }
    }

    fn arm_power_failure(&self, context: &mut Context<'_, Event>, within: u64) {
        let operations = context.rng().below(within) + 1;
        self.vfs.disk().borrow_mut().fail_power_after(operations);
    }

    fn power_failed(&self) -> bool {
        !self.vfs.disk().borrow().is_powered()
    }

    /// The process is gone: the disk takes the power failure, and the
    /// machine restarts.
    fn restart(&mut self, context: &mut Context<'_, Event>) {
        self.connection = None;
        self.vfs.disk().borrow_mut().crash();
        context.after(Duration::from_millis(1), Event::Recover);
    }

    fn recover(&mut self, context: &mut Context<'_, Event>) {
        // A quarter of recoveries risk a power failure while they run. The
        // rest arm the next failure once they finish, so most failures
        // strike commits and checkpoints rather than repeated recoveries.
        let during_recovery = context.rng().below(4) == 0;
        if during_recovery {
            self.arm_power_failure(context, 1_000);
        }
        match self.open_and_read() {
            // Anything read while the power was failing means nothing, so
            // the recovery is judged only if the power stayed on.
            Ok(_) if self.power_failed() => {
                *self.failures.entry(Phase::Recovery).or_default() += 1;
                self.restart(context);
            }
            Ok(recovered) => {
                self.judge(&recovered);
                self.durable = recovered.rows;
                self.connection = Some(recovered.connection);
                if !during_recovery {
                    self.arm_power_failure(context, 400);
                }
            }
            Err(error) => self.failed(Phase::Recovery, &error, context),
        }
    }

    /// Checks a recovered database against everything acknowledged.
    fn judge(&mut self, recovered: &Recovered<'_>) {
        if recovered.journal_mode != "wal" {
            self.violate(format!(
                "the journal mode is {}, not WAL",
                recovered.journal_mode
            ));
        }
        if recovered.integrity != "ok" {
            self.violate(format!("integrity_check failed: {}", recovered.integrity));
        }
        if let Some(id) = recovered.mismatched {
            self.violate(format!("row {id}'s payload does not match its digest"));
        }
        let lost = self
            .durable
            .iter()
            .find(|&(id, digest)| recovered.rows.get(id) != Some(digest))
            .map(|(id, _)| *id);
        if let Some(id) = lost {
            self.violate(format!("acknowledged row {id} was lost"));
        }
        let invented = recovered
            .rows
            .iter()
            .find(|&(id, digest)| self.attempted.get(id) != Some(digest))
            .map(|(id, _)| *id);
        if let Some(id) = invented {
            self.violate(format!("row {id} was never written"));
        }
    }

    /// Opens the database, which recovers it, and reads back everything in
    /// it. What a recovery finds is on the disk, so it must survive from
    /// then on, acknowledged or not.
    fn open_and_read(&self) -> rusqlite::Result<Recovered<'vfs>> {
        let vfs = self.vfs;
        let connection = vfs.open(DATABASE)?;
        connection.execute_batch("PRAGMA locking_mode = EXCLUSIVE")?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        connection.execute_batch(&format!(
            "PRAGMA synchronous = {};
             PRAGMA wal_autocheckpoint = 64;
             CREATE TABLE IF NOT EXISTS ledger (
                 id INTEGER PRIMARY KEY,
                 payload BLOB NOT NULL,
                 digest INTEGER NOT NULL
             )",
            self.synchronous
        ))?;

        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        let mut rows = BTreeMap::new();
        let mut mismatched = None;
        {
            let mut statement = connection.prepare("SELECT id, payload, digest FROM ledger")?;
            let mut results = statement.query([])?;
            while let Some(row) = results.next()? {
                let (id, payload, stored): (i64, Vec<u8>, i64) =
                    (row.get(0)?, row.get(1)?, row.get(2)?);
                if digest(&payload) != stored {
                    mismatched.get_or_insert(id);
                }
                rows.insert(id, stored);
            }
        }
        Ok(Recovered {
            connection,
            journal_mode,
            integrity,
            rows,
            mismatched,
        })
    }

    fn commit(&mut self, context: &mut Context<'_, Event>) {
        let Some(connection) = &self.connection else {
            return;
        };
        let id = self.next_id;
        self.next_id += 1;
        let length = usize::try_from(context.rng().below(16_384)).expect("a small length");
        let mut payload = vec![0; length];
        fill(context.rng(), &mut payload);
        let digest = digest(&payload);
        self.attempted.insert(id, digest);
        let result = connection.execute(
            "INSERT INTO ledger (id, payload, digest) VALUES (?1, ?2, ?3)",
            (id, &payload, digest),
        );
        match result {
            Ok(_) => {
                self.durable.insert(id, digest);
                self.acknowledged += 1;
            }
            Err(error) => self.failed(Phase::Commit, &error, context),
        }
    }

    fn checkpoint(&mut self, context: &mut Context<'_, Event>) {
        let Some(connection) = &self.connection else {
            return;
        };
        let result = connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            row.get::<_, i64>(0)
        });
        if let Err(error) = result {
            self.failed(Phase::Checkpoint, &error, context);
        }
    }
}

impl World for Ledger<'_> {
    type Event = Event;

    fn start(&mut self, context: &mut Context<'_, Event>) {
        context.after(Duration::ZERO, Event::Recover);
        context.after(Duration::from_millis(1), Event::Commit);
        context.after(Duration::from_millis(500), Event::Checkpoint);
    }

    fn apply(&mut self, event: Event, context: &mut Context<'_, Event>) {
        self.vfs.disk().borrow_mut().set_now(context.now().wall);
        match event {
            Event::Recover => self.recover(context),
            Event::Commit => {
                self.commit(context);
                let gap = Duration::from_millis(context.rng().below(20));
                context.after(gap, Event::Commit);
            }
            Event::Checkpoint => {
                self.checkpoint(context);
                let gap = Duration::from_millis(200 + context.rng().below(800));
                context.after(gap, Event::Checkpoint);
            }
        }
    }

    fn check(&self) -> Result<(), String> {
        self.violation.clone().map_or(Ok(()), Err)
    }
}

fn digest(bytes: &[u8]) -> i64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    i64::from_ne_bytes(hasher.finish().to_ne_bytes())
}

fn fill(rng: &mut Rng, buffer: &mut [u8]) {
    for chunk in buffer.chunks_mut(8) {
        let bytes = rng.next_u64().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

struct Outcome {
    failure: Option<String>,
    digest: Option<u64>,
    disk: u64,
    acknowledged: u64,
    failures: BTreeMap<Phase, u64>,
}

fn run_ledger(seed: u64, synchronous: &'static str) -> Outcome {
    let mut seeds = Rng::from_seed(seed);
    let disk = Rc::new(RefCell::new(Disk::new(seeds.fork(), WALL_START)));
    let sqlite_seed = u32::try_from(seeds.below(u64::from(u32::MAX))).expect("below u32::MAX") + 1;
    let vfs = SimVfs::register("sqlite-power-loss", Rc::clone(&disk), sqlite_seed)
        .expect("no other simulation uses SQLite");
    let mut ledger = Ledger::new(&vfs, synchronous);
    let config = Config {
        seed,
        duration: Duration::from_secs(5),
        max_steps: 1_000_000,
        wall_start: WALL_START,
        clock_steps: None,
        trace: false,
    };
    let result = simulation::run(&mut ledger, &config);
    Outcome {
        failure: result.as_ref().err().map(ToString::to_string),
        digest: result.ok().map(|report| report.digest),
        disk: disk.borrow().digest(),
        acknowledged: ledger.acknowledged,
        failures: ledger.failures,
    }
}

#[test]
fn sqlite_keeps_every_acknowledged_commit_through_power_failures_only_with_full_sync() {
    const SEEDS: u64 = 48;
    let mut acknowledged = 0;
    let mut failures: BTreeMap<Phase, u64> = BTreeMap::new();
    for seed in 0..SEEDS {
        let outcome = run_ledger(seed, "FULL");
        if let Some(failure) = outcome.failure {
            panic!("synchronous=FULL, {failure}");
        }
        acknowledged += outcome.acknowledged;
        for (phase, count) in outcome.failures {
            *failures.entry(phase).or_default() += count;
        }
    }
    // Enough commits, and power failures in every phase, that passing means
    // something.
    assert!(
        acknowledged >= SEEDS * 200,
        "{acknowledged} commits were acknowledged"
    );
    for (phase, at_least) in [
        (Phase::Commit, SEEDS * 4),
        (Phase::Checkpoint, SEEDS / 4),
        (Phase::Recovery, SEEDS),
    ] {
        let count = failures.get(&phase).copied().unwrap_or(0);
        assert!(
            count >= at_least,
            "the power failed {count} times during {phase:?}: {failures:?}"
        );
    }

    let (first, second) = (run_ledger(7, "FULL"), run_ledger(7, "FULL"));
    assert_eq!(
        (first.digest, first.disk),
        (second.digest, second.disk),
        "a seed replays to the same events and the same disk"
    );

    // WAL mode with synchronous=NORMAL is documented to lose recent commits
    // on power failure, though not to corrupt the database.
    let normal_lost = (0..16)
        .filter_map(|seed| run_ledger(seed, "NORMAL").failure)
        .filter(|failure| failure.contains("was lost"))
        .count();
    assert!(
        normal_lost > 0,
        "synchronous=NORMAL never lost an acknowledged commit"
    );

    let off_failed = (0..16)
        .filter(|&seed| run_ledger(seed, "OFF").failure.is_some())
        .count();
    assert!(
        off_failed > 0,
        "synchronous=OFF survived every power failure"
    );
}
