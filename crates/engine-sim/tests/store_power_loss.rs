//! The three commit points under power failure.
//!
//! A pipeline runs the real commit owner and store on the simulated disk,
//! and the real scheduler. Clients submit acceptances, whose deliveries go
//! to the scheduler once committed; the scheduler reserves them and hands
//! each permit to a receiver; the receiver accepts, defers, rejects, or
//! loses its reply; the scheduler records each outcome, finds retries and
//! leftovers in the store, and expires what runs out of time. The power
//! fails at any I/O operation, the machine restarts and the store recovers.
//! After every recovery, and at the end, the store is checked against what
//! it acknowledged:
//! - every acknowledged acceptance is stored, its body kept while any of
//!   its deliveries is unfinished, and only then;
//! - every permit was issued only once its reservation was durable;
//! - every acknowledged outcome is durable;
//! - a receiver gets a delivery more than once only if an attempt's outcome
//!   was uncertain, and the delivery counts every such attempt;
//! - no delivery is sent to a recipient whose suppression was acknowledged
//!   before the delivery's reservation was asked for;
//! - no delivery is sent as an identity whose removal was acknowledged
//!   before the delivery's reservation was asked for;
//! - the quota's ledger counts every acknowledged recipient, and none that
//!   was never accepted;
//! - every attempt issued from an egress with a daily cap is counted in the
//!   dispatch ledger, whatever crashes followed;
//! - every acknowledged change to policy is durable: the sender's identity
//!   and login are held or gone as the latest acknowledged change left
//!   them, an identity whose removal was acknowledged never comes back, and
//!   the policy's revision is at least the latest acknowledged;
//! - retention deletes nothing unfinished and nothing inside its window:
//!   an acknowledged message, delivery, journal entry or report
//!   is gone only once its window has passed;
//! - a report's effect on a delivery happens once, however often the report
//!   comes and whatever crashes come between, and a report that
//!   rules its recipient out suppresses the address as an operator's
//!   suppression does;
//! - no attempt goes to a site before the end of a cooldown whose keeping
//!   was acknowledged, across restarts, and the store keeps the latest
//!   acknowledged end of each until its ending is acknowledged;
//! - no delivery the dispatch hook rejects is ever sent, and the hook's
//!   verdict that lets a delivery proceed never lets it past its
//!   suppression or its identity's removal;
//! - no delivery is sent while a hold on its identity is in force whose
//!   putting was acknowledged before its reservation was asked for, until
//!   the hold's lifting is acknowledged;
//! - a graceful stop finishes what is under way and closes the
//!   store, which takes its write-ahead log away, so the next start finds
//!   no attempt to recover;
//! - a disk that fills stops the store with nothing it acknowledged lost:
//!   the process exits, room is made, and the store starts sound.
//!
//! Clients send as the sender the store's policy holds, which they now and
//! then remove and create again under a new ID, as an operator would, while
//! acceptances decided under the old one are still arriving. Their mail goes
//! out from a pool's one egress, whose daily cap never binds. Now and then a
//! bounce report comes for a delivery the receiver took, and now and then
//! one comes again. Now and then the clients hold their identity's mail,
//! accepting it to wait, and lift the hold again. A dispatch hook decides
//! every recipient before its
//! reservation, answering after a moment, so the power fails between its
//! question and its answer too. The retention window is a second, so most of a run's
//! mail is trimmed before it ends. Now and then the operator stops the
//! engine gracefully, and now and then its disk fills.
//!
//! SQLite's random number generator is process-wide, so this binary holds
//! one test, which runs every seed in turn.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::attempt::{Attempt, AttemptResult};
use engine_core::command::{
    Accept, AcceptMessage, Answer, Authority, Command, Commit, CooldownChange, Request,
    Reservation, Response, Suppress,
};
use engine_core::component::Ticket;
use engine_core::delivery::{Delivery, DispatchPermit, QueueState};
use engine_core::feedback::{Claim, Kind, Report};
use engine_core::hook::{self, dispatch};
use engine_core::id::{
    AttemptId, BodyId, ConfigurationId, CredentialId, DeliveryId, EgressId, HoldId, IdGenerator,
    IdentityId, Lane, MessageId, PoolId, ReportId, Shard, SubmissionId,
};
use engine_core::journal::Entry;
use engine_core::message::PolicyRevision;
use engine_core::policy::{Change, Origin, Policy, PolicyRefusal};
use engine_core::retry::RetrySchedule;
use engine_core::rng::Rng;
use engine_core::status::Status;
use engine_core::suppression::{self, Reason};
use engine_core::time::{Monotonic, Timestamp};
use engine_rules::{Rules, Site};
use engine_scheduler::{Attempted, Output, Route, Scheduler, Tls};
use engine_sim::disk::Disk;
use engine_sim::host::Host;
use engine_sim::sender::{self, Sender};
use engine_sim::simulation::{self, Config, Context, World};
use engine_sim::vfs::{SimConnection, SimVfs};
use engine_store::commit_owner::{CommitOwner, GroupLimits};
use engine_store::keys::Keyring;
use engine_store::store::{Store, StoreError, StoreOptions};

const DATABASE: &str = "pipeline.db";
const WALL_START: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);
const SHARD: Shard = Shard::new(1);
const LIMITS: GroupLimits = GroupLimits {
    commands: 32,
    content_bytes: 64 * 1024,
};
/// A small window, byte budget and limit, so deliveries wait in the store,
/// the scheduler's scans find them, and bodies are let go and read back,
/// and quick retries, so deferred deliveries come round again within a run.
fn scheduler_config() -> engine_scheduler::Config {
    engine_scheduler::Config {
        per_transaction: 2,
        window: 16,
        window_bytes: 4 * 1024,
        scan_every: Duration::from_millis(20),
        scan_page: 20,
        retry: RetrySchedule::new(Duration::from_millis(100), Duration::from_millis(500))
            .expect("a valid schedule"),
        route_ttl: Duration::from_millis(200),
        dispatch_hook: true,
        ended_rules: false,
    }
}
/// The shipped receiver rules, with two connections to each site, so
/// four transactions under way.
fn rules() -> Arc<Rules> {
    let defaults = engine_rules::Entry {
        connections: Some(2),
        ..engine_rules::Entry::default()
    };
    Arc::new(
        Rules::new(&BTreeMap::from([(
            engine_rules::DEFAULTS.to_owned(),
            defaults,
        )]))
        .expect("the rules hold"),
    )
}

/// Checkpoints often, so power failures strike them often. A checkpoint
/// runs the same code at any threshold; only how often it runs changes.
/// Keeps finished mail a second, so trims run throughout.
const OPTIONS: StoreOptions = StoreOptions {
    checkpoint_pages: 32,
    feedback_window: WINDOW,
    ..StoreOptions::DEFAULT
};
const WINDOW: Duration = Duration::from_secs(1);

/// A site's mail, as one source sends it.
type SiteKey = (Option<EgressId>, Arc<str>);

#[derive(Debug, Hash)]
enum Event {
    /// The machine starts, or restarts after a power failure.
    Restart,
    Submit,
    Poll,
    Wake(Monotonic),
    SchedulerPoll,
    SchedulerWake(Monotonic),
    /// The receiver finishes with an attempt. `epoch` is the run of the
    /// process that sent it.
    Receive {
        epoch: u64,
        delivery: DeliveryId,
        attempt: AttemptId,
    },
    /// The dispatch hook answers the scheduler's question under `ticket`,
    /// if the process that asked still runs.
    Decided {
        epoch: u64,
        ticket: u64,
    },
    /// The operator stops the engine gracefully, if the process that was
    /// asked still runs.
    Stop {
        epoch: u64,
    },
    /// The bound on a graceful stop's drain.
    StopBound {
        epoch: u64,
    },
    /// The disk fills, if the process still runs.
    Fill {
        epoch: u64,
    },
    /// The final check, with the power on.
    Audit,
}

/// What a request in flight was for.
enum Waiting {
    /// An acceptance, what its sender will know of it, and its deliveries
    /// for the scheduler.
    Accept(Vec<Accepted>, Vec<engine_scheduler::Accepted>),
    /// The scheduler's request, under its own ticket, the outcome it
    /// records, if it records one, and how it changes a site's cooldown.
    Scheduler {
        ticket: Ticket,
        outcome: Option<Recorded>,
        cooled: Option<CooldownChange>,
    },
    /// A suppression, by its matching key.
    Suppress(String),
    /// A policy change.
    Policy(Changing),
    /// A report, as it was sent.
    Report(Report),
}

/// An outcome the scheduler records: its attempt and delivery, its result,
/// and when it happened, which its journal entry keeps.
#[derive(Clone, Copy)]
struct Recorded {
    attempt: AttemptId,
    delivery: DeliveryId,
    result: AttemptResult,
    at: Timestamp,
}

/// What a policy change does to the sender.
#[derive(Clone, Copy)]
enum Changing {
    /// Puts its identity.
    Identity,
    /// Puts its login.
    Login,
    /// Removes its identity.
    Removes(IdentityId),
    /// Holds its identity's mail.
    Holds(IdentityId),
    /// Lifts that hold.
    Lifts(IdentityId),
    /// Puts the pool its mail goes out from.
    Pool,
}

/// An accepted message, as its sender knows it.
#[derive(Clone)]
struct Accepted {
    message: MessageId,
    body: BodyId,
    deliveries: Vec<DeliveryId>,
}

/// What a failed group was doing when the power failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Interrupted {
    Accept,
    Reserve,
    Outcome,
    Expire,
    Policy,
    Feedback,
    /// The failure struck the commit itself, so the answer is unknown.
    Commit,
    Recovery,
    /// A graceful stop's close of the store.
    Close,
}

/// Whether a command committed: `None` when the power cut its commit short.
fn committed<T, R>(commit: &Commit<T, R>) -> Option<bool> {
    match commit {
        Commit::Committed(_) => Some(true),
        Commit::Unknown => None,
        Commit::Refused(_) | Commit::Unavailable => Some(false),
    }
}

/// For a command that did not commit, whether its commit was attempted.
fn uncommitted<T, R>(commit: &Commit<T, R>) -> Option<bool> {
    match commit {
        Commit::Unknown => Some(true),
        Commit::Unavailable => Some(false),
        Commit::Committed(_) | Commit::Refused(_) => None,
    }
}

struct Pipeline<'vfs> {
    vfs: &'vfs SimVfs,
    owner: Option<Host<CommitOwner<SimConnection<'vfs>>>>,
    scheduler: Option<Host<Scheduler>>,
    /// Runs of the process so far. Work from an earlier run is gone.
    epoch: u64,
    admission: IdGenerator,
    next_ticket: u64,
    waiting: BTreeMap<Ticket, Waiting>,
    /// Permits out with the receiver.
    /// Each attempt under way, with its site, whose rules judge its reply.
    permits: BTreeMap<AttemptId, (DispatchPermit, Site)>,
    /// Attempts dispatched whose outcome is not yet recorded: the process
    /// holds them, in a permit or in the scheduler.
    holding: BTreeSet<AttemptId>,
    /// The dispatch hook's questions not yet answered, by ticket.
    consulting: BTreeMap<u64, Vec<dispatch::Recipient>>,
    responses: Vec<Response>,
    outputs: Vec<Output>,
    // Facts the outside world holds, which survive restarts.
    acknowledged: Vec<Accepted>,
    /// Each acknowledged delivery's message, recipient, and when its ID was
    /// issued, just before its acceptance.
    deliveries: BTreeMap<DeliveryId, (MessageId, Address, Timestamp)>,
    /// Each permit issued: its delivery, and when.
    issued: BTreeMap<AttemptId, (DeliveryId, Timestamp)>,
    /// Each acknowledged outcome, its delivery, and when it happened.
    recorded: BTreeMap<AttemptId, (DeliveryId, AttemptResult, Timestamp)>,
    received: BTreeMap<DeliveryId, u32>,
    /// Deliveries the receiver took, in the order it took them, which
    /// reports may come for.
    taken: Vec<DeliveryId>,
    /// Reports sent, which may come again.
    reports: Vec<Report>,
    /// Reports kept as the first copy of their identity, by their answers,
    /// and when they were issued.
    kept_reports: BTreeMap<ReportId, Timestamp>,
    /// Effects each report's identity had on deliveries, by its answers.
    report_effects: BTreeMap<[u8; 32], u32>,
    /// Answers that found their report received before.
    duplicate_reports: usize,
    /// The latest end of each site's cooldown whose keeping was
    /// acknowledged, until its ending is.
    cooldowns: BTreeMap<SiteKey, Timestamp>,
    /// Cooldowns acknowledged as kept.
    cooldowns_kept: usize,
    /// Acknowledged deliveries trimmed by the end.
    trimmed: usize,
    interrupted: BTreeMap<Interrupted, u64>,
    /// The sender acceptances are sent as, and the revision that decided
    /// it, as the latest policy the clients have seen holds it.
    authority: Option<(Sender, PolicyRevision)>,
    /// Policy changes waiting for their answers.
    changing: usize,
    /// Identities whose removal was acknowledged, and when.
    revoked: BTreeMap<IdentityId, Monotonic>,
    /// Each hold on an identity whose putting was acknowledged: when, and
    /// when its lifting was acknowledged or may have committed, or its
    /// identity's removal was.
    holds: Vec<(IdentityId, Monotonic, Option<Monotonic>)>,
    /// Whether the latest acknowledged change left the sender's identity
    /// held: unknown while a change the power cut short may have committed.
    identity_hold: Option<bool>,
    /// Whether the store must hold the sender's identity, as the latest
    /// acknowledged change to it left it: unknown while a later change the
    /// power cut short may or may not have committed.
    identity_held: Option<bool>,
    /// Whether a login's creation was acknowledged. Nothing removes it.
    login_held: bool,
    /// The latest revision of policy acknowledged.
    policy_revision: PolicyRevision,
    /// The configuration the clients send under, once policy holds it.
    pooled: Option<ConfigurationId>,
    /// Attempts issued from an egress with a daily cap.
    capped_issued: u64,
    /// The identity each acknowledged delivery was sent as.
    identity_of: BTreeMap<DeliveryId, IdentityId>,
    /// Reservations that found their authority withdrawn.
    cancelled_reservations: usize,
    /// Recipients of acknowledged acceptances, and of acceptances that may
    /// or may not have committed.
    acknowledged_recipients: u64,
    uncertain_recipients: u64,
    /// Suppressions acknowledged, by matching key, and when.
    suppressed: BTreeMap<String, Monotonic>,
    /// When each delivery's latest reservation was asked for.
    reserve_asked: BTreeMap<DeliveryId, Monotonic>,
    /// Reservations that found their recipient suppressed.
    suppressed_reservations: usize,
    /// The installation's keys, which the operator rotates now and then:
    /// a new key, then, once a start has sealed every secret under it, the
    /// older ones go. A start under the newest has run to the
    /// end with the power on since it came, if `sealed`.
    keys: Vec<(u8, [u8; 32])>,
    sealed: bool,
    rotations: usize,
    retirements: usize,
    /// Asked to stop gracefully: nothing new is submitted, and the scheduler
    /// drains.
    stopping: bool,
    /// The last stop closed the store with nothing under way and the power
    /// on, so the next start must recover no attempt.
    stopped_cleanly: bool,
    /// The disk filled since the last start.
    full: bool,
    drained_stops: usize,
    full_stops: usize,
    violation: Option<String>,
}

impl<'vfs> Pipeline<'vfs> {
    fn new(vfs: &'vfs SimVfs) -> Self {
        Self {
            vfs,
            owner: None,
            scheduler: None,
            epoch: 0,
            admission: IdGenerator::new(SHARD, Lane::new(1).expect("a lane"), None),
            next_ticket: 0,
            waiting: BTreeMap::new(),
            permits: BTreeMap::new(),
            holding: BTreeSet::new(),
            consulting: BTreeMap::new(),
            responses: Vec::new(),
            outputs: Vec::new(),
            acknowledged: Vec::new(),
            deliveries: BTreeMap::new(),
            issued: BTreeMap::new(),
            recorded: BTreeMap::new(),
            received: BTreeMap::new(),
            taken: Vec::new(),
            reports: Vec::new(),
            kept_reports: BTreeMap::new(),
            report_effects: BTreeMap::new(),
            duplicate_reports: 0,
            cooldowns: BTreeMap::new(),
            cooldowns_kept: 0,
            trimmed: 0,
            interrupted: BTreeMap::new(),
            authority: None,
            changing: 0,
            revoked: BTreeMap::new(),
            holds: Vec::new(),
            identity_hold: Some(false),
            identity_held: Some(false),
            login_held: false,
            policy_revision: PolicyRevision::default(),
            pooled: None,
            capped_issued: 0,
            identity_of: BTreeMap::new(),
            cancelled_reservations: 0,
            acknowledged_recipients: 0,
            uncertain_recipients: 0,
            suppressed: BTreeMap::new(),
            reserve_asked: BTreeMap::new(),
            suppressed_reservations: 0,
            keys: vec![(1, [1; 32])],
            sealed: false,
            rotations: 0,
            retirements: 0,
            stopping: false,
            stopped_cleanly: false,
            full: false,
            drained_stops: 0,
            full_stops: 0,
            violation: None,
        }
    }

    fn violate(&mut self, violation: String) {
        self.violation.get_or_insert(violation);
    }

    fn powered(&self) -> bool {
        self.vfs.disk().borrow().is_powered()
    }

    /// Whether the running process still holds `attempt`: its permit, or
    /// its outcome on the way to being recorded.
    fn holds(&self, attempt: AttemptId) -> bool {
        self.holding.contains(&attempt)
    }

    fn arm_power_failure(&self, context: &mut Context<'_, Event>, within: u64) {
        let operations = context.rng().below(within) + 1;
        self.vfs.disk().borrow_mut().fail_power_after(operations);
    }

    /// The process is gone: the disk takes the power failure, and the
    /// machine restarts.
    fn crash(&mut self, context: &mut Context<'_, Event>) {
        self.gone(context);
        self.vfs.disk().borrow_mut().crash();
    }

    /// The process is gone, with whatever it was waiting for, and starts
    /// again.
    fn gone(&mut self, context: &mut Context<'_, Event>) {
        self.owner = None;
        self.scheduler = None;
        self.stopping = false;
        // An acceptance in the commit that the power cut may have committed.
        let mut lifts = Vec::new();
        for waiting in self.waiting.values() {
            match waiting {
                Waiting::Accept(accepted, _) => self.uncertain_recipients += recipients(accepted),
                Waiting::Policy(Changing::Identity | Changing::Removes(_)) => {
                    self.identity_held = None;
                }
                // A lifting the power cut short may have committed: what
                // follows is no longer checked against the hold.
                Waiting::Policy(Changing::Lifts(identity)) => {
                    lifts.push(*identity);
                    self.identity_hold = None;
                }
                Waiting::Policy(Changing::Holds(_)) => self.identity_hold = None,
                _ => {}
            }
        }
        for identity in lifts {
            self.lifted(identity, context.now().monotonic);
        }
        self.waiting.clear();
        self.changing = 0;
        self.permits.clear();
        self.holding.clear();
        self.consulting.clear();
        self.epoch += 1;
        context.after(Duration::from_millis(1), Event::Restart);
    }

    /// Asked to stop, as the shell is: nothing new is taken,
    /// the scheduler finishes what is under way and starts nothing, and
    /// once it has and every answer is in, the store is closed.
    fn stop(&mut self, epoch: u64, context: &mut Context<'_, Event>) {
        if epoch != self.epoch || self.owner.is_none() || self.stopping {
            return;
        }
        self.stopping = true;
        self.tell_scheduler(engine_scheduler::Input::Drain, context);
        context.after(Duration::from_secs(2), Event::StopBound { epoch });
    }

    /// Closes the store once a stop's drain is done: the process exits with
    /// the power on, and the machine starts it again.
    fn close_if_drained(&mut self, context: &mut Context<'_, Event>) {
        let drained = self
            .scheduler
            .as_ref()
            .is_some_and(|scheduler| scheduler.component().is_drained());
        if !self.stopping || !drained || !self.waiting.is_empty() || !self.powered() {
            return;
        }
        self.owner = None;
        self.scheduler = None;
        if !self.powered() {
            *self.interrupted.entry(Interrupted::Close).or_default() += 1;
            return self.crash(context);
        }
        if self.holding.iter().next().is_some() {
            self.violate("a drained stop left an attempt under way".to_owned());
        }
        // Closed, the store takes its write-ahead log away: one left means
        // the stop was not clean, as the next start would say.
        if self
            .vfs
            .disk()
            .borrow()
            .files()
            .any(|(name, bytes)| name.ends_with("-wal") && !bytes.is_empty())
        {
            self.violate("a graceful stop left the write-ahead log behind".to_owned());
        }
        self.stopped_cleanly = true;
        self.drained_stops += 1;
        self.gone(context);
    }

    /// The disk fills, at most a few pages past what it holds now: the
    /// store's next growth, of its log or its file, finds no room.
    fn fill(&mut self, epoch: u64, context: &mut Context<'_, Event>) {
        if epoch != self.epoch || self.owner.is_none() {
            return;
        }
        let room = 4_096 * context.rng().below(4);
        let mut disk = self.vfs.disk().borrow_mut();
        let used = disk.used();
        disk.set_capacity(Some(used + room));
        self.full = true;
    }

    fn request(&mut self, command: Command, waiting: Waiting, context: &mut Context<'_, Event>) {
        let Some(owner) = self.owner.as_mut() else {
            return;
        };
        let ticket = Ticket(self.next_ticket);
        self.next_ticket += 1;
        self.waiting.insert(ticket, waiting);
        if owner.deliver(context.now(), Request { ticket, command }) {
            context.after(Duration::ZERO, Event::Poll);
        }
    }

    fn restart(&mut self, context: &mut Context<'_, Event>) {
        // The operator makes room on a disk that filled before starting it.
        self.vfs.disk().borrow_mut().set_capacity(None);
        self.full = false;
        // A quarter of restarts risk a power failure during recovery; the
        // rest arm the next failure once recovered.
        let during_recovery = context.rng().below(4) == 0;
        if during_recovery {
            self.arm_power_failure(context, 600);
        }
        let newest = self.keys.last().map_or(0, |(id, _)| *id);
        match context.rng().below(8) {
            0 if newest < u8::MAX => {
                self.keys.push((newest + 1, [newest + 1; 32]));
                self.sealed = false;
                self.rotations += 1;
            }
            1 if self.sealed && self.keys.len() > 1 => {
                self.keys.drain(..self.keys.len() - 1);
                self.retirements += 1;
            }
            _ => {}
        }
        let keys = Arc::new(Keyring::new(&self.keys).expect("the installation's keys"));
        let now = context.now().wall;
        let opened = self
            .vfs
            .open(DATABASE)
            .map_err(StoreError::from)
            .and_then(|connection| Store::open(connection, OPTIONS, keys));
        let started = opened.and_then(|store| {
            let after = store.highest_id()?;
            CommitOwner::start(store, LIMITS, now)
                .map(|(owner, abandoned)| (owner, after, abandoned.len()))
        });
        // Anything read while the power was failing means nothing, so a
        // recovery is judged only if the power stayed on throughout.
        let audited = started.and_then(|(owner, after, abandoned)| {
            // Nothing is on its way after a restart, which recovers every
            // attempt in flight.
            let mut problems = audit(self, owner.store(), now, None)?;
            if self.stopped_cleanly && abandoned > 0 {
                problems.push(format!(
                    "a start after a graceful stop recovered {abandoned} attempts"
                ));
            }
            Ok((owner, after, problems))
        });
        if !self.powered() {
            *self.interrupted.entry(Interrupted::Recovery).or_default() += 1;
            return self.crash(context);
        }
        let (owner, after, problems) = match audited {
            Ok(audited) => audited,
            Err(error) => {
                return self.violate(format!("recovery failed with the power on: {error}"));
            }
        };
        if let Some(problem) = problems.into_iter().next() {
            return self.violate(problem);
        }
        self.stopped_cleanly = false;
        self.sealed = true;
        self.admission = IdGenerator::new(SHARD, Lane::new(1).expect("a lane"), after);
        let attempts = IdGenerator::new(SHARD, Lane::new(2).expect("a lane"), after);
        self.owner = Some(Host::new(owner));
        self.scheduler = Some(Host::new(Scheduler::new(
            scheduler_config(),
            rules(),
            attempts,
            context.rng().fork(),
        )));
        // Clients and the scheduler start from the policy the store holds,
        // as the shell does.
        self.adopt_policy(context);
        context.after(Duration::ZERO, Event::SchedulerPoll);
        if !during_recovery {
            self.arm_power_failure(context, 2_000);
        }
        // Now and then this run ends in a graceful stop, or its disk fills.
        let epoch = self.epoch;
        let later = Duration::from_millis(context.rng().below(500));
        match context.rng().below(6) {
            0 => context.after(later, Event::Stop { epoch }),
            1 => context.after(later, Event::Fill { epoch }),
            _ => {}
        }
    }

    fn submit(&mut self, context: &mut Context<'_, Event>) {
        let now = context.now().wall;
        let account = Sender::first().account;
        // Stopping, the engine takes nothing new.
        if self.owner.is_none() || self.stopping {
            return;
        }
        if context.rng().below(12) == 0 {
            return self.report(context);
        }
        // With no sender, the clients create one, under new IDs; a login
        // already held keeps its own.
        let Some((sending, revision)) = self.authority else {
            if self.changing == 0 {
                let created = Sender {
                    account,
                    identity: IdentityId(self.admission.next(now)),
                    credential: CredentialId(self.admission.next(now)),
                };
                if self.pooled.is_none() {
                    let pool = created.pool_changes(
                        ConfigurationId(self.admission.next(now)),
                        PoolId(self.admission.next(now)),
                        EgressId(self.admission.next(now)),
                        Some(1_000_000),
                    );
                    for change in pool {
                        self.changing += 1;
                        self.request(
                            Command::ChangePolicy(change),
                            Waiting::Policy(Changing::Pool),
                            context,
                        );
                    }
                }
                for change in created.changes() {
                    self.changing += 1;
                    let changing = match change {
                        Change::Identity { .. } => Changing::Identity,
                        _ => Changing::Login,
                    };
                    self.request(
                        Command::ChangePolicy(change),
                        Waiting::Policy(changing),
                        context,
                    );
                }
            }
            return;
        };
        // Now and then its identity is removed, while acceptances decided
        // under it go on until the clients see the change.
        if self.changing == 0 && context.rng().below(40) == 0 {
            self.changing += 1;
            let removal = Command::ChangePolicy(sending.removal());
            let removes = Changing::Removes(sending.identity);
            return self.request(removal, Waiting::Policy(removes), context);
        }
        // Now and then its mail is held, accepted to wait, and the hold is
        // lifted again.
        if self.changing == 0 && context.rng().below(30) == 0 {
            self.changing += 1;
            let (change, changing) = if self.identity_hold == Some(true) {
                (
                    Change::Release(sending.target()),
                    Changing::Lifts(sending.identity),
                )
            } else {
                let hold = Change::Hold {
                    id: HoldId(self.admission.next(now)),
                    target: sending.target(),
                    accepting: true,
                    reason: "the simulation's hold".to_owned(),
                };
                (hold, Changing::Holds(sending.identity))
            };
            return self.request(
                Command::ChangePolicy(change),
                Waiting::Policy(changing),
                context,
            );
        }
        // Now and then a recipient is suppressed.
        if context.rng().below(8) == 0 {
            let address = Address::parse(&format!("RCPT{}@example.com", context.rng().below(40)))
                .expect("a valid address");
            let key = suppression::key(&address);
            let command = Command::Suppress(Suppress {
                account,
                addresses: vec![address],
                reason: Reason::Bounce,
                now,
            });
            return self.request(command, Waiting::Suppress(key), context);
        }
        let lifetime = Duration::from_millis(1_000 + context.rng().below(3_000));
        let mut messages = Vec::new();
        for _ in 0..=context.rng().below(2) {
            let length = usize::try_from(64 + context.rng().below(2_048)).expect("small");
            let recipients: Vec<Address> = (0..=context.rng().below(3))
                .map(|_| {
                    Address::parse(&format!("rcpt{}@example.com", context.rng().below(40)))
                        .expect("a valid address")
                })
                .collect();
            let id = MessageId(self.admission.next(now));
            let content = Bytes::from(vec![b'x'; length]);
            messages.push(AcceptMessage::new(
                id,
                content,
                &recipients,
                None,
                &mut self.admission,
                now,
            ));
        }
        let accepted = messages
            .iter()
            .map(|message| Accepted {
                message: message.id,
                body: message.body,
                deliveries: message
                    .recipients
                    .iter()
                    .map(|recipient| recipient.delivery)
                    .collect(),
            })
            .collect();
        let accept = Accept {
            submission: SubmissionId(self.admission.next(now)),
            authority: Authority {
                origin: Origin {
                    configuration: self.pooled,
                    ..sending.authority(revision).origin
                },
                ..sending.authority(revision)
            },
            accepted_at: now,
            expires_at: now.saturating_add(lifetime),
            messages,
        };
        let fresh = accept
            .messages
            .iter()
            .flat_map(|message| {
                message
                    .recipients
                    .iter()
                    .map(|recipient| engine_scheduler::Accepted {
                        delivery: accept
                            .delivery(message, recipient)
                            .expect("expires after acceptance"),
                        content: message.content.clone(),
                    })
            })
            .collect();
        self.request(
            Command::Accept(accept),
            Waiting::Accept(accepted, fresh),
            context,
        );
    }

    /// A bounce report for a delivery the receiver took, saying its
    /// recipient does not exist; or, a third of the time, a report sent
    /// before, come again under a new ID, as a reporter's retry would.
    fn report(&mut self, context: &mut Context<'_, Event>) {
        let now = context.now().wall;
        let id = ReportId(self.admission.next(now));
        let again = !self.reports.is_empty() && context.rng().below(3) == 0;
        let report = if again {
            let index = context.rng().below(self.reports.len() as u64);
            Report {
                id,
                received_at: now,
                ..self.reports[usize::try_from(index).expect("small")].clone()
            }
        } else {
            let Some(&delivery) = self.taken.get(
                usize::try_from(context.rng().below(self.taken.len().max(1) as u64))
                    .expect("small"),
            ) else {
                return;
            };
            let (message, address, _) = self.deliveries[&delivery].clone();
            let mut identity = [0; 32];
            identity[..8].copy_from_slice(&(self.reports.len() as u64).to_be_bytes());
            let report = Report {
                id,
                message: Some(message),
                kind: Kind::DeliveryStatus,
                recipients: vec![Claim {
                    address,
                    failed: true,
                    status: Status::parse("5.1.1"),
                    rules_out_address: true,
                    diagnostic: Some("550 5.1.1 no such user".to_owned()),
                }],
                identity,
                evidence: Bytes::from_static(b"Reporting-MTA: dns; mx.sim.test"),
                received_at: now,
                authenticated: false,
                trusted: true,
                simulated: false,
            };
            self.reports.push(report.clone());
            report
        };
        self.request(
            Command::RecordFeedback(report.clone()),
            Waiting::Report(report),
            context,
        );
    }

    fn poll(&mut self, context: &mut Context<'_, Event>) {
        let Some(owner) = self.owner.as_mut() else {
            return;
        };
        let mut responses = std::mem::take(&mut self.responses);
        if let Some(at) = owner.poll(context.now(), &mut responses) {
            context.at(at, Event::Wake(at));
        }
        let failed = owner.component().has_failed();
        let powered = self.powered();
        if failed && powered && !self.full {
            self.violate("the store failed with the power on and room on its disk".to_owned());
        }
        for response in responses.drain(..) {
            self.answer(response, powered, failed, context);
        }
        self.responses = responses;
        if !powered {
            self.crash(context);
        } else if failed {
            // Stopped by the full disk, the process exits, with the power
            // on: what it wrote stays as it is.
            self.full_stops += 1;
            self.gone(context);
        } else {
            self.close_if_drained(context);
        }
    }

    /// `failed` once the store has stopped, as a full disk stops it: its
    /// answers may then be uncertain with the power on.
    fn answer(
        &mut self,
        response: Response,
        powered: bool,
        failed: bool,
        context: &mut Context<'_, Event>,
    ) {
        let Some(waiting) = self.waiting.remove(&response.ticket) else {
            return self.violate(format!("an answer to no request: {:?}", response.ticket));
        };
        // In WAL mode a group's first write reaches the disk at its commit,
        // so a power failure almost always strikes there.
        let interrupted = match &response.answer {
            Answer::Accepted(commit) => {
                uncommitted(commit).map(|commit| (Interrupted::Accept, commit))
            }
            Answer::Reserved(commit) => {
                uncommitted(commit).map(|commit| (Interrupted::Reserve, commit))
            }
            Answer::Recorded(commit) => {
                uncommitted(commit).map(|commit| (Interrupted::Outcome, commit))
            }
            Answer::Cooled(commit) => {
                uncommitted(commit).map(|commit| (Interrupted::Outcome, commit))
            }
            Answer::Feedback(commit) => {
                uncommitted(commit).map(|commit| (Interrupted::Feedback, commit))
            }
            Answer::Expired(commit) => {
                uncommitted(commit).map(|commit| (Interrupted::Expire, commit))
            }
            Answer::Policy(commit) => {
                uncommitted(commit).map(|commit| (Interrupted::Policy, commit))
            }
            _ => None,
        };
        if let Some((point, at_commit)) = interrupted {
            *self.interrupted.entry(point).or_default() += 1;
            if at_commit {
                *self.interrupted.entry(Interrupted::Commit).or_default() += 1;
            }
            if powered && !failed {
                self.violate(format!(
                    "an uncommitted answer with the power on: {:?}",
                    response.answer
                ));
            }
        }
        match (&waiting, &response.answer) {
            (Waiting::Accept(accepted, _), Answer::Accepted(commit)) => match commit {
                Commit::Committed(()) => self.acknowledged_recipients += recipients(accepted),
                Commit::Unknown => self.uncertain_recipients += recipients(accepted),
                Commit::Refused(_) | Commit::Unavailable => {}
            },
            // A durable change is the store's to keep, whether or not its
            // answer reached the clients before the power failed.
            (Waiting::Policy(changing), Answer::Policy(commit)) => {
                self.changed_policy(*changing, commit, context.now().monotonic);
            }
            (Waiting::Report(report), Answer::Feedback(Commit::Committed(recorded))) => {
                // Its message's deliveries to the address it names, each of
                // which it has an effect on once.
                let named: BTreeSet<String> = report
                    .recipients
                    .iter()
                    .map(|claim| suppression::key(&claim.address))
                    .collect();
                let deliveries = self
                    .deliveries
                    .values()
                    .filter(|(message, address, _)| {
                        Some(*message) == report.message
                            && named.contains(&suppression::key(address))
                    })
                    .count();
                let effects = self.report_effects.entry(report.identity).or_default();
                *effects += recorded.deliveries;
                let effects = *effects;
                if effects as usize > deliveries {
                    self.violate(format!(
                        "a report had {effects} effects on its message's {deliveries} deliveries"
                    ));
                }
                if recorded.duplicate {
                    self.duplicate_reports += 1;
                } else {
                    self.kept_reports.insert(report.id, report.received_at);
                }
            }
            (
                Waiting::Scheduler {
                    cooled: Some(change),
                    ..
                },
                Answer::Recorded(commit),
            ) => self.changed_cooldown(change, committed(commit)),
            (
                Waiting::Scheduler {
                    cooled: Some(change),
                    ..
                },
                Answer::Cooled(commit),
            ) => self.changed_cooldown(change, committed(commit)),
            _ => {}
        }
        // Once the power has failed, or the store, nothing more happens
        // before the process is gone.
        if !powered || failed {
            return;
        }
        match waiting {
            Waiting::Accept(accepted, fresh) => {
                if matches!(response.answer, Answer::Accepted(Commit::Committed(()))) {
                    for item in &fresh {
                        let delivery = &item.delivery;
                        let identity = delivery.origin().identity;
                        self.identity_of.insert(delivery.id(), identity);
                        self.deliveries.insert(
                            delivery.id(),
                            (
                                delivery.message(),
                                delivery.recipient().clone(),
                                delivery.id().0.issued_at(),
                            ),
                        );
                    }
                    self.acknowledged.extend(accepted);
                    self.tell_scheduler(engine_scheduler::Input::Accepted(fresh), context);
                }
            }
            Waiting::Policy(_) => {
                self.changing -= 1;
                if let Answer::Policy(Commit::Committed(_)) = &response.answer {
                    // The clients see the policy as the shell publishes it:
                    // the commit owner's, once the change is durable.
                    self.adopt_policy(context);
                }
            }
            Waiting::Suppress(key) => {
                if matches!(response.answer, Answer::Suppressions(Commit::Committed(_))) {
                    self.suppressed
                        .entry(key)
                        .or_insert(context.now().monotonic);
                }
            }
            // A report that suppressed its recipient did so as an operator's
            // suppression does.
            Waiting::Report(report) => {
                if let Answer::Feedback(Commit::Committed(recorded)) = &response.answer
                    && recorded.suppressed > 0
                {
                    for claim in &report.recipients {
                        self.suppressed
                            .entry(suppression::key(&claim.address))
                            .or_insert(context.now().monotonic);
                    }
                }
            }
            Waiting::Scheduler {
                ticket, outcome, ..
            } => {
                match response.answer {
                    Answer::Reserved(Commit::Committed(Reservation::Suppressed)) => {
                        self.suppressed_reservations += 1;
                    }
                    Answer::Reserved(Commit::Committed(Reservation::Cancelled)) => {
                        self.cancelled_reservations += 1;
                    }
                    _ => {}
                }
                if let Some(Recorded {
                    attempt,
                    delivery,
                    result,
                    at,
                }) = outcome
                {
                    if matches!(response.answer, Answer::Recorded(Commit::Committed(()))) {
                        self.recorded.insert(attempt, (delivery, result, at));
                    }
                    self.holding.remove(&attempt);
                }
                let response = Response {
                    ticket,
                    answer: response.answer,
                };
                self.tell_scheduler(engine_scheduler::Input::Answer(response), context);
            }
        }
    }

    /// Notes what a policy change's answer says the store must hold.
    fn changed_policy(
        &mut self,
        changing: Changing,
        commit: &Commit<PolicyRevision, PolicyRefusal>,
        now: Monotonic,
    ) {
        match (commit, changing) {
            (Commit::Committed(revision), _) => {
                self.policy_revision = self.policy_revision.max(*revision);
                match changing {
                    Changing::Identity => self.identity_held = Some(true),
                    Changing::Login => self.login_held = true,
                    Changing::Removes(identity) => {
                        self.identity_held = Some(false);
                        self.revoked.entry(identity).or_insert(now);
                        // A hold is lifted with what it names.
                        self.lifted(identity, now);
                        self.identity_hold = Some(false);
                    }
                    Changing::Holds(identity) => {
                        self.holds.push((identity, now, None));
                        self.identity_hold = Some(true);
                    }
                    Changing::Lifts(identity) => {
                        self.lifted(identity, now);
                        self.identity_hold = Some(false);
                    }
                    Changing::Pool => {}
                }
            }
            (Commit::Unknown, Changing::Identity | Changing::Removes(_)) => {
                self.identity_held = None;
            }
            (Commit::Unknown, Changing::Lifts(identity)) => {
                self.lifted(identity, now);
                self.identity_hold = None;
            }
            (Commit::Unknown, Changing::Holds(_)) => self.identity_hold = None,
            // A lifting refused finds no hold: a removal took it.
            (Commit::Refused(_), Changing::Lifts(_)) => self.identity_hold = Some(false),
            _ => {}
        }
    }

    /// Ends `identity`'s hold in force, if one is, at `now`.
    fn lifted(&mut self, identity: IdentityId, now: Monotonic) {
        for (held, _, until) in &mut self.holds {
            if *held == identity && until.is_none() {
                *until = Some(now);
            }
        }
    }

    /// Notes what a cooldown change's answer says the store must keep:
    /// `committed` is `None` when the power cut the commit short.
    fn changed_cooldown(&mut self, change: &CooldownChange, committed: Option<bool>) {
        match (change, committed) {
            (CooldownChange::Kept(cooldown), Some(true)) => {
                self.cooldowns_kept += 1;
                let key = (cooldown.egress, Arc::clone(&cooldown.site));
                let until = self.cooldowns.entry(key).or_insert(cooldown.until);
                *until = (*until).max(cooldown.until);
            }
            // An ending that may have committed leaves nothing the store must
            // keep.
            (CooldownChange::Ended { egress, site }, Some(true) | None) => {
                self.cooldowns.remove(&(*egress, Arc::clone(site)));
            }
            _ => {}
        }
    }

    /// Takes the policy the store holds: the sender the clients send as,
    /// the configuration they send under, and the scheduler's policy.
    fn adopt_policy(&mut self, context: &mut Context<'_, Event>) {
        let Some(owner) = &self.owner else {
            return;
        };
        let policy = Arc::clone(owner.component().store().policy());
        self.authority = authority_in(&policy);
        self.pooled = policy.configuration_named(Sender::first().account, sender::POOLED);
        self.tell_scheduler(engine_scheduler::Input::Policy(policy), context);
    }

    fn tell_scheduler(&mut self, input: engine_scheduler::Input, context: &mut Context<'_, Event>) {
        if let Some(scheduler) = self.scheduler.as_mut()
            && scheduler.deliver(context.now(), input)
        {
            context.after(Duration::ZERO, Event::SchedulerPoll);
        }
    }

    /// Polls the scheduler, and carries its requests to the commit owner
    /// and its attempts to the receiver.
    fn poll_scheduler(&mut self, context: &mut Context<'_, Event>) {
        let Some(scheduler) = self.scheduler.as_mut() else {
            return;
        };
        let mut outputs = std::mem::take(&mut self.outputs);
        if let Some(at) = scheduler.poll(context.now(), &mut outputs) {
            context.at(at, Event::SchedulerWake(at));
        }
        let mut resolved = Vec::new();
        for output in outputs.drain(..) {
            match output {
                // Every domain is served by one receiver; routes expire
                // often, so lookups come and go throughout the run.
                Output::Resolve(domain) => resolved.push(engine_scheduler::Input::Resolved {
                    domain,
                    route: Route::Exchanges(vec!["mx.sim.test".to_owned()], Tls::default()),
                    ttl: Duration::from_millis(context.rng().below(400)),
                }),
                Output::Store(Request { ticket, command }) => {
                    if let Command::Reserve(reserve) = &command {
                        self.reserve_asked
                            .insert(reserve.delivery, context.now().monotonic);
                    }
                    let (outcome, cooled) = match &command {
                        Command::RecordOutcome(outcome) => (
                            Some(Recorded {
                                attempt: outcome.permit.attempt(),
                                delivery: outcome.permit.delivery(),
                                result: outcome.disposition.into(),
                                at: outcome.now,
                            }),
                            outcome.cooled.clone(),
                        ),
                        Command::Cooldown(change) => (None, Some(change.clone())),
                        _ => (None, None),
                    };
                    let waiting = Waiting::Scheduler {
                        ticket,
                        outcome,
                        cooled,
                    };
                    self.request(command, waiting, context);
                }
                Output::Inspected { .. } | Output::Ended(_) => {}
                Output::Consult { ticket, recipients } => {
                    self.consulting.insert(ticket.0, recipients);
                    let epoch = self.epoch;
                    let delay = Duration::from_millis(context.rng().below(5));
                    context.after(
                        delay,
                        Event::Decided {
                            epoch,
                            ticket: ticket.0,
                        },
                    );
                }
                Output::Dispatch(dispatch) => {
                    // Nothing goes to a site before a cooldown's acknowledged
                    // end, whatever restarts came between.
                    let site = (
                        dispatch.egress.as_ref().map(|egress| egress.id),
                        Arc::clone(dispatch.site.name()),
                    );
                    if let Some(&until) = self.cooldowns.get(&site)
                        && context.now().wall < until
                    {
                        self.violate(format!(
                            "an attempt went to {site:?} before its cooldown's acknowledged end"
                        ));
                    }
                    if dispatch
                        .egress
                        .as_ref()
                        .is_some_and(|egress| egress.caps.any())
                    {
                        self.capped_issued += dispatch.recipients.len() as u64;
                    }
                    // A transaction's recipients each reach the receiver,
                    // or not, as the receiver decides for each.
                    for (permit, recipient) in dispatch.recipients {
                        let (attempt, delivery) = (permit.attempt(), permit.delivery());
                        let suppressed =
                            self.suppressed.get(&suppression::key(&recipient)).copied();
                        let asked = self.reserve_asked.get(&delivery).copied();
                        if let (Some(suppressed), Some(asked)) = (suppressed, asked)
                            && asked > suppressed
                        {
                            self.violate(format!(
                                "{delivery:?} was sent to {recipient:?}, suppressed before its reservation"
                            ));
                        }
                        let revoked = self
                            .identity_of
                            .get(&delivery)
                            .and_then(|identity| self.revoked.get(identity))
                            .copied();
                        if let (Some(revoked), Some(asked)) = (revoked, asked)
                            && asked > revoked
                        {
                            self.violate(format!(
                                "{delivery:?} was sent as an identity removed before its reservation"
                            ));
                        }
                        let identity = self.identity_of.get(&delivery);
                        let paused = self.holds.iter().any(|(held, from, until)| {
                            Some(held) == identity
                                && asked.is_some_and(|asked| {
                                    asked > *from && until.is_none_or(|until| asked < until)
                                })
                        });
                        if paused {
                            self.violate(format!(
                                "{delivery:?} was sent while a hold acknowledged before its reservation paused its identity"
                            ));
                        }
                        if rejected_by_the_hook(delivery) {
                            self.violate(format!(
                                "{delivery:?} was sent, though the dispatch hook rejects it"
                            ));
                        }
                        self.issued.insert(attempt, (delivery, context.now().wall));
                        self.holding.insert(attempt);
                        self.permits
                            .insert(attempt, (permit, dispatch.site.clone()));
                        let epoch = self.epoch;
                        let delay = Duration::from_millis(1 + context.rng().below(50));
                        context.after(
                            delay,
                            Event::Receive {
                                epoch,
                                delivery,
                                attempt,
                            },
                        );
                    }
                }
            }
        }
        self.outputs = outputs;
        for input in resolved {
            self.tell_scheduler(input, context);
        }
        self.close_if_drained(context);
    }

    /// The dispatch hook answers, and the shell gives its verdicts to the
    /// scheduler if the process that asked still runs.
    fn decided(&mut self, epoch: u64, ticket: u64, context: &mut Context<'_, Event>) {
        if epoch != self.epoch {
            return;
        }
        let Some(recipients) = self.consulting.remove(&ticket) else {
            return;
        };
        let verdicts = recipients.iter().map(decide).collect();
        self.tell_scheduler(
            engine_scheduler::Input::Consulted {
                ticket: Ticket(ticket),
                verdicts,
            },
            context,
        );
    }

    /// The receiver finishes with an attempt, and the transport reports to
    /// the scheduler if the process that sent it still runs.
    fn receive(
        &mut self,
        epoch: u64,
        delivery: DeliveryId,
        attempt: AttemptId,
        context: &mut Context<'_, Event>,
    ) {
        let (accepted, result) = match context.rng().below(20) {
            0..=10 => (true, Attempted::Delivered),
            11..=13 => (false, Attempted::Deferred),
            // The receiver refused service for now: its site cools down.
            14 => (false, Attempted::Throttled),
            15..=16 => (false, Attempted::Rejected),
            // The receiver accepted, and its final reply was lost.
            17..=18 => (true, Attempted::Uncertain),
            // The connection failed before the content was sent.
            _ => (false, Attempted::NotSent),
        };
        // What the receiver accepted, it holds, whether or not the process
        // that sent it still runs.
        if accepted {
            *self.received.entry(delivery).or_default() += 1;
            if self.deliveries.contains_key(&delivery) {
                self.taken.push(delivery);
            }
        }
        if epoch != self.epoch {
            return;
        }
        let Some((permit, site)) = self.permits.remove(&attempt) else {
            return;
        };
        let (evidence, verdict) = match engine_sim::receiver::reply(result) {
            Some(reply) => {
                let (evidence, verdict) = site.judged(reply.code, &reply.text);
                (Some(evidence), verdict)
            }
            None => (None, None),
        };
        self.tell_scheduler(
            engine_scheduler::Input::Finished {
                permit,
                result,
                evidence,
                verdict,
                feedback: None,
                replied: Some(context.now().wall),
            },
            context,
        );
    }
}

/// Whether the dispatch hook rejects `delivery`, as it does whenever it is
/// asked: one in thirteen.
fn rejected_by_the_hook(delivery: DeliveryId) -> bool {
    delivery.0.as_u64().is_multiple_of(13)
}

/// The dispatch hook's verdict: the same for a delivery whenever it is
/// asked, but that it holds one in five at its first attempt.
fn decide(recipient: &dispatch::Recipient) -> dispatch::Verdict {
    if rejected_by_the_hook(recipient.delivery) {
        dispatch::Verdict::Reject(hook::Reason::new("the simulation's rejection"))
    } else if recipient.attempts == 0 && recipient.delivery.0.as_u64().is_multiple_of(5) {
        dispatch::Verdict::Hold(hook::Reason::new("the simulation's hold"))
    } else {
        dispatch::Verdict::Proceed
    }
}

fn recipients(accepted: &[Accepted]) -> u64 {
    accepted
        .iter()
        .map(|message| message.deliveries.len() as u64)
        .sum()
}

/// The sender a policy holds, if it holds both its identity and its login,
/// and the revision that decided it.
fn authority_in(policy: &Policy) -> Option<(Sender, PolicyRevision)> {
    let account = Sender::first().account;
    let from = Address::parse(&format!("anyone@{}", sender::DOMAIN)).expect("a valid address");
    let identity = policy.sender(account, &from)?.id;
    let credential = policy.login(sender::LOGIN)?.id;
    let sending = Sender {
        account,
        identity,
        credential,
    };
    Some((sending, policy.revision()))
}

/// Everything the store must hold at `now`, given what it acknowledged.
/// How long a reservation's permit may be on its way from the store's
/// commit to the scheduler's dispatch, while the process runs: an attempt in
/// flight longer than this that it does not hold is stuck.
const ON_ITS_WAY: Duration = Duration::from_millis(100);

fn audit(
    pipeline: &Pipeline<'_>,
    store: &Store<SimConnection<'_>>,
    now: Timestamp,
    running: Option<Monotonic>,
) -> Result<Vec<String>, StoreError> {
    let mut problems = Vec::new();
    store.verify()?;
    // The queue's counts, kept as deliveries move, are what its rows say.
    let (kept, counted) = (store.queued(), store.count_queued()?);
    if kept != counted {
        problems.push(format!(
            "the queue is kept as {kept:?} but its rows count {counted:?}"
        ));
    }
    // What finished or happened before this may have been trimmed; nothing
    // after it may have been.
    let boundary = now.saturating_sub(WINDOW);
    // When each delivery's latest acknowledged outcome happened.
    let mut finished_at: BTreeMap<DeliveryId, Timestamp> = BTreeMap::new();
    for &(delivery, _, at) in pipeline.recorded.values() {
        let latest = finished_at.entry(delivery).or_insert(at);
        *latest = (*latest).max(at);
    }
    for accepted in &pipeline.acknowledged {
        let mut unfinished = false;
        for &id in &accepted.deliveries {
            match store.delivery(id)?.map(|delivery| delivery.state()) {
                Some(QueueState::Finished { .. }) => {}
                // An attempt is in flight only while its permit is held or on
                // its way to the scheduler, or its outcome is on its way: a
                // restart returns every abandoned one to the queue.
                Some(QueueState::InFlight { attempt, .. })
                    if !pipeline.holds(attempt)
                        && !running.is_some_and(|monotonic| {
                            pipeline.reserve_asked.get(&id).is_some_and(|asked| {
                                monotonic.saturating_duration_since(*asked) < ON_ITS_WAY
                            })
                        }) =>
                {
                    problems.push(format!("{id:?} is stuck in flight for {attempt:?}"));
                }
                Some(_) => unfinished = true,
                // A delivery is trimmed once its window has passed since it
                // finished, which came after its acceptance and every
                // outcome acknowledged.
                None if pipeline.deliveries[&id].2 < boundary
                    && finished_at.get(&id).is_none_or(|&at| at < boundary) => {}
                None => problems.push(format!(
                    "acknowledged delivery {id:?} was lost inside its window"
                )),
            }
        }
        // A message is trimmed once its window has passed since its last
        // delivery finished.
        let finished_inside = accepted
            .deliveries
            .iter()
            .any(|id| finished_at.get(id).is_some_and(|&at| at >= boundary));
        if store.message(accepted.message)?.is_none() && (unfinished || finished_inside) {
            problems.push(format!(
                "acknowledged message {:?} was lost inside its window",
                accepted.message
            ));
        }
        let kept = store.body(accepted.body)?.is_some();
        if kept != unfinished {
            problems.push(format!(
                "message {:?}'s body is {} with deliveries {}",
                accepted.message,
                if kept { "kept" } else { "gone" },
                if unfinished {
                    "unfinished"
                } else {
                    "all finished"
                },
            ));
        }
    }
    // The ledger holds every recipient acknowledged, and none that never
    // reached a commit.
    let ledger = store.sent_stored(Sender::first().account)?;
    let (known, possible) = (
        pipeline.acknowledged_recipients,
        pipeline.acknowledged_recipients + pipeline.uncertain_recipients,
    );
    if !(known..=possible).contains(&ledger) {
        problems.push(format!(
            "the ledger holds {ledger} recipients, outside the {known} to {possible} accepted"
        ));
    }
    // Every attempt issued from a capped egress is counted, and stays
    // counted through every crash.
    let counted: u64 = store
        .dispatched()
        .iter()
        .map(|(_, _, window)| window.total(WALL_START.saturating_add(Duration::from_secs(5))))
        .sum();
    if counted < pipeline.capped_issued {
        problems.push(format!(
            "{} attempts issued from a capped egress, and only {counted} counted",
            pipeline.capped_issued
        ));
    }
    // Every acknowledged change to policy is durable.
    let policy = store.policy();
    if policy.revision() < pipeline.policy_revision {
        problems.push(format!(
            "policy is at {:?}, before the acknowledged {:?}",
            policy.revision(),
            pipeline.policy_revision
        ));
    }
    let held = policy
        .identity_named(Sender::first().account, sender::DOMAIN)
        .is_some();
    if pipeline
        .identity_held
        .is_some_and(|expected| held != expected)
    {
        problems.push(format!(
            "the sender's identity is {}, though its {} was acknowledged",
            if held { "held" } else { "gone" },
            if held { "removal" } else { "creation" },
        ));
    }
    if pipeline.login_held && policy.login(sender::LOGIN).is_none() {
        problems.push("the acknowledged login was lost".to_owned());
    }
    for identity in pipeline.revoked.keys() {
        if policy.identity(*identity).is_some() {
            problems.push(format!(
                "{identity:?} is back after its removal was acknowledged"
            ));
        }
    }
    // Every attempt that ended has its entry in the journal.
    let ended: BTreeMap<AttemptId, Attempt> = store
        .entries(0, usize::MAX)?
        .into_iter()
        .filter_map(|(_, entry)| match entry {
            Entry::Attempted { attempt, .. } => Some((attempt.id, attempt)),
            _ => None,
        })
        .collect();
    for (&attempt, &(delivery, issued)) in &pipeline.issued {
        // A durable reservation leaves its attempt in flight until the
        // attempt ends, abandoned at a restart if nothing else. Its entry,
        // which happened after it was issued, is trimmed only once that is
        // before the window.
        let stored = store.delivery(delivery)?;
        let in_flight = matches!(
            stored.as_ref().map(Delivery::state),
            Some(QueueState::InFlight { attempt: current, .. }) if current == attempt
        );
        let recorded = ended
            .get(&attempt)
            .is_some_and(|stored| stored.delivery == delivery);
        let trimmed = stored.is_none() || issued < boundary;
        if !in_flight && !recorded && !trimmed {
            problems.push(format!(
                "a permit was issued for {attempt:?} with no durable reservation"
            ));
        }
    }
    for (&attempt, &(_, result, at)) in &pipeline.recorded {
        let stored = ended.get(&attempt).and_then(|stored| stored.ended);
        if stored.map(|ended| ended.result) != Some(result) && at >= boundary {
            problems.push(format!(
                "the acknowledged outcome of {attempt:?} was lost: {stored:?}"
            ));
        }
    }
    for (&id, &received) in &pipeline.received {
        // A trimmed delivery's attempts are past counting.
        let Some(delivery) = store.delivery(id)? else {
            continue;
        };
        let uncertain = delivery.uncertain_attempts();
        if received > 1 + uncertain {
            problems.push(format!(
                "{id:?} reached its receiver {received} times with {uncertain} uncertain attempts"
            ));
        }
    }
    // Every report kept as the first of its kind stays until its window
    // passes.
    for (&report, &issued) in &pipeline.kept_reports {
        if issued >= boundary && store.report(report)?.is_none() {
            problems.push(format!("acknowledged report {report:?} was lost"));
        }
    }
    // Every cooldown kept stays, at its latest acknowledged end or later,
    // until its ending is acknowledged.
    let cooldowns = store.dispatch_ledger()?.cooldowns;
    for ((egress, site), &until) in &pipeline.cooldowns {
        let kept = cooldowns
            .iter()
            .find(|kept| kept.egress == *egress && kept.site == *site);
        if kept.is_none_or(|kept| kept.until < until) {
            problems.push(format!(
                "{site}'s cooldown from {egress:?} until {until:?} was lost: the store keeps {kept:?}"
            ));
        }
    }
    Ok(problems)
}

impl World for Pipeline<'_> {
    type Event = Event;

    fn start(&mut self, context: &mut Context<'_, Event>) {
        context.after(Duration::ZERO, Event::Restart);
        context.after(Duration::from_millis(1), Event::Submit);
        context.after(Duration::from_millis(4_990), Event::Audit);
    }

    fn apply(&mut self, event: Event, context: &mut Context<'_, Event>) {
        self.vfs.disk().borrow_mut().set_now(context.now().wall);
        match event {
            Event::Restart => self.restart(context),
            Event::Submit => {
                self.submit(context);
                let gap = Duration::from_millis(context.rng().below(30));
                context.after(gap, Event::Submit);
            }
            Event::Poll => self.poll(context),
            Event::Wake(at) => {
                if self.owner.as_mut().is_some_and(|owner| owner.take_wake(at)) {
                    self.poll(context);
                }
            }
            Event::SchedulerPoll => self.poll_scheduler(context),
            Event::SchedulerWake(at) => {
                if self
                    .scheduler
                    .as_mut()
                    .is_some_and(|scheduler| scheduler.take_wake(at))
                {
                    self.poll_scheduler(context);
                }
            }
            Event::Receive {
                epoch,
                delivery,
                attempt,
            } => self.receive(epoch, delivery, attempt, context),
            Event::Decided { epoch, ticket } => self.decided(epoch, ticket, context),
            Event::Stop { epoch } => self.stop(epoch, context),
            Event::StopBound { epoch } => {
                if epoch == self.epoch && self.stopping {
                    self.violate(
                        "a graceful stop's drain did not finish within its bound".to_owned(),
                    );
                }
            }
            Event::Fill { epoch } => self.fill(epoch, context),
            Event::Audit => {
                let Some(owner) = self.owner.take() else {
                    return;
                };
                self.vfs.disk().borrow_mut().fail_power_after(u64::MAX);
                let store = owner.component().store();
                for &id in self.deliveries.keys() {
                    if store.delivery(id).is_ok_and(|delivery| delivery.is_none()) {
                        self.trimmed += 1;
                    }
                }
                match audit(
                    self,
                    owner.component().store(),
                    context.now().wall,
                    Some(context.now().monotonic),
                ) {
                    Ok(problems) => {
                        if let Some(problem) = problems.into_iter().next() {
                            self.violate(format!("at the end: {problem}"));
                        }
                    }
                    Err(error) => self.violate(format!("the final audit failed: {error}")),
                }
            }
        }
    }

    fn check(&self) -> Result<(), String> {
        self.violation.clone().map_or(Ok(()), Err)
    }
}

struct Outcome {
    failure: Option<String>,
    digest: Option<u64>,
    disk: u64,
    acknowledged: usize,
    issued: usize,
    recorded: usize,
    duplicated: usize,
    suppressed: usize,
    cancelled: usize,
    /// Attempts issued from the capped egress.
    capped: u64,
    /// Syncs of the main database file, which only checkpoints make.
    checkpoints: u64,
    trimmed: usize,
    reports_kept: usize,
    reports_again: usize,
    report_effects: u32,
    cooldowns_kept: usize,
    rotations: usize,
    retirements: usize,
    drained_stops: usize,
    full_stops: usize,
    interrupted: BTreeMap<Interrupted, u64>,
}

fn run_pipeline(seed: u64) -> Outcome {
    let mut seeds = Rng::from_seed(seed);
    let disk = Rc::new(RefCell::new(Disk::new(seeds.fork(), WALL_START)));
    let sqlite_seed = u32::try_from(seeds.below(u64::from(u32::MAX))).expect("below u32::MAX") + 1;
    let vfs = SimVfs::register("store-power-loss", Rc::clone(&disk), sqlite_seed)
        .expect("no other simulation uses SQLite");
    let mut pipeline = Pipeline::new(&vfs);
    let config = Config {
        seed,
        duration: Duration::from_secs(5),
        max_steps: 2_000_000,
        wall_start: WALL_START,
        clock_steps: None,
        trace: false,
    };
    let result = simulation::run(&mut pipeline, &config);
    Outcome {
        failure: result.as_ref().err().map(ToString::to_string),
        digest: result.ok().map(|report| report.digest),
        disk: disk.borrow().digest(),
        acknowledged: pipeline.acknowledged.len(),
        issued: pipeline.issued.len(),
        recorded: pipeline.recorded.len(),
        duplicated: pipeline
            .received
            .values()
            .filter(|&&received| received > 1)
            .count(),
        suppressed: pipeline.suppressed_reservations,
        cancelled: pipeline.cancelled_reservations,
        capped: pipeline.capped_issued,
        checkpoints: disk.borrow().syncs_of(DATABASE),
        trimmed: pipeline.trimmed,
        reports_kept: pipeline.kept_reports.len(),
        reports_again: pipeline.duplicate_reports,
        report_effects: pipeline.report_effects.values().sum(),
        cooldowns_kept: pipeline.cooldowns_kept,
        rotations: pipeline.rotations,
        retirements: pipeline.retirements,
        drained_stops: pipeline.drained_stops,
        full_stops: pipeline.full_stops,
        interrupted: pipeline.interrupted,
    }
}

#[test]
fn every_commit_point_survives_power_failure() {
    const SEEDS: u64 = 32;
    let (mut acknowledged, mut issued, mut recorded, mut duplicated) = (0, 0, 0, 0);
    let (mut suppressed, mut cancelled, mut capped) = (0, 0, 0);
    let mut checkpoints = 0;
    let (mut trimmed, mut reports_kept, mut reports_again, mut report_effects) = (0, 0, 0, 0);
    let (mut cooldowns_kept, mut rotations, mut retirements) = (0, 0, 0);
    let (mut drained_stops, mut full_stops) = (0, 0);
    let mut interrupted: BTreeMap<Interrupted, u64> = BTreeMap::new();
    for seed in 0..SEEDS {
        let outcome = run_pipeline(seed);
        if let Some(failure) = outcome.failure {
            panic!("{failure}");
        }
        acknowledged += outcome.acknowledged;
        issued += outcome.issued;
        recorded += outcome.recorded;
        duplicated += outcome.duplicated;
        suppressed += outcome.suppressed;
        cancelled += outcome.cancelled;
        capped += outcome.capped;
        checkpoints += outcome.checkpoints;
        trimmed += outcome.trimmed;
        reports_kept += outcome.reports_kept;
        reports_again += outcome.reports_again;
        report_effects += outcome.report_effects;
        cooldowns_kept += outcome.cooldowns_kept;
        rotations += outcome.rotations;
        retirements += outcome.retirements;
        drained_stops += outcome.drained_stops;
        full_stops += outcome.full_stops;
        for (point, count) in outcome.interrupted {
            *interrupted.entry(point).or_default() += count;
        }
    }
    // Enough of everything that passing means something.
    let counts = format!(
        "acknowledged {acknowledged}, issued {issued}, from the capped egress {capped}, recorded {recorded}, duplicated {duplicated}, suppressed {suppressed}, cancelled {cancelled}, checkpoints {checkpoints}, trimmed {trimmed}, reports kept {reports_kept}, again {reports_again}, with effects on {report_effects}, cooldowns kept {cooldowns_kept}, keys rotated {rotations}, older keys retired {retirements}, graceful stops {drained_stops}, stops on a full disk {full_stops}, interrupted {interrupted:?}"
    );
    let seeds = usize::try_from(SEEDS).expect("small");
    assert!(
        acknowledged >= seeds * 50 && issued >= seeds * 50 && recorded >= seeds * 50,
        "{counts}"
    );
    assert!(
        duplicated > 0,
        "no delivery reached its receiver twice: {counts}"
    );
    assert!(
        capped as usize * 2 >= issued,
        "most attempts go out from the capped egress: {counts}"
    );
    assert!(checkpoints >= SEEDS * 10, "too few checkpoints: {counts}");
    assert!(
        suppressed > 0,
        "no reservation found its recipient suppressed: {counts}"
    );
    assert!(
        cancelled > 0,
        "no reservation found its authority withdrawn: {counts}"
    );
    assert!(
        trimmed >= seeds * 10,
        "retention trimmed too few deliveries: {counts}"
    );
    assert!(
        reports_kept > 0 && reports_again > 0 && report_effects > 0,
        "too few reports, or none again: {counts}"
    );
    assert!(cooldowns_kept > 0, "no cooldown was kept: {counts}");
    assert!(
        rotations > 0 && retirements > 0,
        "no key rotated and its older one retired: {counts}"
    );
    assert!(
        drained_stops >= seeds / 2 && full_stops >= seeds / 2,
        "too few graceful stops, or stops on a full disk: {counts}"
    );
    for point in [
        Interrupted::Accept,
        Interrupted::Reserve,
        Interrupted::Outcome,
        Interrupted::Feedback,
        Interrupted::Commit,
        Interrupted::Recovery,
    ] {
        assert!(
            interrupted.get(&point).copied().unwrap_or(0) > 0,
            "never interrupted {point:?}: {counts}"
        );
    }

    let (first, second) = (run_pipeline(5), run_pipeline(5));
    assert_eq!(
        (first.digest, first.disk),
        (second.digest, second.disk),
        "a seed replays to the same events and the same disk"
    );
}
