//! The engine's work, counted exactly.
//!
//! Fixed scenarios run the real commit owner, store and scheduler on the
//! simulated disk with the power on, and count every write: commits through
//! SQLite's commit hook, rows by table through its update hook, and syncs
//! and bytes by file on the disk, with the reads the scheduler asks for.
//! The counts are exact, so any change in the engine's work shows in them.
//!
//! Each scenario checks its counts against the store's budget, and the
//! report sets every count beside the last run's, in `target/tmp`, where
//! `cargo xtask check` prints what changed.
//!
//! A commit takes [`SYNC`] of simulated time, as a sync does on a disk, so
//! commands that arrive meanwhile wait for the next group.
//!
//! SQLite's random number generator is process-wide, so this binary holds
//! one test, which runs every scenario in turn.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::command::{
    Accept, AcceptMessage, Answer, Command, Commit, CooldownChange, RecordOutcome, Request,
    Reservation, Response, Suppress,
};
use engine_core::component::Ticket;
use engine_core::delivery::{DispatchPermit, Disposition};
use engine_core::event::EventKind;
use engine_core::feedback::{Claim, Kind, Report};
use engine_core::hook::{self, dispatch};
use engine_core::id::{
    AttemptId, ConfigurationId, DeliveryId, EgressId, HoldId, IdGenerator, Lane, MessageId, PoolId,
    ReportId, Shard, SubscriptionId,
};
use engine_core::message::PolicyRevision;
use engine_core::policy::Change;
use engine_core::retry::RetrySchedule;
use engine_core::rng::Rng;
use engine_core::status::Status;
use engine_core::suppression::Reason;
use engine_core::time::{Monotonic, Timestamp};
use engine_events::Events;
use engine_rules::{Rules, Site};
use engine_scheduler::{Attempted, Output, Route, Scheduler, Tls};
use engine_sim::disk::Disk;
use engine_sim::host::Host;
use engine_sim::sender::Sender as Identity;
use engine_sim::simulation::{self, Config, Context, World};
use engine_sim::vfs::{SimConnection, SimVfs};
use engine_store::commit_owner::{CommitOwner, GroupLimits};
use engine_store::store::{Store, StoreOptions};
use rusqlite::hooks::Action;

const WALL_START: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);
const SHARD: Shard = Shard::new(1);
const DATABASE: &str = "work.db";
const WAL: &str = "work.db-wal";
/// How long a commit's sync takes.
const SYNC: Duration = Duration::from_millis(1);
/// How long the receiver takes over an attempt.
const RECEIVER: Duration = Duration::from_millis(5);
const BODY_BYTES: usize = 16 * 1024;
const THROTTLED_DOMAIN: &str = "throttled.test";
const THROTTLED_SITE: &str = "mx.throttled.test";

/// What the receiver does with an attempt.
#[derive(Clone, Copy)]
enum Receiver {
    Accepts,
    /// Defers each delivery's first attempt, and accepts the next.
    DefersFirst,
    /// Throttles this many attempts to its own site, then accepts.
    Throttles(u32),
    /// Throttles every attempt until this time, then accepts: its whole
    /// queue waits, due, in the window, through scan after scan.
    ThrottlesUntil(Duration),
    /// Defers every attempt until this time, then accepts.
    ClosedUntil(Duration),
}

struct Scenario {
    name: &'static str,
    summary: &'static str,
    messages: usize,
    /// Recipients of each message, which share its body.
    recipients: usize,
    /// Messages submitted a second.
    rate: u64,
    receiver: Receiver,
    /// A graceful restart at this time, once nothing is in flight.
    restart: Option<Duration>,
    /// Whether every tenth message's recipient is suppressed before any is
    /// sent.
    suppressed: bool,
    /// The sender's identity removed at this time, which withdraws the
    /// authority of its mail still waiting.
    revoke: Option<Duration>,
    /// Whether its mail is sent under a configuration with a subscription
    /// to every kind of event, whose batches its receiver takes.
    subscribed: bool,
    /// Whether its mail goes out from a pool's one egress, with a daily cap
    /// that never binds, so every reservation counts in the dispatch ledger.
    warming: bool,
    /// A feedback window short enough for the run to trim what it sent,
    /// which it waits for.
    retention: Option<Duration>,
    /// Once every recipient's outcome is durable, a bounce report that
    /// rules the address out, for every this-many'th message.
    bounce_every: Option<usize>,
    /// Whether a dispatch hook decides each recipient before its
    /// reservation, answering at once and holding every tenth it is first
    /// asked about.
    hooked: bool,
    /// A hold on its sender's identity from the start, accepting its mail,
    /// lifted at this time.
    paused: Option<Duration>,
}

static SCENARIOS: [Scenario; 14] = [
    Scenario {
        name: "single",
        summary: "2,000 messages of one recipient, at 5,000 a second, all accepted",
        messages: 2_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "fan-out",
        summary: "40 messages of 50 recipients sharing each body, all accepted",
        messages: 40,
        recipients: 50,
        rate: 100,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "retry",
        summary: "1,000 messages, each deferred once and then accepted",
        messages: 1_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::DefersFirst,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "throttled",
        summary: "1,000 messages, a tenth to a site that throttles twice",
        messages: 1_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Throttles(2),
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "cooling",
        summary: "500 messages to one site that throttles for 30 seconds, then accepts",
        messages: 500,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::ThrottlesUntil(Duration::from_secs(30)),
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "restart",
        summary: "1,000 messages deferred while the receiver is closed, a graceful restart, then the drain",
        messages: 1_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::ClosedUntil(Duration::from_secs(25)),
        restart: Some(Duration::from_secs(15)),
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "suppressed",
        summary: "1,000 messages, a tenth to recipients suppressed before any is sent",
        messages: 1_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: true,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "revoked",
        summary: "1,000 messages deferred while the receiver is closed, then their identity removed",
        messages: 1_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::ClosedUntil(Duration::from_secs(25)),
        restart: None,
        suppressed: false,
        revoke: Some(Duration::from_secs(15)),
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "subscribed",
        summary: "2,000 messages of one recipient, all accepted, under a subscription to every event",
        messages: 2_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: true,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "warming",
        summary: "2,000 messages of one recipient, all accepted, from an egress whose daily cap never binds",
        messages: 2_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: true,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "retained",
        summary: "2,000 messages of one recipient, all accepted, then trimmed once a 30-second feedback window passes",
        messages: 2_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: Some(Duration::from_secs(30)),
        bounce_every: None,
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "bounced",
        summary: "2,000 messages of one recipient, all accepted, then a bounce report for every 33rd",
        messages: 2_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: Some(33),
        hooked: false,
        paused: None,
    },
    Scenario {
        name: "hooked",
        summary: "2,000 messages of one recipient, all accepted, through a dispatch hook that holds every tenth once",
        messages: 2_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: true,
        paused: None,
    },
    Scenario {
        name: "paused",
        summary: "2,000 messages of one recipient, all accepted while a hold pauses their identity, sent once it is lifted 10 seconds in",
        messages: 2_000,
        recipients: 1,
        rate: 5_000,
        receiver: Receiver::Accepts,
        restart: None,
        suppressed: false,
        revoke: None,
        subscribed: false,
        warming: false,
        retention: None,
        bounce_every: None,
        hooked: false,
        paused: Some(Duration::from_secs(10)),
    },
];

const CONFIGURATION: &str = "receipts";
const SUBSCRIPTION: &str = "hooks";

/// The shipped receiver rules with the harness's 64 connections to each
/// site no provider claims (`bench/harness/images/nitromta/config.toml`).
fn rules() -> Arc<Rules> {
    let defaults = engine_rules::Entry {
        connections: Some(64),
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

/// The harness's settings for the engine
/// (`bench/harness/images/nitromta/config.toml`), and the shell's defaults
/// for the rest.
fn scheduler_config(dispatch_hook: bool) -> engine_scheduler::Config {
    engine_scheduler::Config {
        per_transaction: 100,
        window: 100_000,
        window_bytes: 256 * 1024 * 1024,
        scan_every: Duration::from_secs(1),
        scan_page: 1_000,
        retry: RetrySchedule::new(Duration::from_secs(10), Duration::from_secs(60))
            .expect("a valid schedule"),
        route_ttl: Duration::from_secs(3_600),
        dispatch_hook,
        ended_rules: false,
    }
}

/// A write SQLite reported.
enum Write {
    Commit,
    Row(String, &'static str),
}

fn change(action: Action) -> &'static str {
    match action {
        Action::SQLITE_INSERT => "inserted",
        Action::SQLITE_UPDATE => "updated",
        Action::SQLITE_DELETE => "deleted",
        _ => "changed",
    }
}

/// Everything counted, by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Counts(BTreeMap<String, u64>);

impl Counts {
    fn add(&mut self, name: &str, count: u64) {
        *self.0.entry(name.to_owned()).or_default() += count;
    }

    fn get(&self, name: &str) -> u64 {
        self.0.get(name).copied().unwrap_or(0)
    }

    /// What was counted since `before`.
    fn since(&self, before: &Self) -> Self {
        let mut since = Self::default();
        for (name, &count) in &self.0 {
            let delta = count - before.get(name);
            if delta > 0 {
                since.add(name, delta);
            }
        }
        since
    }
}

#[derive(Debug, Hash)]
enum Event {
    Start,
    Submit,
    Poll,
    /// A commit's sync is done, so its answers go out.
    Synced,
    Wake(Monotonic),
    SchedulerPoll,
    SchedulerWake(Monotonic),
    Receive(AttemptId),
    Restart,
    Revoke,
    /// The scenario's hold is lifted.
    Lift,
    EventsPoll,
    EventsWake(Monotonic),
    /// The subscriber has taken a batch.
    Posted(u64),
}

enum Waiting {
    /// An acceptance, and its deliveries for the scheduler once it commits.
    Accept(Vec<engine_scheduler::Accepted>),
    /// A request the scheduler made, under its own ticket, and whether it
    /// records a delivered outcome.
    Scheduler(Ticket, bool),
    Suppress,
    /// A policy change, and whether it is one of the sender's, made before
    /// the scenario starts.
    Policy(bool),
    /// A request event delivery made, under its own ticket.
    Events(Ticket),
    Report,
}

struct Run<'vfs> {
    scenario: &'static Scenario,
    vfs: &'vfs SimVfs,
    writes: mpsc::Receiver<Write>,
    sender: Sender<Write>,
    owner: Option<Host<CommitOwner<SimConnection<'vfs>>>>,
    scheduler: Option<Host<Scheduler>>,
    events: Option<Host<Events>>,
    /// The configuration its mail is sent under, once it exists.
    configuration: Option<ConfigurationId>,
    ids: IdGenerator,
    /// The policy revision acceptances are decided under.
    revision: PolicyRevision,
    /// The sender's changes not yet committed.
    provisioning: usize,
    submitted: usize,
    next_ticket: u64,
    waiting: BTreeMap<Ticket, Waiting>,
    /// A commit's answers, while its sync is under way.
    syncing: Option<Vec<Response>>,
    /// Each attempt under way, with its site, whose rules judge its reply.
    permits: BTreeMap<AttemptId, (DispatchPermit, Site)>,
    tries: BTreeMap<DeliveryId, u32>,
    throttled: u32,
    /// Recipients the dispatch hook was asked about.
    consulted: u64,
    /// Recipients whose delivered outcome, or suppression, is durable.
    delivered: usize,
    /// The last delivery submitted: trimmed oldest first, it goes last.
    last_delivery: Option<DeliveryId>,
    /// Each message submitted, where the scenario reports bounces.
    messages: Vec<MessageId>,
    /// Bounce reports recorded, and whether they were sent.
    reported: usize,
    reports_sent: bool,
    counts: Counts,
    /// What was counted once the store was created, which is not the
    /// scenario's work.
    baseline: Counts,
    /// What the run counted once every recipient's outcome was durable,
    /// and what the graceful restart did.
    done: Option<Counts>,
    restart: Option<Counts>,
    /// Whether the scenario's hold is lifted, as its change was
    /// acknowledged.
    lifted: bool,
    /// Each site's cooldown as last given to the store to keep, by its end.
    cooldowns: BTreeMap<(Option<EgressId>, Arc<str>), Timestamp>,
    violation: Option<String>,
}

impl<'vfs> Run<'vfs> {
    fn new(scenario: &'static Scenario, vfs: &'vfs SimVfs) -> Self {
        let (sender, writes) = mpsc::channel();
        Self {
            scenario,
            vfs,
            writes,
            sender,
            owner: None,
            scheduler: None,
            events: None,
            configuration: None,
            ids: IdGenerator::new(SHARD, Lane::new(1).expect("a lane"), None),
            revision: PolicyRevision::default(),
            provisioning: 0,
            submitted: 0,
            next_ticket: 0,
            waiting: BTreeMap::new(),
            syncing: None,
            permits: BTreeMap::new(),
            tries: BTreeMap::new(),
            throttled: 0,
            consulted: 0,
            delivered: 0,
            last_delivery: None,
            messages: Vec::new(),
            reported: 0,
            reports_sent: false,
            counts: Counts::default(),
            baseline: Counts::default(),
            done: None,
            restart: None,
            lifted: false,
            cooldowns: BTreeMap::new(),
            violation: None,
        }
    }

    fn total(&self) -> usize {
        self.scenario.messages * self.scenario.recipients
    }

    /// A message's recipient: `index` the message, `recipient` which of it.
    fn address(&self, index: usize, recipient: usize) -> Address {
        let domain = match self.scenario.receiver {
            Receiver::Throttles(_) if index.is_multiple_of(10) => THROTTLED_DOMAIN.to_owned(),
            Receiver::ThrottlesUntil(_) => THROTTLED_DOMAIN.to_owned(),
            _ => format!(
                "d{}.test",
                (index * self.scenario.recipients + recipient) % 1_000
            ),
        };
        Address::parse(&format!("r{index}-{recipient}@{domain}")).expect("a valid address")
    }

    /// Counts the writes SQLite has reported, and returns how many were
    /// commits.
    fn drain(&mut self) -> u64 {
        let mut commits = 0;
        while let Ok(write) = self.writes.try_recv() {
            match write {
                Write::Commit => commits += 1,
                Write::Row(table, change) => self.counts.add(&format!("rows {table} {change}"), 1),
            }
        }
        self.counts.add("commits", commits);
        commits
    }

    /// Everything counted so far: SQLite's writes, the disk's, and the
    /// run's own.
    fn snapshot(&mut self) -> Counts {
        self.drain();
        let mut counts = self.counts.clone();
        let disk = self.vfs.disk().borrow();
        counts.add("syncs of the log", disk.syncs_of(WAL));
        counts.add("syncs of the database", disk.syncs_of(DATABASE));
        counts.add("bytes written to the log", disk.written_to(WAL));
        counts.add("bytes written to the database", disk.written_to(DATABASE));
        counts
    }

    /// Opens the store, with SQLite's hooks reporting its writes, and starts
    /// the commit owner and the scheduler on it.
    fn open(&mut self, context: &mut Context<'_, Event>) {
        let mut connection = self.vfs.open(DATABASE).expect("the store opens");
        let rows = self.sender.clone();
        connection
            .preupdate_hook(Some(move |action, _: &str, table: &str, _: &_| {
                let _ = rows.send(Write::Row(table.to_owned(), change(action)));
            }))
            .expect("the update hook installs");
        let commits = self.sender.clone();
        connection
            .commit_hook(Some(move || {
                let _ = commits.send(Write::Commit);
                false
            }))
            .expect("the commit hook installs");
        let mut options = StoreOptions::default();
        if let Some(window) = self.scenario.retention {
            options.feedback_window = window;
        }
        let store =
            Store::open(connection, options, engine_sim::sender::keys()).expect("the store opens");
        let after = store.highest_id().expect("the high-water mark reads");
        let (owner, _) = CommitOwner::start(store, GroupLimits::default(), context.now().wall)
            .expect("the commit owner starts");
        self.owner = Some(Host::new(owner));
        self.scheduler = Some(Host::new(Scheduler::new(
            scheduler_config(self.scenario.hooked),
            rules(),
            IdGenerator::new(SHARD, Lane::new(2).expect("a lane"), after),
            context.rng().fork(),
        )));
        // The scheduler starts from the policy the store holds, as the
        // shell's does.
        let policy = Arc::clone(
            self.owner
                .as_ref()
                .expect("the store is open")
                .component()
                .store()
                .policy(),
        );
        self.tell_scheduler(engine_scheduler::Input::Policy(policy), context);
        context.after(Duration::ZERO, Event::SchedulerPoll);
    }

    fn submit(&mut self, context: &mut Context<'_, Event>) {
        let now = context.now().wall;
        let index = self.submitted;
        let recipients: Vec<Address> = (0..self.scenario.recipients)
            .map(|recipient| self.address(index, recipient))
            .collect();
        let message = AcceptMessage::new(
            MessageId(self.ids.next(now)),
            Bytes::from(vec![b'x'; BODY_BYTES]),
            &recipients,
            None,
            &mut self.ids,
            now,
        );
        let mut authority = Identity::first().authority(self.revision);
        authority.origin.configuration = self.configuration;
        let accept = Accept::new(
            authority,
            vec![message],
            &mut self.ids,
            now,
            Duration::from_secs(86_400),
        );
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
        self.last_delivery = accept
            .messages
            .iter()
            .flat_map(|message| &message.recipients)
            .map(|recipient| recipient.delivery)
            .last();
        if self.scenario.bounce_every.is_some() {
            self.messages
                .extend(accept.messages.iter().map(|message| message.id));
        }
        self.request(Command::Accept(accept), Waiting::Accept(fresh), context);
        self.submitted += 1;
        if self.submitted < self.scenario.messages {
            let gap = Duration::from_secs(1) / u32::try_from(self.scenario.rate).expect("small");
            context.after(gap, Event::Submit);
        }
    }

    fn request(&mut self, command: Command, waiting: Waiting, context: &mut Context<'_, Event>) {
        let Some(owner) = self.owner.as_mut() else {
            return self.violate("a request with the store closed".to_owned());
        };
        let ticket = Ticket(self.next_ticket);
        self.next_ticket += 1;
        self.waiting.insert(ticket, waiting);
        // While a sync is under way, the next poll waits for it.
        if owner.deliver(context.now(), Request { ticket, command }) && self.syncing.is_none() {
            context.after(Duration::ZERO, Event::Poll);
        }
    }

    fn poll(&mut self, context: &mut Context<'_, Event>) {
        if self.syncing.is_some() {
            return;
        }
        let Some(owner) = self.owner.as_mut() else {
            return;
        };
        let mut responses = Vec::new();
        let wake = owner.poll(context.now(), &mut responses);
        if self.drain() > 0 {
            // The group's answers go out once its sync is done.
            self.syncing = Some(responses);
            context.after(SYNC, Event::Synced);
            return;
        }
        if let Some(at) = wake {
            context.at(at, Event::Wake(at));
        }
        for response in responses {
            self.answer(response, context);
        }
    }

    fn synced(&mut self, context: &mut Context<'_, Event>) {
        for response in self.syncing.take().unwrap_or_default() {
            self.answer(response, context);
        }
        context.after(Duration::ZERO, Event::Poll);
    }

    fn answer(&mut self, response: Response, context: &mut Context<'_, Event>) {
        let Some(waiting) = self.waiting.remove(&response.ticket) else {
            return self.violate(format!("an answer to no request: {:?}", response.ticket));
        };
        match waiting {
            Waiting::Accept(fresh) => {
                if matches!(response.answer, Answer::Accepted(Commit::Committed(()))) {
                    self.tell_scheduler(engine_scheduler::Input::Accepted(fresh), context);
                } else {
                    self.violate(format!("an acceptance failed: {:?}", response.answer));
                }
            }
            Waiting::Suppress => {
                if !matches!(response.answer, Answer::Suppressions(Commit::Committed(_))) {
                    self.violate(format!("a suppression failed: {:?}", response.answer));
                }
            }
            Waiting::Policy(provisioning) => {
                let Answer::Policy(Commit::Committed(revision)) = response.answer else {
                    return self.violate(format!("a policy change failed: {:?}", response.answer));
                };
                self.revision = revision;
                if provisioning {
                    self.provisioning -= 1;
                    if self.provisioning == 0 {
                        self.begin(context);
                    }
                } else {
                    self.lifted = self.scenario.paused.is_some();
                    // As the shell does, each committed revision is the
                    // scheduler's.
                    let owner = self.owner.as_ref().expect("the store is open");
                    let policy = Arc::clone(owner.component().store().policy());
                    self.tell_scheduler(engine_scheduler::Input::Policy(policy), context);
                }
            }
            Waiting::Scheduler(ticket, delivers) => {
                if delivers && matches!(response.answer, Answer::Recorded(Commit::Committed(()))) {
                    self.delivered += 1;
                }
                // A suppressed recipient, or one whose authority was
                // withdrawn, is done with, without an attempt.
                // Each permit is an attempt, whether or not its transaction
                // is sent: one held back while its site cools down is
                // recorded all the same.
                match &response.answer {
                    Answer::Released(Commit::Committed(())) => self.counts.add("released", 1),
                    Answer::Parked(Commit::Committed(())) => self.counts.add("parked", 1),
                    _ => {}
                }
                if let Answer::Reserved(Commit::Committed(reservation)) = &response.answer {
                    let unsent = match reservation {
                        Reservation::Suppressed => Some("suppressed"),
                        Reservation::Cancelled => Some("cancelled"),
                        Reservation::Paused => {
                            self.counts.add("parked", 1);
                            None
                        }
                        Reservation::Permit(_) => {
                            self.counts.add("attempts", 1);
                            None
                        }
                    };
                    if let Some(name) = unsent {
                        self.counts.add(name, 1);
                        self.delivered += 1;
                    }
                }
                match &response.answer {
                    Answer::Due(Ok(due)) | Answer::Expiring(Ok(due)) => {
                        self.counts.add("scans", 1);
                        self.counts.add("deliveries scanned", due.len() as u64);
                    }
                    Answer::Body(_) | Answer::Content(_) => self.counts.add("bodies read", 1),
                    _ => {}
                }
                let response = Response {
                    ticket,
                    answer: response.answer,
                };
                self.tell_scheduler(engine_scheduler::Input::Answer(response), context);
            }
            Waiting::Report => {
                if matches!(response.answer, Answer::Feedback(Commit::Committed(_))) {
                    self.reported += 1;
                } else {
                    self.violate(format!("a report failed: {:?}", response.answer));
                }
            }
            Waiting::Events(ticket) => {
                if let Answer::Events(Ok(Some(owed))) = &response.answer {
                    self.counts.add("event reads", 1);
                    self.counts.add("events read", owed.entries.len() as u64);
                }
                let response = Response {
                    ticket,
                    answer: response.answer,
                };
                self.tell_events(engine_events::Input::Answer(response), context);
            }
        }
    }

    fn tell_events(&mut self, input: engine_events::Input, context: &mut Context<'_, Event>) {
        if let Some(events) = self.events.as_mut()
            && events.deliver(context.now(), input)
        {
            context.after(Duration::ZERO, Event::EventsPoll);
        }
    }

    fn poll_events(&mut self, context: &mut Context<'_, Event>) {
        let Some(events) = self.events.as_mut() else {
            return;
        };
        let mut outputs = Vec::new();
        let wake = events.poll(context.now(), &mut outputs);
        if let Some(at) = wake
            && self.done.is_none()
        {
            context.at(at, Event::EventsWake(at));
        }
        for output in outputs {
            match output {
                engine_events::Output::Request(Request { ticket, command }) => {
                    if matches!(command, Command::Acknowledge { .. }) {
                        self.counts.add("acknowledgements", 1);
                    }
                    self.request(command, Waiting::Events(ticket), context);
                }
                engine_events::Output::Post(post) => {
                    self.counts.add("batches posted", 1);
                    self.counts.add("bytes posted", post.body.len() as u64);
                    context.after(RECEIVER, Event::Posted(post.id));
                }
                // No operator asks for a replay here.
                engine_events::Output::Replaying { .. } => {}
            }
        }
    }

    /// Whether every event committed so far is delivered: the cursor stands
    /// at the journal's end.
    fn caught_up(&self) -> bool {
        let Some(owner) = self.owner.as_ref() else {
            return false;
        };
        let store = owner.component().store();
        let Some(subscription) = store.policy().subscriptions().next() else {
            return true;
        };
        store
            .cursor(subscription.id)
            .expect("the cursor reads")
            .is_some_and(|cursor| {
                store
                    .entries(cursor, 1)
                    .expect("the journal reads")
                    .is_empty()
            })
    }

    /// How many bounce reports the scenario sends.
    fn reports(&self) -> usize {
        self.scenario
            .bounce_every
            .map_or(0, |every| self.scenario.messages.div_ceil(every))
    }

    /// Sends a bounce report for every `bounce_every`th message's first
    /// recipient, which the receiver had accepted.
    fn report(&mut self, context: &mut Context<'_, Event>) {
        let Some(every) = self.scenario.bounce_every else {
            return;
        };
        let now = context.now().wall;
        for index in (0..self.scenario.messages).step_by(every) {
            let report = Report {
                id: ReportId(self.ids.next(now)),
                message: Some(self.messages[index]),
                kind: Kind::DeliveryStatus,
                recipients: vec![Claim {
                    address: self.address(index, 0),
                    failed: true,
                    status: Status::parse("5.1.1"),
                    rules_out_address: true,
                    diagnostic: Some("550 5.1.1 no such user".to_owned()),
                }],
                identity: {
                    let mut identity = [0; 32];
                    identity[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    identity
                },
                evidence: Bytes::from(vec![b'r'; 2_048]),
                received_at: now,
                authenticated: false,
                trusted: true,
                simulated: false,
            };
            self.counts.add("reports", 1);
            self.request(Command::RecordFeedback(report), Waiting::Report, context);
        }
    }

    /// Whether everything it sent is trimmed, where the scenario trims:
    /// every delivery, and the journal but for its newest entry, which
    /// stays.
    fn trimmed(&self) -> bool {
        let (Some(_), Some(last), Some(owner)) = (
            self.scenario.retention,
            self.last_delivery,
            self.owner.as_ref(),
        ) else {
            return true;
        };
        let store = owner.component().store();
        store.delivery(last).expect("the delivery reads").is_none()
            && store.entries(0, 2).expect("the journal reads").len() == 1
    }

    fn tell_scheduler(&mut self, input: engine_scheduler::Input, context: &mut Context<'_, Event>) {
        if let Some(scheduler) = self.scheduler.as_mut()
            && scheduler.deliver(context.now(), input)
        {
            context.after(Duration::ZERO, Event::SchedulerPoll);
        }
    }

    fn poll_scheduler(&mut self, context: &mut Context<'_, Event>) {
        let Some(scheduler) = self.scheduler.as_mut() else {
            return;
        };
        let mut outputs = Vec::new();
        let wake = scheduler.poll(context.now(), &mut outputs);
        // Once every outcome is durable, the scheduler's scans would go on
        // until the end of the run, so its wakes stop there.
        if let Some(at) = wake
            && self.done.is_none()
        {
            context.at(at, Event::SchedulerWake(at));
        }
        let mut resolved = Vec::new();
        // The hook's verdicts, given at once.
        let mut decided = Vec::new();
        for output in outputs {
            match output {
                Output::Resolve(domain) => {
                    let exchange = if &*domain == THROTTLED_DOMAIN {
                        THROTTLED_SITE
                    } else {
                        "mx.sim.test"
                    };
                    resolved.push(engine_scheduler::Input::Resolved {
                        domain,
                        route: Route::Exchanges(vec![exchange.to_owned()], Tls::default()),
                        ttl: Duration::from_secs(3_600),
                    });
                }
                Output::Store(Request { ticket, command }) => {
                    let delivers = matches!(
                        &command,
                        Command::RecordOutcome(outcome)
                            if outcome.disposition == Disposition::Delivered
                    );
                    // A cooldown the scheduler gives the store to keep, with
                    // an outcome or on its own, only as it begins, grows or
                    // ends: never again while it runs unchanged.
                    let change = match &command {
                        Command::RecordOutcome(RecordOutcome {
                            cooled: Some(change),
                            feedback: None,
                            ..
                        }) => Some(change.clone()),
                        Command::Cooldown(change) => Some(change.clone()),
                        _ => None,
                    };
                    if let Some(change) = change {
                        self.counts.add("cooldowns kept", 1);
                        let now = context.now().wall;
                        match change {
                            CooldownChange::Kept(kept) => {
                                let key = (kept.egress, Arc::clone(&kept.site));
                                if let Some(&last) = self.cooldowns.get(&key)
                                    && last > now
                                    && kept.until <= last
                                {
                                    return self.violate(format!(
                                        "{} kept again without growing",
                                        kept.site
                                    ));
                                }
                                self.cooldowns.insert(key, kept.until);
                            }
                            CooldownChange::Ended { egress, site } => {
                                if self
                                    .cooldowns
                                    .remove(&(egress, Arc::clone(&site)))
                                    .is_none()
                                {
                                    return self.violate(format!("{site} ended, never kept"));
                                }
                            }
                        }
                    }
                    self.request(command, Waiting::Scheduler(ticket, delivers), context);
                }
                Output::Inspected { .. } | Output::Ended(_) => {}
                Output::Consult { ticket, recipients } => {
                    let verdicts = recipients
                        .iter()
                        .map(|recipient| {
                            self.consulted += 1;
                            if recipient.attempts == 0 && self.consulted % 10 == 1 {
                                self.counts.add("held by the hook", 1);
                                dispatch::Verdict::Hold(hook::Reason::new("the hook's test hold"))
                            } else {
                                dispatch::Verdict::Proceed
                            }
                        })
                        .collect();
                    self.counts.add("consultations", 1);
                    decided.push(engine_scheduler::Input::Consulted { ticket, verdicts });
                }
                Output::Dispatch(dispatch) => {
                    if self.scenario.paused.is_some() && !self.lifted {
                        return self
                            .violate("mail went out while its hold was in force".to_owned());
                    }
                    self.counts.add("transactions", 1);
                    for (permit, _) in dispatch.recipients {
                        let attempt = permit.attempt();
                        self.permits
                            .insert(attempt, (permit, dispatch.site.clone()));
                        context.after(RECEIVER, Event::Receive(attempt));
                    }
                }
            }
        }
        for input in resolved.into_iter().chain(decided) {
            self.tell_scheduler(input, context);
        }
    }

    fn receive(&mut self, attempt: AttemptId, context: &mut Context<'_, Event>) {
        let Some((permit, site)) = self.permits.remove(&attempt) else {
            return;
        };
        let tries = self.tries.entry(permit.delivery()).or_default();
        *tries += 1;
        let result = match self.scenario.receiver {
            Receiver::Accepts => Attempted::Delivered,
            Receiver::DefersFirst if *tries == 1 => Attempted::Deferred,
            Receiver::DefersFirst => Attempted::Delivered,
            Receiver::Throttles(times)
                if &**site.name() == THROTTLED_SITE && self.throttled < times =>
            {
                self.throttled += 1;
                Attempted::Throttled
            }
            Receiver::Throttles(_) => Attempted::Delivered,
            Receiver::ThrottlesUntil(until)
                if u128::from(context.now().monotonic.as_micros()) < until.as_micros() =>
            {
                Attempted::Throttled
            }
            Receiver::ThrottlesUntil(_) => Attempted::Delivered,
            Receiver::ClosedUntil(until)
                if u128::from(context.now().monotonic.as_micros()) < until.as_micros() =>
            {
                Attempted::Deferred
            }
            Receiver::ClosedUntil(_) => Attempted::Delivered,
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

    /// The scenario proper, once its sender exists: what it counts starts
    /// here.
    fn begin(&mut self, context: &mut Context<'_, Event>) {
        self.baseline = self.snapshot();
        let policy = Arc::clone(
            self.owner
                .as_ref()
                .expect("the store is open")
                .component()
                .store()
                .policy(),
        );
        self.tell_scheduler(engine_scheduler::Input::Policy(policy), context);
        if self.scenario.subscribed {
            let owner = self.owner.as_ref().expect("the store is open");
            let policy = Arc::clone(owner.component().store().policy());
            let config = engine_events::Config {
                batch: 1_000,
                batch_bytes: 1 << 20,
                idle: Duration::from_millis(200),
                retry: RetrySchedule::new(Duration::from_secs(1), Duration::from_secs(300))
                    .expect("a valid schedule"),
                park_after: Duration::from_secs(86_400),
            };
            self.events = Some(Host::new(Events::new(config, context.rng().fork())));
            self.tell_events(engine_events::Input::Policy(policy), context);
        }
        if self.scenario.suppressed {
            let now = context.now().wall;
            let addresses: Vec<Address> = (0..self.scenario.messages)
                .step_by(10)
                .map(|index| self.address(index, 0))
                .collect();
            self.counts
                .add("addresses suppressed", addresses.len() as u64);
            let command = Command::Suppress(Suppress {
                account: Identity::first().account,
                addresses,
                reason: Reason::Operator,
                now,
            });
            self.request(command, Waiting::Suppress, context);
        }
        context.after(Duration::from_millis(1), Event::Submit);
    }

    /// Stops gracefully, with nothing in flight, and starts again.
    fn restart(&mut self, context: &mut Context<'_, Event>) {
        if !(self.permits.is_empty() && self.waiting.is_empty() && self.syncing.is_none()) {
            return context.after(Duration::from_millis(1), Event::Restart);
        }
        let before = self.snapshot();
        // Closing the store checkpoints its log.
        self.scheduler = None;
        self.owner = None;
        self.open(context);
        self.restart = Some(self.snapshot().since(&before));
    }

    fn violate(&mut self, violation: String) {
        self.violation.get_or_insert(violation);
    }
}

impl World for Run<'_> {
    type Event = Event;

    fn start(&mut self, context: &mut Context<'_, Event>) {
        context.after(Duration::ZERO, Event::Start);
        if let Some(at) = self.scenario.restart {
            context.after(at, Event::Restart);
        }
        if let Some(at) = self.scenario.revoke {
            context.after(at, Event::Revoke);
        }
        if let Some(at) = self.scenario.paused {
            context.after(at, Event::Lift);
        }
    }

    fn apply(&mut self, event: Event, context: &mut Context<'_, Event>) {
        self.vfs.disk().borrow_mut().set_now(context.now().wall);
        match event {
            Event::Start => {
                self.open(context);
                let mut changes = Identity::first().changes().to_vec();
                if self.scenario.warming {
                    let now = context.now().wall;
                    let configuration = ConfigurationId(self.ids.next(now));
                    self.configuration = Some(configuration);
                    changes.extend(Identity::first().pool_changes(
                        configuration,
                        PoolId(self.ids.next(now)),
                        EgressId(self.ids.next(now)),
                        Some(1_000_000),
                    ));
                }
                if self.scenario.subscribed {
                    let account = Identity::first().account;
                    let now = context.now().wall;
                    let configuration = ConfigurationId(self.ids.next(now));
                    self.configuration = Some(configuration);
                    changes.push(Change::Configuration {
                        id: configuration,
                        account,
                        name: CONFIGURATION.to_owned(),
                        pool: None,
                    });
                    changes.push(Change::Subscription {
                        id: SubscriptionId(self.ids.next(now)),
                        account,
                        name: SUBSCRIPTION.to_owned(),
                        configuration: CONFIGURATION.to_owned(),
                        url: "https://hooks.sim.test/in".to_owned(),
                        events: EventKind::ALL.into_iter().collect(),
                        secret: [7; 32],
                    });
                }
                if self.scenario.paused.is_some() {
                    changes.push(Change::Hold {
                        id: HoldId(self.ids.next(context.now().wall)),
                        target: Identity::first().target(),
                        accepting: true,
                        reason: "the scenario's hold".to_owned(),
                    });
                }
                self.provisioning = changes.len();
                for change in changes {
                    self.request(
                        Command::ChangePolicy(change),
                        Waiting::Policy(true),
                        context,
                    );
                }
            }
            Event::Revoke => {
                self.counts.add("policy changes", 1);
                let removal = Command::ChangePolicy(Identity::first().removal());
                self.request(removal, Waiting::Policy(false), context);
            }
            Event::Lift => {
                self.counts.add("policy changes", 1);
                let lift = Command::ChangePolicy(Change::Release(Identity::first().target()));
                self.request(lift, Waiting::Policy(false), context);
            }
            Event::Submit => self.submit(context),
            Event::Poll => self.poll(context),
            Event::Synced => self.synced(context),
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
            Event::Receive(attempt) => self.receive(attempt, context),
            Event::Restart => self.restart(context),
            Event::EventsPoll => self.poll_events(context),
            Event::EventsWake(at) => {
                if self
                    .events
                    .as_mut()
                    .is_some_and(|events| events.take_wake(at))
                {
                    self.poll_events(context);
                }
            }
            Event::Posted(post) => self.tell_events(
                engine_events::Input::Posted {
                    post,
                    failure: None,
                },
                context,
            ),
        }
        if self.delivered == self.total() && !self.reports_sent {
            self.reports_sent = true;
            self.report(context);
        }
        if self.done.is_none()
            && self.delivered == self.total()
            && self.caught_up()
            && self.trimmed()
            && self.reported == self.reports()
        {
            self.done = Some(self.snapshot().since(&self.baseline));
        }
    }

    fn check(&self) -> Result<(), String> {
        self.violation.clone().map_or(Ok(()), Err)
    }
}

/// Runs a scenario, and returns what it counted, with the graceful
/// restart's own work apart.
fn run(scenario: &'static Scenario) -> (Counts, Option<Counts>) {
    let disk = Rc::new(RefCell::new(Disk::new(Rng::from_seed(1), WALL_START)));
    let vfs = SimVfs::register(&format!("work-{}", scenario.name), disk, 1)
        .expect("a VFS name of its own");
    let mut run = Run::new(scenario, &vfs);
    let config = Config {
        seed: 1,
        duration: Duration::from_secs(300),
        max_steps: 10_000_000,
        wall_start: WALL_START,
        clock_steps: None,
        trace: false,
    };
    if let Err(failure) = simulation::run(&mut run, &config) {
        panic!("{}: {failure}", scenario.name);
    }
    let Some(done) = run.done.take() else {
        panic!(
            "{}: {} of {} recipients delivered by the end of the run",
            scenario.name,
            run.delivered,
            run.total()
        );
    };
    if scenario.restart.is_some() && run.restart.is_none() {
        panic!("{}: the restart never happened", scenario.name);
    }
    (done, run.restart.take())
}

/// The store's budget: every row it may write, for the work it
/// does. A delivery's row is written at its acceptance and twice for each
/// attempt (reservation and outcome), or once when it finishes unsent; the
/// journal gains an entry for each message accepted, each attempt ended and
/// each delivery finished unsent, and nothing else holds an attempt; a
/// message's counter is written as its deliveries finish, at most once for
/// each in a commit group; a policy change writes its record and the
/// revision.
fn budget(scenario: &Scenario, counts: &Counts) -> Vec<String> {
    let messages = scenario.messages as u64;
    let recipients = (scenario.messages * scenario.recipients) as u64;
    let attempts = counts.get("attempts");
    let commits = counts.get("commits");
    let unsent = counts.get("suppressed") + counts.get("cancelled");
    let policy = counts.get("policy changes");
    let allowed = BTreeMap::from([
        ("rows bodies inserted", messages),
        ("rows bodies deleted", messages),
        ("rows messages inserted", messages),
        ("rows messages updated", recipients),
        ("rows deliveries inserted", recipients),
        // A hold's parking and its release, once each.
        (
            "rows deliveries updated",
            2 * attempts + unsent + counts.get("parked") + counts.get("released"),
        ),
        (
            "rows journal inserted",
            messages + attempts + unsent + counts.get("reports"),
        ),
        ("rows highest_id updated", commits),
        ("rows policy inserted", policy),
        ("rows policy deleted", policy),
        ("rows policy_revision updated", policy),
        // The ledger's minute, once for each group that accepted.
        ("rows sent inserted", commits),
        ("rows sent updated", commits),
        (
            "rows suppressions inserted",
            counts.get("addresses suppressed") + counts.get("reports"),
        ),
        // Nothing for an event: the cursor moves once for each batch.
        ("rows cursors updated", counts.get("acknowledgements")),
        // An (egress, site)'s window, once for each group that reserved
        // from the egress.
        ("rows dispatched inserted", commits),
        ("rows dispatched updated", commits),
        // A report's row, its effect's record, its bounce's entry and its
        // suppression, and nothing for the rest of the mail.
        ("rows feedback inserted", counts.get("reports")),
        ("rows feedback_effects inserted", counts.get("reports")),
        // A site's cooldown, in the commit that began or grew it,
        // once it has ended, deleted once.
        ("rows cooldowns inserted", counts.get("cooldowns kept")),
        ("rows cooldowns updated", counts.get("cooldowns kept")),
        ("rows cooldowns deleted", counts.get("cooldowns kept")),
        // Once the feedback window passes, each row once.
        ("rows deliveries deleted", recipients),
        ("rows messages deleted", messages),
        ("rows journal deleted", messages + attempts + unsent),
    ]);
    let mut broken = Vec::new();
    for (name, &count) in &counts.0 {
        if !name.starts_with("rows ") {
            continue;
        }
        let limit = allowed.get(name.as_str()).copied().unwrap_or(0);
        if count > limit {
            broken.push(format!(
                "{}: {name} {count}, more than {limit}",
                scenario.name
            ));
        }
    }
    // A hold parks each recipient it covers once, and its lifting releases
    // each once.
    if scenario.paused.is_some() {
        for name in ["parked", "released"] {
            if counts.get(name) != recipients {
                broken.push(format!(
                    "{}: {name} {} for {recipients} recipients",
                    scenario.name,
                    counts.get(name)
                ));
            }
        }
    }
    // Each recipient's acceptance, reservation and outcome share their
    // commits with other work.
    if commits > recipients {
        broken.push(format!(
            "{}: {commits} commits for {recipients} recipients",
            scenario.name
        ));
    }
    // A scan reads a delivery at most once each time it comes due: once
    // after its acceptance, and once after each attempt that defers it.
    let scanned = counts.get("deliveries scanned");
    if scanned > recipients + attempts {
        broken.push(format!(
            "{}: {scanned} deliveries scanned for {recipients} recipients and {attempts} attempts",
            scenario.name
        ));
    }
    // One sync of the log for each commit, and two for each checkpoint:
    // before it copies the log, and when the log starts again.
    let syncs = counts.get("syncs of the log");
    let checkpoints = counts.get("syncs of the database");
    if syncs > commits + 2 * checkpoints {
        broken.push(format!(
            "{}: {syncs} syncs of the log for {commits} commits and {checkpoints} checkpoints",
            scenario.name
        ));
    }
    broken
}

/// Sets every count beside the last run's, and writes the report and the
/// counts for the next run to compare with.
#[allow(clippy::disallowed_methods)]
fn record(results: &[(&Scenario, Counts)]) {
    let directory = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let last_path = directory.join("work-counts.last");
    let previous: BTreeMap<String, u64> = std::fs::read_to_string(&last_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (name, count) = line.rsplit_once(' ')?;
            Some((name.to_owned(), count.parse().ok()?))
        })
        .collect();
    let (mut report, mut changes, mut last) = (String::new(), String::new(), String::new());
    for (scenario, counts) in results {
        let _ = writeln!(report, "{}: {}", scenario.name, scenario.summary);
        let recipients = (scenario.messages * scenario.recipients) as u64;
        for (name, &count) in &counts.0 {
            let key = format!("{} {name}", scenario.name);
            let was = match previous.get(&key) {
                Some(&was) if was == count => String::new(),
                Some(&was) => {
                    let _ = writeln!(changes, "  {key}: {was} -> {count}");
                    format!("  (was {was})")
                }
                None => "  (new)".to_owned(),
            };
            let _ = writeln!(
                report,
                "  {name:<40} {count:>12} {:>10.2} per recipient{was}",
                count as f64 / recipients as f64
            );
            let _ = writeln!(last, "{key} {count}");
        }
    }
    let changes = if previous.is_empty() {
        "no earlier run to compare with\n".to_owned()
    } else if changes.is_empty() {
        "no count changed since the last run\n".to_owned()
    } else {
        changes
    };
    std::fs::write(directory.join("work-counts.txt"), report).expect("the report is written");
    std::fs::write(directory.join("work-counts.changes"), changes)
        .expect("the changes are written");
    std::fs::write(last_path, last).expect("the counts are written");
}

#[test]
fn the_engine_does_no_more_work_than_its_budget() {
    let mut results = Vec::new();
    let mut broken = Vec::new();
    for scenario in &SCENARIOS {
        let (counts, restart) = run(scenario);
        broken.extend(budget(scenario, &counts));
        if let Some(restart) = &restart {
            // A graceful restart checkpoints the log, and writes no row.
            let rows: u64 = restart
                .0
                .iter()
                .filter(|(name, _)| name.starts_with("rows "))
                .map(|(_, &count)| count)
                .sum();
            if rows > 0 {
                broken.push(format!("{}: the restart wrote {rows} rows", scenario.name));
            }
        }
        results.push((scenario, counts));
    }
    // The counts are a regression signal only if a scenario replays to the
    // same counts.
    assert_eq!(
        run(&SCENARIOS[0]).0,
        results[0].1,
        "a scenario replays to the same counts"
    );
    record(&results);
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}
