//! The scheduler, in its first form: deliveries routed to the
//! receiver site their domain's exchanges make, reserved durably within a
//! limit per site, dispatched with their content in memory, their outcomes
//! recorded with retry timing, and expired when their time runs out.
//!
//! A domain's route is looked up once and kept for its time to live. Mail
//! queues per set of exchanges, and the domains that name the same ones
//! share their queue. The receiver rules say which site a set
//! of exchanges makes: a provider's, such as Google's, whose many sets of
//! exchanges share its limit, its budget and its cooldown, or else its own.
//! Deliveries of one message waiting together in a queue share one
//! transaction: one body sent, each recipient reserved and
//! recorded on its own. A site's limit counts transactions, and its queues
//! take turns at it. A receiver that refuses service for now cools down as
//! one site: its waiting deliveries stay as they are, no attempt
//! starts until the cooldown ends, and then one at a time until one is
//! delivered. No other site waits on it.
//!
//! Each delivery goes out from an egress: chosen as it is queued
//! for its site, from its configuration's pool, and kept by its reservation
//! from then on. New mail spreads by its message over the pool's egresses
//! with budget left for the site, so a warming egress takes its share until
//! its daily cap is spent, then waits for its window. A queue,
//! its connection limit and its cooldown are an (egress, site)'s, and a
//! held queue holds its mail: nothing moves to another egress to get around
//! a cooldown or a cap. With no egress in policy, mail goes out from the
//! host's own address, as one queue per site.
//!
//! A build with a dispatch hook has it decide each transaction's
//! recipients before their reservations: those it holds wait for their next
//! retry and those it rejects fail, with its reason, before any budget is
//! spent or body read. Those it lets proceed are reserved as any other, so
//! suppression and current authority still apply to them.
//!
//! A hold parks the mail it covers as its reservation is asked
//! for: the store marks it held in the reservation's commit and gives no
//! permit, and the window lets it go, so a paused tenant's backlog never
//! crowds out the rest. Lifting a hold, and every start, sends the
//! scheduler once through the held mail, in pages, releasing what no hold
//! covers any longer.
//!
//! It holds a bounded window of deliveries in memory, as Postfix's active
//! queue does, with a budget of bytes for their bodies: past it, a delivery
//! waits without its body and reads it back when it is due. The rest wait
//! in the store, where a periodic scan finds them: after a restart, after a
//! deferral, or when the window was full. Each scan resumes where the last
//! one stopped, so it never reads again what the window holds. The store
//! stays the one authority on each delivery's state; what the scheduler
//! holds is a cache of work to do.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::attempt::Evidence;
use engine_core::budget::{BUCKET, Signal, Window};
use engine_core::command::{
    Answer, Command, Commit, CooldownChange, Counted, DuePosition, Expire, Park, Postpone,
    RecordOutcome, Release, Request, Reservation, Reserve, Response, SiteCooldown,
};
use engine_core::component::{Component, Ticket};
use engine_core::delivery::{Delivery, DispatchPermit, Disposition, QueueState, Refusal};
use engine_core::hook::{Reason, dispatch};
use engine_core::id::{
    AttemptId, DeliveryId, EgressId, IdGenerator, IdentityId, MessageId, TenantId,
};
use engine_core::policy::{Egress, Policy, Sources};
use engine_core::retry::RetrySchedule;
use engine_core::rng::Rng;
use engine_core::time::{Monotonic, Now, Timestamp};
use engine_rules::{self as rules, Rules, Verdict};
pub use engine_smtp::route::{Route, Tls};

mod inspect;
pub use inspect::{Capped, Cooling, Hold, Inspection, QueueReport, Report};

/// Transactions a site may have under way for each connection its rules
/// allow: one being sent, and one waiting for the connection.
const TRANSACTIONS_PER_CONNECTION: usize = 2;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Recipients of one message that share a transaction at most.
    pub per_transaction: usize,
    /// Deliveries held in memory at most.
    pub window: usize,
    /// Bytes of message bodies held in memory at most, each body counted
    /// once however many deliveries share it.
    pub window_bytes: usize,
    /// How often the store is scanned for due and expiring deliveries.
    pub scan_every: Duration,
    /// Deliveries a scan reads beyond those already held.
    pub scan_page: usize,
    /// Retry timing, and the timing of a throttled site's cooldowns.
    pub retry: RetrySchedule,
    /// How long a domain's route is kept at most, whatever its records
    /// allow.
    pub route_ttl: Duration,
    /// Whether a dispatch hook decides each recipient before its
    /// reservation. Without one, nothing is asked.
    pub dispatch_hook: bool,
    /// Whether each outcome's end carries the receiver rules its reply
    /// matched, for a debug line: only while the shell writes those, as
    /// the names are copied for it.
    pub ended_rules: bool,
}

/// A delivery just accepted, with its message's content.
#[derive(Debug)]
pub struct Accepted {
    pub delivery: Delivery,
    pub content: Bytes,
}

/// What an attempt came to, as the transport saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempted {
    Delivered,
    Rejected,
    Deferred,
    /// The receiver refused service for now, or it was never tried because
    /// its site had: the site cools down, and it waits for the cooldown.
    Throttled,
    /// The attempt never reached the point where the receiver could accept
    /// the message.
    NotSent,
    /// The receiver may have accepted it, and its answer was lost.
    Uncertain,
    /// Capture mode took it in place of delivery.
    Captured,
}

#[derive(Debug)]
pub enum Input {
    Accepted(Vec<Accepted>),
    /// The commit owner's answer to a request the scheduler made.
    Answer(Response),
    /// What became of a dispatched attempt.
    Finished {
        permit: DispatchPermit,
        result: Attempted,
        /// What the receiver last said, if it said anything.
        evidence: Option<Evidence>,
        /// The receiver rules' verdict on what it said: a reply
        /// that throttles cools its site down whatever its code, and a
        /// rejection that rules the address out suppresses it.
        verdict: Option<Verdict>,
        /// A report of the attempt its transport already has, recorded with
        /// its outcome: the mailbox simulator's complaint.
        feedback: Option<Box<engine_core::feedback::Report>>,
        /// When the receiver replied, if `evidence` is its reply to this
        /// attempt, as its own transaction's or as the one reply of a
        /// session that refused it counted once: only such a reply counts
        /// toward warmup, never one another attempt or the
        /// session already gave, and on the day it came.
        replied: Option<Timestamp>,
    },
    /// Where a domain's mail goes, in answer to `Output::Resolve`, and for
    /// how long that holds.
    Resolved {
        domain: Box<str>,
        route: Route,
        ttl: Duration,
    },
    /// Policy at a new revision: the egresses mail goes out from, and their
    /// caps.
    Policy(Arc<Policy>),
    /// Asks where deliveries wait, or how the queues stand, for the
    /// operator: answered with `Output::Inspected` under the
    /// caller's ticket.
    Inspect {
        ticket: Ticket,
        inspection: Inspection,
    },
    /// A site refused a session from `egress` with a reply that throttles
    /// it, outside any attempt: it cools down for at least
    /// `minimum`, whether or not any of its mail was under way.
    SiteThrottled {
        site: rules::Site,
        egress: Option<EgressId>,
        reply: Option<Evidence>,
        minimum: Duration,
    },
    /// The dispatch hook's verdicts on `Output::Consult`'s recipients, one
    /// each, in order.
    Consulted {
        ticket: Ticket,
        verdicts: Vec<dispatch::Verdict>,
    },
    /// Stop starting attempts, before the engine stops.
    /// Transactions under way, and those whose reservations were asked for,
    /// finish and their outcomes are recorded; nothing new is scanned for
    /// or reserved, and mail accepted meanwhile waits in the store for the
    /// next start.
    Drain,
}

#[derive(Debug)]
pub enum Output {
    /// A request for the commit owner.
    Store(Request),
    /// Look up where this domain's mail goes (a lowercase domain), and
    /// answer with `Input::Resolved`.
    Resolve(Box<str>),
    /// Send this attempt: its reservation is durable.
    Dispatch(Dispatch),
    /// Ask the dispatch hook about these recipients, and answer with
    /// `Input::Consulted` under the ticket.
    Consult {
        ticket: Ticket,
        recipients: Vec<dispatch::Recipient>,
    },
    /// The answer to `Input::Inspect`, under its ticket.
    Inspected { ticket: Ticket, report: Report },
    /// An outcome recorded, whether an attempt's or one given without, for
    /// the shell's counts and logs.
    Ended(Ended),
}

/// An outcome the scheduler records: the attempt's, how it ended, where it
/// went, its message's tenant, and its reply's code and the receiver rules
/// it matched, if it had any. A delivery given no attempt went to no site.
#[derive(Debug)]
pub struct Ended {
    pub delivery: DeliveryId,
    pub attempt: AttemptId,
    pub result: Attempted,
    pub site: Option<rules::Site>,
    pub egress: Option<EgressId>,
    pub tenant: Option<TenantId>,
    pub code: Option<u16>,
    pub rules: Option<String>,
}

/// One transaction: a message to one or more of its recipients at one site,
/// each with the permit its reservation gave.
#[derive(Debug)]
pub struct Dispatch {
    pub message: MessageId,
    pub recipients: Vec<(DispatchPermit, Address)>,
    /// The receiver site, and the rules that apply there: its attempts
    /// from one egress share its connections.
    pub site: rules::Site,
    /// The queue it came from, which its exchanges make.
    pub queue: Arc<str>,
    /// The egress it goes out from, shared with policy: the host's own
    /// address when absent.
    pub egress: Option<Arc<Egress>>,
    /// The queue's exchanges, most preferred first.
    pub exchanges: Arc<[String]>,
    /// What its connections' TLS must prove.
    pub tls: Tls,
    /// The domain its mail is for, on a DANE route: a DANE-TA certificate
    /// may be valid for it rather than its exchange (RFC 7672, 3.2.2).
    pub next_hop: Option<Arc<str>>,
    /// The domain its return path is at, if not the installation's: its
    /// identity's MAIL FROM domain, while that is verified.
    pub return_domain: Option<Arc<str>>,
    pub content: Bytes,
}

#[derive(Debug)]
struct Item {
    delivery: Delivery,
    content: Option<Bytes>,
    /// When it was counted against its capped egress's budget, as it was
    /// taken for a transaction; refunded if no permit came of it.
    spent: Option<Timestamp>,
}

/// Where a queue's mail goes out from: an egress, or the host's own address.
type Source = Option<EgressId>;

/// A queue: mail from one source to one set of exchanges, by their name.
type Queue = (Source, Arc<str>);

/// A site, as one source sees it: its limit, its budget and its cooldown.
type SiteKey = (Source, Arc<str>);

/// Where a domain's mail goes: the exchanges it names, the queue they
/// make, and the site they belong to.
#[derive(Clone, Debug)]
struct Destination {
    /// The exchanges' name, sorted and joined, and what their TLS must
    /// prove: their queue's.
    queue: Arc<str>,
    /// Most preferred first.
    exchanges: Arc<[String]>,
    tls: Tls,
    /// Its domain, on a DANE route, whose queue is the domain's own: which
    /// names its exchanges' certificates may hold depends on the domain.
    next_hop: Option<Arc<str>>,
    site: rules::Site,
}

/// A queue's source and destination, which its transactions carry.
#[derive(Clone, Debug)]
struct Path {
    source: Source,
    destination: Destination,
}

impl Path {
    fn queue(&self) -> Queue {
        (self.source, Arc::clone(&self.destination.queue))
    }

    fn site(&self) -> SiteKey {
        (self.source, Arc::clone(self.destination.site.name()))
    }
}

/// Deliveries of one message taken together for one transaction, while
/// their reservations are made: its queue, the body it carries, how many
/// reservations are unanswered, and each one made, with its recipient and
/// its attempts so far.
#[derive(Debug)]
/// An attempt dispatched and not yet finished: its path, how many attempts
/// its delivery has had, its transaction, and its message's tenant.
#[derive(Clone)]
struct Flight {
    path: Path,
    attempts: u32,
    transaction: u64,
    tenant: Option<TenantId>,
}

struct Group {
    path: Path,
    message: MessageId,
    /// Its message's tenant and identity, which every recipient of a group
    /// shares.
    tenant: Option<TenantId>,
    identity: IdentityId,
    content: Bytes,
    unanswered: usize,
    reserved: Vec<(DispatchPermit, Address, u32)>,
}

/// What an outstanding request was for.
#[derive(Debug)]
enum Waiting {
    /// A scan for due deliveries, with the limit it asked for, and the
    /// scan's epoch when it was asked for.
    Due {
        limit: usize,
        epoch: u64,
    },
    Expiring,
    /// A group's body, read back, for its queue.
    Content(Path, Vec<Item>),
    /// The dispatch hook's verdicts on a group, before its body is read or
    /// its reservations made.
    Consult(Path, Vec<Item>),
    /// A reservation for a member of a group.
    Reserve(u64, Item),
    /// The reservation of a delivery given no attempt, from the egress it
    /// goes out from, recorded as the settlement says once it is held.
    Settle(Item, Settlement, Option<EgressId>),
    /// An outcome being recorded.
    Outcome(DeliveryId),
    Expire,
    /// The dispatch ledger's windows and the sites' cooldowns, as the
    /// scheduler starts.
    Dispatched,
    /// A cooldown being kept.
    Cool,
    /// A delivery a hold covers being parked, as it is to go out from the
    /// egress given, which waits in its queue again if the store finds no
    /// hold covers it.
    Park(Destination, Item, Option<EgressId>),
    /// A page of held mail, of at most this many, being read.
    Held(usize),
    /// A held delivery being released.
    Release(Delivery),
    /// A delivery its egress has no room for being put off.
    Postpone(Item),
}

/// What becomes of a delivery given no attempt.
#[derive(Clone, Debug)]
enum Settlement {
    /// Never to be delivered: its domain accepts no mail, or the dispatch
    /// hook rejected it, for the engine's reason.
    Rejected(Option<Evidence>),
    /// Not to be sent for now, for the engine's reason: its domain's lookup
    /// failed, its policy permits none of its exchanges, or the
    /// dispatch hook held it.
    Deferred(Evidence),
}

#[derive(Debug)]
enum Domain {
    /// Its route is being looked up, and these deliveries wait for it.
    Resolving(Vec<Item>),
    Routed {
        destination: Destination,
        until: Monotonic,
    },
}

/// A queue's deliveries, in line for their exchanges.
#[derive(Debug)]
struct Line {
    destination: Destination,
    ready: VecDeque<Item>,
}

/// A site, from one source: what its queues share.
#[derive(Debug)]
struct Site {
    limits: rules::Limits,
    /// Its queues, by name.
    queues: BTreeSet<Arc<str>>,
    /// The queue it last started a transaction from: its next round of
    /// dispatch begins after it, so its queues take turns.
    served: Option<Arc<str>>,
    /// Deliveries waiting in its queues.
    ready: usize,
    /// Transactions taken from its queues whose outcomes are not all
    /// recorded.
    active: usize,
    /// Set by a throttle, and cleared by the next delivered attempt once
    /// it has run out.
    cooldown: Option<Cooldown>,
}

#[derive(Debug)]
struct Cooldown {
    /// Throttles since the site last delivered.
    throttles: u32,
    /// No attempt starts before this, and then one at a time.
    until: Monotonic,
    /// The same moment on the wall clock, for deliveries deferred to it.
    until_wall: Timestamp,
    /// What the receiver said when it throttled.
    reply: Option<Evidence>,
    /// When it is forgotten, once it has run out with no probe delivered
    /// and nothing of its site is held: the retry schedule's longest
    /// interval after its end.
    forget_at: Monotonic,
}

/// Deliveries put off until a capped egress has room for them at a site,
/// counted by the bucket each comes due in, while that is to
/// come: the next one put off there waits behind them.
#[derive(Debug, Default)]
struct PutOff {
    due: BTreeMap<Timestamp, u64>,
    count: u64,
}

impl PutOff {
    /// How many are still to come at `now`, those come due forgotten.
    fn ahead(&mut self, now: Timestamp) -> u64 {
        let ahead = self
            .due
            .split_off(&Timestamp::from_micros(now.as_micros().saturating_add(1)));
        self.count -= self.due.values().sum::<u64>();
        self.due = ahead;
        self.count
    }

    /// How many are still to come at `now`, as `ahead` says, forgetting
    /// none.
    fn to_come(&self, now: Timestamp) -> u64 {
        self.due
            .range(Timestamp::from_micros(now.as_micros().saturating_add(1))..)
            .map(|(_, count)| count)
            .sum()
    }

    fn add(&mut self, until: Timestamp) {
        let micros = u64::try_from(BUCKET.as_micros()).unwrap_or(u64::MAX);
        let bucket = until.as_micros().div_ceil(micros).saturating_mul(micros);
        *self.due.entry(Timestamp::from_micros(bucket)).or_default() += 1;
        self.count += 1;
    }
}

impl Site {
    fn cooling(&self, now: Monotonic) -> bool {
        self.cooldown
            .as_ref()
            .is_some_and(|cooldown| cooldown.until > now)
    }

    /// Transactions it may have under way now.
    fn limit(&self, now: Monotonic) -> usize {
        match &self.cooldown {
            _ if self.cooling(now) => 0,
            // The cooldown is over: one probe at a time until one delivers.
            Some(_) => 1,
            None => self.limits.connections * TRANSACTIONS_PER_CONNECTION,
        }
    }

    /// Whether nothing keeps it: no queue, nothing under way, and no
    /// cooldown to remember. A cooldown that has run out, with no probe
    /// delivered since, is remembered until it is to be forgotten: mail
    /// that comes meanwhile probes one at a time, and a throttle backs off
    /// further.
    fn is_idle(&self, now: Monotonic) -> bool {
        self.queues.is_empty()
            && self.active == 0
            && self
                .cooldown
                .as_ref()
                .is_none_or(|cooldown| now >= cooldown.forget_at)
    }
}

pub struct Scheduler {
    config: Config,
    rules: Arc<Rules>,
    attempts: IdGenerator,
    rng: Rng,
    next_ticket: u64,
    domains: BTreeMap<Box<str>, Domain>,
    queues: BTreeMap<Queue, Line>,
    sites: BTreeMap<SiteKey, Site>,
    policy: Arc<Policy>,
    /// Whether policy has been given. Until it is, nothing is placed: the
    /// policy says where mail may go out from, and a scheduler
    /// without it would send pooled mail from the host's own address.
    policy_given: bool,
    /// Deliveries whose pool has no egress, that came before the first
    /// policy, or that could go out from a capped egress before the
    /// dispatch ledger is read, with their destination: they wait to be
    /// placed.
    unplaced: Vec<(Destination, Item)>,
    /// The dispatch ledger: each capped egress's reservations at each site,
    /// by the site's name, over the last 24 hours, counted as they are
    /// asked for. Until the store's windows are read, no capped egress
    /// dispatches.
    budgets: BTreeMap<(EgressId, Arc<str>), Window>,
    /// What each capped egress put off at each site until it has room.
    put_off: BTreeMap<(EgressId, Arc<str>), PutOff>,
    ledger_read: bool,
    /// Every delivery held in memory, waiting for its route, in a site's
    /// queue or under way, so a scan does not take it twice.
    held: BTreeSet<DeliveryId>,
    /// The bodies held deliveries keep, by message: each body's length and
    /// how many deliveries keep it.
    bodies: BTreeMap<MessageId, (usize, u32)>,
    body_bytes: usize,
    /// Where the next due scan resumes: just past the last delivery a scan
    /// took. `None` scans from the start.
    after: Option<DuePosition>,
    /// How often the due scan was started again from the start; a scan's
    /// answer moves `after` on only if none was since it was asked for.
    scan_epoch: u64,
    waiting: BTreeMap<Ticket, Waiting>,
    /// Attempts dispatched and not yet finished.
    flights: BTreeMap<DeliveryId, Flight>,
    /// Groups whose reservations are being made, by number.
    groups: BTreeMap<u64, Group>,
    /// Transactions dispatched, by their group's number: how many of their
    /// outcomes are unrecorded.
    transactions: BTreeMap<u64, usize>,
    next_group: u64,
    accepted: Vec<Accepted>,
    answers: VecDeque<Response>,
    finished: VecDeque<Finished>,
    throttled: VecDeque<(rules::Site, Option<EgressId>, Option<Evidence>, Duration)>,
    resolved: VecDeque<(Box<str>, Route, Duration)>,
    consulted: VecDeque<(Ticket, Vec<dispatch::Verdict>)>,
    inspections: VecDeque<(Ticket, Inspection)>,
    adopted: Option<Arc<Policy>>,
    next_scan: Option<Monotonic>,
    scanning: bool,
    /// Asked to drain (`Input::Drain`).
    draining: bool,
    /// Where the pass through held mail resumes, when a page of it is to
    /// be read: from the start, at each start and when a hold is lifted.
    release_from: Option<Option<DeliveryId>>,
    /// A page of held mail is being read, or its releases are being made:
    /// the next page waits for them.
    release_reading: bool,
    /// Releases asked for and not yet answered.
    releasing: usize,
    /// A hold was lifted during the pass, so another follows it.
    release_again: bool,
    failed: bool,
}

/// An attempt's end, as `Input::Finished` gives it.
type Finished = (
    DispatchPermit,
    Attempted,
    Option<Evidence>,
    Option<Verdict>,
    Option<Box<engine_core::feedback::Report>>,
    Option<Timestamp>,
);

impl Scheduler {
    /// `rules` says which site each set of exchanges makes, and its limits;
    /// `attempts` issues attempt IDs, resuming after the store's highest
    /// ID; `rng` jitters retries.
    pub fn new(config: Config, rules: Arc<Rules>, attempts: IdGenerator, rng: Rng) -> Self {
        Self {
            config,
            rules,
            attempts,
            rng,
            next_ticket: 0,
            domains: BTreeMap::new(),
            queues: BTreeMap::new(),
            sites: BTreeMap::new(),
            policy: Arc::default(),
            policy_given: false,
            unplaced: Vec::new(),
            budgets: BTreeMap::new(),
            put_off: BTreeMap::new(),
            ledger_read: false,
            held: BTreeSet::new(),
            bodies: BTreeMap::new(),
            body_bytes: 0,
            after: None,
            scan_epoch: 0,
            waiting: BTreeMap::new(),
            flights: BTreeMap::new(),
            groups: BTreeMap::new(),
            transactions: BTreeMap::new(),
            next_group: 0,
            accepted: Vec::new(),
            answers: VecDeque::new(),
            finished: VecDeque::new(),
            throttled: VecDeque::new(),
            resolved: VecDeque::new(),
            consulted: VecDeque::new(),
            inspections: VecDeque::new(),
            adopted: None,
            next_scan: None,
            scanning: false,
            draining: false,
            release_from: Some(None),
            release_reading: false,
            releasing: 0,
            release_again: false,
            failed: false,
        }
    }

    /// The store failed under it; it does nothing more until restarted.
    pub fn has_failed(&self) -> bool {
        self.failed
    }

    /// Whether, asked to drain, it has nothing left under way: every
    /// attempt it dispatched has its outcome recorded.
    pub fn is_drained(&self) -> bool {
        self.draining
            && self.flights.is_empty()
            && self.groups.is_empty()
            && self.finished.is_empty()
            && !self.waiting.values().any(|waiting| {
                matches!(
                    waiting,
                    Waiting::Reserve(..)
                        | Waiting::Content(..)
                        | Waiting::Consult(..)
                        | Waiting::Outcome(_)
                        | Waiting::Settle(..)
                        | Waiting::Expire
                        | Waiting::Cool
                        | Waiting::Park(..)
                        | Waiting::Release(_)
                )
            })
    }

    /// Deliveries held in memory.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Bytes of bodies held in memory.
    pub fn body_bytes(&self) -> usize {
        self.body_bytes
    }

    /// Counts a held delivery's body, unless it would pass the window's
    /// byte budget: then the delivery lets it go, and reads it again when it
    /// is due. A body another delivery already keeps costs nothing more.
    fn keep(&mut self, item: &mut Item) {
        let Some(content) = &item.content else {
            return;
        };
        let message = item.delivery.message();
        if let Some((_, keepers)) = self.bodies.get_mut(&message) {
            *keepers += 1;
        } else if self.body_bytes + content.len() > self.config.window_bytes {
            item.content = None;
        } else {
            self.body_bytes += content.len();
            self.bodies.insert(message, (content.len(), 1));
        }
    }

    /// The delivery lets go of its body, which is returned.
    fn let_go(&mut self, item: &mut Item) -> Option<Bytes> {
        let content = item.content.take()?;
        let message = item.delivery.message();
        if let Some((length, keepers)) = self.bodies.get_mut(&message) {
            *keepers -= 1;
            if *keepers == 0 {
                self.body_bytes -= *length;
                self.bodies.remove(&message);
            }
        }
        Some(content)
    }

    /// Queues a delivery for its exchanges, from the egress it goes out
    /// from. While its site cools down, a delivery waits without its body,
    /// which is read again when it is dispatched, so a backlog for a
    /// throttled receiver holds records, never bodies. A delivery whose
    /// pool has no egress waits for one, and so does any that comes before
    /// policy.
    fn wait(&mut self, now: Now, destination: Destination, item: Item, out: &mut Vec<Output>) {
        let placed = self.place(now.wall, destination.site.name(), &item.delivery);
        // Mail a hold covers is parked before it takes a place in a queue or
        // waits for one, whatever would keep it from dispatch.
        let egress = placed.unwrap_or_else(|| item.delivery.egress());
        if self.policy.holds_back(
            item.delivery.id(),
            item.delivery.account(),
            item.delivery.origin(),
            egress,
        ) {
            return self.park(now, destination, item, egress, out);
        }
        self.queue(now, destination, item, placed, out);
    }

    /// Queues a delivery from where it was `placed`, as `wait` does, but
    /// with no hold's check: none covers it. Mail its capped egress has no
    /// room for leaves memory until it has, so a spent budget never fills
    /// the window.
    fn queue(
        &mut self,
        now: Now,
        destination: Destination,
        item: Item,
        placed: Option<Source>,
        out: &mut Vec<Output>,
    ) {
        if let Some(Some(egress)) = placed
            && let Some(until) =
                self.room_later(now.wall, egress, destination.site.name(), &item.delivery)
        {
            return self.postpone(now, item, egress, until, out);
        }
        self.place_in(now, destination, item, placed);
    }

    /// Queues a delivery from where it was `placed`, or among the unplaced.
    fn place_in(
        &mut self,
        now: Now,
        destination: Destination,
        mut item: Item,
        placed: Option<Source>,
    ) {
        let Some(source) = placed else {
            self.let_go(&mut item);
            self.unplaced.push((destination, item));
            return;
        };
        let path = Path {
            source,
            destination,
        };
        let site = self.site(&path);
        site.ready += 1;
        if site.cooling(now.monotonic) {
            self.let_go(&mut item);
        }
        self.queues
            .entry(path.queue())
            .or_insert_with(|| Line {
                destination: path.destination,
                ready: VecDeque::new(),
            })
            .ready
            .push_back(item);
    }

    /// Notes a delivery the store parked: if no hold this policy holds
    /// covers it, the hold that did was lifted before the scheduler saw it,
    /// and a pass through the held mail releases it.
    fn parked(&mut self, delivery: &Delivery, egress: Option<EgressId>) {
        if self
            .policy
            .holds_back(delivery.id(), delivery.account(), delivery.origin(), egress)
        {
            return;
        }
        if self.release_reading || self.release_from.is_some() {
            self.release_again = true;
        } else {
            self.release_from = Some(None);
        }
    }

    /// When capped `egress` has room for `delivery` at `site`, if it has
    /// none now: its place behind what waits there and what was
    /// put off before it, as the reservations in its window leave it. Its
    /// expiry if that comes first, or if its cap there is nothing. Never
    /// further off than the retry schedule's longest wait, so a cap raised
    /// meanwhile, or room a refund made, is found by then.
    fn room_later(
        &mut self,
        now: Timestamp,
        egress: EgressId,
        site: &Arc<str>,
        delivery: &Delivery,
    ) -> Option<Timestamp> {
        let held = self.policy.egress(egress)?;
        let cap = held.caps.at(site)?;
        if !self.ledger_read {
            return None;
        }
        let waiting = self
            .sites
            .get(&(Some(egress), Arc::clone(site)))
            .map_or(0, |site| site.ready as u64);
        if self.budget(now, held, site) > waiting {
            return None;
        }
        let key = (egress, Arc::clone(site));
        let put_off = self.put_off.entry(key.clone()).or_default();
        let place = waiting + put_off.ahead(now);
        let room = match self.budgets.get(&key) {
            Some(window) => window.room_at(now, cap, place),
            None => Window::default().room_at(now, cap, place),
        };
        let expires = delivery.expires_at();
        let latest = now.saturating_add(self.config.retry.max());
        let until = match room.filter(|room| *room < expires) {
            Some(room) => room.min(latest),
            None => expires.min(latest),
        };
        put_off.add(until);
        Some(until)
    }

    /// Asks the store to put off a delivery capped `egress` has no room for
    /// until `until`, as it is to go out from that egress: it
    /// leaves memory, and is read back once due.
    fn postpone(
        &mut self,
        now: Now,
        mut item: Item,
        egress: EgressId,
        until: Timestamp,
        out: &mut Vec<Output>,
    ) {
        self.let_go(&mut item);
        let command = Command::Postpone(Postpone {
            delivery: item.delivery.id(),
            seen: item.delivery.generation(),
            egress: Some(egress),
            until,
            now: now.wall,
        });
        self.request(command, Waiting::Postpone(item), out);
    }

    /// Asks the store to park a delivery a hold covers, as it is to go out
    /// from `egress`: it leaves memory once parked, or waits in
    /// its queue again if the store finds no hold covers it.
    fn park(
        &mut self,
        now: Now,
        destination: Destination,
        mut item: Item,
        egress: Option<EgressId>,
        out: &mut Vec<Output>,
    ) {
        self.let_go(&mut item);
        let command = Command::Park(Park {
            delivery: item.delivery.id(),
            seen: item.delivery.generation(),
            egress,
            now: now.wall,
        });
        self.request(command, Waiting::Park(destination, item, egress), out);
    }

    /// The site `path` leads to, as its source sees it, with `path`'s queue
    /// among its own.
    fn site(&mut self, path: &Path) -> &mut Site {
        let site = self.sites.entry(path.site()).or_insert_with(|| Site {
            limits: path.destination.site.limits(),
            queues: BTreeSet::new(),
            served: None,
            ready: 0,
            active: 0,
            cooldown: None,
        });
        site.queues.insert(Arc::clone(&path.destination.queue));
        site
    }

    /// Where `delivery` goes out from to `site`: the egress it has, while
    /// it is one of its sources, else one spread by its message over those
    /// with budget left. `None` if its pool has no egress,
    /// before any policy is given, or before the ledger is read when one of
    /// its egresses is capped.
    fn place(&self, now: Timestamp, site: &str, delivery: &Delivery) -> Option<Source> {
        if !self.policy_given {
            return None;
        }
        let configuration = delivery.origin().configuration;
        let egresses = match self.policy.sources(delivery.account(), configuration) {
            Sources::Host => return Some(None),
            Sources::Egresses(egresses) => egresses,
        };
        if let Some(kept) = delivery.egress()
            && egresses.iter().any(|egress| egress.id == kept)
        {
            return Some(Some(kept));
        }
        // A capped egress's room is unknown until the ledger is read, so
        // mail that could go out from one waits for it.
        if !self.ledger_read && egresses.iter().any(|egress| egress.caps.any()) {
            return None;
        }
        let open: Vec<&Egress> = egresses
            .iter()
            .copied()
            .filter(|egress| self.room(now, egress, site) > 0)
            .collect();
        let among = if open.is_empty() { &egresses } else { &open };
        let index = spread(delivery.message(), site, among.len())?;
        Some(Some(among[index].id))
    }

    /// Deliveries `egress` may still take for `site` today: its cap, less
    /// what it reserved in the window and what waits in its queue. None for
    /// a capped egress until the store's windows are read.
    fn room(&self, now: Timestamp, egress: &Egress, site: &str) -> u64 {
        let queued = self
            .sites
            .get(&(Some(egress.id), Arc::from(site)))
            .map_or(0, |site| site.ready as u64);
        self.budget(now, egress, site).saturating_sub(queued)
    }

    /// Reservations `egress` may still make for `site` today.
    fn budget(&self, now: Timestamp, egress: &Egress, site: &str) -> u64 {
        let Some(cap) = egress.caps.at(site) else {
            return u64::MAX;
        };
        if !self.ledger_read {
            return 0;
        }
        let used = self
            .budgets
            .get(&(egress.id, Arc::from(site)))
            .map_or(0, |window| window.total(now));
        cap.saturating_sub(used)
    }

    /// Reservations a site may take now, as its egress's budget allows.
    fn site_budget(&self, now: Timestamp, site: &SiteKey) -> u64 {
        match site.0.and_then(|id| self.policy.egress(id)) {
            Some(egress) => self.budget(now, egress, &site.1),
            None => u64::MAX,
        }
    }

    /// Counts a delivery taken for a transaction against its egress's
    /// budget at its site: its reservation is asked for at once, or once
    /// its body is read back.
    fn spend(&mut self, now: Timestamp, site: &SiteKey) -> bool {
        let Some(egress) = site.0.filter(|egress| {
            self.policy
                .egress(*egress)
                .is_some_and(|held| held.caps.at(&site.1).is_some())
        }) else {
            return false;
        };
        self.budgets
            .entry((egress, Arc::clone(&site.1)))
            .or_default()
            .add(now);
        true
    }

    /// Takes back what `item` was counted against its egress's budget at
    /// `path`'s site when no permit came of it, which the store therefore
    /// never counted.
    fn refund(&mut self, path: &Path, item: &mut Item) {
        if let (Some(egress), Some(at)) = (path.source, item.spent.take())
            && let Some(window) = self
                .budgets
                .get_mut(&(egress, Arc::clone(path.destination.site.name())))
        {
            window.remove(at);
        }
    }

    /// Takes policy at a new revision. Deliveries that waited for an egress
    /// are placed again, and so are those queued at a source that is no
    /// longer one of theirs: the operator took their egress out of their
    /// pool, or gave or took away their configuration's pool.
    fn adopt(&mut self, now: Now, policy: Arc<Policy>, out: &mut Vec<Output>) {
        // A hold lifted, or lifted with what it named, or a fence that no
        // longer holds, starts a pass through the held mail, or
        // another once the one under way ends.
        let fencing = |policy: &Policy| policy.fence().is_some_and(|fence| !fence.discarding);
        let lifted = self
            .policy
            .holds()
            .any(|hold| policy.holds().all(|kept| kept.id != hold.id))
            || (fencing(&self.policy) && !fencing(&policy));
        if lifted {
            if self.release_reading || self.release_from.is_some() {
                self.release_again = true;
            } else {
                self.release_from = Some(None);
            }
        }
        self.policy = policy;
        self.policy_given = true;
        let mut replace = std::mem::take(&mut self.unplaced);
        let queues: Vec<Queue> = self.queues.keys().cloned().collect();
        for queue in queues {
            let Some(line) = self.queues.get_mut(&queue) else {
                continue;
            };
            // Placed again: what no longer goes out from its source. Parked
            // as it is to go out from it: what a hold now covers.
            let mut covered = VecDeque::new();
            let (gone, kept): (VecDeque<Item>, VecDeque<Item>) = std::mem::take(&mut line.ready)
                .into_iter()
                .filter_map(|item| {
                    let delivery = &item.delivery;
                    let held = self.policy.holds_back(
                        delivery.id(),
                        delivery.account(),
                        delivery.origin(),
                        queue.0,
                    );
                    if held {
                        covered.push_back(item);
                        return None;
                    }
                    Some(item)
                })
                .partition(|item| {
                    !self.policy.sends_from(
                        item.delivery.account(),
                        item.delivery.origin().configuration,
                        queue.0,
                    )
                });
            line.ready = kept;
            let path = Path {
                source: queue.0,
                destination: line.destination.clone(),
            };
            if let Some(site) = self.sites.get_mut(&path.site()) {
                site.ready -= gone.len() + covered.len();
            }
            replace.extend(
                gone.into_iter()
                    .map(|item| (path.destination.clone(), item)),
            );
            for item in covered {
                self.park(now, path.destination.clone(), item, queue.0, out);
            }
            self.forget_if_idle(&path);
        }
        for (destination, item) in replace {
            self.wait(now, destination, item, out);
        }
        self.put_off_past_caps(now, out);
    }

    /// Puts off what waits at a capped egress past what its cap now has
    /// room for, as mail placed there would be: a cap lowered
    /// leaves no more queued there than it takes, the newest put off first.
    fn put_off_past_caps(&mut self, now: Now, out: &mut Vec<Output>) {
        if !self.ledger_read {
            return;
        }
        let over: Vec<(SiteKey, usize)> = self
            .sites
            .iter()
            .filter_map(|(key, site)| {
                let budget = usize::try_from(self.site_budget(now.wall, key)).unwrap_or(usize::MAX);
                (key.0.is_some() && site.ready > budget).then(|| (key.clone(), site.ready - budget))
            })
            .collect();
        for (key, mut excess) in over {
            let (Some(egress), Some(site)) = (key.0, self.sites.get(&key)) else {
                continue;
            };
            let names: Vec<Arc<str>> = site.queues.iter().rev().cloned().collect();
            for name in names {
                while excess > 0 {
                    let Some(item) = self
                        .queues
                        .get_mut(&(key.0, Arc::clone(&name)))
                        .and_then(|line| line.ready.pop_back())
                    else {
                        break;
                    };
                    excess -= 1;
                    if let Some(site) = self.sites.get_mut(&key) {
                        site.ready -= 1;
                    }
                    match self.room_later(now.wall, egress, &key.1, &item.delivery) {
                        Some(until) => self.postpone(now, item, egress, until, out),
                        None => {
                            // Room after all: back where it was.
                            if let Some(line) = self.queues.get_mut(&(key.0, Arc::clone(&name))) {
                                line.ready.push_back(item);
                            }
                            if let Some(site) = self.sites.get_mut(&key) {
                                site.ready += 1;
                            }
                            excess = 0;
                        }
                    }
                }
                let emptied = self
                    .queues
                    .get(&(key.0, Arc::clone(&name)))
                    .filter(|line| line.ready.is_empty())
                    .map(|line| line.destination.clone());
                if let Some(destination) = emptied {
                    self.forget_if_idle(&Path {
                        source: key.0,
                        destination,
                    });
                }
            }
        }
    }

    /// Forgets `path`'s queue once nothing waits in it. Its site, once
    /// nothing keeps that, is forgotten as the scheduler polls.
    fn forget_if_idle(&mut self, path: &Path) {
        let queue = path.queue();
        if self
            .queues
            .get(&queue)
            .is_some_and(|line| line.ready.is_empty())
        {
            self.queues.remove(&queue);
            if let Some(site) = self.sites.get_mut(&path.site()) {
                site.queues.remove(&queue.1);
            }
        }
    }

    fn request(&mut self, command: Command, waiting: Waiting, out: &mut Vec<Output>) {
        let ticket = Ticket(self.next_ticket);
        self.next_ticket += 1;
        self.waiting.insert(ticket, waiting);
        out.push(Output::Store(Request { ticket, command }));
    }

    /// Queues a held delivery at its domain's site, looking its route up
    /// first when it is not known.
    fn enqueue(&mut self, now: Now, item: Item, out: &mut Vec<Output>) {
        let domain: Box<str> = item
            .delivery
            .recipient()
            .domain()
            .to_ascii_lowercase()
            .into();
        match self.domains.get_mut(&domain) {
            Some(Domain::Routed { destination, until }) if *until > now.monotonic => {
                let destination = destination.clone();
                self.wait(now, destination, item, out);
            }
            Some(Domain::Resolving(waiting)) => waiting.push(item),
            _ => {
                self.domains
                    .insert(domain.clone(), Domain::Resolving(vec![item]));
                out.push(Output::Resolve(domain));
            }
        }
    }

    fn resolved(
        &mut self,
        now: Now,
        domain: Box<str>,
        route: Route,
        ttl: Duration,
        out: &mut Vec<Output>,
    ) {
        // An answer for a domain no longer waiting is stale.
        let Some(Domain::Resolving(waiting)) = self.domains.remove(&domain) else {
            return;
        };
        // Draining, nothing new is reserved, settlements included: what
        // waited for the route waits in the store for the next start.
        if self.draining {
            for item in waiting {
                self.held.remove(&item.delivery.id());
            }
            return;
        }
        match route {
            Route::Exchanges(exchanges, tls) => {
                let set = rules::exchange_set(&exchanges);
                let (queue, next_hop) = if tls.dane {
                    let queue = format!("{set}{} {domain}", tls.suffix());
                    (queue, Some(Arc::from(&*domain)))
                } else {
                    (format!("{set}{}", tls.suffix()), None)
                };
                let destination = Destination {
                    queue: queue.into(),
                    site: self.rules.site(&exchanges),
                    exchanges: exchanges.into(),
                    tls,
                    next_hop,
                };
                let until = now.monotonic.saturating_add(ttl.min(self.config.route_ttl));
                if self.domains.len() >= self.config.window {
                    self.forget_routes(now.monotonic);
                }
                self.domains.insert(
                    domain,
                    Domain::Routed {
                        destination: destination.clone(),
                        until,
                    },
                );
                for item in waiting {
                    self.wait(now, destination.clone(), item, out);
                }
            }
            Route::Refused => {
                for item in waiting {
                    let egress = item.delivery.egress();
                    self.settle(now, item, Settlement::Rejected(None), egress, out);
                }
            }
            Route::Unresolved(reason) => {
                let evidence = Evidence::local(&reason);
                for item in waiting {
                    let settlement = Settlement::Deferred(evidence.clone());
                    let egress = item.delivery.egress();
                    self.settle(now, item, settlement, egress, out);
                }
            }
        }
    }

    /// Records the outcome of a delivery given no attempt, once it is
    /// reserved from `egress`, which a hold on it covers too. It is never
    /// sent, so its body is let go.
    fn settle(
        &mut self,
        now: Now,
        mut item: Item,
        settlement: Settlement,
        egress: Option<EgressId>,
        out: &mut Vec<Output>,
    ) {
        self.let_go(&mut item);
        let command = Command::Reserve(Reserve {
            delivery: item.delivery.id(),
            seen: item.delivery.generation(),
            attempt: AttemptId(self.attempts.next(now.wall)),
            egress,
            site: None,
            now: now.wall,
        });
        self.request(command, Waiting::Settle(item, settlement, egress), out);
    }

    /// Starts the due scan again from the start, past any scan already
    /// asked for.
    /// Routes are kept for as many domains as the window holds deliveries
    /// at most: those run out are forgotten, then any others
    /// until half are left, each looked up again when next needed. A domain
    /// being looked up keeps what waits for it.
    fn forget_routes(&mut self, now: Monotonic) {
        let mut over = self.domains.len().saturating_sub(self.config.window / 2);
        self.domains.retain(|_, domain| match domain {
            Domain::Routed { until, .. } if *until <= now => false,
            Domain::Routed { .. } if over > 0 => {
                over -= 1;
                false
            }
            _ => true,
        });
    }

    fn rescan(&mut self) {
        self.after = None;
        self.scan_epoch += 1;
    }

    /// The delivery is no longer held. Once every outcome of its
    /// transaction is recorded, its site may start another.
    fn release(&mut self, delivery: DeliveryId) {
        self.held.remove(&delivery);
        let Some(Flight {
            path, transaction, ..
        }) = self.flights.remove(&delivery)
        else {
            return;
        };
        if let Some(unrecorded) = self.transactions.get_mut(&transaction) {
            *unrecorded -= 1;
            if *unrecorded == 0 {
                self.transactions.remove(&transaction);
                self.end_transaction(&path);
            }
        }
    }

    /// A transaction from `path`'s queue is over, or never started.
    fn end_transaction(&mut self, path: &Path) {
        if let Some(site) = self.sites.get_mut(&path.site()) {
            site.active = site.active.saturating_sub(1);
        }
        // An idle site is forgotten, unless it is still cooling down.
        self.forget_if_idle(path);
    }

    /// Starts a group's transaction: its reservations, once its body is
    /// held, read back first if none of its members keeps it.
    fn start(&mut self, now: Now, path: Path, items: Vec<Item>, out: &mut Vec<Output>) {
        match items.iter().find_map(|item| item.content.clone()) {
            Some(content) => self.reserve(now, path, content, items, out),
            None => {
                let command = Command::Content(items[0].delivery.message());
                self.request(command, Waiting::Content(path, items), out);
            }
        }
    }

    /// Asks the dispatch hook about a group's members, before
    /// its body is read or its reservations made.
    fn consult(&mut self, path: Path, items: Vec<Item>, out: &mut Vec<Output>) {
        let site = path.destination.site.name();
        let recipients = items
            .iter()
            .map(|item| dispatch::Recipient {
                delivery: item.delivery.id(),
                message: item.delivery.message(),
                address: item.delivery.recipient().clone(),
                origin: *item.delivery.origin(),
                attempts: item.delivery.attempts(),
                site: Arc::clone(site),
                egress: path.source,
            })
            .collect();
        let ticket = Ticket(self.next_ticket);
        self.next_ticket += 1;
        self.waiting.insert(ticket, Waiting::Consult(path, items));
        out.push(Output::Consult { ticket, recipients });
    }

    /// The dispatch hook's verdicts on a group. Those it lets proceed start
    /// their transaction together; those it holds wait for their next
    /// retry, and those it rejects fail, each with its reason, no attempt
    /// and no budget spent.
    fn consulted(
        &mut self,
        now: Now,
        ticket: Ticket,
        verdicts: Vec<dispatch::Verdict>,
        out: &mut Vec<Output>,
    ) {
        if !matches!(self.waiting.get(&ticket), Some(Waiting::Consult(..))) {
            return;
        }
        let Some(Waiting::Consult(path, items)) = self.waiting.remove(&ticket) else {
            return;
        };
        // Draining, nothing new is reserved: the group waits in the store
        // for the next start.
        if self.draining {
            for mut item in items {
                self.refund(&path, &mut item);
                self.let_go(&mut item);
                self.held.remove(&item.delivery.id());
            }
            return self.end_transaction(&path);
        }
        let mut verdicts = verdicts.into_iter();
        let mut proceeding = Vec::with_capacity(items.len());
        for mut item in items {
            // The shell answers for every member; one it left out is held.
            let verdict = verdicts.next().unwrap_or_else(|| {
                dispatch::Verdict::Hold(Reason::new("the dispatch hook gave no verdict"))
            });
            let settlement = match verdict {
                dispatch::Verdict::Proceed => {
                    proceeding.push(item);
                    continue;
                }
                dispatch::Verdict::Hold(reason) => Settlement::Deferred(Evidence::held(&format!(
                    "held by the dispatch hook: {reason}"
                ))),
                dispatch::Verdict::Reject(reason) => Settlement::Rejected(Some(Evidence::local(
                    &format!("rejected by the dispatch hook: {reason}"),
                ))),
            };
            self.refund(&path, &mut item);
            self.settle(now, item, settlement, path.source, out);
        }
        if proceeding.is_empty() {
            self.end_transaction(&path);
        } else {
            self.start(now, path, proceeding, out);
        }
    }

    /// Reserves each member of a group, which carries `content` for them
    /// all.
    fn reserve(
        &mut self,
        now: Now,
        path: Path,
        content: Bytes,
        items: Vec<Item>,
        out: &mut Vec<Output>,
    ) {
        let number = self.next_group;
        self.next_group += 1;
        let (egress, site) = (path.source, Arc::clone(path.destination.site.name()));
        self.groups.insert(
            number,
            Group {
                path,
                message: items[0].delivery.message(),
                tenant: items[0].delivery.origin().tenant,
                identity: items[0].delivery.origin().identity,
                content,
                unanswered: items.len(),
                reserved: Vec::with_capacity(items.len()),
            },
        );
        for mut item in items {
            self.let_go(&mut item);
            let command = Command::Reserve(Reserve {
                delivery: item.delivery.id(),
                seen: item.delivery.generation(),
                attempt: AttemptId(self.attempts.next(now.wall)),
                egress,
                site: Some(Arc::clone(&site)),
                now: now.wall,
            });
            self.request(command, Waiting::Reserve(number, item), out);
        }
    }

    /// A member of group `number` has its reservation's answer. Once every
    /// member has one, the group is sent with those that have permits.
    fn reserved(
        &mut self,
        now: Now,
        number: u64,
        item: Item,
        commit: Commit<Reservation, Refusal>,
        out: &mut Vec<Output>,
    ) {
        let Some(group) = self.groups.get_mut(&number) else {
            self.failed = true;
            return;
        };
        match commit {
            Commit::Committed(Reservation::Permit(permit)) => group.reserved.push((
                permit,
                item.delivery.recipient().clone(),
                item.delivery.attempts() + 1,
            )),
            // Its recipient is suppressed, or its authority was withdrawn:
            // it finished without an attempt.
            Commit::Committed(Reservation::Suppressed | Reservation::Cancelled) => {
                self.held.remove(&item.delivery.id());
            }
            // A hold parked it, and the pass that releases it finds it in
            // the store.
            Commit::Committed(Reservation::Paused) => {
                self.held.remove(&item.delivery.id());
                let source = group.path.source;
                self.parked(&item.delivery, source);
            }
            // Placed under older policy: it is placed again under current
            // policy at once.
            Commit::Refused(Refusal::Unsourced) => self.enqueue(now, item, out),
            // Something changed the delivery since it was read (it expired,
            // or another attempt finished it): the store's state stands, and
            // a scan from the start finds it if it is due.
            Commit::Refused(_) => {
                self.rescan();
                self.held.remove(&item.delivery.id());
            }
            Commit::Unknown | Commit::Unavailable => {
                self.failed = true;
                return;
            }
        }
        let group = self.groups.get_mut(&number).expect("looked up above");
        group.unanswered -= 1;
        if group.unanswered == 0 {
            let group = self.groups.remove(&number).expect("looked up above");
            self.send(number, group, out, now.monotonic);
        }
    }

    /// Sends a group as one transaction once every reservation is answered,
    /// with the members whose reservations committed.
    fn send(&mut self, number: u64, group: Group, out: &mut Vec<Output>, now: Monotonic) {
        if group.reserved.is_empty() {
            return self.end_transaction(&group.path);
        }
        self.transactions.insert(number, group.reserved.len());
        let recipients: Vec<(DispatchPermit, Address)> = group
            .reserved
            .into_iter()
            .map(|(permit, recipient, attempts)| {
                let flight = Flight {
                    path: group.path.clone(),
                    attempts,
                    transaction: number,
                    tenant: group.tenant,
                };
                self.flights.insert(permit.delivery(), flight);
                (permit, recipient)
            })
            .collect();
        let egress = match group.path.source {
            None => None,
            Some(id) => match self.policy.shared_egress(id) {
                Some(egress) => Some(egress),
                // Removed since it was chosen: the attempts are not sent,
                // and go back to be placed again.
                None => {
                    for (permit, _) in recipients {
                        self.finished.push_back((
                            permit,
                            Attempted::NotSent,
                            None,
                            None,
                            None,
                            None,
                        ));
                    }
                    return;
                }
            },
        };
        // Its site began cooling down while its reservations were made: the
        // attempts are not sent, and wait for the cooldown's end.
        if self
            .sites
            .get(&group.path.site())
            .is_some_and(|site| site.cooling(now))
        {
            for (permit, _) in recipients {
                self.finished
                    .push_back((permit, Attempted::Throttled, None, None, None, None));
            }
            return;
        }
        let destination = group.path.destination;
        let return_domain = self
            .policy
            .identity(group.identity)
            .and_then(|identity| identity.return_domain())
            .cloned();
        out.push(Output::Dispatch(Dispatch {
            message: group.message,
            recipients,
            site: destination.site,
            queue: destination.queue,
            exchanges: destination.exchanges,
            tls: destination.tls,
            next_hop: destination.next_hop,
            egress,
            return_domain,
            content: group.content,
        }));
    }

    fn answer(&mut self, now: Now, response: Response, out: &mut Vec<Output>) {
        let Some(waiting) = self.waiting.remove(&response.ticket) else {
            return;
        };
        match (waiting, response.answer) {
            (Waiting::Reserve(number, mut item), Answer::Reserved(commit))
                if !matches!(
                    commit,
                    Commit::Committed(Reservation::Permit(_))
                        | Commit::Unknown
                        | Commit::Unavailable
                ) =>
            {
                // No permit came of it, so the store never counted it.
                if let Some(path) = self.groups.get(&number).map(|group| group.path.clone()) {
                    self.refund(&path, &mut item);
                }
                self.reserved(now, number, item, commit, out);
            }
            (Waiting::Reserve(number, item), Answer::Reserved(commit)) => {
                self.reserved(now, number, item, commit, out);
            }
            (Waiting::Due { limit, epoch }, Answer::Due(Ok(deliveries))) => {
                self.scanning = false;
                let full = deliveries.len() >= limit;
                // A scan started again since this one was asked for must
                // not be moved on past what it is to find again.
                let current = epoch == self.scan_epoch;
                for delivery in deliveries {
                    if self.held.len() >= self.config.window {
                        break;
                    }
                    // The next scan resumes past this one, which the window
                    // now holds, or held already as it was accepted.
                    if let QueueState::Ready { due_at } = delivery.state()
                        && current
                    {
                        self.after = Some(DuePosition {
                            due_at,
                            delivery: delivery.id(),
                        });
                    }
                    if self.held.insert(delivery.id()) {
                        let item = Item {
                            delivery,
                            content: None,
                            spent: None,
                        };
                        self.enqueue(now, item, out);
                    }
                }
                // A full page may have left due deliveries behind: scan
                // again as soon as the window has room.
                if full {
                    self.next_scan = Some(now.monotonic);
                }
            }
            (Waiting::Expiring, Answer::Expiring(Ok(deliveries))) => {
                for delivery in deliveries {
                    if !self.flights.contains_key(&delivery.id()) {
                        let command = Command::Expire(Expire {
                            delivery: delivery.id(),
                            now: now.wall,
                        });
                        self.request(command, Waiting::Expire, out);
                    }
                }
            }
            (Waiting::Content(path, items), Answer::Content(Ok(content))) => match content {
                Some(content) if !self.draining => self.reserve(now, path, content, items, out),
                // The message is gone, and whatever finished it stands; or
                // the scheduler is draining, and reserves nothing new.
                _ => {
                    for mut item in items {
                        self.refund(&path, &mut item);
                        self.held.remove(&item.delivery.id());
                    }
                    self.end_transaction(&path);
                }
            },
            (Waiting::Dispatched, Answer::Dispatched(Ok(ledger))) => {
                self.budgets = ledger
                    .windows
                    .into_iter()
                    .map(|(egress, site, window)| ((egress, site), window))
                    .collect();
                // A cooldown kept from before the start holds as it did:
                // its end is on the wall clock. One that
                // has run out with no probe delivered is remembered as it
                // would have been.
                let horizon = self.config.retry.max();
                for kept in ledger.cooldowns {
                    let forget = kept.until.saturating_add(horizon);
                    // One past its horizon is done with, and the store forgets it.
                    if forget <= now.wall {
                        let ended = CooldownChange::Ended {
                            egress: kept.egress,
                            site: kept.site,
                        };
                        self.request(Command::Cooldown(ended), Waiting::Cool, out);
                        continue;
                    }
                    let limits = self.rules.limits_of(&kept.site);
                    let site = self
                        .sites
                        .entry((kept.egress, Arc::clone(&kept.site)))
                        .or_insert_with(|| Site {
                            limits,
                            queues: BTreeSet::new(),
                            served: None,
                            ready: 0,
                            active: 0,
                            cooldown: None,
                        });
                    // Both deadlines count forward from now, so a monotonic
                    // clock that starts at the start never shortens or
                    // lengthens them; one already run out ends now.
                    let ahead = |at: Timestamp| {
                        now.monotonic
                            .saturating_add(at.saturating_duration_since(now.wall))
                    };
                    site.cooldown = Some(Cooldown {
                        throttles: kept.throttles,
                        until: ahead(kept.until),
                        until_wall: kept.until,
                        reply: kept.reply,
                        forget_at: ahead(forget),
                    });
                }
                self.ledger_read = true;
                // Mail that waited for the windows is placed with them.
                for (destination, item) in std::mem::take(&mut self.unplaced) {
                    self.wait(now, destination, item, out);
                }
            }
            (Waiting::Settle(item, settlement, egress), Answer::Reserved(commit)) => match commit {
                Commit::Committed(Reservation::Suppressed | Reservation::Cancelled) => {
                    self.release(item.delivery.id());
                }
                Commit::Committed(Reservation::Paused) => {
                    self.release(item.delivery.id());
                    self.parked(&item.delivery, egress);
                }
                Commit::Committed(Reservation::Permit(permit)) => {
                    let (disposition, evidence, result) = match settlement {
                        Settlement::Rejected(evidence) => {
                            (Disposition::Rejected, evidence, Attempted::Rejected)
                        }
                        Settlement::Deferred(evidence) => (
                            Disposition::Deferred {
                                not_before: self.retry(now.wall, item.delivery.attempts() + 1),
                            },
                            Some(evidence),
                            Attempted::Deferred,
                        ),
                    };
                    let delivery = permit.delivery();
                    out.push(Output::Ended(Ended {
                        delivery,
                        attempt: permit.attempt(),
                        result,
                        site: None,
                        egress,
                        tenant: item.delivery.origin().tenant,
                        code: evidence.as_ref().map(|evidence| evidence.code),
                        rules: evidence
                            .as_ref()
                            .filter(|evidence| {
                                self.config.ended_rules && !evidence.rules.is_empty()
                            })
                            .map(|evidence| evidence.rules.clone()),
                    }));
                    let command = Command::RecordOutcome(RecordOutcome {
                        permit,
                        disposition,
                        evidence,
                        suppress: false,
                        cooled: None,
                        feedback: None,
                        // No receiver was asked.
                        counted: None,
                        now: now.wall,
                    });
                    self.request(command, Waiting::Outcome(delivery), out);
                }
                Commit::Refused(_) => {
                    self.rescan();
                    self.release(item.delivery.id());
                }
                Commit::Unknown | Commit::Unavailable => self.failed = true,
            },
            (Waiting::Outcome(delivery), Answer::Recorded(commit)) => match commit {
                Commit::Committed(()) | Commit::Refused(_) => {
                    self.release(delivery);
                }
                Commit::Unknown | Commit::Unavailable => self.failed = true,
            },
            (Waiting::Expire, Answer::Expired(commit)) => {
                if matches!(commit, Commit::Unknown | Commit::Unavailable) {
                    self.failed = true;
                }
            }
            (Waiting::Cool, Answer::Cooled(commit)) => {
                if matches!(commit, Commit::Unknown | Commit::Unavailable) {
                    self.failed = true;
                }
            }
            (Waiting::Held(limit), Answer::Held(Ok(deliveries))) => {
                if deliveries.len() >= limit {
                    self.release_from = deliveries.last().map(|delivery| Some(delivery.id()));
                } else if std::mem::take(&mut self.release_again) {
                    self.release_from = Some(None);
                }
                for delivery in deliveries {
                    let covered = self.policy.holds_back(
                        delivery.id(),
                        delivery.account(),
                        delivery.origin(),
                        delivery.egress(),
                    );
                    if !covered {
                        let command = Command::Release(Release {
                            delivery: delivery.id(),
                            seen: delivery.generation(),
                        });
                        self.releasing += 1;
                        self.request(command, Waiting::Release(delivery), out);
                    }
                }
                // The next page waits for this one's releases.
                self.release_reading = self.releasing > 0;
            }
            (Waiting::Release(delivery), Answer::Released(commit)) => {
                self.releasing -= 1;
                self.release_reading = self.releasing > 0;
                // A hold lifted while the last page's releases were made
                // starts the pass that follows.
                if !self.release_reading
                    && self.release_from.is_none()
                    && std::mem::take(&mut self.release_again)
                {
                    self.release_from = Some(None);
                }
                match commit {
                    // Due when it was, it may be behind the due scan's place.
                    Commit::Committed(()) => self.rescan(),
                    // A hold in the store's policy covers it, which may be
                    // lifted before the scheduler sees it.
                    Commit::Refused(Refusal::Held) => self.parked(&delivery, delivery.egress()),
                    // It expired meanwhile, or another release came first.
                    Commit::Refused(_) => {}
                    Commit::Unknown | Commit::Unavailable => self.failed = true,
                }
            }
            (Waiting::Park(destination, item, egress), Answer::Parked(commit)) => match commit {
                Commit::Committed(()) => {
                    self.held.remove(&item.delivery.id());
                    self.parked(&item.delivery, egress);
                }
                // Its hold is lifted, as the scheduler's policy will soon say:
                // it queues as it would have, against the caps that hold now.
                Commit::Refused(Refusal::NotHeld) => {
                    let placed = self.place(now.wall, destination.site.name(), &item.delivery);
                    self.queue(now, destination, item, placed, out);
                }
                // Something changed it since it was read: the store's state
                // stands.
                Commit::Refused(_) => {
                    self.rescan();
                    self.held.remove(&item.delivery.id());
                }
                Commit::Unknown | Commit::Unavailable => self.failed = true,
            },
            (Waiting::Postpone(item), Answer::Postponed(commit)) => match commit {
                Commit::Committed(()) | Commit::Refused(Refusal::PastExpiry) => {
                    self.held.remove(&item.delivery.id());
                }
                // Something changed it since it was read: the store's state
                // stands.
                Commit::Refused(_) => {
                    self.rescan();
                    self.held.remove(&item.delivery.id());
                }
                Commit::Unknown | Commit::Unavailable => self.failed = true,
            },
            // Every other pairing is a read the store could not answer.
            _ => self.failed = true,
        }
    }

    fn outcome(&mut self, now: Now, finished: Finished, out: &mut Vec<Output>) {
        let (permit, result, evidence, verdict, feedback, replied) = finished;
        let Some(Flight {
            path,
            attempts,
            tenant,
            ..
        }) = self.flights.get(&permit.delivery()).cloned()
        else {
            return;
        };
        // A reply that throttles cools its site down whatever its code, at
        // least for the rule's minimum.
        let throttle = verdict.as_ref().and_then(|verdict| verdict.throttle);
        let mut cooled = None;
        let disposition = match result {
            Attempted::Delivered => {
                // A delivered probe ends a cooldown that has run out, and the
                // store forgets it; an attempt that was under way when the
                // site throttled shows nothing of whether it has recovered,
                // so it ends none.
                if let Some(site) = self.sites.get_mut(&path.site())
                    && !site.cooling(now.monotonic)
                    && site.cooldown.take().is_some()
                {
                    cooled = Some(CooldownChange::Ended {
                        egress: path.source,
                        site: Arc::clone(path.destination.site.name()),
                    });
                }
                Disposition::Delivered
            }
            Attempted::Captured => Disposition::Captured,
            Attempted::Rejected => {
                if let Some(minimum) = throttle {
                    cooled = self
                        .cool(now, &path, evidence.clone(), minimum)
                        .1
                        .map(CooldownChange::Kept);
                }
                Disposition::Rejected
            }
            Attempted::Throttled => {
                let minimum = throttle.unwrap_or_default();
                let (not_before, kept) = self.cool(now, &path, evidence.clone(), minimum);
                cooled = kept.map(CooldownChange::Kept);
                Disposition::Deferred { not_before }
            }
            Attempted::Deferred | Attempted::NotSent => Disposition::Deferred {
                not_before: self.retry(now.wall, attempts),
            },
            Attempted::Uncertain => Disposition::Uncertain {
                not_before: self.retry(now.wall, attempts),
            },
        };
        // A rejection whose reply rules the address out suppresses it.
        let suppress = matches!(disposition, Disposition::Rejected)
            && verdict.is_some_and(|verdict| verdict.rules_out_address);
        let counted = replied
            .and_then(|at| self.counted(&path, result, evidence.as_ref(), throttle.is_some(), at));
        let delivery = permit.delivery();
        out.push(Output::Ended(Ended {
            delivery,
            attempt: permit.attempt(),
            result,
            site: Some(path.destination.site.clone()),
            egress: path.source,
            tenant,
            code: evidence.as_ref().map(|evidence| evidence.code),
            rules: evidence
                .as_ref()
                .filter(|evidence| self.config.ended_rules && !evidence.rules.is_empty())
                .map(|evidence| evidence.rules.clone()),
        }));
        let command = Command::RecordOutcome(RecordOutcome {
            permit,
            disposition,
            evidence,
            suppress,
            cooled,
            feedback,
            counted,
            now: now.wall,
        });
        self.request(command, Waiting::Outcome(delivery), out);
    }

    /// What a receiver's reply to an attempt shows at its site, counted
    /// toward warmup at an egress capped there. The engine's own
    /// account, an uncertain attempt or a capture counts nothing.
    fn counted(
        &self,
        path: &Path,
        result: Attempted,
        evidence: Option<&Evidence>,
        throttles: bool,
        at: Timestamp,
    ) -> Option<Counted> {
        let site = path.destination.site.name();
        path.source
            .and_then(|egress| self.policy.egress(egress))
            .filter(|egress| egress.caps.at(site).is_some())?;
        let code = evidence
            .filter(|evidence| !evidence.is_local())
            .map(|evidence| evidence.code)?;
        let signal = match result {
            Attempted::Delivered => Signal::Delivered,
            Attempted::Captured | Attempted::Uncertain => return None,
            Attempted::Throttled => Signal::Throttled,
            _ if throttles => Signal::Throttled,
            Attempted::Rejected => Signal::Failed,
            // A session refused before any transaction: as its reply says.
            Attempted::NotSent if code >= 500 => Signal::Failed,
            Attempted::Deferred | Attempted::NotSent => Signal::Deferred,
        };
        Some(Counted {
            site: Arc::clone(site),
            signal,
            at,
        })
    }

    /// Ends the attempts that finished once the store had failed: not
    /// recorded, as nothing can be, but counted, as every outcome is.
    fn unrecorded(&mut self, out: &mut Vec<Output>) {
        while let Some((permit, result, evidence, ..)) = self.finished.pop_front() {
            let Some(flight) = self.flights.get(&permit.delivery()) else {
                continue;
            };
            out.push(Output::Ended(Ended {
                delivery: permit.delivery(),
                attempt: permit.attempt(),
                result,
                site: Some(flight.path.destination.site.clone()),
                egress: flight.path.source,
                tenant: flight.tenant,
                code: evidence.as_ref().map(|evidence| evidence.code),
                rules: None,
            }));
        }
    }

    /// Cools a throttled site down, for at least `minimum`, and returns
    /// when it may be tried again. Attempts already under way when it
    /// throttled come back throttled too, and one cooldown covers them all.
    fn cool(
        &mut self,
        now: Now,
        path: &Path,
        reply: Option<Evidence>,
        minimum: Duration,
    ) -> (Timestamp, Option<SiteCooldown>) {
        let limits = path.destination.site.limits();
        self.cool_site(now, path.site(), limits, reply, minimum)
    }

    /// Cools `key`'s site down, as `cool` does, whether or not anything of
    /// its is held: a refusal of a session may throttle a site with nothing
    /// queued (`Input::SiteThrottled`). Returns, with the cooldown's end,
    /// the cooldown for the store to keep when it began or grew.
    fn cool_site(
        &mut self,
        now: Now,
        key: SiteKey,
        limits: rules::Limits,
        reply: Option<Evidence>,
        minimum: Duration,
    ) -> (Timestamp, Option<SiteCooldown>) {
        let site = self.sites.entry(key.clone()).or_insert_with(|| Site {
            limits,
            queues: BTreeSet::new(),
            served: None,
            ready: 0,
            active: 0,
            cooldown: None,
        });
        if let Some(cooldown) = &mut site.cooldown
            && cooldown.until > now.monotonic
        {
            // A later reply's rule may ask for longer than the cooldown has
            // left: the monotonic clock decides, as it does for every live
            // timer, and the wall clock's deadline only grows.
            let at_least = now.monotonic.saturating_add(minimum);
            if at_least <= cooldown.until {
                return (cooldown.until_wall, None);
            }
            cooldown.until = at_least;
            cooldown.until_wall = cooldown.until_wall.max(now.wall.saturating_add(minimum));
            cooldown.forget_at = at_least.saturating_add(self.config.retry.max());
            return (cooldown.until_wall, Some(kept(&key, cooldown)));
        }
        let throttles = site
            .cooldown
            .as_ref()
            .map_or(0, |cooldown| cooldown.throttles)
            + 1;
        let until_wall = self
            .config
            .retry
            .not_before(now.wall, throttles, &mut self.rng)
            .max(now.wall.saturating_add(minimum));
        let until = now
            .monotonic
            .saturating_add(until_wall.saturating_duration_since(now.wall));
        let cooldown = site.cooldown.insert(Cooldown {
            throttles,
            until,
            until_wall,
            reply,
            forget_at: until.saturating_add(self.config.retry.max()),
        });
        let kept = kept(&key, cooldown);
        // Its waiting deliveries let their bodies go, in every queue.
        let queues: Vec<Arc<str>> = site.queues.iter().cloned().collect();
        for name in queues {
            let Some(mut ready) = self
                .queues
                .get_mut(&(key.0, name.clone()))
                .map(|line| std::mem::take(&mut line.ready))
            else {
                continue;
            };
            for item in &mut ready {
                self.let_go(item);
            }
            if let Some(line) = self.queues.get_mut(&(key.0, name)) {
                line.ready = ready;
            }
        }
        (until_wall, Some(kept))
    }

    /// The queue's next transaction, if its site's limit and its egress's
    /// budget allow another now: the delivery first in line, with the
    /// deliveries of its message just behind it, up to `per_transaction`.
    fn next_group(&mut self, now: Now, queue: &Queue) -> Option<(Path, Vec<Item>)> {
        // Nothing starts before the ledger is read, with the cooldowns a
        // restart keeps.
        if !self.ledger_read {
            return None;
        }
        let line = self.queues.get(queue)?;
        let path = Path {
            source: queue.0,
            destination: line.destination.clone(),
        };
        let key = path.site();
        let budget = self.site_budget(now.wall, &key);
        let site = self.sites.get(&key)?;
        if budget == 0 || site.active >= site.limit(now.monotonic) {
            return None;
        }
        let largest = usize::try_from(budget).map_or(self.config.per_transaction, |budget| {
            budget.min(self.config.per_transaction)
        });
        let line = self.queues.get_mut(queue)?;
        let first = line.ready.pop_front()?;
        let message = first.delivery.message();
        let mut group = vec![first];
        while group.len() < largest
            && line
                .ready
                .front()
                .is_some_and(|next| next.delivery.message() == message)
        {
            group.extend(line.ready.pop_front());
        }
        let site = self.sites.get_mut(&key)?;
        site.active += 1;
        site.ready -= group.len();
        Some((path, group))
    }

    fn retry(&mut self, now: Timestamp, attempts: u32) -> Timestamp {
        self.config.retry.not_before(now, attempts, &mut self.rng)
    }
}

/// `cooldown`, at `key`'s site, as the store keeps it.
fn kept(key: &SiteKey, cooldown: &Cooldown) -> SiteCooldown {
    SiteCooldown {
        egress: key.0,
        site: Arc::clone(&key.1),
        until: cooldown.until_wall,
        throttles: cooldown.throttles,
        reply: cooldown.reply.clone(),
    }
}

/// Which of `count` egresses a message's recipients at `site` go out from:
/// the same for all of them, and spread evenly over messages.
fn spread(message: MessageId, site: &str, count: usize) -> Option<usize> {
    if count == 0 {
        return None;
    }
    // FNV-1a over the message's ID and the site's name.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in message
        .0
        .as_u64()
        .to_be_bytes()
        .iter()
        .chain(site.as_bytes())
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    usize::try_from(hash % count as u64).ok()
}

impl Component for Scheduler {
    type Input = Input;
    type Output = Output;

    fn handle(&mut self, _now: Now, input: Input) {
        match input {
            Input::Accepted(accepted) => self.accepted.extend(accepted),
            Input::Answer(response) => self.answers.push_back(response),
            Input::Finished {
                permit,
                result,
                evidence,
                verdict,
                feedback,
                replied,
            } => self
                .finished
                .push_back((permit, result, evidence, verdict, feedback, replied)),
            Input::Resolved { domain, route, ttl } => {
                self.resolved.push_back((domain, route, ttl));
            }
            Input::Policy(policy) => self.adopted = Some(policy),
            Input::Consulted { ticket, verdicts } => self.consulted.push_back((ticket, verdicts)),
            Input::Inspect { ticket, inspection } => {
                self.inspections.push_back((ticket, inspection));
            }
            Input::Drain => self.draining = true,
            Input::SiteThrottled {
                site,
                egress,
                reply,
                minimum,
            } => self.throttled.push_back((site, egress, reply, minimum)),
        }
    }

    fn poll(&mut self, now: Now, out: &mut Vec<Output>) -> Option<Monotonic> {
        if self.failed {
            self.unrecorded(out);
            return None;
        }
        if let Some(policy) = self.adopted.take() {
            self.adopt(now, policy, out);
        }
        while let Some((ticket, inspection)) = self.inspections.pop_front() {
            let report = self.inspect(now, &inspection);
            out.push(Output::Inspected { ticket, report });
        }
        // Capped egresses wait for the store's windows.
        if !self.ledger_read
            && !self
                .waiting
                .values()
                .any(|waiting| matches!(waiting, Waiting::Dispatched))
        {
            self.request(Command::Dispatched, Waiting::Dispatched, out);
        }
        // A delivery accepted while the window is full waits in the store,
        // and a scan finds it, as one accepted while draining does at the
        // next start.
        let accepted = std::mem::take(&mut self.accepted);
        let draining = self.draining;
        for accepted in accepted.into_iter().filter(|_| !draining) {
            if self.held.len() < self.config.window && self.held.insert(accepted.delivery.id()) {
                let mut item = Item {
                    delivery: accepted.delivery,
                    content: Some(accepted.content),
                    spent: None,
                };
                self.keep(&mut item);
                self.enqueue(now, item, out);
            }
        }
        while let Some((domain, route, ttl)) = self.resolved.pop_front() {
            self.resolved(now, domain, route, ttl, out);
        }
        while let Some(response) = self.answers.pop_front() {
            self.answer(now, response, out);
            if self.failed {
                self.unrecorded(out);
                return None;
            }
        }
        while let Some((ticket, verdicts)) = self.consulted.pop_front() {
            self.consulted(now, ticket, verdicts, out);
        }
        while let Some((site, egress, reply, minimum)) = self.throttled.pop_front() {
            let key = (egress, Arc::clone(site.name()));
            if let (_, Some(kept)) = self.cool_site(now, key, site.limits(), reply, minimum) {
                let kept = CooldownChange::Kept(kept);
                self.request(Command::Cooldown(kept), Waiting::Cool, out);
            }
        }
        while let Some(finished) = self.finished.pop_front() {
            self.outcome(now, finished, out);
        }

        // Draining, the scheduler only finishes what is under way, and is
        // woken by its answers and outcomes.
        if self.draining {
            return None;
        }
        // The pass through held mail, a page at a time, once policy says
        // what is held.
        if self.policy_given
            && !self.release_reading
            && let Some(after) = self.release_from.take()
        {
            self.release_reading = true;
            let limit = self.config.scan_page;
            self.request(Command::Held { after, limit }, Waiting::Held(limit), out);
        }
        let next_scan = *self.next_scan.get_or_insert(now.monotonic);
        if now.monotonic >= next_scan && !self.scanning {
            self.next_scan = Some(now.monotonic.saturating_add(self.config.scan_every));
            // Routes past their time are forgotten; the next delivery for
            // such a domain looks it up again.
            self.domains.retain(|_, domain| match domain {
                Domain::Routed { until, .. } => *until > now.monotonic,
                Domain::Resolving(_) => true,
            });
            // And what was put off, once it has all come due.
            self.put_off
                .retain(|_, put_off| put_off.ahead(now.wall) > 0);
            if self.held.len() < self.config.window {
                // With nothing held, or a wall clock that stepped back, the
                // scan starts again from the beginning.
                if self.held.is_empty() || self.after.is_some_and(|after| after.due_at > now.wall) {
                    self.rescan();
                }
                self.scanning = true;
                let limit = self.config.scan_page;
                self.request(
                    Command::Due {
                        now: now.wall,
                        after: self.after,
                        limit,
                    },
                    Waiting::Due {
                        limit,
                        epoch: self.scan_epoch,
                    },
                    out,
                );
            }
            let limit = self.config.scan_page;
            self.request(
                Command::Expiring {
                    now: now.wall,
                    limit,
                },
                Waiting::Expiring,
                out,
            );
        }

        // A site that nothing keeps is forgotten: one a refused session
        // cooled down, with nothing of its queued, once its cooldown ends.
        // The store forgets the cooldown of a site forgotten with one.
        let idle: Vec<SiteKey> = self
            .sites
            .iter()
            .filter(|(_, site)| site.is_idle(now.monotonic))
            .map(|(key, _)| key.clone())
            .collect();
        for key in idle {
            if let Some(site) = self.sites.remove(&key)
                && site.cooldown.is_some()
            {
                let ended = CooldownChange::Ended {
                    egress: key.0,
                    site: key.1,
                };
                self.request(Command::Cooldown(ended), Waiting::Cool, out);
            }
        }
        // Each site starts what its limit allows, and none waits on another.
        // Its queues take turns: each round takes one transaction from each
        // of its queues that may start one, beginning after the queue it
        // served last.
        let sites: Vec<SiteKey> = self.sites.keys().cloned().collect();
        for key in sites {
            let Some(site) = self.sites.get(&key) else {
                continue;
            };
            let mut names: Vec<Arc<str>> = site.queues.iter().cloned().collect();
            if let Some(served) = &site.served {
                let after = names.partition_point(|name| name <= served);
                names.rotate_left(after);
            }
            loop {
                let mut started = false;
                for name in &names {
                    let Some((path, mut items)) = self.next_group(now, &(key.0, Arc::clone(name)))
                    else {
                        continue;
                    };
                    started = true;
                    if let Some(site) = self.sites.get_mut(&key) {
                        site.served = Some(Arc::clone(name));
                    }
                    for item in &mut items {
                        item.spent = self.spend(now.wall, &key).then_some(now.wall);
                    }
                    if self.config.dispatch_hook {
                        self.consult(path, items, out);
                    } else {
                        self.start(now, path, items, out);
                    }
                }
                if !started {
                    break;
                }
            }
        }
        // A site cooling down, or whose egress's budget is spent, with
        // deliveries waiting, wakes the scheduler when it may go on.
        let held = self
            .sites
            .iter()
            .filter(|(_, site)| site.ready > 0)
            .filter_map(|(key, site)| {
                let cooled = site.cooldown.as_ref().map(|cooldown| cooldown.until);
                let frees = (self.site_budget(now.wall, key) == 0)
                    .then(|| {
                        let egress = key.0?;
                        let window = self.budgets.get(&(egress, Arc::clone(&key.1)))?;
                        let at = window.frees_at(now.wall)?;
                        Some(
                            now.monotonic
                                .saturating_add(at.saturating_duration_since(now.wall)),
                        )
                    })
                    .flatten();
                cooled.into_iter().chain(frees).max()
            })
            .filter(|until| *until > now.monotonic)
            .min();
        match (self.next_scan, held) {
            (Some(scan), Some(held)) => Some(scan.min(held)),
            (scan, held) => scan.or(held),
        }
    }
}

#[cfg(test)]
mod tests {
    use engine_core::command::DispatchLedger;
    use engine_core::id::{
        AccountId, ConfigurationId, HoldId, Id, IdentityId, Lane, MessageId, PoolId, Shard,
    };
    use engine_core::policy::{Change, Origin, Target};

    use super::*;

    /// When a test's receiver replied.
    const REPLIED: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);

    fn config() -> Config {
        Config {
            per_transaction: 50,
            window: 4,
            window_bytes: 1 << 20,
            scan_every: Duration::from_secs(1),
            scan_page: 10,
            retry: RetrySchedule::new(Duration::from_secs(60), Duration::from_secs(3600)).unwrap(),
            route_ttl: Duration::from_secs(300),
            dispatch_hook: false,
            ended_rules: true,
        }
    }

    fn at(millis: u64) -> Now {
        Now {
            wall: Timestamp::from_micros(1_800_000_000_000_000 + millis * 1000),
            monotonic: Monotonic::from_micros(millis * 1000),
        }
    }

    /// A scheduler given an empty policy, as the shell gives the store's
    /// at its start, and an empty dispatch ledger.
    fn scheduler() -> Scheduler {
        let mut scheduler = unadopted();
        scheduler.handle(at(0), Input::Policy(Arc::default()));
        scheduler
    }

    /// The receiver rules, with one connection to each site that no
    /// provider claims: two transactions under way.
    fn rules() -> Arc<Rules> {
        let overrides = BTreeMap::from([(
            rules::DEFAULTS.to_owned(),
            rules::Entry {
                connections: Some(1),
                ..rules::Entry::default()
            },
        )]);
        Arc::new(Rules::new(&overrides).unwrap())
    }

    fn unadopted() -> Scheduler {
        let attempts = IdGenerator::new(Shard::new(0), Lane::new(1).unwrap(), None);
        Scheduler::new(config(), rules(), attempts, Rng::from_seed(7))
    }

    fn origin() -> Origin {
        Origin {
            identity: IdentityId(Id::from_u64(2).unwrap()),
            tenant: Some(TenantId(Id::from_u64(3).unwrap())),
            configuration: None,
        }
    }

    fn delivery(n: u64, recipient: &str) -> Delivery {
        let id = |value: u64| Id::from_u64(value).unwrap();
        Delivery::new(
            DeliveryId(id(id_base() + n)),
            MessageId(id(id_base() + 1000 + n)),
            AccountId(id(1)),
            origin(),
            Address::parse(recipient).unwrap(),
            at(0).wall,
            at(0).wall.saturating_add(Duration::from_secs(86_400)),
        )
        .unwrap()
    }

    fn id_base() -> u64 {
        1 << 40
    }

    fn accepted(delivery: Delivery) -> Accepted {
        Accepted {
            delivery,
            content: Bytes::from_static(b"content"),
        }
    }

    /// Polls, answering every route lookup as `exchange` says and the read
    /// of the dispatch ledger with an empty one, and returns everything else
    /// the scheduler asked for.
    fn poll_routed(
        scheduler: &mut Scheduler,
        now: Now,
        exchange: impl Fn(&str) -> Route,
    ) -> Vec<Output> {
        poll_with(scheduler, now, &exchange, Some(&DispatchLedger::default()))
    }

    /// As `poll_routed`, answering the ledger's read with `ledger`, or
    /// leaving it among what is returned when there is none.
    fn poll_with(
        scheduler: &mut Scheduler,
        now: Now,
        exchange: &impl Fn(&str) -> Route,
        ledger: Option<&DispatchLedger>,
    ) -> Vec<Output> {
        let mut out = Vec::new();
        scheduler.poll(now, &mut out);
        let mut rest = Vec::new();
        let mut answered = false;
        for output in out {
            match output {
                Output::Resolve(domain) => {
                    let route = exchange(&domain);
                    scheduler.handle(
                        now,
                        Input::Resolved {
                            domain,
                            route,
                            ttl: Duration::from_secs(3600),
                        },
                    );
                    answered = true;
                }
                Output::Store(Request {
                    ticket,
                    command: Command::Dispatched,
                }) if ledger.is_some() => {
                    let answer = Answer::Dispatched(Ok(ledger.cloned().unwrap_or_default()));
                    scheduler.handle(now, Input::Answer(Response { ticket, answer }));
                    answered = true;
                }
                other => rest.push(other),
            }
        }
        if answered {
            rest.extend(poll_with(scheduler, now, exchange, ledger));
        }
        rest
    }

    /// Every domain is its own site.
    fn poll(scheduler: &mut Scheduler, now: Now) -> Vec<Output> {
        poll_routed(scheduler, now, |domain| {
            Route::Exchanges(vec![format!("mx.{domain}")], Tls::default())
        })
    }

    /// The reservations among `outputs`, answered as the store would.
    fn reserve_all(
        outputs: &[Output],
        deliveries: &mut BTreeMap<DeliveryId, Delivery>,
    ) -> Vec<Response> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Reserve(reserve),
                }) => {
                    let delivery = deliveries.get_mut(&reserve.delivery).unwrap();
                    let permit = delivery
                        .reserve(reserve.seen, reserve.attempt, reserve.egress, reserve.now)
                        .unwrap();
                    Some(Response {
                        ticket: *ticket,
                        answer: Answer::Reserved(Commit::Committed(Reservation::Permit(permit))),
                    })
                }
                _ => None,
            })
            .collect()
    }

    fn reserved(outputs: &[Output]) -> Vec<DeliveryId> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Reserve(reserve),
                    ..
                }) => Some(reserve.delivery),
                _ => None,
            })
            .collect()
    }

    /// The permit of a dispatch to one recipient.
    fn permit(dispatch: Dispatch) -> DispatchPermit {
        let mut recipients = dispatch.recipients.into_iter();
        let (permit, _) = recipients.next().expect("a recipient");
        assert!(recipients.next().is_none(), "one recipient");
        permit
    }

    fn dispatches(outputs: Vec<Output>) -> Vec<Dispatch> {
        outputs
            .into_iter()
            .filter_map(|output| match output {
                Output::Dispatch(dispatch) => Some(dispatch),
                _ => None,
            })
            .collect()
    }

    fn outcomes(outputs: &[Output]) -> Vec<(Ticket, &RecordOutcome)> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::RecordOutcome(outcome),
                }) => Some((*ticket, outcome)),
                _ => None,
            })
            .collect()
    }

    fn recorded(ticket: Ticket) -> Input {
        Input::Answer(Response {
            ticket,
            answer: Answer::Recorded(Commit::Committed(())),
        })
    }

    /// Accepts the deliveries, and dispatches what the scheduler reserves.
    fn dispatch_accepted(
        scheduler: &mut Scheduler,
        store: &mut BTreeMap<DeliveryId, Delivery>,
        now: Now,
        deliveries: Vec<Delivery>,
        exchange: impl Fn(&str) -> Route + Copy,
    ) -> Vec<Dispatch> {
        let batch = deliveries
            .into_iter()
            .map(|delivery| {
                store.insert(delivery.id(), delivery.clone());
                accepted(delivery)
            })
            .collect();
        scheduler.handle(now, Input::Accepted(batch));
        let out = poll_routed(scheduler, now, exchange);
        for response in reserve_all(&out, store) {
            scheduler.handle(now, Input::Answer(response));
        }
        dispatches(poll_routed(scheduler, now, exchange))
    }

    const ACCOUNT: AccountId = AccountId(Id::from_u64(1).unwrap());
    const POOLED: ConfigurationId = ConfigurationId(Id::from_u64(3).unwrap());

    /// A policy whose configuration sends from a pool of these egresses:
    /// each an ID and its daily cap.
    fn pooled(egresses: &[(u64, Option<u64>)]) -> Arc<Policy> {
        let mut policy = Policy::default();
        let changes = [
            Change::Pool {
                id: PoolId(Id::from_u64(4).unwrap()),
                account: ACCOUNT,
                name: "warm".to_owned(),
            },
            Change::Configuration {
                id: POOLED,
                account: ACCOUNT,
                name: "receipts".to_owned(),
                pool: Some("warm".to_owned()),
            },
        ];
        for change in changes {
            policy.apply(change).unwrap();
        }
        for &(id, daily_cap) in egresses {
            policy
                .apply(Change::Egress {
                    id: EgressId(Id::from_u64(id).unwrap()),
                    account: ACCOUNT,
                    address: format!("203.0.113.{id}").parse().unwrap(),
                    helo: format!("mta{id}.bench.test"),
                    pool: Some("warm".to_owned()),
                    daily_cap,
                })
                .unwrap();
        }
        Arc::new(policy)
    }

    fn egress(id: u64) -> EgressId {
        EgressId(Id::from_u64(id).unwrap())
    }

    /// Recipient `n` of message `message`, sent under the pooled
    /// configuration.
    fn of(message: u64, n: u64, recipient: &str) -> Delivery {
        let id = |value: u64| Id::from_u64(value).unwrap();
        Delivery::new(
            DeliveryId(id(id_base() + n)),
            MessageId(id(id_base() + 1000 + message)),
            ACCOUNT,
            Origin {
                configuration: Some(POOLED),
                ..origin()
            },
            Address::parse(recipient).unwrap(),
            at(0).wall,
            at(0).wall.saturating_add(Duration::from_secs(86_400)),
        )
        .unwrap()
    }

    /// A scheduler under `policy`, whose read of the dispatch ledger is
    /// answered with no windows.
    fn under(policy: Arc<Policy>) -> Scheduler {
        let mut scheduler = scheduler();
        scheduler.handle(at(0), Input::Policy(policy));
        let mut out = Vec::new();
        scheduler.poll(at(0), &mut out);
        for output in out {
            if let Output::Store(Request {
                ticket,
                command: Command::Dispatched,
            }) = output
            {
                let answer = Answer::Dispatched(Ok(DispatchLedger::default()));
                scheduler.handle(at(0), Input::Answer(Response { ticket, answer }));
            }
        }
        scheduler
    }

    fn sink(_: &str) -> Route {
        Route::Exchanges(vec!["mx.sink.test".to_owned()], Tls::default())
    }

    fn sent_from(dispatch: &Dispatch) -> Option<EgressId> {
        dispatch.egress.as_ref().map(|egress| egress.id)
    }

    #[test]
    fn a_messages_recipients_share_an_egress_which_a_retry_keeps() {
        let mut scheduler = under(pooled(&[(10, None), (11, None)]));
        let mut store = BTreeMap::new();
        let deliveries = vec![of(1, 1, "a@sink.test"), of(1, 2, "b@sink.test")];
        let dispatched = dispatch_accepted(&mut scheduler, &mut store, at(0), deliveries, sink);
        assert_eq!(dispatched.len(), 1, "one transaction");
        assert_eq!(dispatched[0].recipients.len(), 2);
        let chosen = sent_from(&dispatched[0]).expect("an egress of the pool");
        let from = dispatched[0].egress.as_ref().unwrap();
        assert_eq!(from.helo, format!("mta{}.bench.test", chosen.0.as_u64()));
        for delivery in store.values() {
            assert_eq!(delivery.egress(), Some(chosen), "the reservation keeps it");
        }

        // A delivery that went out from the other egress before goes out
        // from it again, whichever its message would spread to.
        let other = if chosen == egress(10) { 11 } else { 10 };
        let mut kept = of(2, 3, "c@sink.test");
        let permit = kept
            .reserve(
                kept.generation(),
                AttemptId(Id::from_u64(1 << 41).unwrap()),
                Some(egress(other)),
                at(0).wall,
            )
            .unwrap();
        kept.record_outcome(
            permit,
            Disposition::Deferred {
                not_before: at(0).wall,
            },
            at(0).wall,
        )
        .unwrap();
        let dispatched = dispatch_accepted(&mut scheduler, &mut store, at(1), vec![kept], sink);
        assert_eq!(sent_from(&dispatched[0]), Some(egress(other)));
    }

    #[test]
    fn a_warming_egress_takes_its_cap_and_the_rest_goes_to_the_others() {
        let mut scheduler = under(pooled(&[(10, Some(1)), (11, None)]));
        let mut store = BTreeMap::new();
        let deliveries = (1..=4)
            .map(|n| of(n, n, &format!("r{n}@sink.test")))
            .collect();
        let dispatched = dispatch_accepted(&mut scheduler, &mut store, at(0), deliveries, sink);
        assert_eq!(
            dispatched.len(),
            3,
            "two at a time from each egress to the site"
        );
        let from_warming = store
            .values()
            .filter(|delivery| delivery.egress() == Some(egress(10)))
            .count();
        assert!(
            from_warming <= 1,
            "{from_warming} from an egress capped at 1"
        );
    }

    #[test]
    fn mail_a_spent_budget_holds_back_is_put_off_until_there_is_room_and_never_fills_the_window() {
        let site: Arc<str> = Arc::from("mx.sink.test");
        // The egress may send two a day at the site, and sent both just
        // under a day ago: it has room again in twenty minutes.
        let mut window = Window::default();
        let sent = at(0).wall.saturating_sub(Duration::from_secs(86_400 - 600));
        window.add(sent);
        window.add(sent);
        let ledger = DispatchLedger {
            windows: vec![(egress(10), Arc::clone(&site), window.clone())],
            cooldowns: Vec::new(),
        };
        let room = window.room_at(at(0).wall, 2, 0).unwrap();
        assert_eq!(room, at(1_200_000).wall);
        let mut scheduler = unadopted();
        scheduler.handle(at(0), Input::Policy(pooled(&[(10, Some(2))])));
        // As many as the window holds, accepted at once.
        let deliveries: Vec<Delivery> = (1..=4)
            .map(|n| of(n, n, &format!("r{n}@sink.test")))
            .collect();
        scheduler.handle(
            at(0),
            Input::Accepted(deliveries.iter().cloned().map(accepted).collect()),
        );
        let out = poll_with(&mut scheduler, at(0), &sink, Some(&ledger));
        assert!(reserved(&out).is_empty());
        let postponed: Vec<(Ticket, Postpone)> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Postpone(postpone),
                }) => Some((*ticket, *postpone)),
                _ => None,
            })
            .collect();
        // Two in line for the room, and two the egress has no room for
        // before they expire, put off the retry schedule's longest wait, to
        // be weighed again then.
        let longest = at(0).wall.saturating_add(Duration::from_secs(3600));
        let mut until: Vec<Timestamp> = postponed.iter().map(|(_, put)| put.until).collect();
        until.sort();
        assert_eq!(until, [room, room, longest, longest]);
        assert!(
            postponed
                .iter()
                .all(|(_, put)| put.egress == Some(egress(10))),
            "each keeps its egress"
        );
        assert_eq!(scheduler.body_bytes(), 0, "their bodies are let go");
        for (ticket, _) in &postponed {
            scheduler.handle(
                at(0),
                Input::Answer(Response {
                    ticket: *ticket,
                    answer: Answer::Postponed(Commit::Committed(())),
                }),
            );
        }
        poll_with(&mut scheduler, at(0), &sink, Some(&ledger));
        assert_eq!(scheduler.held(), 0, "the window is free for other mail");

        // Read back once due, there is room for it: it goes, from its egress.
        let put = postponed
            .iter()
            .find(|(_, put)| put.until == room)
            .map(|(_, put)| *put)
            .unwrap();
        let mut back = deliveries
            .iter()
            .find(|delivery| delivery.id() == put.delivery)
            .unwrap()
            .clone();
        back.postpone(back.generation(), put.egress, put.until, at(0).wall)
            .unwrap();
        let out = poll_with(&mut scheduler, at(1_200_000), &sink, Some(&ledger));
        let ticket = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Due { .. },
                }) => Some(*ticket),
                _ => None,
            })
            .expect("a scan, the window having room");
        scheduler.handle(
            at(1_200_000),
            Input::Answer(Response {
                ticket,
                answer: Answer::Due(Ok(vec![back.clone()])),
            }),
        );
        let out = poll_with(&mut scheduler, at(1_200_000), &sink, Some(&ledger));
        let read = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Content(_),
                }) => Some(*ticket),
                _ => None,
            })
            .expect("its body read back");
        scheduler.handle(
            at(1_200_000),
            Input::Answer(Response {
                ticket: read,
                answer: Answer::Content(Ok(Some(Bytes::from_static(b"content")))),
            }),
        );
        let out = poll_with(&mut scheduler, at(1_200_000), &sink, Some(&ledger));
        let reservations: Vec<&Reserve> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Reserve(reserve),
                    ..
                }) => Some(reserve),
                _ => None,
            })
            .collect();
        assert_eq!(
            reservations
                .iter()
                .map(|reserve| (reserve.delivery, reserve.egress))
                .collect::<Vec<_>>(),
            [(back.id(), Some(egress(10)))]
        );
    }

    #[test]
    fn a_sites_own_cap_binds_there_and_its_outcomes_name_what_the_receiver_said() {
        let mut policy = Arc::unwrap_or_clone(pooled(&[(10, Some(1))]));
        policy
            .apply(Change::Cap {
                account: ACCOUNT,
                address: "203.0.113.10".parse().unwrap(),
                site: Some("mx.sink.test".to_owned()),
                cap: Some(3),
            })
            .unwrap();
        let mut scheduler = under(Arc::new(policy));
        let mut store = BTreeMap::new();
        // Two messages of two recipients: two transactions, the site's
        // concurrency, with four recipients the site's cap holds to three.
        let deliveries = (1..=4)
            .map(|n: u64| of(n.div_ceil(2), n, &format!("r{n}@sink.test")))
            .collect();
        let dispatched = dispatch_accepted(&mut scheduler, &mut store, at(0), deliveries, sink);
        let recipients: Vec<DispatchPermit> = dispatched
            .into_iter()
            .flat_map(|dispatch| dispatch.recipients)
            .map(|(permit, _)| permit)
            .collect();
        assert_eq!(recipients.len(), 3, "the site's own cap, not the egress's");
        // A reply of its own counts; one its session or another gave, or
        // none, does not.
        let mut permits = recipients.into_iter();
        let finished = [
            (
                Attempted::Delivered,
                Some(Evidence::new(250, "2.0.0 Ok")),
                true,
            ),
            (
                Attempted::Deferred,
                Some(Evidence::new(451, "4.3.0 Later")),
                false,
            ),
            (
                Attempted::NotSent,
                Some(Evidence::new(554, "5.7.1 Blocked")),
                true,
            ),
        ];
        for (result, evidence, replied) in finished {
            scheduler.handle(
                at(1),
                Input::Finished {
                    permit: permits.next().unwrap(),
                    result,
                    evidence,
                    verdict: None,
                    feedback: None,
                    replied: replied.then_some(REPLIED),
                },
            );
        }
        let mut out = Vec::new();
        scheduler.poll(at(1), &mut out);
        let counted: Vec<Option<Signal>> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::RecordOutcome(outcome),
                    ..
                }) => Some(outcome.counted.as_ref().map(|counted| {
                    assert_eq!(&*counted.site, "mx.sink.test");
                    counted.signal
                })),
                _ => None,
            })
            .collect();
        assert_eq!(
            counted,
            [Some(Signal::Delivered), None, Some(Signal::Failed)],
            "a session refused with 5xx fails"
        );
    }

    #[test]
    fn mail_whose_pool_has_no_egress_waits_for_one() {
        let mut scheduler = under(pooled(&[]));
        let mut store = BTreeMap::new();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![of(1, 1, "a@sink.test")],
            sink,
        );
        assert!(
            dispatched.is_empty(),
            "not from the host's address, nor any other"
        );
        scheduler.handle(at(1), Input::Policy(pooled(&[(12, None)])));
        // It let its body go while it waited, and reads it back.
        for output in poll_routed(&mut scheduler, at(1), sink) {
            if let Output::Store(Request {
                ticket,
                command: Command::Content(_),
            }) = output
            {
                let answer = Answer::Content(Ok(Some(Bytes::from_static(b"content"))));
                scheduler.handle(at(1), Input::Answer(Response { ticket, answer }));
            }
        }
        let out = poll_routed(&mut scheduler, at(1), sink);
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(1), Input::Answer(response));
        }
        let dispatched = dispatches(poll_routed(&mut scheduler, at(1), sink));
        assert_eq!(sent_from(&dispatched[0]), Some(egress(12)));
    }

    /// A policy whose configuration sends from the host's own address.
    fn unpooled() -> Arc<Policy> {
        let mut policy = Policy::default();
        policy
            .apply(Change::Configuration {
                id: POOLED,
                account: ACCOUNT,
                name: "receipts".to_owned(),
                pool: None,
            })
            .unwrap();
        Arc::new(policy)
    }

    #[test]
    fn mail_queued_for_the_host_moves_when_its_configuration_gains_a_pool() {
        let mut scheduler = under(unpooled());
        let mut store = BTreeMap::new();
        let deliveries = (1..=3)
            .map(|n| of(n, n, &format!("r{n}@sink.test")))
            .collect();
        let dispatched = dispatch_accepted(&mut scheduler, &mut store, at(0), deliveries, sink);
        assert_eq!(dispatched.len(), 2, "two at a time to the site");
        assert!(
            dispatched
                .iter()
                .all(|dispatch| sent_from(dispatch).is_none())
        );
        // The third waits at the host's queue while its configuration is
        // given a pool, and goes out from the pool's egress.
        scheduler.handle(at(1), Input::Policy(pooled(&[(12, None)])));
        let out = poll_routed(&mut scheduler, at(1), sink);
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(1), Input::Answer(response));
        }
        let dispatched = dispatches(poll_routed(&mut scheduler, at(1), sink));
        assert_eq!(dispatched.len(), 1);
        assert_eq!(sent_from(&dispatched[0]), Some(egress(12)));
    }

    #[test]
    fn pooled_mail_waits_for_the_ledger_and_goes_where_there_is_room() {
        let site = "mx.sink.test";
        // A message whose recipients spread to egress 10 when both have room.
        let message = (1..100)
            .find(|&n| {
                let id = MessageId(Id::from_u64(id_base() + 1000 + n).unwrap());
                spread(id, site, 2) == Some(0)
            })
            .unwrap();
        let mut scheduler = unadopted();
        scheduler.handle(
            at(0),
            Input::Policy(pooled(&[(10, Some(1)), (11, Some(100))])),
        );
        let mut store = BTreeMap::new();
        let delivery = of(message, 1, "a@sink.test");
        store.insert(delivery.id(), delivery.clone());
        scheduler.handle(at(0), Input::Accepted(vec![accepted(delivery)]));
        let out = poll_with(&mut scheduler, at(0), &sink, None);
        let ledger = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Dispatched,
                }) => Some(*ticket),
                _ => None,
            })
            .expect("the ledger is read");
        assert!(reserved(&out).is_empty(), "not placed before the ledger");

        // Egress 10 spent its cap at the site today, which the ledger says.
        let mut spent = Window::default();
        spent.add(at(0).wall);
        let answer = Answer::Dispatched(Ok(DispatchLedger {
            windows: vec![(egress(10), Arc::from(site), spent)],
            cooldowns: Vec::new(),
        }));
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket: ledger,
                answer,
            }),
        );
        // It let its body go while it waited, and reads it back.
        for output in poll_routed(&mut scheduler, at(1), sink) {
            if let Output::Store(Request {
                ticket,
                command: Command::Content(_),
            }) = output
            {
                let answer = Answer::Content(Ok(Some(Bytes::from_static(b"content"))));
                scheduler.handle(at(1), Input::Answer(Response { ticket, answer }));
            }
        }
        let out = poll_routed(&mut scheduler, at(1), sink);
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(1), Input::Answer(response));
        }
        let dispatched = dispatches(poll_routed(&mut scheduler, at(1), sink));
        assert_eq!(sent_from(&dispatched[0]), Some(egress(11)));
    }

    #[test]
    fn a_reservation_refused_for_its_source_is_placed_again_at_once() {
        let mut scheduler = under(pooled(&[(10, None)]));
        let delivery = of(1, 1, "a@sink.test");
        scheduler.handle(at(0), Input::Accepted(vec![accepted(delivery)]));
        let reservation = |outputs: &[Output]| {
            outputs.iter().find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Reserve(reserve),
                }) => Some((*ticket, reserve.egress)),
                _ => None,
            })
        };
        let out = poll_routed(&mut scheduler, at(0), sink);
        let (ticket, from) = reservation(&out).expect("a reservation");
        assert_eq!(from, Some(egress(10)));
        // Egress 10 leaves the pool before the store answers, which refuses
        // the reservation for it.
        scheduler.handle(at(1), Input::Policy(pooled(&[(11, None)])));
        let answer = Answer::Reserved(Commit::Refused(Refusal::Unsourced));
        scheduler.handle(at(1), Input::Answer(Response { ticket, answer }));
        let mut out = poll_routed(&mut scheduler, at(1), sink);
        // It let its body go for the reservation, and reads it back.
        for output in &out {
            if let Output::Store(Request {
                ticket,
                command: Command::Content(_),
            }) = output
            {
                let answer = Answer::Content(Ok(Some(Bytes::from_static(b"content"))));
                scheduler.handle(
                    at(1),
                    Input::Answer(Response {
                        ticket: *ticket,
                        answer,
                    }),
                );
                out = poll_routed(&mut scheduler, at(1), sink);
                break;
            }
        }
        let (_, from) = reservation(&out).expect("reserved again, without a scan");
        assert_eq!(from, Some(egress(11)));
    }

    #[test]
    fn draining_finishes_what_is_under_way_and_starts_nothing() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "a@sink.test")],
            sink,
        );
        assert_eq!(dispatched.len(), 1);
        scheduler.handle(at(1), Input::Drain);
        // Mail accepted now waits in the store for the next start.
        scheduler.handle(
            at(1),
            Input::Accepted(vec![accepted(delivery(2, "b@sink.test"))]),
        );
        let out = poll_routed(&mut scheduler, at(1), sink);
        assert!(out.is_empty(), "nothing new: {out:?}");
        assert!(!scheduler.is_drained(), "an attempt is under way");

        let permit = permit(dispatched.into_iter().next().unwrap());
        scheduler.handle(
            at(2),
            Input::Finished {
                permit,
                result: Attempted::Delivered,
                evidence: None,
                verdict: None,
                feedback: None,
                replied: None,
            },
        );
        let out = poll(&mut scheduler, at(2));
        let ticket = outcomes(&out)[0].0;
        assert!(!scheduler.is_drained(), "its outcome is not yet recorded");
        scheduler.handle(at(2), recorded(ticket));
        assert!(poll(&mut scheduler, at(2)).is_empty());
        assert!(scheduler.is_drained());
    }

    #[test]
    fn a_reservation_that_gives_no_permit_spends_no_budget() {
        let mut scheduler = under(pooled(&[(10, Some(1))]));
        let mut store = BTreeMap::new();
        let first = of(1, 1, "a@sink.test");
        store.insert(first.id(), first.clone());
        scheduler.handle(at(0), Input::Accepted(vec![accepted(first)]));
        let out = poll_routed(&mut scheduler, at(0), sink);
        let ticket = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Reserve(_),
                }) => Some(*ticket),
                _ => None,
            })
            .expect("a reservation");
        // Its recipient is suppressed: it finishes without an attempt, and
        // the store counts no reservation.
        let answer = Answer::Reserved(Commit::Committed(Reservation::Suppressed));
        scheduler.handle(at(0), Input::Answer(Response { ticket, answer }));
        poll(&mut scheduler, at(0));
        let second = of(2, 2, "b@sink.test");
        let dispatched = dispatch_accepted(&mut scheduler, &mut store, at(1), vec![second], sink);
        assert_eq!(
            dispatched.len(),
            1,
            "the egress's one reservation today is still to be made"
        );
    }

    #[test]
    fn a_route_resolved_while_draining_starts_nothing() {
        let mut scheduler = scheduler();
        scheduler.handle(
            at(0),
            Input::Accepted(vec![accepted(delivery(1, "a@refused.test"))]),
        );
        let mut out = Vec::new();
        scheduler.poll(at(0), &mut out);
        assert!(out.iter().any(
            |output| matches!(output, Output::Resolve(domain) if &**domain == "refused.test")
        ));
        scheduler.handle(at(1), Input::Drain);
        // A route that refuses mail would settle the delivery with a
        // reservation, which draining never asks for.
        scheduler.handle(
            at(1),
            Input::Resolved {
                domain: "refused.test".into(),
                route: Route::Refused,
                ttl: Duration::from_secs(60),
            },
        );
        let mut out = Vec::new();
        scheduler.poll(at(1), &mut out);
        assert!(out.is_empty(), "{out:?}");
        assert!(scheduler.is_drained());
    }

    #[test]
    fn an_inspection_says_where_each_delivery_waits_and_why() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        // One goes out, and its receiver throttles it.
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "a@sink.test")],
            sink,
        );
        let permit = permit(dispatched.into_iter().next().unwrap());
        scheduler.handle(
            at(1),
            Input::Finished {
                permit,
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(421, "4.7.0 Slow down")),
                verdict: None,
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        let out = poll(&mut scheduler, at(1));
        for (ticket, _) in outcomes(&out) {
            scheduler.handle(at(1), recorded(ticket));
        }
        poll(&mut scheduler, at(1));
        // Another waits behind its cooldown; a third, at a new domain, for
        // its route.
        let (cooled, routing) = (delivery(2, "b@sink.test"), delivery(3, "c@new.test"));
        let ids = [cooled.id(), routing.id(), delivery(1, "a@sink.test").id()];
        scheduler.handle(
            at(2),
            Input::Accepted(vec![accepted(cooled), accepted(routing)]),
        );
        scheduler.poll(at(2), &mut Vec::new());
        scheduler.handle(
            at(2),
            Input::Inspect {
                ticket: Ticket(9),
                inspection: Inspection::Explain(ids.to_vec()),
            },
        );
        let mut out = Vec::new();
        scheduler.poll(at(2), &mut out);
        let report = out
            .into_iter()
            .find_map(|output| match output {
                Output::Inspected {
                    ticket: Ticket(9),
                    report,
                } => Some(report),
                _ => None,
            })
            .expect("answered");
        let Report::Holds(holds) = report else {
            panic!("holds");
        };
        assert_eq!(
            holds.len(),
            2,
            "the throttled one waits in the store: {holds:?}"
        );
        let Hold::Queued { ahead, cooling, .. } = &holds[0].1 else {
            panic!("queued: {holds:?}");
        };
        assert_eq!(*ahead, 0);
        let cooling = cooling.as_ref().expect("its site cools down");
        assert_eq!(cooling.reply, Some(Evidence::new(421, "4.7.0 Slow down")));
        assert_eq!(
            holds[1].1,
            Hold::Routing {
                domain: "new.test".into()
            }
        );
    }

    #[test]
    fn nothing_is_placed_before_the_first_policy() {
        let mut scheduler = unadopted();
        let mut store = BTreeMap::new();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![of(1, 1, "a@sink.test")],
            sink,
        );
        assert!(
            dispatched.is_empty(),
            "not from the host's address before policy names the pool's egresses"
        );
        scheduler.handle(at(1), Input::Policy(pooled(&[(12, None)])));
        let mut out = Vec::new();
        scheduler.poll(at(1), &mut out);
        for output in out {
            match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Dispatched,
                }) => {
                    let answer = Answer::Dispatched(Ok(DispatchLedger::default()));
                    scheduler.handle(at(1), Input::Answer(Response { ticket, answer }));
                }
                // It let its body go while it waited, and reads it back.
                Output::Store(Request {
                    ticket,
                    command: Command::Content(_),
                }) => {
                    let answer = Answer::Content(Ok(Some(Bytes::from_static(b"content"))));
                    scheduler.handle(at(1), Input::Answer(Response { ticket, answer }));
                }
                _ => {}
            }
        }
        let out = poll_routed(&mut scheduler, at(1), sink);
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(1), Input::Answer(response));
        }
        let dispatched = dispatches(poll_routed(&mut scheduler, at(1), sink));
        assert_eq!(sent_from(&dispatched[0]), Some(egress(12)));
    }

    #[test]
    fn an_accepted_delivery_is_routed_reserved_dispatched_and_recorded() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let mut out = Vec::new();
        scheduler.handle(
            at(0),
            Input::Accepted(vec![accepted(delivery(1, "r@Sink.Test"))]),
        );
        scheduler.poll(at(0), &mut out);
        assert!(
            out.iter().any(
                |output| matches!(output, Output::Resolve(domain) if &**domain == "sink.test")
            )
        );

        let mut scheduler = self::scheduler();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r@Sink.Test")],
            |_| Route::Exchanges(vec!["mx.sink.test".to_owned()], Tls::default()),
        );
        assert_eq!(dispatched.len(), 1);
        assert_eq!(
            (
                &**dispatched[0].site.name(),
                &dispatched[0].exchanges[..],
                &dispatched[0].content[..]
            ),
            (
                "mx.sink.test",
                &["mx.sink.test".to_owned()][..],
                &b"content"[..]
            )
        );
        let permit = permit(dispatched.into_iter().next().unwrap());
        let (delivery, attempt) = (permit.delivery(), permit.attempt());
        scheduler.handle(
            at(2),
            Input::Finished {
                permit,
                result: Attempted::Delivered,
                evidence: None,
                verdict: None,
                feedback: None,
                replied: None,
            },
        );
        let out = poll(&mut scheduler, at(2));
        // Its end, for the shell's counts: where it went, and for whom.
        let ended = out
            .iter()
            .find_map(|output| match output {
                Output::Ended(ended) => Some(ended),
                _ => None,
            })
            .expect("its end");
        assert_eq!(
            (
                ended.delivery,
                ended.attempt,
                ended.result,
                ended.egress,
                ended.tenant
            ),
            (
                delivery,
                attempt,
                Attempted::Delivered,
                None,
                origin().tenant
            )
        );
        assert_eq!(
            ended.site.as_ref().map(|site| &**site.name()),
            Some("mx.sink.test")
        );
        let recorded = outcomes(&out);
        assert_eq!(recorded[0].1.disposition, Disposition::Delivered);
        scheduler.handle(at(3), self::recorded(recorded[0].0));
        poll(&mut scheduler, at(3));
        assert_eq!(scheduler.held(), 0);
    }

    #[test]
    fn domains_sharing_exchanges_share_a_site_and_its_limit_and_others_do_not_wait() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let deliveries = vec![
            delivery(1, "a@one.test"),
            delivery(2, "b@two.test"),
            delivery(3, "c@one.test"),
            delivery(4, "d@other.test"),
        ];
        for delivery in &deliveries {
            store.insert(delivery.id(), delivery.clone());
        }
        let batch = deliveries.into_iter().map(accepted).collect();
        scheduler.handle(at(0), Input::Accepted(batch));
        // one.test and two.test are served by the same exchange.
        let out = poll_routed(&mut scheduler, at(0), |domain| {
            let exchange = if domain == "other.test" {
                "mx.other.test"
            } else {
                "mx.shared.test"
            };
            Route::Exchanges(vec![exchange.to_owned()], Tls::default())
        });
        let reserved = reserved(&out);
        let shared = [
            delivery(1, "a@one.test").id(),
            delivery(2, "b@two.test").id(),
            delivery(3, "c@one.test").id(),
        ];
        assert_eq!(reserved.len(), 3);
        assert_eq!(reserved.iter().filter(|id| shared.contains(id)).count(), 2);
        assert!(reserved.contains(&delivery(4, "d@other.test").id()));
    }

    /// The receiver rules with a provider, Hosted, that claims every
    /// exchange under hosted.test: one connection from each egress, so two
    /// transactions under way, shared by all its queues, and a reply that
    /// throttles it for two hours.
    fn hosted() -> Arc<Rules> {
        let overrides: BTreeMap<String, rules::Entry> = BTreeMap::from([
            (
                rules::DEFAULTS.to_owned(),
                rules::Entry {
                    connections: Some(1),
                    ..rules::Entry::default()
                },
            ),
            (
                "Hosted".to_owned(),
                rules::Entry {
                    exchanges: Some(vec![".hosted.test".to_owned()]),
                    connections: Some(1),
                    throttles: Some(vec![rules::ThrottleEntry {
                        name: "slow".to_owned(),
                        pattern: "slow down".to_owned(),
                        cooldown_seconds: 7200,
                    }]),
                    ..rules::Entry::default()
                },
            ),
        ]);
        Arc::new(Rules::new(&overrides).unwrap())
    }

    fn hosting(rules: Arc<Rules>) -> Scheduler {
        hosting_with(config(), rules)
    }

    fn hosting_with(config: Config, rules: Arc<Rules>) -> Scheduler {
        let attempts = IdGenerator::new(Shard::new(0), Lane::new(1).unwrap(), None);
        let mut scheduler = Scheduler::new(config, rules, attempts, Rng::from_seed(7));
        scheduler.handle(at(0), Input::Policy(Arc::default()));
        scheduler
    }

    /// Records every outcome among `out` as the store would, and polls.
    fn record_all(scheduler: &mut Scheduler, out: &[Output], now: Now) -> Vec<Output> {
        for (ticket, _) in outcomes(out) {
            scheduler.handle(now, recorded(ticket));
        }
        poll_routed(scheduler, now, hosted_route)
    }

    /// a.test and b.test each have their own exchanges, both Hosted's;
    /// other.test is a site of its own.
    fn hosted_route(domain: &str) -> Route {
        let exchange = match domain {
            "other.test" => "mx.other.test".to_owned(),
            domain => format!("mx.{domain}.hosted.test"),
        };
        Route::Exchanges(vec![exchange], Tls::default())
    }

    /// The verdict `rules` give a reply from `exchange`.
    fn verdict(rules: &Rules, exchange: &str, code: u16, text: &str) -> Option<Verdict> {
        Some(rules.site(&[exchange.to_owned()]).verdict(code, text))
    }

    #[test]
    fn a_providers_queues_share_its_limit_and_take_turns_at_it() {
        let mut scheduler = hosting(hosted());
        let mut store = BTreeMap::new();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![
                delivery(1, "r1@a.test"),
                delivery(2, "r2@a.test"),
                delivery(3, "r3@b.test"),
                delivery(4, "r4@other.test"),
            ],
            hosted_route,
        );
        let sent: Vec<(&str, &str)> = dispatched
            .iter()
            .map(|dispatch| (&**dispatch.site.name(), &*dispatch.queue))
            .collect();
        // Hosted's two transactions are one from each of its queues, though
        // a.test has two waiting, each to its own exchanges; other.test's
        // site has its own limit.
        assert_eq!(
            sent,
            [
                ("Hosted", "mx.a.test.hosted.test"),
                ("Hosted", "mx.b.test.hosted.test"),
                ("mx.other.test", "mx.other.test"),
            ]
        );
        assert_eq!(
            &dispatched[1].exchanges[..],
            ["mx.b.test.hosted.test".to_owned()]
        );
    }

    #[test]
    fn a_shared_sites_freed_place_goes_to_its_next_queue_whatever_other_sites_start() {
        let config = Config {
            window: 8,
            ..config()
        };
        let mut scheduler = hosting_with(config, hosted());
        let mut store = BTreeMap::new();
        let mut first = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![
                delivery(1, "r1@a.test"),
                delivery(2, "r2@a.test"),
                delivery(3, "r3@a.test"),
            ],
            hosted_route,
        );
        assert_eq!(first.len(), 2, "Hosted's limit");
        // b.test waits for a place at Hosted; other.test, a site of its own,
        // starts meanwhile.
        let other = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(10),
            vec![delivery(4, "r4@b.test"), delivery(5, "r5@other.test")],
            hosted_route,
        );
        assert_eq!(&**other[0].site.name(), "mx.other.test");
        // A place frees at Hosted: b.test's turn, not a.test's again.
        scheduler.handle(
            at(20),
            Input::Finished {
                permit: permit(first.remove(0)),
                result: Attempted::Delivered,
                evidence: None,
                verdict: None,
                feedback: None,
                replied: None,
            },
        );
        let out = poll_routed(&mut scheduler, at(20), hosted_route);
        let out = record_all(&mut scheduler, &out, at(20));
        assert_eq!(reserved(&out), [delivery(4, "r4@b.test").id()]);
    }

    #[test]
    fn an_attempt_under_way_when_its_site_throttled_does_not_end_the_cooldown() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        let mut dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r1@a.test"), delivery(2, "r2@b.test")],
            hosted_route,
        );
        let reply = "4.7.1 slow down";
        scheduler.handle(
            at(10),
            Input::Finished {
                permit: permit(dispatched.remove(0)),
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(451, reply)),
                verdict: verdict(&rules, "mx.a.test.hosted.test", 451, reply),
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        // The other attempt, under way all along, is delivered afterwards.
        scheduler.handle(
            at(20),
            Input::Finished {
                permit: permit(dispatched.remove(0)),
                result: Attempted::Delivered,
                evidence: None,
                verdict: None,
                feedback: None,
                replied: None,
            },
        );
        let out = poll_routed(&mut scheduler, at(20), hosted_route);
        record_all(&mut scheduler, &out, at(20));
        let held = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(60_000),
            vec![delivery(3, "r3@a.test")],
            hosted_route,
        );
        assert!(held.is_empty(), "Hosted still cools for its two hours");
    }

    #[test]
    fn a_cooldown_is_kept_with_the_outcome_that_began_it_and_holds_after_a_restart() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        let mut dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r1@a.test"), delivery(2, "r2@b.test")],
            hosted_route,
        );
        let finish = |scheduler: &mut Scheduler, dispatch: Dispatch, reply: &str| {
            let exchange = dispatch.exchanges[0].clone();
            scheduler.handle(
                at(10),
                Input::Finished {
                    permit: permit(dispatch),
                    result: Attempted::Throttled,
                    evidence: Some(Evidence::new(451, reply)),
                    verdict: verdict(&rules, &exchange, 451, reply),
                    feedback: None,
                    replied: Some(REPLIED),
                },
            );
        };
        finish(&mut scheduler, dispatched.remove(0), "4.7.1 slow down");
        finish(&mut scheduler, dispatched.remove(0), "4.7.1 slow down");
        let out = poll_routed(&mut scheduler, at(10), hosted_route);
        let kept: Vec<Option<SiteCooldown>> = outcomes(&out)
            .iter()
            .map(|(_, outcome)| match &outcome.cooled {
                Some(CooldownChange::Kept(kept)) => Some(kept.clone()),
                Some(CooldownChange::Ended { .. }) => panic!("ended"),
                None => None,
            })
            .collect();
        // The first throttle's outcome keeps the cooldown it began; the
        // second's asks for no longer, and keeps nothing.
        let Some(first) = &kept[0] else {
            panic!("{kept:?}");
        };
        assert_eq!((&*first.site, first.throttles), ("Hosted", 1));
        assert!(first.until.saturating_duration_since(at(10).wall) >= Duration::from_secs(7200));
        assert_eq!(first.reply.as_ref().map(|reply| reply.code), Some(451));
        assert_eq!(kept[1], None);

        // A scheduler that starts after a restart, from the ledger keeping
        // it, holds the site's mail until it ends.
        let mut restarted = hosting(Arc::clone(&rules));
        let ledger = DispatchLedger {
            windows: Vec::new(),
            cooldowns: vec![first.clone()],
        };
        let mut store = BTreeMap::new();
        let accept = |scheduler: &mut Scheduler, store: &mut BTreeMap<_, _>, now, delivery| {
            let delivery: Delivery = delivery;
            store.insert(delivery.id(), delivery.clone());
            scheduler.handle(now, Input::Accepted(vec![accepted(delivery)]));
            let out = poll_with(scheduler, now, &hosted_route, Some(&ledger));
            reserved(&out)
        };
        let held = accept(&mut restarted, &mut store, at(20), delivery(3, "r3@a.test"));
        assert!(held.is_empty(), "the kept cooldown holds");
        let after = accept(
            &mut restarted,
            &mut store,
            at(7_300_000),
            delivery(4, "r4@b.test"),
        );
        assert!(!after.is_empty(), "and ends when it did");
    }

    #[test]
    fn a_delivered_probe_ends_the_cooldown_in_the_store_and_one_ended_holds_to_a_probe() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        let mut first = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r1@a.test")],
            hosted_route,
        );
        let reply = "4.7.1 slow down";
        scheduler.handle(
            at(10),
            Input::Finished {
                permit: permit(first.remove(0)),
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(451, reply)),
                verdict: verdict(&rules, "mx.a.test.hosted.test", 451, reply),
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        let out = poll_routed(&mut scheduler, at(10), hosted_route);
        let Some(CooldownChange::Kept(kept)) = outcomes(&out)[0].1.cooled.clone() else {
            panic!("kept");
        };
        record_all(&mut scheduler, &out, at(10));

        // After a restart, once the cooldown has run out, the site still
        // takes one probe at a time.
        let mut restarted = hosting(Arc::clone(&rules));
        let ledger = DispatchLedger {
            windows: Vec::new(),
            cooldowns: vec![kept],
        };
        let after = at(7_300_000);
        let mut store = BTreeMap::new();
        let batch = [delivery(2, "r2@a.test"), delivery(3, "r3@b.test")];
        for delivery in &batch {
            store.insert(delivery.id(), delivery.clone());
        }
        restarted.handle(after, Input::Accepted(batch.map(accepted).into()));
        let out = poll_with(&mut restarted, after, &hosted_route, Some(&ledger));
        assert_eq!(reserved(&out).len(), 1, "one probe at a time");
        for response in reserve_all(&out, &mut store) {
            restarted.handle(after, Input::Answer(response));
        }
        let probe = dispatches(poll_routed(&mut restarted, after, hosted_route)).remove(0);
        // The probe is delivered: the cooldown ends, and the store forgets it.
        restarted.handle(
            after,
            Input::Finished {
                permit: permit(probe),
                result: Attempted::Delivered,
                evidence: None,
                verdict: None,
                feedback: None,
                replied: None,
            },
        );
        let out = poll_routed(&mut restarted, after, hosted_route);
        assert!(matches!(
            &outcomes(&out)[0].1.cooled,
            Some(CooldownChange::Ended { site, .. }) if &**site == "Hosted"
        ));
    }

    /// The cooldowns `out` asks the store to end.
    fn ended(out: &[Output]) -> Vec<&str> {
        out.iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Cooldown(CooldownChange::Ended { site, .. }),
                    ..
                }) => Some(&**site),
                _ => None,
            })
            .collect()
    }

    /// A Hosted cooldown begun at ten milliseconds by a reply asking two
    /// hours: it runs out just past 7,200 seconds, and is forgotten an hour
    /// after.
    fn throttled_at_ten_milliseconds(rules: &Arc<Rules>) -> Scheduler {
        let mut scheduler = hosting(Arc::clone(rules));
        let mut store = BTreeMap::new();
        let mut first = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r1@a.test")],
            hosted_route,
        );
        let reply = "4.7.1 slow down";
        scheduler.handle(
            at(10),
            Input::Finished {
                permit: permit(first.remove(0)),
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(451, reply)),
                verdict: verdict(rules, "mx.a.test.hosted.test", 451, reply),
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        let out = poll_routed(&mut scheduler, at(10), hosted_route);
        record_all(&mut scheduler, &out, at(10));
        scheduler
    }

    #[test]
    fn a_cooldown_run_out_still_takes_one_probe_and_backs_off_from_its_count() {
        let rules = hosted();
        let mut scheduler = throttled_at_ten_milliseconds(&rules);
        let mut store = BTreeMap::new();
        // Run out, with nothing of Hosted held since: its mail still probes
        // one at a time.
        let mut probing = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(7_300_000),
            vec![delivery(2, "r2@a.test"), delivery(3, "r3@b.test")],
            hosted_route,
        );
        assert_eq!(probing.len(), 1, "one probe at a time");
        // The probe is throttled too: the next cooldown counts two.
        let probe = probing.remove(0);
        let exchange = probe.exchanges[0].clone();
        let reply = "4.7.1 slow down";
        scheduler.handle(
            at(7_300_000),
            Input::Finished {
                permit: permit(probe),
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(451, reply)),
                verdict: verdict(&rules, &exchange, 451, reply),
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        let out = poll_routed(&mut scheduler, at(7_300_000), hosted_route);
        let Some(CooldownChange::Kept(kept)) = outcomes(&out)[0].1.cooled.clone() else {
            panic!("kept");
        };
        assert_eq!(kept.throttles, 2);
    }

    #[test]
    fn a_site_with_nothing_held_forgets_its_run_out_cooldown_at_its_horizon() {
        let rules = hosted();
        let mut scheduler = throttled_at_ten_milliseconds(&rules);
        let at_seconds = |seconds: u64| at(seconds * 1000);
        assert!(
            ended(&poll_routed(
                &mut scheduler,
                at_seconds(10_799),
                hosted_route
            ))
            .is_empty()
        );
        assert_eq!(
            ended(&poll_routed(
                &mut scheduler,
                at_seconds(10_801),
                hosted_route
            )),
            ["Hosted"]
        );
    }

    #[test]
    fn a_restart_counts_a_kept_cooldowns_horizon_from_now_whatever_the_monotonic_clock() {
        let rules = hosted();
        let kept = SiteCooldown {
            egress: None,
            site: "Hosted".into(),
            until: at(0).wall,
            throttles: 3,
            reply: None,
        };
        // The engine starts 3,500 seconds after the cooldown ran out, its
        // monotonic clock at nought: 100 seconds of the horizon are left.
        let started = Now {
            wall: at(0).wall.saturating_add(Duration::from_secs(3_500)),
            monotonic: Monotonic::from_micros(0),
        };
        let mut restarted = hosting(Arc::clone(&rules));
        let ledger = DispatchLedger {
            windows: Vec::new(),
            cooldowns: vec![kept.clone()],
        };
        let out = poll_with(&mut restarted, started, &hosted_route, Some(&ledger));
        assert!(ended(&out).is_empty(), "within its horizon");
        let later = Now {
            wall: started.wall.saturating_add(Duration::from_secs(200)),
            monotonic: Monotonic::from_micros(200_000_000),
        };
        let out = poll_routed(&mut restarted, later, hosted_route);
        assert_eq!(ended(&out), ["Hosted"], "forgotten 100 seconds in");

        // One already past its horizon at the start is forgotten at once,
        // and limits nothing: mail queued for its site before the ledger
        // came goes out to the site's whole limit.
        let mut restarted = hosting(rules);
        let past = Now {
            wall: at(0).wall.saturating_add(Duration::from_secs(3_700)),
            monotonic: Monotonic::from_micros(0),
        };
        let mut store = BTreeMap::new();
        let waiting = [delivery(1, "r1@a.test"), delivery(2, "r2@b.test")];
        for delivery in &waiting {
            store.insert(delivery.id(), delivery.clone());
        }
        restarted.handle(past, Input::Accepted(waiting.map(accepted).into()));
        let out = poll_with(&mut restarted, past, &hosted_route, Some(&ledger));
        assert_eq!(ended(&out), ["Hosted"]);
        assert_eq!(reserved(&out).len(), 2, "no probe limit");
    }

    #[test]
    fn a_refused_sessions_cooldown_is_kept_by_its_own_command() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        scheduler.handle(
            at(0),
            Input::SiteThrottled {
                site: rules.site(&["mx.a.test.hosted.test".to_owned()]),
                egress: None,
                reply: Some(Evidence::new(421, "4.7.0 slow down")),
                minimum: Duration::from_secs(900),
            },
        );
        let out = poll_routed(&mut scheduler, at(0), hosted_route);
        let kept: Vec<&SiteCooldown> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Cooldown(CooldownChange::Kept(kept)),
                    ..
                }) => Some(kept),
                _ => None,
            })
            .collect();
        assert_eq!(kept.len(), 1);
        assert!(kept[0].until.saturating_duration_since(at(0).wall) >= Duration::from_secs(900));
    }

    #[test]
    fn a_wall_clock_that_jumps_never_shortens_a_cooldown() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        let mut dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r1@a.test"), delivery(2, "r2@b.test")],
            hosted_route,
        );
        // The first throttle cools Hosted for the retry schedule's time,
        // between 30 and 60 seconds.
        let reply = "4.7.0 try again later";
        scheduler.handle(
            at(0),
            Input::Finished {
                permit: permit(dispatched.remove(0)),
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(421, reply)),
                verdict: verdict(&rules, "mx.a.test.hosted.test", 421, reply),
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        let out = poll_routed(&mut scheduler, at(0), hosted_route);
        record_all(&mut scheduler, &out, at(0));
        // Ten seconds on, the wall clock has jumped an hour, and another
        // throttle with no minimum comes back.
        let jumped = Now {
            wall: at(10_000).wall.saturating_add(Duration::from_secs(3600)),
            monotonic: at(10_000).monotonic,
        };
        scheduler.handle(
            jumped,
            Input::Finished {
                permit: permit(dispatched.remove(0)),
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(421, reply)),
                verdict: verdict(&rules, "mx.b.test.hosted.test", 421, reply),
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        let out = poll_routed(&mut scheduler, jumped, hosted_route);
        record_all(&mut scheduler, &out, jumped);
        // At twenty seconds, still within the first cooldown, nothing starts.
        let later = Now {
            wall: jumped.wall.saturating_add(Duration::from_secs(10)),
            monotonic: at(20_000).monotonic,
        };
        let held = dispatch_accepted(
            &mut scheduler,
            &mut store,
            later,
            vec![delivery(3, "r3@a.test")],
            hosted_route,
        );
        assert!(held.is_empty(), "the cooldown holds on the monotonic clock");
    }

    #[test]
    fn a_group_whose_site_began_cooling_during_its_reservations_is_not_sent() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        for delivery in [delivery(1, "r1@a.test"), delivery(2, "r2@b.test")] {
            store.insert(delivery.id(), delivery.clone());
            scheduler.handle(at(0), Input::Accepted(vec![accepted(delivery)]));
        }
        let out = poll_routed(&mut scheduler, at(0), hosted_route);
        let mut answers = reserve_all(&out, &mut store);
        assert_eq!(answers.len(), 2);
        // a.test's reservation is answered first, and its attempt goes out.
        let late = answers.pop().unwrap();
        scheduler.handle(at(0), Input::Answer(answers.remove(0)));
        let sent = dispatches(poll_routed(&mut scheduler, at(0), hosted_route));
        assert_eq!(sent.len(), 1);
        let reply = "4.7.1 slow down";
        let exchange = sent[0].exchanges[0].clone();
        scheduler.handle(
            at(5),
            Input::Finished {
                permit: permit(sent.into_iter().next().unwrap()),
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(451, reply)),
                verdict: verdict(&rules, &exchange, 451, reply),
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        let out = poll_routed(&mut scheduler, at(5), hosted_route);
        record_all(&mut scheduler, &out, at(5));
        // b.test's reservation is answered during the cooldown: its attempt
        // is not sent, and waits for the cooldown's end.
        scheduler.handle(at(6), Input::Answer(late));
        let out = poll_routed(&mut scheduler, at(6), hosted_route);
        assert!(
            !out.iter()
                .any(|output| matches!(output, Output::Dispatch(_))),
            "{out:?}"
        );
        let deferred: Vec<Disposition> = outcomes(&out)
            .iter()
            .map(|(_, outcome)| outcome.disposition)
            .collect();
        assert!(
            matches!(deferred[..], [Disposition::Deferred { not_before }]
                if not_before.saturating_duration_since(at(6).wall) >= Duration::from_secs(7000)),
            "{deferred:?}"
        );
    }

    #[test]
    fn a_refused_session_cools_its_site_though_nothing_of_it_is_held() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        scheduler.handle(
            at(0),
            Input::SiteThrottled {
                site: rules.site(&["mx.a.test.hosted.test".to_owned()]),
                egress: None,
                reply: Some(Evidence::new(421, "4.7.0 slow down")),
                minimum: Duration::from_secs(900),
            },
        );
        poll_routed(&mut scheduler, at(0), hosted_route);
        let held = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(600_000),
            vec![delivery(1, "r1@b.test")],
            hosted_route,
        );
        assert!(held.is_empty(), "Hosted cools for the refusal's minimum");
        let sent = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(901_000),
            vec![delivery(2, "r2@other.test")],
            hosted_route,
        );
        assert_eq!(sent.len(), 1, "another site does not wait");
    }

    #[test]
    fn a_later_throttle_whose_rule_asks_longer_stretches_the_cooldown() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r1@a.test"), delivery(2, "r2@b.test")],
            hosted_route,
        );
        let replies = [
            ("mx.a.test.hosted.test", "4.7.0 try again later"),
            ("mx.b.test.hosted.test", "4.7.1 slow down"),
        ];
        for (dispatch, (exchange, reply)) in dispatched.into_iter().zip(replies) {
            scheduler.handle(
                at(10),
                Input::Finished {
                    permit: permit(dispatch),
                    result: Attempted::Throttled,
                    evidence: Some(Evidence::new(421, reply)),
                    verdict: verdict(&rules, exchange, 421, reply),
                    feedback: None,
                    replied: Some(REPLIED),
                },
            );
        }
        let out = poll_routed(&mut scheduler, at(10), hosted_route);
        let ends: Vec<Duration> = outcomes(&out)
            .iter()
            .map(|(_, outcome)| match outcome.disposition {
                Disposition::Deferred { not_before } => {
                    not_before.saturating_duration_since(at(10).wall)
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert!(
            ends[0] < Duration::from_secs(7200),
            "the schedule's cooldown"
        );
        assert!(
            ends[1] >= Duration::from_secs(7200),
            "stretched to the later rule's minimum"
        );
    }

    #[test]
    fn a_throttle_at_one_queue_cools_its_whole_site_for_at_least_the_rules_minimum() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        let mut dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r1@a.test")],
            hosted_route,
        );
        let reply = "4.7.1 slow down";
        scheduler.handle(
            at(10),
            Input::Finished {
                permit: permit(dispatched.remove(0)),
                result: Attempted::Throttled,
                evidence: Some(Evidence::new(451, reply)),
                verdict: verdict(&rules, "mx.a.test.hosted.test", 451, reply),
                feedback: None,
                replied: Some(REPLIED),
            },
        );
        let out = poll_routed(&mut scheduler, at(10), hosted_route);
        let Disposition::Deferred { not_before } = outcomes(&out)[0].1.disposition else {
            panic!("deferred to the cooldown's end");
        };
        assert!(not_before.saturating_duration_since(at(10).wall) >= Duration::from_secs(7200));
        for (ticket, _) in outcomes(&out) {
            scheduler.handle(at(10), recorded(ticket));
        }
        // b.test's queue is the same site's, so it waits; other.test's does
        // not.
        let after = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(20),
            vec![delivery(2, "r2@b.test"), delivery(3, "r3@other.test")],
            hosted_route,
        );
        let sites: Vec<&str> = after
            .iter()
            .map(|dispatch| &**dispatch.site.name())
            .collect();
        assert_eq!(sites, ["mx.other.test"]);
    }

    #[test]
    fn a_rejection_that_throttles_still_rejects_and_one_that_rules_the_address_out_suppresses() {
        let rules = hosted();
        let mut scheduler = hosting(Arc::clone(&rules));
        let mut store = BTreeMap::new();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r1@a.test"), delivery(2, "r2@other.test")],
            hosted_route,
        );
        let replies = [
            (
                "mx.a.test.hosted.test",
                "5.7.1 slow down, your address is blocked",
            ),
            ("mx.other.test", "5.1.1 no such user"),
        ];
        for (dispatch, (exchange, reply)) in dispatched.into_iter().zip(replies) {
            scheduler.handle(
                at(10),
                Input::Finished {
                    permit: permit(dispatch),
                    result: Attempted::Rejected,
                    evidence: Some(Evidence::new(550, reply)),
                    verdict: verdict(&rules, exchange, 550, reply),
                    feedback: None,
                    replied: Some(REPLIED),
                },
            );
        }
        let out = poll_routed(&mut scheduler, at(10), hosted_route);
        let recorded: Vec<(Disposition, bool)> = outcomes(&out)
            .iter()
            .map(|(_, outcome)| (outcome.disposition, outcome.suppress))
            .collect();
        assert_eq!(
            recorded,
            [
                (Disposition::Rejected, false),
                (Disposition::Rejected, true)
            ]
        );
        for (ticket, _) in outcomes(&out) {
            scheduler.handle(at(10), self::recorded(ticket));
        }
        // The throttling rejection cooled Hosted down.
        let after = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(20),
            vec![delivery(3, "r3@b.test")],
            hosted_route,
        );
        assert!(after.is_empty());
    }

    #[test]
    fn an_attempt_that_finishes_as_the_store_fails_is_still_ended() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let deliveries = vec![delivery(1, "a@one.test"), delivery(2, "b@two.test")];
        let dispatched =
            dispatch_accepted(&mut scheduler, &mut store, at(0), deliveries, |domain| {
                Route::Exchanges(vec![format!("mx.{domain}")], Tls::default())
            });
        assert_eq!(dispatched.len(), 2);
        let mut permits = dispatched.into_iter().map(permit);
        let (first, second) = (permits.next().unwrap(), permits.next().unwrap());
        let ended = |output: &Output, delivery| matches!(output, Output::Ended(ended) if ended.delivery == delivery);
        let finished = |permit| Input::Finished {
            permit,
            result: Attempted::Delivered,
            evidence: None,
            verdict: None,
            feedback: None,
            replied: None,
        };
        let second_delivery = second.delivery();
        scheduler.handle(at(1), finished(second));
        let out = poll(&mut scheduler, at(1));
        assert!(out.iter().any(|output| ended(output, second_delivery)));
        // The store fails recording the second as the first finishes: the
        // first is not recorded, but it is ended, so it is counted.
        let ticket = outcomes(&out)[0].0;
        let first_delivery = first.delivery();
        scheduler.handle(
            at(2),
            Input::Answer(Response {
                ticket,
                answer: Answer::Recorded(Commit::Unavailable),
            }),
        );
        scheduler.handle(at(2), finished(first));
        let out = poll(&mut scheduler, at(2));
        assert!(scheduler.has_failed());
        assert!(
            out.iter().any(|output| ended(output, first_delivery)),
            "{out:?}"
        );
        assert!(outcomes(&out).is_empty(), "nothing is recorded");
    }

    #[test]
    fn a_refused_route_is_rejected_without_an_attempt() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let refused = delivery(1, "r@nowhere.test");
        store.insert(refused.id(), refused.clone());
        scheduler.handle(at(0), Input::Accepted(vec![accepted(refused)]));
        let out = poll_routed(&mut scheduler, at(0), |_| Route::Refused);
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(0), Input::Answer(response));
        }
        let out = poll(&mut scheduler, at(0));
        assert!(
            !out.iter()
                .any(|output| matches!(output, Output::Dispatch(_)))
        );
        let recorded = outcomes(&out);
        assert_eq!(recorded[0].1.disposition, Disposition::Rejected);
        // Ended with no site, counted as every outcome is.
        assert!(out.iter().any(|output| matches!(
            output,
            Output::Ended(Ended {
                result: Attempted::Rejected,
                site: None,
                tenant,
                ..
            }) if *tenant == origin().tenant
        )));
        scheduler.handle(at(1), self::recorded(recorded[0].0));
        poll(&mut scheduler, at(1));
        assert_eq!(scheduler.held(), 0);
    }

    #[test]
    fn an_unusable_route_waits_with_the_engines_reason() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let waiting = delivery(1, "r@withheld.test");
        store.insert(waiting.id(), waiting.clone());
        scheduler.handle(at(0), Input::Accepted(vec![accepted(waiting)]));
        let reason = "MTA-STS: the policy of withheld.test permits none of its exchanges";
        let out = poll_routed(&mut scheduler, at(0), |_| {
            Route::Unresolved(reason.to_owned())
        });
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(0), Input::Answer(response));
        }
        let out = poll(&mut scheduler, at(0));
        assert!(
            !out.iter()
                .any(|output| matches!(output, Output::Dispatch(_)))
        );
        let recorded = outcomes(&out);
        assert!(matches!(
            recorded[0].1.disposition,
            Disposition::Deferred { .. }
        ));
        assert_eq!(recorded[0].1.evidence, Some(Evidence::local(reason)));
    }

    /// A scheduler under `policy` whose build has a dispatch hook.
    fn hooked(policy: Arc<Policy>) -> Scheduler {
        let mut scheduler = under(policy);
        scheduler.config.dispatch_hook = true;
        scheduler
    }

    fn consults(outputs: &[Output]) -> Vec<(Ticket, Vec<DeliveryId>)> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Consult { ticket, recipients } => Some((
                    *ticket,
                    recipients
                        .iter()
                        .map(|recipient| recipient.delivery)
                        .collect(),
                )),
                _ => None,
            })
            .collect()
    }

    /// The reservations among `outputs`: each delivery, and the site it is
    /// reserved at, which a delivery given no attempt has none of.
    fn reservations(outputs: &[Output]) -> Vec<(DeliveryId, Option<Arc<str>>)> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Reserve(reserve),
                    ..
                }) => Some((reserve.delivery, reserve.site.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_dispatch_hook_decides_each_recipient_before_its_reservation() {
        let mut scheduler = hooked(pooled(&[(10, Some(100))]));
        let deliveries: Vec<Delivery> = (1..=3)
            .map(|n| of(1, n, &format!("r{n}@sink.test")))
            .collect();
        let ids: Vec<DeliveryId> = deliveries.iter().map(Delivery::id).collect();
        let mut store: BTreeMap<DeliveryId, Delivery> = deliveries
            .iter()
            .map(|delivery| (delivery.id(), delivery.clone()))
            .collect();
        scheduler.handle(
            at(0),
            Input::Accepted(deliveries.into_iter().map(accepted).collect()),
        );
        let out = poll_routed(&mut scheduler, at(0), sink);
        // Asked about as one transaction, and nothing reserved yet.
        assert!(reservations(&out).is_empty());
        let [(ticket, asked)] = consults(&out).try_into().expect("one question");
        assert_eq!(asked, ids);
        let report = scheduler.inspect(at(0), &Inspection::Explain(vec![ids[0]]));
        assert!(matches!(
            report,
            Report::Holds(holds) if matches!(holds[0].1, Hold::Consulting { .. })
        ));

        scheduler.handle(
            at(0),
            Input::Consulted {
                ticket,
                verdicts: vec![
                    dispatch::Verdict::Proceed,
                    dispatch::Verdict::Hold(Reason::new("later")),
                    dispatch::Verdict::Reject(Reason::new("never")),
                ],
            },
        );
        let out = poll_routed(&mut scheduler, at(0), sink);
        // The one it lets proceed is reserved at its site; the others are
        // given no attempt.
        let reserved = reservations(&out);
        assert_eq!(reserved.len(), 3);
        for (delivery, site) in &reserved {
            assert_eq!(site.is_some(), *delivery == ids[0], "{delivery:?}");
        }
        // Each from the egress chosen for it, which a hold on it covers.
        for output in &out {
            if let Output::Store(Request {
                command: Command::Reserve(reserve),
                ..
            }) = output
            {
                assert_eq!(reserve.egress, Some(egress(10)), "{reserve:?}");
            }
        }
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(0), Input::Answer(response));
        }
        let out = poll_routed(&mut scheduler, at(0), sink);
        let recorded: BTreeMap<DeliveryId, &RecordOutcome> = outcomes(&out)
            .into_iter()
            .map(|(_, outcome)| (outcome.permit.delivery(), outcome))
            .collect();
        assert_eq!(recorded.len(), 2);
        let held = recorded[&ids[1]];
        assert!(matches!(held.disposition, Disposition::Deferred { .. }));
        assert_eq!(
            held.evidence,
            Some(Evidence::held("held by the dispatch hook: later"))
        );
        let rejected = recorded[&ids[2]];
        assert_eq!(rejected.disposition, Disposition::Rejected);
        assert_eq!(
            rejected.evidence,
            Some(Evidence::local("rejected by the dispatch hook: never"))
        );
        let dispatched = dispatches(out);
        assert_eq!(dispatched.len(), 1);
        assert_eq!(
            permit(dispatched.into_iter().next().unwrap()).delivery(),
            ids[0]
        );
        // Only the one sent is counted against its egress's budget.
        let spent: u64 = scheduler
            .budgets
            .values()
            .map(|window| window.total(at(0).wall))
            .sum();
        assert_eq!(spent, 1);
    }

    #[test]
    fn a_transaction_the_dispatch_hook_holds_whole_frees_its_place() {
        let mut scheduler = hooked(pooled(&[(10, Some(100))]));
        let mut store = BTreeMap::new();
        // One connection: two transactions under way at most.
        let deliveries: Vec<Delivery> = (1..=3)
            .map(|n| of(n, n, &format!("r{n}@sink.test")))
            .collect();
        for delivery in &deliveries {
            store.insert(delivery.id(), delivery.clone());
        }
        scheduler.handle(
            at(0),
            Input::Accepted(deliveries.into_iter().map(accepted).collect()),
        );
        let out = poll_routed(&mut scheduler, at(0), sink);
        let asked = consults(&out);
        assert_eq!(asked.len(), 2, "the site's limit");
        let (ticket, _) = asked[0];
        let hold = dispatch::Verdict::Hold(Reason::new("not now"));
        scheduler.handle(
            at(0),
            Input::Consulted {
                ticket,
                verdicts: vec![hold],
            },
        );
        let out = poll_routed(&mut scheduler, at(0), sink);
        // The held one's place goes to the third, which is asked about.
        assert_eq!(consults(&out).len(), 1);
        assert_eq!(reservations(&out).len(), 1, "the held one's settlement");
        let spent: u64 = scheduler
            .budgets
            .values()
            .map(|window| window.total(at(0).wall))
            .sum();
        assert_eq!(spent, 2, "the two being asked about, not the held one");
    }

    #[test]
    fn a_drain_during_a_consultation_lets_its_bodies_go() {
        let mut scheduler = hooked(pooled(&[(10, None)]));
        let delivery = of(1, 1, "r1@sink.test");
        scheduler.handle(at(0), Input::Accepted(vec![accepted(delivery)]));
        let out = poll_routed(&mut scheduler, at(0), sink);
        assert_eq!(scheduler.body_bytes(), 7, "its body is kept");
        let (ticket, _) = consults(&out)[0];
        scheduler.handle(at(0), Input::Drain);
        scheduler.handle(
            at(0),
            Input::Consulted {
                ticket,
                verdicts: vec![dispatch::Verdict::Proceed],
            },
        );
        poll_routed(&mut scheduler, at(0), sink);
        assert!(scheduler.is_drained());
        assert_eq!((scheduler.held(), scheduler.body_bytes()), (0, 0));
    }

    #[test]
    fn a_consultation_reads_no_body_and_a_drain_during_it_reserves_nothing() {
        let mut scheduler = hooked(pooled(&[(10, None)]));
        // No room for any body: each is read back once it is to be sent.
        scheduler.config.window_bytes = 0;
        let mut store = BTreeMap::new();
        let first = of(1, 1, "r1@sink.test");
        let second = of(2, 2, "r2@other.test");
        store.insert(first.id(), first.clone());
        store.insert(second.id(), second.clone());
        scheduler.handle(
            at(0),
            Input::Accepted(vec![accepted(first.clone()), accepted(second.clone())]),
        );
        let route = |domain: &str| Route::Exchanges(vec![format!("mx.{domain}")], Tls::default());
        let out = poll_routed(&mut scheduler, at(0), route);
        let asked = consults(&out);
        assert_eq!(asked.len(), 2);
        let content_reads = |out: &[Output]| {
            out.iter()
                .filter(|output| {
                    matches!(
                        output,
                        Output::Store(Request {
                            command: Command::Content(_),
                            ..
                        })
                    )
                })
                .count()
        };
        assert_eq!(content_reads(&out), 0, "no body read before the verdict");
        scheduler.handle(
            at(0),
            Input::Consulted {
                ticket: asked[0].0,
                verdicts: vec![dispatch::Verdict::Proceed],
            },
        );
        let out = poll_routed(&mut scheduler, at(0), route);
        assert_eq!(content_reads(&out), 1, "read once it may proceed");

        // Draining, the other's verdict reserves nothing, and the scheduler
        // drains once the first's read is answered.
        scheduler.handle(at(0), Input::Drain);
        scheduler.handle(
            at(0),
            Input::Consulted {
                ticket: asked[1].0,
                verdicts: vec![dispatch::Verdict::Proceed],
            },
        );
        let out = poll_routed(&mut scheduler, at(0), route);
        assert!(reservations(&out).is_empty());
        assert!(!scheduler.is_drained(), "the first's read is outstanding");
        let read = scheduler
            .waiting
            .iter()
            .find_map(|(ticket, waiting)| {
                matches!(waiting, Waiting::Content(..)).then_some(*ticket)
            })
            .expect("the first's read");
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket: read,
                answer: Answer::Content(Ok(Some(Bytes::from_static(b"content")))),
            }),
        );
        let out = poll_routed(&mut scheduler, at(0), route);
        assert!(reservations(&out).is_empty());
        assert!(scheduler.is_drained());
        assert_eq!(scheduler.held(), 0);
    }

    /// `policy` with a hold on what `target` names.
    fn holding(policy: &Arc<Policy>, value: u64, target: Target) -> Arc<Policy> {
        let mut policy = (**policy).clone();
        policy
            .apply(Change::Hold {
                id: HoldId(Id::from_u64(value).unwrap()),
                target,
                accepting: true,
                reason: "a test's hold".to_owned(),
            })
            .unwrap();
        Arc::new(policy)
    }

    fn receipts() -> Target {
        Target::Configuration {
            account: ACCOUNT,
            name: "receipts".to_owned(),
        }
    }

    /// The read of a page of held mail among `outputs`: its ticket and
    /// where it starts.
    fn held_read(outputs: &[Output]) -> Option<(Ticket, Option<DeliveryId>)> {
        outputs.iter().find_map(|output| match output {
            Output::Store(Request {
                ticket,
                command: Command::Held { after, .. },
            }) => Some((*ticket, *after)),
            _ => None,
        })
    }

    #[test]
    fn a_reservation_a_hold_paused_lets_its_delivery_go_and_spends_nothing() {
        // A hold the scheduler has not seen yet: the store's reservation
        // decides.
        let mut scheduler = under(pooled(&[(10, Some(100))]));
        let mut store = BTreeMap::new();
        let deliveries = vec![of(1, 1, "a@sink.test"), of(1, 2, "b@sink.test")];
        for delivery in &deliveries {
            store.insert(delivery.id(), delivery.clone());
        }
        let paused = deliveries[0].id();
        scheduler.handle(
            at(0),
            Input::Accepted(deliveries.into_iter().map(accepted).collect()),
        );
        let out = poll_routed(&mut scheduler, at(0), sink);
        // The store parks the paused one in its reservation's commit.
        assert_eq!(reserved(&out)[0], paused);
        let first = first_ticket(&out);
        for response in reserve_all(&out, &mut store) {
            let answer = if response.ticket == first {
                Answer::Reserved(Commit::Committed(Reservation::Paused))
            } else {
                response.answer
            };
            scheduler.handle(
                at(0),
                Input::Answer(Response {
                    ticket: response.ticket,
                    answer,
                }),
            );
        }
        let dispatched = dispatches(poll_routed(&mut scheduler, at(0), sink));
        assert_eq!(dispatched.len(), 1);
        assert_eq!(
            dispatched[0].recipients.len(),
            1,
            "its transaction goes on without it"
        );
        assert_ne!(dispatched[0].recipients[0].0.delivery(), paused);
        assert_eq!(scheduler.held(), 1, "the paused one left memory");
        let spent: u64 = scheduler
            .budgets
            .values()
            .map(|window| window.total(at(0).wall))
            .sum();
        assert_eq!(spent, 1, "and spent none of its egress's budget");
    }

    /// The ticket of the first reservation among `outputs`.
    fn first_ticket(outputs: &[Output]) -> Ticket {
        outputs
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Reserve(_),
                }) => Some(*ticket),
                _ => None,
            })
            .expect("a reservation")
    }

    #[test]
    fn covered_mail_parks_before_it_queues_whatever_holds_up_its_dispatch() {
        // An egress with no budget for the day: nothing could be reserved.
        let mut scheduler = under(holding(&pooled(&[(10, Some(0))]), 9, receipts()));
        let covered = of(1, 1, "a@sink.test");
        scheduler.handle(at(0), Input::Accepted(vec![accepted(covered.clone())]));
        let out = poll_routed(&mut scheduler, at(0), sink);
        let parks: Vec<&Park> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Park(park),
                    ..
                }) => Some(park),
                _ => None,
            })
            .collect();
        assert_eq!(parks.len(), 1);
        assert_eq!(
            (parks[0].delivery, parks[0].egress),
            (covered.id(), Some(egress(10)))
        );
        assert_eq!(scheduler.body_bytes(), 0, "its body is let go");
        let ticket = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Park(_),
                }) => Some(*ticket),
                _ => None,
            })
            .unwrap();
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket,
                answer: Answer::Parked(Commit::Committed(())),
            }),
        );
        poll_routed(&mut scheduler, at(0), sink);
        assert_eq!(scheduler.held(), 0);
    }

    #[test]
    fn mail_parked_under_a_hold_already_lifted_starts_a_pass() {
        let mut scheduler = scheduler();
        let out = poll_with(
            &mut scheduler,
            at(0),
            &sink,
            Some(&DispatchLedger::default()),
        );
        let (ticket, _) = held_read(&out).expect("the start's pass");
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket,
                answer: Answer::Held(Ok(Vec::new())),
            }),
        );
        let mut store = BTreeMap::new();
        let delivery = delivery(1, "a@sink.test");
        store.insert(delivery.id(), delivery.clone());
        scheduler.handle(at(1), Input::Accepted(vec![accepted(delivery)]));
        let out = poll_routed(&mut scheduler, at(1), sink);
        assert!(held_read(&out).is_none());
        // The store parks it under a hold put and lifted before the
        // scheduler saw either.
        let ticket = first_ticket(&out);
        scheduler.handle(
            at(1),
            Input::Answer(Response {
                ticket,
                answer: Answer::Reserved(Commit::Committed(Reservation::Paused)),
            }),
        );
        let out = poll_routed(&mut scheduler, at(2), sink);
        assert_eq!(held_read(&out).map(|(_, after)| after), Some(None));
    }

    #[test]
    fn a_page_of_the_pass_waits_for_its_releases_before_the_next() {
        let attempts = IdGenerator::new(Shard::new(0), Lane::new(1).unwrap(), None);
        let config = Config {
            scan_page: 2,
            ..config()
        };
        let mut scheduler = Scheduler::new(config, rules(), attempts, Rng::from_seed(7));
        scheduler.handle(at(0), Input::Policy(pooled(&[(10, None)])));
        let out = poll_with(
            &mut scheduler,
            at(0),
            &sink,
            Some(&DispatchLedger::default()),
        );
        let (ticket, _) = held_read(&out).expect("the start's pass");
        let parked = |n| {
            let mut delivery = of(n, n, &format!("r{n}@sink.test"));
            delivery
                .park(delivery.generation(), None, at(0).wall)
                .unwrap();
            delivery
        };
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket,
                answer: Answer::Held(Ok(vec![parked(1), parked(2)])),
            }),
        );
        let out = poll(&mut scheduler, at(1));
        let releases: Vec<Ticket> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Release(_),
                }) => Some(*ticket),
                _ => None,
            })
            .collect();
        assert_eq!(releases.len(), 2);
        assert!(
            held_read(&out).is_none(),
            "a full page, but its releases are open"
        );
        for ticket in releases {
            scheduler.handle(
                at(1),
                Input::Answer(Response {
                    ticket,
                    answer: Answer::Released(Commit::Committed(())),
                }),
            );
        }
        let out = poll(&mut scheduler, at(2));
        let (_, after) = held_read(&out).expect("the next page");
        assert_eq!(after, Some(parked(2).id()));
    }

    /// Answers the start's pass through held mail with `page`, and returns
    /// what the scheduler asked next.
    fn start_pass(scheduler: &mut Scheduler, page: Vec<Delivery>) -> Vec<Output> {
        let out = poll_with(scheduler, at(0), &sink, Some(&DispatchLedger::default()));
        let (ticket, _) = held_read(&out).expect("the start's pass");
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket,
                answer: Answer::Held(Ok(page)),
            }),
        );
        poll(scheduler, at(1))
    }

    fn release_tickets(out: &[Output]) -> Vec<Ticket> {
        out.iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Release(_),
                }) => Some(*ticket),
                _ => None,
            })
            .collect()
    }

    fn parked_at(n: u64, egress: Option<EgressId>) -> Delivery {
        let mut delivery = of(n, n, &format!("r{n}@sink.test"));
        delivery
            .park(delivery.generation(), egress, at(0).wall)
            .unwrap();
        delivery
    }

    #[test]
    fn a_hold_lifted_while_the_last_pages_releases_are_made_starts_another_pass() {
        let address = "203.0.113.10".parse().unwrap();
        let unheld = pooled(&[(10, None)]);
        let held = holding(&unheld, 8, Target::Egress(address));
        let mut scheduler = scheduler();
        scheduler.handle(at(0), Input::Policy(Arc::clone(&held)));
        // A short page: the one its egress's hold covers stays.
        let out = start_pass(
            &mut scheduler,
            vec![parked_at(1, None), parked_at(2, Some(egress(10)))],
        );
        let releases = release_tickets(&out);
        assert_eq!(releases.len(), 1);
        scheduler.handle(at(1), Input::Policy(unheld));
        poll(&mut scheduler, at(1));
        scheduler.handle(
            at(1),
            Input::Answer(Response {
                ticket: releases[0],
                answer: Answer::Released(Commit::Committed(())),
            }),
        );
        let out = poll(&mut scheduler, at(2));
        assert_eq!(held_read(&out).map(|(_, after)| after), Some(None));
    }

    #[test]
    fn a_release_refused_for_a_hold_the_scheduler_has_not_seen_starts_another_pass() {
        let mut scheduler = scheduler();
        scheduler.handle(at(0), Input::Policy(pooled(&[(10, None)])));
        let out = start_pass(&mut scheduler, vec![parked_at(1, None)]);
        let releases = release_tickets(&out);
        scheduler.handle(
            at(1),
            Input::Answer(Response {
                ticket: releases[0],
                answer: Answer::Released(Commit::Refused(Refusal::Held)),
            }),
        );
        let out = poll(&mut scheduler, at(2));
        assert_eq!(held_read(&out).map(|(_, after)| after), Some(None));
    }

    #[test]
    fn a_cap_lowered_under_what_is_queued_puts_the_rest_off() {
        // Three queued at an egress capped at four, its site cooling.
        let mut scheduler = unadopted();
        scheduler.handle(at(0), Input::Policy(pooled(&[(10, Some(4))])));
        let ledger = DispatchLedger {
            windows: Vec::new(),
            cooldowns: vec![SiteCooldown {
                egress: Some(egress(10)),
                site: Arc::from("mx.sink.test"),
                until: at(86_400_000).wall,
                throttles: 1,
                reply: None,
            }],
        };
        let deliveries: Vec<Delivery> = (1..=3)
            .map(|n| of(n, n, &format!("r{n}@sink.test")))
            .collect();
        scheduler.handle(
            at(0),
            Input::Accepted(deliveries.iter().cloned().map(accepted).collect()),
        );
        let out = poll_with(&mut scheduler, at(0), &sink, Some(&ledger));
        assert!(
            !out.iter().any(|output| matches!(
                output,
                Output::Store(Request {
                    command: Command::Postpone(_),
                    ..
                })
            )),
            "room for all three"
        );
        // Lowered to one: the newest two are put off, the first stays.
        scheduler.handle(at(1), Input::Policy(pooled(&[(10, Some(1))])));
        let out = poll_with(&mut scheduler, at(1), &sink, Some(&ledger));
        let mut postponed: Vec<DeliveryId> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Postpone(postpone),
                    ..
                }) => Some(postpone.delivery),
                _ => None,
            })
            .collect();
        postponed.sort();
        assert_eq!(postponed, [deliveries[1].id(), deliveries[2].id()]);
        let site = (Some(egress(10)), Arc::from("mx.sink.test"));
        assert_eq!(scheduler.sites[&site].ready, 1);
        // The operator's queue shows them on the site's row.
        let Report::Queues(queues) = scheduler.inspect(at(1), &Inspection::Queues { most: 10 })
        else {
            panic!("a queue report");
        };
        let shown: Vec<(&str, usize, u64)> = queues
            .iter()
            .map(|queue| (&*queue.queue, queue.waiting, queue.put_off))
            .collect();
        assert_eq!(shown, [("mx.sink.test", 1, 2)]);
    }

    #[test]
    fn mail_whose_park_finds_no_hold_queues_against_the_caps_that_hold_now() {
        // Three parked under a hold at an egress capped at four, its site
        // cooling.
        let address = "203.0.113.10".parse().unwrap();
        let mut scheduler = unadopted();
        scheduler.handle(
            at(0),
            Input::Policy(holding(
                &pooled(&[(10, Some(4))]),
                8,
                Target::Egress(address),
            )),
        );
        let ledger = DispatchLedger {
            windows: Vec::new(),
            cooldowns: vec![SiteCooldown {
                egress: Some(egress(10)),
                site: Arc::from("mx.sink.test"),
                until: at(86_400_000).wall,
                throttles: 1,
                reply: None,
            }],
        };
        poll_with(&mut scheduler, at(0), &sink, Some(&ledger));
        let deliveries: Vec<Delivery> = (1..=3)
            .map(|n| of(n, n, &format!("r{n}@sink.test")))
            .collect();
        scheduler.handle(
            at(0),
            Input::Accepted(deliveries.iter().cloned().map(accepted).collect()),
        );
        let parks: Vec<Ticket> = poll_with(&mut scheduler, at(0), &sink, Some(&ledger))
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Park(_),
                }) => Some(*ticket),
                _ => None,
            })
            .collect();
        assert_eq!(parks.len(), 3);
        // The hold is lifted and the cap lowered to one before the store
        // answers: nothing is queued yet for the new cap to put off.
        scheduler.handle(at(1), Input::Policy(pooled(&[(10, Some(1))])));
        for ticket in parks {
            scheduler.handle(
                at(1),
                Input::Answer(Response {
                    ticket,
                    answer: Answer::Parked(Commit::Refused(Refusal::NotHeld)),
                }),
            );
        }
        // Back from the store, the first queues and the newest two are put
        // off.
        let postponed: Vec<DeliveryId> = poll_with(&mut scheduler, at(1), &sink, Some(&ledger))
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Postpone(postpone),
                    ..
                }) => Some(postpone.delivery),
                _ => None,
            })
            .collect();
        assert_eq!(postponed, [deliveries[1].id(), deliveries[2].id()]);
        let site = (Some(egress(10)), Arc::from("mx.sink.test"));
        assert_eq!(scheduler.sites[&site].ready, 1);
    }

    #[test]
    fn queued_mail_a_new_hold_covers_parks_from_its_queues_egress() {
        // Mail queued at an egress whose site cools down for the day.
        let mut scheduler = unadopted();
        scheduler.handle(at(0), Input::Policy(pooled(&[(10, None)])));
        let ledger = DispatchLedger {
            windows: Vec::new(),
            cooldowns: vec![SiteCooldown {
                egress: Some(egress(10)),
                site: Arc::from("mx.sink.test"),
                until: at(86_400_000).wall,
                throttles: 1,
                reply: None,
            }],
        };
        let deliveries: Vec<Delivery> = (1..=3)
            .map(|n| of(n, n, &format!("r{n}@sink.test")))
            .collect();
        let ids: Vec<DeliveryId> = deliveries.iter().map(Delivery::id).collect();
        scheduler.handle(
            at(0),
            Input::Accepted(deliveries.into_iter().map(accepted).collect()),
        );
        let out = poll_with(&mut scheduler, at(0), &sink, Some(&ledger));
        assert!(reserved(&out).is_empty(), "cooling, so nothing starts");
        // Another egress joins the pool as the first is held: what waits at
        // the first parks there, and never moves to the other.
        let both = pooled(&[(10, None), (11, None)]);
        let address = "203.0.113.10".parse().unwrap();
        scheduler.handle(
            at(1),
            Input::Policy(holding(&both, 8, Target::Egress(address))),
        );
        let out = poll_routed(&mut scheduler, at(1), sink);
        assert!(reserved(&out).is_empty(), "nothing goes out from the other");
        let parked: Vec<(Ticket, Park)> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Park(park),
                }) => Some((*ticket, *park)),
                _ => None,
            })
            .collect();
        assert_eq!(
            parked
                .iter()
                .map(|(_, park)| park.delivery)
                .collect::<Vec<_>>(),
            ids
        );
        assert!(
            parked
                .iter()
                .all(|(_, park)| park.egress == Some(egress(10)))
        );
        // Parked under a hold the scheduler holds, no pass is needed.
        for (ticket, _) in parked {
            scheduler.handle(
                at(1),
                Input::Answer(Response {
                    ticket,
                    answer: Answer::Parked(Commit::Committed(())),
                }),
            );
        }
        assert!(held_read(&poll_routed(&mut scheduler, at(2), sink)).is_none());
        assert_eq!(scheduler.held(), 0);
    }

    /// `policy` fenced, as a restored store's is, over every
    /// delivery up to the `n`th.
    fn fenced(policy: &Arc<Policy>, n: u64, discarding: bool) -> Arc<Policy> {
        let mut policy = (**policy).clone();
        policy.set_fence(
            Some(engine_core::policy::Fence {
                below: Id::from_u64(id_base() + n).unwrap(),
                taken: at(0).wall,
                restored: at(0).wall,
                discarding,
            }),
            true,
        );
        Arc::new(policy)
    }

    #[test]
    fn a_fence_parks_what_its_copy_held_and_once_it_holds_no_more_a_pass_releases_it() {
        let unheld = pooled(&[(10, None)]);
        let mut scheduler = scheduler();
        scheduler.handle(at(0), Input::Policy(fenced(&unheld, 5, false)));
        let out = poll_with(
            &mut scheduler,
            at(0),
            &sink,
            Some(&DispatchLedger::default()),
        );
        let (ticket, _) = held_read(&out).expect("the start's pass");
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket,
                answer: Answer::Held(Ok(Vec::new())),
            }),
        );
        // What the copy held parks before it queues; what came after goes.
        let restored = of(1, 1, "a@sink.test");
        let new = of(2, 6, "b@sink.test");
        scheduler.handle(
            at(1),
            Input::Accepted(vec![accepted(restored.clone()), accepted(new.clone())]),
        );
        let out = poll_routed(&mut scheduler, at(1), sink);
        let parked: Vec<DeliveryId> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Park(park),
                    ..
                }) => Some(park.delivery),
                _ => None,
            })
            .collect();
        assert_eq!(parked, [restored.id()]);
        assert_eq!(reserved(&out), [new.id()]);
        // Discarded, the fence holds no more: a pass releases what it held,
        // for its reservation to cancel.
        scheduler.handle(at(2), Input::Policy(fenced(&unheld, 5, true)));
        let out = poll(&mut scheduler, at(2));
        let (ticket, after) = held_read(&out).expect("a pass for the fence");
        assert_eq!(after, None);
        let mut held = restored.clone();
        held.park(held.generation(), Some(egress(10)), at(1).wall)
            .unwrap();
        scheduler.handle(
            at(2),
            Input::Answer(Response {
                ticket,
                answer: Answer::Held(Ok(vec![held.clone()])),
            }),
        );
        let out = poll(&mut scheduler, at(3));
        let released: Vec<DeliveryId> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    command: Command::Release(release),
                    ..
                }) => Some(release.delivery),
                _ => None,
            })
            .collect();
        assert_eq!(released, [held.id()]);
    }

    #[test]
    fn lifting_a_hold_releases_what_no_hold_still_covers_in_one_pass() {
        let unheld = pooled(&[(10, None)]);
        let address = "203.0.113.10".parse().unwrap();
        let both = holding(&holding(&unheld, 9, receipts()), 8, Target::Egress(address));
        let mut scheduler = scheduler();
        scheduler.handle(at(0), Input::Policy(Arc::clone(&both)));
        // Every start goes through the held mail once.
        let out = poll_with(
            &mut scheduler,
            at(0),
            &sink,
            Some(&DispatchLedger::default()),
        );
        let (ticket, after) = held_read(&out).expect("the start's pass");
        assert_eq!(after, None);
        let empty = |ticket| {
            Input::Answer(Response {
                ticket,
                answer: Answer::Held(Ok(Vec::new())),
            })
        };
        scheduler.handle(at(0), empty(ticket));
        assert!(
            held_read(&poll(&mut scheduler, at(1))).is_none(),
            "one pass"
        );

        // The configuration's hold is lifted; the egress's stays.
        let parked = |message, n, egress: Option<EgressId>| {
            let mut delivery = of(message, n, &format!("r{n}@sink.test"));
            delivery
                .park(delivery.generation(), egress, at(0).wall)
                .unwrap();
            delivery
        };
        let still_held = parked(1, 1, Some(egress(10)));
        let freed = parked(2, 2, None);
        let lifted = holding(&unheld, 8, Target::Egress(address));
        scheduler.handle(at(2), Input::Policy(Arc::clone(&lifted)));
        let out = poll(&mut scheduler, at(2));
        let (ticket, after) = held_read(&out).expect("a pass for the lifted hold");
        assert_eq!(after, None);
        // A hold put and lifted while the page is read: a second pass
        // follows the first.
        scheduler.handle(at(2), Input::Policy(holding(&lifted, 7, receipts())));
        poll(&mut scheduler, at(2));
        scheduler.handle(at(2), Input::Policy(lifted));
        poll(&mut scheduler, at(2));
        scheduler.handle(
            at(2),
            Input::Answer(Response {
                ticket,
                answer: Answer::Held(Ok(vec![still_held.clone(), freed.clone()])),
            }),
        );
        let out = poll(&mut scheduler, at(3));
        let released: Vec<(Ticket, DeliveryId)> = out
            .iter()
            .filter_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Release(release),
                }) => Some((*ticket, release.delivery)),
                _ => None,
            })
            .collect();
        assert_eq!(released.len(), 1);
        assert_eq!(
            released[0].1,
            freed.id(),
            "the egress still holds the other"
        );
        assert!(held_read(&out).is_none(), "the release is open");
        scheduler.handle(
            at(3),
            Input::Answer(Response {
                ticket: released[0].0,
                answer: Answer::Released(Commit::Committed(())),
            }),
        );
        let out = poll(&mut scheduler, at(3));
        let (ticket, after) = held_read(&out).expect("the second pass");
        assert_eq!(after, None);
        scheduler.handle(
            at(3),
            Input::Answer(Response {
                ticket,
                answer: Answer::Held(Ok(vec![still_held.clone()])),
            }),
        );
        let out = poll(&mut scheduler, at(4));
        assert!(!out.iter().any(|output| matches!(
            output,
            Output::Store(Request {
                command: Command::Release(_),
                ..
            })
        )));
        assert!(held_read(&out).is_none(), "the passes are over");
    }

    #[test]
    fn dane_routes_queue_by_domain_at_one_site() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let dane = Tls {
            dane: true,
            sts: false,
        };
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r@a.test"), delivery(2, "r@b.test")],
            |_| Route::Exchanges(vec!["mx.shared.test".to_owned()], dane),
        );
        let mut queues: Vec<(&str, Option<&str>, &str)> = dispatched
            .iter()
            .map(|dispatch| {
                (
                    &*dispatch.queue,
                    dispatch.next_hop.as_deref(),
                    &**dispatch.site.name(),
                )
            })
            .collect();
        queues.sort_unstable();
        assert_eq!(
            queues,
            [
                (
                    "mx.shared.test dane a.test",
                    Some("a.test"),
                    "mx.shared.test"
                ),
                (
                    "mx.shared.test dane b.test",
                    Some("b.test"),
                    "mx.shared.test"
                )
            ]
        );
    }

    #[test]
    fn routes_that_must_prove_different_things_queue_apart_at_one_site() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r@plain.test"), delivery(2, "r@sts.test")],
            |domain| {
                let tls = Tls {
                    dane: false,
                    sts: domain == "sts.test",
                };
                Route::Exchanges(vec!["mx.shared.test".to_owned()], tls)
            },
        );
        let mut queues: Vec<(&str, &str, bool)> = dispatched
            .iter()
            .map(|dispatch| (&*dispatch.queue, &**dispatch.site.name(), dispatch.tls.sts))
            .collect();
        queues.sort_unstable();
        assert_eq!(
            queues,
            [
                ("mx.shared.test", "mx.shared.test", false),
                ("mx.shared.test sts", "mx.shared.test", true)
            ]
        );
    }

    #[test]
    fn a_deferral_is_retried_on_the_schedule_and_leaves_memory() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![delivery(1, "r@sink.test")],
            |_| Route::Exchanges(vec!["mx.sink.test".to_owned()], Tls::default()),
        );
        scheduler.handle(
            at(5),
            Input::Finished {
                permit: permit(dispatched.into_iter().next().unwrap()),
                result: Attempted::NotSent,
                evidence: None,
                verdict: None,
                feedback: None,
                replied: None,
            },
        );
        let out = poll(&mut scheduler, at(5));
        let Disposition::Deferred { not_before } = outcomes(&out)[0].1.disposition else {
            panic!("deferred");
        };
        // The first retry comes between half the first backoff and all of it.
        let delay = not_before.saturating_duration_since(at(5).wall);
        assert!(
            delay >= Duration::from_secs(30) && delay <= Duration::from_secs(60),
            "{delay:?}"
        );
    }

    #[test]
    fn a_throttled_site_cools_down_once_then_probes_while_others_carry_on() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let exchange =
            |domain: &str| Route::Exchanges(vec![format!("mx.{domain}")], Tls::default());
        let dispatched = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(0),
            vec![
                delivery(1, "a@slow.test"),
                delivery(2, "b@slow.test"),
                delivery(3, "c@slow.test"),
            ],
            exchange,
        );
        assert_eq!(dispatched.len(), 2);

        // Both attempts under way come back throttled: one cooldown.
        for dispatch in dispatched {
            scheduler.handle(
                at(10),
                Input::Finished {
                    permit: permit(dispatch),
                    result: Attempted::Throttled,
                    evidence: None,
                    verdict: None,
                    feedback: None,
                    replied: None,
                },
            );
        }
        let out = poll(&mut scheduler, at(10));
        let deferred: Vec<Timestamp> = outcomes(&out)
            .iter()
            .map(|(_, outcome)| match outcome.disposition {
                Disposition::Deferred { not_before } => not_before,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(deferred.len(), 2);
        assert_eq!(deferred[0], deferred[1]);
        let cooldown = deferred[0].saturating_duration_since(at(10).wall);
        assert!(cooldown >= Duration::from_secs(30) && cooldown <= Duration::from_secs(60));
        for (ticket, _) in outcomes(&out) {
            scheduler.handle(at(10), recorded(ticket));
        }

        // The third waits while the site cools, and nothing about it is
        // rewritten; another site is dispatched meanwhile.
        let out = poll(&mut scheduler, at(11));
        assert!(reserved(&out).is_empty());
        let other = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(12),
            vec![delivery(4, "d@fast.test")],
            exchange,
        );
        assert_eq!(other.len(), 1);

        // Once it has cooled, one probe at a time, and after a delivered
        // probe, the site's whole limit again.
        // It waited without its content, so the content is read first.
        let after = 10_000 + cooldown.as_millis() as u64 + 1;
        let out = poll(&mut scheduler, at(after));
        let waited = delivery(3, "c@slow.test");
        let ticket = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Content(message),
                }) if *message == waited.message() => Some(*ticket),
                _ => None,
            })
            .unwrap();
        scheduler.handle(
            at(after),
            Input::Answer(Response {
                ticket,
                answer: Answer::Content(Ok(Some(Bytes::from_static(b"stored")))),
            }),
        );
        let out = poll(&mut scheduler, at(after));
        assert_eq!(reserved(&out), [waited.id()]);
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(after), Input::Answer(response));
        }
        let probe = dispatches(poll(&mut scheduler, at(after))).remove(0);
        let more = dispatch_accepted(
            &mut scheduler,
            &mut store,
            at(after),
            vec![delivery(5, "e@slow.test"), delivery(6, "f@slow.test")],
            exchange,
        );
        assert!(more.is_empty());
        scheduler.handle(
            at(after + 1),
            Input::Finished {
                permit: permit(probe),
                result: Attempted::Delivered,
                evidence: None,
                verdict: None,
                feedback: None,
                replied: None,
            },
        );
        let out = poll(&mut scheduler, at(after + 1));
        assert_eq!(reserved(&out), [delivery(5, "e@slow.test").id()]);
    }

    #[test]
    fn routes_are_kept_for_as_many_domains_as_the_window_holds_deliveries() {
        let mut scheduler = scheduler();
        for n in 1..=5 {
            let domain: Box<str> = format!("d{n}.test").into();
            scheduler
                .domains
                .insert(domain.clone(), Domain::Resolving(Vec::new()));
            scheduler.handle(
                at(0),
                Input::Resolved {
                    domain,
                    route: Route::Exchanges(vec![format!("mx.d{n}.test")], Tls::default()),
                    ttl: Duration::from_secs(3600),
                },
            );
            poll(&mut scheduler, at(0));
        }
        // The fifth found the window's four kept: half were forgotten.
        assert_eq!(scheduler.domains.len(), 3);
        assert!(scheduler.domains.contains_key("d5.test"));
    }

    #[test]
    fn the_window_bounds_what_is_held_and_a_scan_reads_what_it_left() {
        let mut scheduler = scheduler();
        let batch: Vec<Accepted> = (1..=5)
            .map(|n| accepted(delivery(n, &format!("r{n}@d{n}.test"))))
            .collect();
        scheduler.handle(at(0), Input::Accepted(batch));
        let out = poll(&mut scheduler, at(0));
        // The window holds 4, so no scan for more is made.
        assert_eq!(scheduler.held(), 4);
        assert!(!out.iter().any(|output| matches!(
            output,
            Output::Store(Request {
                command: Command::Due { .. },
                ..
            })
        )));

        // A delivery found by a scan has no content in memory: it is
        // routed, read, then reserved.
        let mut scheduler = self::scheduler();
        let out = poll(&mut scheduler, at(0));
        let ticket = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Due { limit: 10, .. },
                }) => Some(*ticket),
                _ => None,
            })
            .unwrap();
        let found = delivery(5, "r5@d5.test");
        scheduler.handle(
            at(1),
            Input::Answer(Response {
                ticket,
                answer: Answer::Due(Ok(vec![found.clone()])),
            }),
        );
        let out = poll(&mut scheduler, at(1));
        let ticket = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Content(message),
                }) if *message == found.message() => Some(*ticket),
                _ => None,
            })
            .unwrap();
        let content = Answer::Content(Ok(Some(Bytes::from_static(b"stored"))));
        scheduler.handle(
            at(2),
            Input::Answer(Response {
                ticket,
                answer: content,
            }),
        );
        let out = poll(&mut scheduler, at(2));
        assert_eq!(reserved(&out), [found.id()]);
    }

    /// The due scan the scheduler asks for in `out`: its ticket, and where
    /// it resumes.
    fn due_scan(out: &[Output]) -> (Ticket, Option<DuePosition>) {
        out.iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Due { after, .. },
                }) => Some((*ticket, *after)),
                _ => None,
            })
            .expect("a due scan")
    }

    #[test]
    fn a_scan_resumes_past_what_it_took_and_starts_again_once_nothing_is_held() {
        let mut scheduler = scheduler();
        let (ticket, after) = due_scan(&poll(&mut scheduler, at(0)));
        assert_eq!(after, None);
        let found = [delivery(1, "r1@d1.test"), delivery(2, "r2@d2.test")];
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket,
                answer: Answer::Due(Ok(found.to_vec())),
            }),
        );
        poll(&mut scheduler, at(0));
        assert_eq!(scheduler.held(), 2);
        // The next scan reads on from the second, never again the first two.
        let (_, after) = due_scan(&poll(&mut scheduler, at(1_000)));
        assert_eq!(
            after,
            Some(DuePosition {
                due_at: at(0).wall,
                delivery: found[1].id(),
            })
        );
    }

    #[test]
    fn a_body_past_the_byte_budget_waits_without_it_and_is_read_back() {
        let attempts = IdGenerator::new(Shard::new(0), Lane::new(1).unwrap(), None);
        // Room for one 7-byte body, not two.
        let config = Config {
            window_bytes: 10,
            ..config()
        };
        let mut scheduler = Scheduler::new(config, rules(), attempts, Rng::from_seed(7));
        scheduler.handle(at(0), Input::Policy(Arc::default()));
        let (first, second) = (delivery(1, "r1@d1.test"), delivery(2, "r2@d2.test"));
        let mut store: BTreeMap<DeliveryId, Delivery> = [first.clone(), second.clone()]
            .into_iter()
            .map(|delivery| (delivery.id(), delivery))
            .collect();
        scheduler.handle(
            at(0),
            Input::Accepted(vec![accepted(first.clone()), accepted(second.clone())]),
        );
        // While their routes are looked up, one body is kept and one let go.
        let mut out = Vec::new();
        scheduler.poll(at(0), &mut out);
        assert_eq!(scheduler.body_bytes(), 7, "one body kept, one let go");
        for output in out {
            match output {
                Output::Resolve(domain) => {
                    let route = Route::Exchanges(vec![format!("mx.{domain}")], Tls::default());
                    let ttl = Duration::from_secs(3600);
                    scheduler.handle(at(0), Input::Resolved { domain, route, ttl });
                }
                Output::Store(Request {
                    ticket,
                    command: Command::Dispatched,
                }) => {
                    let answer = Answer::Dispatched(Ok(DispatchLedger::default()));
                    scheduler.handle(at(0), Input::Answer(Response { ticket, answer }));
                }
                _ => {}
            }
        }
        let out = poll(&mut scheduler, at(0));
        // The first goes straight to its reservation; the second reads its
        // body back first.
        assert_eq!(reserved(&out), [first.id()]);
        let read = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Content(message),
                }) if *message == second.message() => Some(*ticket),
                _ => None,
            })
            .expect("the second's body is read back");
        for response in reserve_all(&out, &mut store) {
            scheduler.handle(at(0), Input::Answer(response));
        }
        scheduler.handle(
            at(0),
            Input::Answer(Response {
                ticket: read,
                answer: Answer::Content(Ok(Some(Bytes::from_static(b"content")))),
            }),
        );
        // The first is sent with the body it kept; the second's reservation
        // follows its read.
        let out = poll(&mut scheduler, at(0));
        let responses = reserve_all(&out, &mut store);
        let sent = dispatches(out);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].recipients[0].0.delivery(), first.id());
        for response in responses {
            scheduler.handle(at(0), Input::Answer(response));
        }
        let sent = dispatches(poll(&mut scheduler, at(0)));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].recipients[0].0.delivery(), second.id());
        assert_eq!(&sent[0].content[..], b"content");
        assert_eq!(
            scheduler.body_bytes(),
            0,
            "every body went with its attempt"
        );
    }

    #[test]
    fn recipients_of_one_message_at_one_site_share_a_transaction() {
        let mut scheduler = scheduler();
        let mut store = BTreeMap::new();
        let id = |value: u64| Id::from_u64(value).unwrap();
        let message = MessageId(id(id_base() + 5_000));
        let deliveries: Vec<Delivery> = (1..=3)
            .map(|n| {
                Delivery::new(
                    DeliveryId(id(id_base() + n)),
                    message,
                    AccountId(id(1)),
                    origin(),
                    Address::parse(&format!("r{n}@d{n}.test")).unwrap(),
                    at(0).wall,
                    at(0).wall.saturating_add(Duration::from_secs(86_400)),
                )
                .unwrap()
            })
            .collect();
        // Three domains, one receiver site.
        let shared = |_: &str| Route::Exchanges(vec!["mx.shared.test".to_owned()], Tls::default());
        let dispatched = dispatch_accepted(&mut scheduler, &mut store, at(0), deliveries, shared);
        assert_eq!(dispatched.len(), 1, "one transaction");
        let transaction = dispatched.into_iter().next().unwrap();
        assert_eq!(transaction.recipients.len(), 3);

        // Each recipient's outcome is its own; the transaction is over once
        // all three are recorded.
        for (permit, _) in transaction.recipients {
            scheduler.handle(
                at(1),
                Input::Finished {
                    permit,
                    result: Attempted::Delivered,
                    evidence: None,
                    verdict: None,
                    feedback: None,
                    replied: None,
                },
            );
        }
        let out = poll_routed(&mut scheduler, at(1), shared);
        let tickets: Vec<Ticket> = outcomes(&out).iter().map(|(ticket, _)| *ticket).collect();
        assert_eq!(tickets.len(), 3);
        for ticket in tickets {
            scheduler.handle(at(1), recorded(ticket));
        }
        poll_routed(&mut scheduler, at(1), shared);
        assert_eq!(scheduler.held(), 0);
    }

    #[test]
    fn a_failed_store_stops_the_scheduler() {
        let mut scheduler = scheduler();
        scheduler.handle(
            at(0),
            Input::Accepted(vec![accepted(delivery(1, "r@sink.test"))]),
        );
        let out = poll(&mut scheduler, at(0));
        let ticket = out
            .iter()
            .find_map(|output| match output {
                Output::Store(Request {
                    ticket,
                    command: Command::Reserve(_),
                }) => Some(*ticket),
                _ => None,
            })
            .unwrap();
        scheduler.handle(
            at(1),
            Input::Answer(Response {
                ticket,
                answer: Answer::Reserved(Commit::Unavailable),
            }),
        );
        assert!(poll(&mut scheduler, at(1)).is_empty());
        assert!(scheduler.has_failed());
    }
}
