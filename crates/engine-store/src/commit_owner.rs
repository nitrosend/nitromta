//! The commit owner: the store's one writer.
//!
//! It takes commands as they arrive and commits them in groups. Every
//! command waiting when it is polled, up to the group's limits, goes into
//! one transaction with one synchronous commit, so the sync's cost is
//! shared and nothing waits on a timer: at low load a group is one command.
//! Each command is its own atomic unit inside the group, under a savepoint,
//! so a refused command changes nothing while the rest still commit.
//! Answers go out only once their commit is durable. Outcomes go first,
//! then expiries, then bounce and complaint reports, then suppression and
//! policy changes, then reservations, then acceptances: work in flight is
//! settled before new work is admitted, and a suppression or a withdrawn
//! authority applies to the reservations behind it.
//!
//! It also trims what finished before the feedback window: a
//! bounded batch in a group that is committing anyway, or, when nothing
//! else waits, in a commit of its own once something is due.
//!
//! When storage fails, the commit owner stops. The group that failed is
//! answered as precisely as can be known, every later command is answered
//! as unavailable, and nothing more is written until the store is reopened.

use std::borrow::Borrow;
use std::collections::VecDeque;
use std::time::Duration;

use engine_core::address::Address;
use engine_core::attempt::Attempt;
use engine_core::command::{
    Accept, AcceptRefusal, Answer, Command, Commit, CooldownChange, DataKey, DuePosition, Expire,
    FeedbackRecorded, FenceDecision, Inspect, Park, ParkedEvents, Postpone, RecordOutcome, Release,
    Request, Reservation, Reserve, Response, Suppress, Unavailable, Unfenced, Unsuppress,
};
use engine_core::component::{Component, Ticket};
use engine_core::delivery::Refusal;
use engine_core::feedback::Report;
use engine_core::id::{AccountId, BodyId, DeliveryId, Id, MessageId, SubscriptionId, TenantId};
use engine_core::message::PolicyRevision;
use engine_core::policy::{Change, PolicyRefusal};
use engine_core::sts;
use engine_core::suppression;
use engine_core::time::{Monotonic, Now, Timestamp};
use rusqlite::Connection;

use crate::store::{Finishing, Store, StoreError, Trimmed, count_finished};

/// The most rows of each table one trim deletes, so a group that carries a
/// trim stays short.
const TRIM_BATCH: usize = 1_000;

/// The least time between trims that found nothing more to do.
const TRIM_EVERY: Duration = Duration::from_secs(1);

/// How much one group may hold.
#[derive(Clone, Copy, Debug)]
pub struct GroupLimits {
    pub commands: usize,
    /// Bytes of message content. An acceptance larger than this still
    /// commits, in a group of its own.
    pub content_bytes: usize,
}

/// The engine's limits: enough for every command a busy moment brings,
/// while one acceptance larger than the bytes still commits alone.
impl Default for GroupLimits {
    fn default() -> Self {
        Self {
            commands: 4096,
            content_bytes: 64 * 1024 * 1024,
        }
    }
}

pub struct CommitOwner<C> {
    store: Store<C>,
    limits: GroupLimits,
    /// Outcomes, and cooldowns kept apart from any outcome, in the order
    /// they came, so a cooldown commits no later than the outcomes it
    /// deferred.
    outcomes: VecDeque<(Ticket, Unit)>,
    expiries: VecDeque<(Ticket, Expire)>,
    reports: VecDeque<(Ticket, Report)>,
    /// Suppression and policy changes, in the order they came.
    administration: VecDeque<(Ticket, Unit)>,
    reservations: VecDeque<(Ticket, Reserve)>,
    acceptances: VecDeque<(Ticket, Accept)>,
    reads: VecDeque<(Ticket, Read)>,
    /// When the next trim is due, by the wall clock trims are decided on.
    trim_after: Timestamp,
    /// What made storage fail: the commit owner stops once it has.
    failure: Option<StoreError>,
}

#[derive(Debug)]
enum Read {
    Due {
        now: Timestamp,
        after: Option<DuePosition>,
        limit: usize,
    },
    Expiring {
        now: Timestamp,
        limit: usize,
    },
    Body(BodyId),
    Content(MessageId),
    Events {
        subscription: SubscriptionId,
        after: Option<u64>,
        until: Option<u64>,
        limit: usize,
    },
    ParkedEvents {
        account: AccountId,
        subscription: String,
        from: Option<u64>,
        limit: usize,
    },
    Dispatched,
    Evidence {
        day: u64,
    },
    TenantKey {
        tenant: TenantId,
        key: DataKey,
    },
    ForgetTenantKey(TenantId),
    KeyHeld {
        key: u8,
        from: Option<Vec<u8>>,
    },
    Inspect(Inspect),
    StsPolicies {
        now: Timestamp,
        domain: Option<Box<str>>,
        limit: usize,
    },
    Fenced,
    Held {
        after: Option<DeliveryId>,
        limit: usize,
    },
    Sent {
        account: AccountId,
        now: Timestamp,
    },
    Suppression {
        account: AccountId,
        address: Address,
    },
    Suppressions(suppression::List),
}

/// One command in a group.
enum Unit {
    Accept(Accept),
    Reserve(Reserve),
    Outcome(RecordOutcome),
    Expire(Expire),
    Park(Park),
    Release(Release),
    Postpone(Postpone),
    Feedback(Box<Report>),
    Suppress(Suppress),
    Unsuppress(Unsuppress),
    ChangePolicy(Change),
    Acknowledge {
        subscription: SubscriptionId,
        through: u64,
    },
    ParkEvents(ParkedEvents),
    UnparkEvents {
        subscription: SubscriptionId,
        first: u64,
    },
    EventsFailing {
        subscription: SubscriptionId,
        first: u64,
        since: Timestamp,
    },
    Cooldown(CooldownChange),
    Sts(sts::Policy),
    DecideFence(FenceDecision),
}

/// What applying a unit decided, before the group commits.
enum Applied {
    Accepted(Result<(), AcceptRefusal>),
    Reserved(Result<Reservation, Refusal>),
    Recorded(Result<(), Refusal>),
    Expired(Result<(), Refusal>),
    Parked(Result<(), Refusal>),
    Released(Result<(), Refusal>),
    Postponed(Result<(), Refusal>),
    Feedback(FeedbackRecorded),
    Suppressions(u64),
    Policy(Result<PolicyRevision, PolicyRefusal>),
    Acknowledged(Result<(), Refusal>),
    EventsParked(Result<(), Refusal>),
    EventsUnparked(Result<(), Refusal>),
    EventsFailing(Result<(), Refusal>),
    Cooled,
    StsKept,
    FenceDecided(Result<PolicyRevision, Unfenced>),
}

/// Where a group failed.
struct GroupFailure {
    error: StoreError,
    /// The failure came from the commit itself, so what the group changed
    /// may or may not be durable.
    at_commit: bool,
}

impl<C: Borrow<Connection>> CommitOwner<C> {
    /// Starts the commit owner, first returning every delivery whose attempt
    /// was in flight when the store last stopped to the queue. Returns
    /// those attempts, now marked abandoned.
    pub fn start(
        mut store: Store<C>,
        limits: GroupLimits,
        now: Timestamp,
    ) -> Result<(Self, Vec<Attempt>), StoreError> {
        store.execute("BEGIN IMMEDIATE")?;
        store.expire_sent(now);
        if let Err(error) = store.expire_dispatched(now) {
            let _ = store.execute("ROLLBACK");
            return Err(error);
        }
        let recovered = store
            .recover_in_flight(now)
            .and_then(|(abandoned, finished)| store.finish(&finished).map(|()| abandoned))
            .and_then(|abandoned| store.flush_sent().map(|()| abandoned));
        let abandoned = match recovered {
            Ok(abandoned) => abandoned,
            Err(error) => {
                let _ = store.execute("ROLLBACK");
                return Err(error);
            }
        };
        store.execute("COMMIT")?;
        store.settle_moves(true);
        store.commit_moves(true);
        let owner = Self {
            store,
            limits,
            outcomes: VecDeque::new(),
            expiries: VecDeque::new(),
            reports: VecDeque::new(),
            administration: VecDeque::new(),
            reservations: VecDeque::new(),
            acceptances: VecDeque::new(),
            reads: VecDeque::new(),
            trim_after: now,
            failure: None,
        };
        Ok((owner, abandoned))
    }

    pub fn store(&self) -> &Store<C> {
        &self.store
    }

    /// The store, for reads that bring its ledger up to date.
    pub fn store_mut(&mut self) -> &mut Store<C> {
        &mut self.store
    }

    pub fn has_failed(&self) -> bool {
        self.failure.is_some()
    }

    /// What made storage fail, if it has.
    pub fn failure(&self) -> Option<&StoreError> {
        self.failure.as_ref()
    }

    fn has_work(&self) -> bool {
        !(self.outcomes.is_empty()
            && self.expiries.is_empty()
            && self.reports.is_empty()
            && self.administration.is_empty()
            && self.reservations.is_empty()
            && self.acceptances.is_empty()
            && self.reads.is_empty())
    }

    /// The next group: outcomes, expiries and reservations first, then
    /// acceptances within the content budget.
    fn take_group(&mut self) -> Vec<(Ticket, Unit)> {
        let mut group = Vec::new();
        let mut content_bytes = 0;
        while group.len() < self.limits.commands {
            if let Some(unit) = self.outcomes.pop_front() {
                group.push(unit);
            } else if let Some((ticket, expire)) = self.expiries.pop_front() {
                group.push((ticket, Unit::Expire(expire)));
            } else if let Some((ticket, report)) = self.reports.pop_front() {
                group.push((ticket, Unit::Feedback(Box::new(report))));
            } else if let Some(change) = self.administration.pop_front() {
                group.push(change);
            } else if let Some((ticket, reserve)) = self.reservations.pop_front() {
                group.push((ticket, Unit::Reserve(reserve)));
            } else if let Some((_, accept)) = self.acceptances.front() {
                let size: usize = accept
                    .messages
                    .iter()
                    .map(|message| message.content.len())
                    .sum();
                if content_bytes > 0 && content_bytes + size > self.limits.content_bytes {
                    break;
                }
                content_bytes += size;
                let (ticket, accept) = self.acceptances.pop_front().expect("looked at above");
                group.push((ticket, Unit::Accept(accept)));
            } else {
                break;
            }
        }
        group
    }

    fn commit_group(&mut self, now: Now, out: &mut Vec<Response>) -> Result<(), StoreError> {
        let group = self.take_group();
        if group.is_empty() {
            return Ok(());
        }
        // A trim that is due rides the group, its time fixed here as a
        // command's is before it reaches the store.
        let trim = (now.wall >= self.trim_after).then_some(now.wall);
        let highest = group.iter().filter_map(|(_, unit)| unit.highest_id()).max();
        let undecided: Vec<(Ticket, Answer, Answer)> = group
            .iter()
            .map(|(ticket, unit)| {
                let unknown = unit.answer(Uncommitted::Unknown);
                (*ticket, unknown, unit.answer(Uncommitted::Unavailable))
            })
            .collect();
        let mut decided = Vec::with_capacity(group.len());
        match self.apply_group(group, &mut decided, highest, trim) {
            Ok(trimmed) => {
                if let Some(trimmed) = trimmed {
                    self.schedule_trim(now, &trimmed);
                }
                let answers = decided.into_iter().map(Applied::committed);
                for ((ticket, _, _), answer) in undecided.into_iter().zip(answers) {
                    out.push(Response { ticket, answer });
                }
                Ok(())
            }
            Err(failure) => {
                let _ = self.store.execute("ROLLBACK");
                let mut decided = decided.into_iter();
                for (ticket, unknown, unavailable) in undecided {
                    // A refusal changed nothing, so it stands. A change is of
                    // unknown durability only if the commit itself failed.
                    let answer = match decided.next() {
                        Some(applied) if applied.is_refusal() => applied.committed(),
                        Some(_) if failure.at_commit => unknown,
                        _ => unavailable,
                    };
                    out.push(Response { ticket, answer });
                }
                Err(failure.error)
            }
        }
    }

    fn apply_group(
        &mut self,
        group: Vec<(Ticket, Unit)>,
        decided: &mut Vec<Applied>,
        highest: Option<Id>,
        trim: Option<Timestamp>,
    ) -> Result<Option<Trimmed>, GroupFailure> {
        let before = |error| GroupFailure {
            error,
            at_commit: false,
        };
        // Moves a failed group left are not counts.
        self.store.commit_moves(false);
        self.store.execute("BEGIN IMMEDIATE").map_err(before)?;
        // Deliveries each committed unit finished, by message: a message's
        // count is written once for the group, however many finished.
        let mut finished = Finishing::new();
        for (_, unit) in group {
            self.store.execute("SAVEPOINT unit").map_err(before)?;
            let mut finishing = None;
            let applied = match unit {
                Unit::Accept(accept) => {
                    Applied::Accepted(self.store.accept(&accept).map_err(before)?)
                }
                Unit::Reserve(reserve) => {
                    let result = self.store.reserve(&reserve).map_err(before)?;
                    Applied::Reserved(result.map(|(reservation, message)| {
                        finishing = message;
                        reservation
                    }))
                }
                Unit::Suppress(suppress) => {
                    Applied::Suppressions(self.store.suppress(&suppress).map_err(before)?)
                }
                Unit::Unsuppress(unsuppress) => {
                    Applied::Suppressions(self.store.unsuppress(&unsuppress).map_err(before)?)
                }
                Unit::ChangePolicy(change) => {
                    Applied::Policy(self.store.change_policy(change).map_err(before)?)
                }
                Unit::Acknowledge {
                    subscription,
                    through,
                } => Applied::Acknowledged(
                    self.store
                        .acknowledge(subscription, through)
                        .map_err(before)?,
                ),
                Unit::ParkEvents(parked) => {
                    Applied::EventsParked(self.store.park_events(&parked).map_err(before)?)
                }
                Unit::UnparkEvents {
                    subscription,
                    first,
                } => Applied::EventsUnparked(
                    self.store
                        .unpark_events(subscription, first)
                        .map_err(before)?,
                ),
                Unit::EventsFailing {
                    subscription,
                    first,
                    since,
                } => Applied::EventsFailing(
                    self.store
                        .events_failing(subscription, first, since)
                        .map_err(before)?,
                ),
                Unit::Cooldown(change) => {
                    self.store.change_cooldown(&change).map_err(before)?;
                    Applied::Cooled
                }
                Unit::Sts(policy) => {
                    self.store.keep_sts(&policy).map_err(before)?;
                    Applied::StsKept
                }
                Unit::DecideFence(decision) => {
                    Applied::FenceDecided(self.store.decide_fence(decision).map_err(before)?)
                }
                Unit::Outcome(mut outcome) => {
                    let feedback = outcome.feedback.take();
                    let delivery = outcome.permit.delivery();
                    let result = self.store.record_outcome(outcome).map_err(before)?;
                    // A report its transport already has follows the outcome
                    // it is of, in its commit, for its delivery alone.
                    if result.is_ok()
                        && let Some(report) = feedback
                    {
                        self.store
                            .record_report_of(&report, delivery)
                            .map_err(before)?;
                    }
                    Applied::Recorded(result.map(|message| finishing = message))
                }
                Unit::Expire(expire) => {
                    let result = self.store.expire(&expire).map_err(before)?;
                    Applied::Expired(result.map(|message| finishing = Some(message)))
                }
                Unit::Park(park) => Applied::Parked(self.store.park(&park).map_err(before)?),
                Unit::Release(release) => {
                    Applied::Released(self.store.release(&release).map_err(before)?)
                }
                Unit::Postpone(postpone) => {
                    Applied::Postponed(self.store.postpone(&postpone).map_err(before)?)
                }
                Unit::Feedback(report) => {
                    Applied::Feedback(self.store.record_feedback(&report).map_err(before)?)
                }
            };
            // A refused command changes nothing, including anything it wrote
            // before it was refused.
            let close = if applied.is_refusal() {
                "ROLLBACK TO unit; RELEASE unit"
            } else {
                "RELEASE unit"
            };
            self.store.execute(close).map_err(before)?;
            self.store.settle_moves(!applied.is_refusal());
            if !applied.is_refusal()
                && let Some(message) = finishing
            {
                count_finished(&mut finished, message);
            }
            decided.push(applied);
        }
        self.store.finish(&finished).map_err(before)?;
        self.store.flush_sent().map_err(before)?;
        self.store.flush_dispatched().map_err(before)?;
        if let Some(highest) = highest {
            self.store.raise_highest_id(highest).map_err(before)?;
        }
        let trimmed = trim
            .map(|at| self.store.trim(at, TRIM_BATCH))
            .transpose()
            .map_err(before)?;
        self.store.execute("COMMIT").map_err(|error| GroupFailure {
            error,
            at_commit: true,
        })?;
        self.store.commit_moves(true);
        Ok(trimmed)
    }

    /// Trims while nothing else waits, in a commit of its own, made only if
    /// the trim deleted something.
    fn trim_alone(&mut self, now: Now) -> Result<(), StoreError> {
        self.store.execute("BEGIN IMMEDIATE")?;
        let trimmed = match self.store.trim(now.wall, TRIM_BATCH) {
            Ok(trimmed) => trimmed,
            Err(error) => {
                let _ = self.store.execute("ROLLBACK");
                return Err(error);
            }
        };
        self.store.execute(if trimmed.changed() {
            "COMMIT"
        } else {
            "ROLLBACK"
        })?;
        self.schedule_trim(now, &trimmed);
        Ok(())
    }

    /// When to trim next: at once while trims delete and a search left rows
    /// unread; [`TRIM_EVERY`] on while a search reads on and finds nothing
    /// due; else once the oldest entry left passes the window, and never
    /// sooner than [`TRIM_EVERY`].
    fn schedule_trim(&mut self, now: Now, trimmed: &Trimmed) {
        self.trim_after = if trimmed.more && trimmed.changed() {
            now.wall
        } else if trimmed.more {
            now.wall.saturating_add(TRIM_EVERY)
        } else {
            trimmed
                .oldest
                .unwrap_or(now.wall)
                .saturating_add(self.store.feedback_window())
                .max(now.wall.saturating_add(TRIM_EVERY))
        };
    }

    /// Answers waiting reads, up to the group's command limit.
    fn answer_reads(&mut self, out: &mut Vec<Response>) -> Result<(), StoreError> {
        for _ in 0..self.limits.commands {
            let Some((ticket, read)) = self.reads.pop_front() else {
                break;
            };
            let (answer, result) = match read {
                Read::Due { now, after, limit } => {
                    wrap(self.store.due(now, after, limit), Answer::Due)
                }
                Read::Expiring { now, limit } => {
                    wrap(self.store.expiring(now, limit), Answer::Expiring)
                }
                Read::Body(id) => wrap(self.store.body(id), Answer::Body),
                Read::Content(id) => wrap(self.store.content(id), Answer::Content),
                Read::Events {
                    subscription,
                    after,
                    until,
                    limit,
                } => wrap(
                    self.store.owed(subscription, after, until, limit),
                    Answer::Events,
                ),
                Read::ParkedEvents {
                    account,
                    subscription,
                    from,
                    limit,
                } => wrap(
                    self.store
                        .parked_events(account, &subscription, from, limit),
                    Answer::ParkedEvents,
                ),
                Read::Dispatched => wrap(self.store.dispatch_ledger(), Answer::Dispatched),
                Read::Evidence { day } => wrap(self.store.evidence(day), Answer::Evidence),
                Read::TenantKey { tenant, key } => {
                    self.store.add_tenant_key(tenant, &key);
                    (Answer::Keyed(Ok(())), Ok(()))
                }
                Read::ForgetTenantKey(tenant) => {
                    self.store.forget_tenant_key(tenant);
                    (Answer::Keyed(Ok(())), Ok(()))
                }
                Read::KeyHeld { key, from } => {
                    wrap(self.store.key_held(key, from.as_deref()), Answer::KeyHeld)
                }
                Read::Inspect(inspect) => wrap(self.store.inspect(inspect), Answer::Inspected),
                Read::StsPolicies { now, domain, limit } => wrap(
                    self.store.sts_policies(now, domain.as_deref(), limit),
                    Answer::StsPolicies,
                ),
                Read::Held { after, limit } => wrap(self.store.held(after, limit), Answer::Held),
                Read::Fenced => wrap(self.store.fenced(), Answer::Fenced),
                Read::Sent { account, now } => {
                    wrap(Ok(self.store.sent(account, now)), Answer::Sent)
                }
                Read::Suppression { account, address } => wrap(
                    self.store.suppression(account, &address),
                    Answer::Suppression,
                ),
                Read::Suppressions(list) => {
                    wrap(self.store.suppressions(&list), Answer::SuppressionPage)
                }
            };
            out.push(Response { ticket, answer });
            result?;
        }
        Ok(())
    }

    /// Answers everything waiting, now that the store has failed.
    fn answer_unavailable(&mut self, out: &mut Vec<Response>) {
        out.extend(self.outcomes.drain(..).map(|(ticket, unit)| Response {
            ticket,
            answer: unit.answer(Uncommitted::Unavailable),
        }));
        out.extend(self.expiries.drain(..).map(|(ticket, _)| Response {
            ticket,
            answer: Answer::Expired(Commit::Unavailable),
        }));
        out.extend(self.reports.drain(..).map(|(ticket, _)| Response {
            ticket,
            answer: Answer::Feedback(Commit::Unavailable),
        }));
        out.extend(
            self.administration
                .drain(..)
                .map(|(ticket, unit)| Response {
                    ticket,
                    answer: unit.answer(Uncommitted::Unavailable),
                }),
        );
        out.extend(self.reservations.drain(..).map(|(ticket, _)| Response {
            ticket,
            answer: Answer::Reserved(Commit::Unavailable),
        }));
        out.extend(self.acceptances.drain(..).map(|(ticket, _)| Response {
            ticket,
            answer: Answer::Accepted(Commit::Unavailable),
        }));
        out.extend(self.reads.drain(..).map(|(ticket, read)| Response {
            ticket,
            answer: match read {
                Read::Due { .. } => Answer::Due(Err(Unavailable)),
                Read::Expiring { .. } => Answer::Expiring(Err(Unavailable)),
                Read::Body(_) => Answer::Body(Err(Unavailable)),
                Read::Content(_) => Answer::Content(Err(Unavailable)),
                Read::Events { .. } => Answer::Events(Err(Unavailable)),
                Read::ParkedEvents { .. } => Answer::ParkedEvents(Err(Unavailable)),
                Read::Dispatched => Answer::Dispatched(Err(Unavailable)),
                Read::Evidence { .. } => Answer::Evidence(Err(Unavailable)),
                Read::TenantKey { .. } | Read::ForgetTenantKey(_) => {
                    Answer::Keyed(Err(Unavailable))
                }
                Read::KeyHeld { .. } => Answer::KeyHeld(Err(Unavailable)),
                Read::Inspect(_) => Answer::Inspected(Err(Unavailable)),
                Read::StsPolicies { .. } => Answer::StsPolicies(Err(Unavailable)),
                Read::Held { .. } => Answer::Held(Err(Unavailable)),
                Read::Fenced => Answer::Fenced(Err(Unavailable)),
                Read::Sent { .. } => Answer::Sent(Err(Unavailable)),
                Read::Suppression { .. } => Answer::Suppression(Err(Unavailable)),
                Read::Suppressions(_) => Answer::SuppressionPage(Err(Unavailable)),
            },
        }));
    }
}

impl<C: Borrow<Connection>> Component for CommitOwner<C> {
    type Input = Request;
    type Output = Response;

    fn handle(&mut self, _now: Now, request: Request) {
        let Request { ticket, command } = request;
        match command {
            Command::Accept(accept) => self.acceptances.push_back((ticket, accept)),
            Command::Reserve(reserve) => self.reservations.push_back((ticket, reserve)),
            Command::RecordOutcome(outcome) => {
                self.outcomes.push_back((ticket, Unit::Outcome(outcome)));
            }
            Command::Expire(expire) => self.expiries.push_back((ticket, expire)),
            Command::Park(park) => self.outcomes.push_back((ticket, Unit::Park(park))),
            Command::Release(release) => {
                self.outcomes.push_back((ticket, Unit::Release(release)));
            }
            Command::Postpone(postpone) => {
                self.outcomes.push_back((ticket, Unit::Postpone(postpone)));
            }
            Command::Held { after, limit } => {
                self.reads.push_back((ticket, Read::Held { after, limit }));
            }
            Command::RecordFeedback(report) => self.reports.push_back((ticket, report)),
            Command::Suppress(suppress) => self
                .administration
                .push_back((ticket, Unit::Suppress(suppress))),
            Command::Unsuppress(unsuppress) => self
                .administration
                .push_back((ticket, Unit::Unsuppress(unsuppress))),
            Command::ChangePolicy(change) => self
                .administration
                .push_back((ticket, Unit::ChangePolicy(change))),
            Command::Due { now, after, limit } => self
                .reads
                .push_back((ticket, Read::Due { now, after, limit })),
            Command::Expiring { now, limit } => self
                .reads
                .push_back((ticket, Read::Expiring { now, limit })),
            Command::Body(id) => self.reads.push_back((ticket, Read::Body(id))),
            Command::Content(id) => self.reads.push_back((ticket, Read::Content(id))),
            Command::Events {
                subscription,
                after,
                until,
                limit,
            } => self.reads.push_back((
                ticket,
                Read::Events {
                    subscription,
                    after,
                    until,
                    limit,
                },
            )),
            Command::ParkedEvents {
                account,
                subscription,
                from,
                limit,
            } => self.reads.push_back((
                ticket,
                Read::ParkedEvents {
                    account,
                    subscription,
                    from,
                    limit,
                },
            )),
            Command::EventsFailing {
                subscription,
                first,
                since,
            } => self.administration.push_back((
                ticket,
                Unit::EventsFailing {
                    subscription,
                    first,
                    since,
                },
            )),
            Command::ParkEvents(parked) => self
                .administration
                .push_back((ticket, Unit::ParkEvents(parked))),
            Command::UnparkEvents {
                subscription,
                first,
            } => self.administration.push_back((
                ticket,
                Unit::UnparkEvents {
                    subscription,
                    first,
                },
            )),
            Command::Dispatched => self.reads.push_back((ticket, Read::Dispatched)),
            Command::Evidence { day } => self.reads.push_back((ticket, Read::Evidence { day })),
            Command::TenantKey { tenant, key } => {
                self.reads
                    .push_back((ticket, Read::TenantKey { tenant, key }));
            }
            Command::ForgetTenantKey(tenant) => {
                self.reads
                    .push_back((ticket, Read::ForgetTenantKey(tenant)));
            }
            Command::KeyHeld { key, from } => {
                self.reads.push_back((ticket, Read::KeyHeld { key, from }));
            }
            Command::Cooldown(change) => self.outcomes.push_back((ticket, Unit::Cooldown(change))),
            Command::Inspect(inspect) => self.reads.push_back((ticket, Read::Inspect(inspect))),
            Command::KeepSts(policy) => self.outcomes.push_back((ticket, Unit::Sts(policy))),
            Command::StsPolicies { now, domain, limit } => {
                self.reads
                    .push_back((ticket, Read::StsPolicies { now, domain, limit }));
            }
            Command::Acknowledge {
                subscription,
                through,
            } => self.administration.push_back((
                ticket,
                Unit::Acknowledge {
                    subscription,
                    through,
                },
            )),
            Command::DecideFence(decision) => self
                .administration
                .push_back((ticket, Unit::DecideFence(decision))),
            Command::Fenced => self.reads.push_back((ticket, Read::Fenced)),
            Command::Sent { account, now } => {
                self.reads.push_back((ticket, Read::Sent { account, now }));
            }
            Command::Suppression { account, address } => {
                let read = Read::Suppression { account, address };
                self.reads.push_back((ticket, read));
            }
            Command::Suppressions(list) => {
                self.reads.push_back((ticket, Read::Suppressions(list)));
            }
        }
    }

    fn poll(&mut self, now: Now, out: &mut Vec<Response>) -> Option<Monotonic> {
        if self.failure.is_none() {
            self.failure = self.commit_group(now, out).err();
        }
        if self.failure.is_none() {
            self.failure = self.answer_reads(out).err();
        }
        if self.failure.is_none() && !self.has_work() && now.wall >= self.trim_after {
            self.failure = self.trim_alone(now).err();
        }
        if self.failure.is_some() {
            self.answer_unavailable(out);
            return None;
        }
        // The wake for the next trim is taken from the clocks each time, so
        // a wall clock that stepped back delays it and never spins.
        let wait = self.trim_after.saturating_duration_since(now.wall);
        Some(now.monotonic.saturating_add(if self.has_work() {
            Duration::ZERO
        } else {
            wait
        }))
    }
}

impl Unit {
    /// The highest ID it creates, which the high-water mark must cover.
    fn highest_id(&self) -> Option<Id> {
        match self {
            Self::Accept(accept) => accept
                .messages
                .iter()
                .flat_map(|message| {
                    let deliveries = message
                        .recipients
                        .iter()
                        .map(|recipient| recipient.delivery.0);
                    [message.id.0, message.body.0].into_iter().chain(deliveries)
                })
                .chain([accept.submission.0])
                .max(),
            Self::Reserve(reserve) => Some(reserve.attempt.0),
            Self::Feedback(report) => Some(report.id.0),
            Self::ChangePolicy(change) => change.created(),
            Self::Outcome(_)
            | Self::Expire(_)
            | Self::Park(_)
            | Self::Release(_)
            | Self::Postpone(_)
            | Self::Suppress(_)
            | Self::Unsuppress(_)
            | Self::Acknowledge { .. }
            | Self::ParkEvents(_)
            | Self::UnparkEvents { .. }
            | Self::EventsFailing { .. }
            | Self::Cooldown(_)
            | Self::Sts(_)
            | Self::DecideFence(_) => None,
        }
    }

    /// Its answer when its group did not commit.
    fn answer(&self, uncommitted: Uncommitted) -> Answer {
        match self {
            Self::Accept(_) => Answer::Accepted(uncommitted.commit()),
            Self::Reserve(_) => Answer::Reserved(uncommitted.commit()),
            Self::Outcome(_) => Answer::Recorded(uncommitted.commit()),
            Self::Expire(_) => Answer::Expired(uncommitted.commit()),
            Self::Park(_) => Answer::Parked(uncommitted.commit()),
            Self::Release(_) => Answer::Released(uncommitted.commit()),
            Self::Postpone(_) => Answer::Postponed(uncommitted.commit()),
            Self::Feedback(_) => Answer::Feedback(uncommitted.commit()),
            Self::Suppress(_) | Self::Unsuppress(_) => Answer::Suppressions(uncommitted.commit()),
            Self::ChangePolicy(_) => Answer::Policy(uncommitted.commit()),
            Self::Acknowledge { .. } => Answer::Acknowledged(uncommitted.commit()),
            Self::ParkEvents(_) => Answer::EventsParked(uncommitted.commit()),
            Self::UnparkEvents { .. } => Answer::EventsUnparked(uncommitted.commit()),
            Self::EventsFailing { .. } => Answer::EventsFailing(uncommitted.commit()),
            Self::Cooldown(_) => Answer::Cooled(uncommitted.commit()),
            Self::Sts(_) => Answer::StsKept(uncommitted.commit()),
            Self::DecideFence(_) => Answer::FenceDecided(uncommitted.commit()),
        }
    }
}

/// Why a command's group did not commit.
#[derive(Clone, Copy)]
enum Uncommitted {
    /// The commit itself failed.
    Unknown,
    /// Storage failed before the commit.
    Unavailable,
}

impl Uncommitted {
    fn commit<T, R>(self) -> Commit<T, R> {
        match self {
            Self::Unknown => Commit::Unknown,
            Self::Unavailable => Commit::Unavailable,
        }
    }
}

impl Applied {
    fn is_refusal(&self) -> bool {
        match self {
            Self::Accepted(result) => result.is_err(),
            Self::Reserved(result) => result.is_err(),
            Self::Recorded(result)
            | Self::Expired(result)
            | Self::Parked(result)
            | Self::Released(result)
            | Self::Postponed(result)
            | Self::EventsParked(result)
            | Self::EventsUnparked(result)
            | Self::EventsFailing(result)
            | Self::Acknowledged(result) => result.is_err(),
            Self::Policy(result) => result.is_err(),
            Self::FenceDecided(result) => result.is_err(),
            Self::Suppressions(_) | Self::Feedback(_) | Self::Cooled | Self::StsKept => false,
        }
    }

    /// Its answer once the group has committed.
    fn committed(self) -> Answer {
        fn commit<T, R>(result: Result<T, R>) -> Commit<T, R> {
            match result {
                Ok(value) => Commit::Committed(value),
                Err(refusal) => Commit::Refused(refusal),
            }
        }
        match self {
            Self::Accepted(result) => Answer::Accepted(commit(result)),
            Self::Reserved(result) => Answer::Reserved(commit(result)),
            Self::Recorded(result) => Answer::Recorded(commit(result)),
            Self::Expired(result) => Answer::Expired(commit(result)),
            Self::Parked(result) => Answer::Parked(commit(result)),
            Self::Released(result) => Answer::Released(commit(result)),
            Self::Postponed(result) => Answer::Postponed(commit(result)),
            Self::Suppressions(changed) => Answer::Suppressions(Commit::Committed(changed)),
            Self::Feedback(recorded) => Answer::Feedback(Commit::Committed(recorded)),
            Self::Policy(result) => Answer::Policy(commit(result)),
            Self::Acknowledged(result) => Answer::Acknowledged(commit(result)),
            Self::EventsParked(result) => Answer::EventsParked(commit(result)),
            Self::EventsUnparked(result) => Answer::EventsUnparked(commit(result)),
            Self::EventsFailing(result) => Answer::EventsFailing(commit(result)),
            Self::Cooled => Answer::Cooled(Commit::Committed(())),
            Self::StsKept => Answer::StsKept(Commit::Committed(())),
            Self::FenceDecided(result) => Answer::FenceDecided(commit(result)),
        }
    }
}

/// A read's answer, and whether the store failed answering it.
fn wrap<T>(
    result: Result<T, StoreError>,
    answer: fn(Result<T, Unavailable>) -> Answer,
) -> (Answer, Result<(), StoreError>) {
    match result {
        Ok(value) => (answer(Ok(value)), Ok(())),
        Err(error) => (answer(Err(Unavailable)), Err(error)),
    }
}
