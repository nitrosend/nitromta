//! Commands to the commit owner, and its answers.
//!
//! Every ID, timestamp and random value in a command is fixed before it
//! reaches the commit owner, so applying it reads no clock or outside
//! state, and the ordered stream of commands is a log that a replica could
//! apply in turn. A command that changes state carries the IDs of what it
//! creates, so applying it twice changes nothing the second time.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::address::Address;
use crate::attempt::Evidence;
use crate::budget::{Counts, Signal, Window};
use crate::component::Ticket;
use crate::delivery::{Delivery, DispatchPermit, Disposition, Generation, Refusal};
use crate::feedback::Report;
use crate::id::{
    AccountId, AttemptId, BodyId, CredentialId, DeliveryId, EgressId, IdGenerator, MessageId,
    SubmissionId, SubscriptionId, TemplateId, TenantId,
};
use crate::journal::Entry;
use crate::message::{Mail, PolicyRevision};
use crate::policy::{Change, Denial, Fence, Hold, Origin, PolicyRefusal, Target};
use crate::sts;
use crate::suppression::{self, Reason};
use crate::time::Timestamp;

/// A command, with the ticket its answer goes back under.
#[derive(Debug)]
pub struct Request {
    pub ticket: Ticket,
    pub command: Command,
}

/// The most recipients one message may have. Every adapter keeps to it,
/// and the store holds them to it, so the deliveries a report finds are
/// within a known span of IDs.
pub const MAX_RECIPIENTS: usize = 10_000;

#[derive(Debug)]
pub enum Command {
    Accept(Accept),
    Reserve(Reserve),
    RecordOutcome(RecordOutcome),
    Expire(Expire),
    /// Parks a waiting delivery a hold covers before its reservation,
    /// refused if none does.
    Park(Park),
    /// Releases a held delivery no hold covers any longer, refused while
    /// one does.
    Release(Release),
    /// Puts off a waiting delivery whose egress has no room for it now,
    /// keeping that egress.
    Postpone(Postpone),
    /// Adds addresses to an account's suppression list, or replaces their
    /// reason.
    Suppress(Suppress),
    /// Removes addresses from an account's suppression list.
    Unsuppress(Unsuppress),
    /// Changes policy, answered with the revision it made. The commit owner
    /// holds the policy, and the shell publishes each committed revision.
    ChangePolicy(Change),
    /// Waiting deliveries whose next attempt is due by `now`, earliest
    /// first, from just past `after`: a scan resumes where the last one
    /// stopped rather than reading again what it already took.
    Due {
        now: Timestamp,
        after: Option<DuePosition>,
        limit: usize,
    },
    /// Waiting and held deliveries whose expiry has passed by `now`,
    /// earliest first.
    Expiring {
        now: Timestamp,
        limit: usize,
    },
    /// Held deliveries by ID, from just past `after`: the pass
    /// that releases what no hold covers any longer.
    Held {
        after: Option<DeliveryId>,
        limit: usize,
    },
    Body(BodyId),
    /// A message's prepared content, for a delivery whose content is not
    /// in memory.
    Content(MessageId),
    /// The events a subscription owes from the journal, reading
    /// at most `limit` entries past `after`, or past its cursor if `after`
    /// is absent, and none past `until` if it is given.
    Events {
        subscription: SubscriptionId,
        after: Option<u64>,
        until: Option<u64>,
        limit: usize,
    },
    /// Parks a batch of a subscription's events past its budget:
    /// its span is recorded, and its cursor moved past it, in one
    /// commit.
    ParkEvents(ParkedEvents),
    /// A subscription's parked batches, the subscription named in its
    /// account, oldest first: at most `limit`, from the one whose first
    /// event is at `from` or the next after it.
    ParkedEvents {
        account: AccountId,
        subscription: String,
        from: Option<u64>,
        limit: usize,
    },
    /// The batch whose first event is at `first` first failed at `since`:
    /// its budget runs from then, across restarts, until the
    /// cursor moves past it. Nothing if the cursor already has.
    EventsFailing {
        subscription: SubscriptionId,
        first: u64,
        since: Timestamp,
    },
    /// Removes a parked batch, a replay of which was taken.
    UnparkEvents {
        subscription: SubscriptionId,
        first: u64,
    },
    /// Every event a subscription owed up to `through` was delivered: its
    /// cursor moves there, and never back.
    Acknowledge {
        subscription: SubscriptionId,
        through: u64,
    },
    /// The dispatch ledger's windows and the sites' cooldowns, which the
    /// scheduler starts from.
    Dispatched,
    /// Each (egress, site)'s warmup evidence on the UTC day `day`, days
    /// since the Unix epoch.
    Evidence {
        day: u64,
    },
    /// Seals `tenant`'s mail under `key` from now on, while per-tenant keys
    /// are on, and opens what it sealed. The store keeps the key
    /// in memory alone: its file is the shell's.
    TenantKey {
        tenant: TenantId,
        key: DataKey,
    },
    /// Forgets `tenant`'s key, once the tenant is removed: what it sealed
    /// reads as erased.
    ForgetTenantKey(TenantId),
    /// A page of the scan for the records still sealed under installation
    /// key `key`, from where the last page left off, or from the start:
    /// what decides whether the key may be retired.
    KeyHeld {
        key: u8,
        from: Option<Vec<u8>>,
    },
    /// A site's cooldown changed outside any attempt's outcome: a session's
    /// refusal throttled it, or the scheduler forgot it.
    Cooldown(CooldownChange),
    /// A bounce or complaint report, recorded with what it proves about
    /// its message's deliveries.
    RecordFeedback(Report),
    /// A delivery, or a message's deliveries, as they stand, for the
    /// operator's `explain`.
    Inspect(Inspect),
    /// A domain's MTA-STS policy, as delivery fetched it: the store keeps
    /// it in place of an older fetch's until it runs out.
    KeepSts(sts::Policy),
    /// The MTA-STS policies the store keeps that still hold at `now`:
    /// `domain`'s alone, if one is named; else those fetched last, at most
    /// `limit`, which delivery starts from.
    StsPolicies {
        now: Timestamp,
        domain: Option<Box<str>>,
        limit: usize,
    },
    /// The operator's decision on a restored store's fence,
    /// answered with the policy revision it made: refused if the store has
    /// no fence.
    DecideFence(FenceDecision),
    /// The store's fence, if it has one, and how many deliveries it covers
    /// that are not finished.
    Fenced,
    /// The recipients `account` accepted in the 24 hours up to `now`, as
    /// its daily quota counts them.
    Sent {
        account: AccountId,
        now: Timestamp,
    },
    /// Whether `address` is on `account`'s suppression list, and why.
    Suppression {
        account: AccountId,
        address: Address,
    },
    /// A page of an account's suppression list.
    Suppressions(suppression::List),
}

/// The operator's decision on a fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceDecision {
    /// The fence goes, and each delivery it held is sent as it is due,
    /// whether or not it was delivered after the copy was taken.
    Release,
    /// Each delivery it covers is cancelled as it falls due, unsent.
    Discard,
}

/// The store has no fence to decide on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unfenced;

/// What `Command::Inspect` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inspect {
    Delivery(DeliveryId),
    Message(MessageId),
}

/// An answer, under the ticket of the command it answers.
#[derive(Debug)]
pub struct Response {
    pub ticket: Ticket,
    pub answer: Answer,
}

#[derive(Debug)]
pub enum Answer {
    Accepted(Commit<(), AcceptRefusal>),
    Reserved(Commit<Reservation, Refusal>),
    Recorded(Commit<(), Refusal>),
    Expired(Commit<(), Refusal>),
    Parked(Commit<(), Refusal>),
    Released(Commit<(), Refusal>),
    Postponed(Commit<(), Refusal>),
    /// How many suppressions the change added, replaced or removed. A
    /// suppression change is never refused.
    Suppressions(Commit<u64, Infallible>),
    Policy(Commit<PolicyRevision, PolicyRefusal>),
    Due(Result<Vec<Delivery>, Unavailable>),
    Expiring(Result<Vec<Delivery>, Unavailable>),
    Held(Result<Vec<Delivery>, Unavailable>),
    Body(Result<Option<Bytes>, Unavailable>),
    Content(Result<Option<Bytes>, Unavailable>),
    /// None if there is no such subscription.
    Events(Result<Option<Owed>, Unavailable>),
    /// Refused with [`Refusal::Gone`] if there is no such subscription.
    Acknowledged(Commit<(), Refusal>),
    /// Refused with [`Refusal::Gone`] if there is no such subscription.
    EventsParked(Commit<(), Refusal>),
    /// The subscription's ID and its parked batches, oldest first; none if
    /// there is no such subscription.
    ParkedEvents(Result<Option<(SubscriptionId, Vec<ParkedEvents>)>, Unavailable>),
    /// Refused with [`Refusal::Gone`] if there is no such parked batch.
    EventsUnparked(Commit<(), Refusal>),
    /// Refused with [`Refusal::Gone`] if there is no such subscription.
    EventsFailing(Commit<(), Refusal>),
    Dispatched(Result<DispatchLedger, Unavailable>),
    Evidence(Result<DayEvidence, Unavailable>),
    Keyed(Result<(), Unavailable>),
    KeyHeld(Result<KeyHeld, Unavailable>),
    Cooled(Commit<(), Infallible>),
    /// A report is never refused: one received before changes nothing.
    Feedback(Commit<FeedbackRecorded, Infallible>),
    /// The deliveries an inspection found: none if there are none.
    Inspected(Result<Vec<Inspected>, Unavailable>),
    StsKept(Commit<(), Infallible>),
    StsPolicies(Result<Vec<sts::Policy>, Unavailable>),
    FenceDecided(Commit<PolicyRevision, Unfenced>),
    /// The fence, and the unfinished deliveries it covers.
    Fenced(Result<Option<(Fence, u64)>, Unavailable>),
    Sent(Result<u64, Unavailable>),
    Suppression(Result<Option<suppression::Suppressed>, Unavailable>),
    SuppressionPage(Result<suppression::Page, Unavailable>),
}

/// A delivery an inspection found, with what the receiver said when its
/// last attempt ended without delivering it, while the journal keeps that,
/// and the hold that pauses it, if it is held, with what the hold is on as
/// a release names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspected {
    pub delivery: Delivery,
    pub reply: Option<Evidence>,
    pub hold: Option<(Hold, Target)>,
    /// The restored store's fence, if it covers this unfinished delivery.
    pub fence: Option<Fence>,
}

/// What recording a report did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedbackRecorded {
    /// It was received before and had no effect it had not had.
    pub duplicate: bool,
    /// The deliveries of its message it had an effect on.
    pub deliveries: u32,
    /// The recipients it suppressed.
    pub suppressed: u32,
    /// Each effect of a trusted report the first time it had it, for the
    /// counts.
    pub effects: Vec<Reported>,
    /// It named no message the engine sent, and the quarantine for such
    /// reports was full, so it was not kept.
    pub unkept: bool,
}

/// A report's first effect on a delivery: a bounce or a complaint, and
/// where its delivery went out from and for whom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported {
    pub complaint: bool,
    pub egress: Option<EgressId>,
    pub tenant: Option<TenantId>,
}

/// What a subscription owes from part of the journal.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Owed {
    /// The entries it owes, in order, each at its position.
    pub entries: Vec<(u64, Entry)>,
    /// Each of those entries' deliveries: its message and recipient. A
    /// delivery whose record is gone is absent.
    pub deliveries: BTreeMap<DeliveryId, (MessageId, Address)>,
    /// For a topic's subscriber, what was kept of each of their messages
    /// for SES's shape: a message with none kept is absent.
    pub mailed: BTreeMap<MessageId, Mailed>,
    /// The last position read, owed or not, which its cursor may move to
    /// once the entries are delivered.
    pub through: u64,
    /// When the batch at its cursor first failed, if it is failing: given
    /// only to a read from the cursor whose first entry is that batch's.
    pub failing_since: Option<Timestamp>,
}

/// A message as SES-shaped events say it: when it was accepted, and what
/// was kept of it, if its configuration published as it was accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailed {
    pub accepted_at: Timestamp,
    pub mail: Option<Mail>,
}

/// A batch of a subscription's events parked past its budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedEvents {
    pub subscription: SubscriptionId,
    /// The journal positions of its first event and of the last entry it
    /// covers.
    pub first: u64,
    pub through: u64,
    /// When it was parked, the posts it had, and why its last failed.
    pub at: Timestamp,
    pub attempts: u32,
    pub failure: String,
}

/// A waiting delivery's place in the order the due scan reads: by due time,
/// then by ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DuePosition {
    pub due_at: Timestamp,
    pub delivery: DeliveryId,
}

/// What became of a command that changes state.
#[derive(Debug, PartialEq, Eq)]
pub enum Commit<T, R> {
    /// It is durable.
    Committed(T),
    /// It was refused, and changed nothing.
    Refused(R),
    /// Storage failed as it was committed, so it may or may not be durable.
    Unknown,
    /// It was not applied, because the store has failed. It is safe to send
    /// again once the store is reopened.
    Unavailable,
}

/// The store has failed, and answers no reads until it is reopened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unavailable;

/// What a submission was accepted under: the credential that submitted it
/// for its account, the origin policy resolved for it, and the revision of
/// policy that decided both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authority {
    pub account: AccountId,
    pub credential: CredentialId,
    pub origin: Origin,
    pub revision: PolicyRevision,
    /// The kept template its content was rendered from, if any, which its
    /// tenant must still be able to send with.
    pub template: Option<TemplateId>,
}

/// The first commit point: a submission's messages and their deliveries,
/// accepted together or not at all.
#[derive(Clone, Debug)]
pub struct Accept {
    pub submission: SubmissionId,
    pub authority: Authority,
    pub accepted_at: Timestamp,
    /// When its deliveries expire, if they have not finished.
    pub expires_at: Timestamp,
    pub messages: Vec<AcceptMessage>,
}

impl Accept {
    /// A submission of `messages` under `authority`, accepted at `now` and
    /// expiring `lifetime` later. Its ID is drawn from `ids`.
    pub fn new(
        authority: Authority,
        messages: Vec<AcceptMessage>,
        ids: &mut IdGenerator,
        now: Timestamp,
        lifetime: Duration,
    ) -> Self {
        Self {
            submission: SubmissionId(ids.next(now)),
            authority,
            accepted_at: now,
            expires_at: now.saturating_add(lifetime),
            messages,
        }
    }

    /// The delivery this acceptance creates for `recipient` of `message`,
    /// exactly as the store records it: ready from acceptance until it
    /// expires. `None` if it would expire as it is accepted.
    pub fn delivery(&self, message: &AcceptMessage, recipient: &Recipient) -> Option<Delivery> {
        Delivery::new(
            recipient.delivery,
            message.id,
            self.authority.account,
            self.authority.origin,
            recipient.address.clone(),
            self.accepted_at,
            self.expires_at,
        )
    }
}

#[derive(Clone, Debug)]
pub struct AcceptMessage {
    pub id: MessageId,
    pub body: BodyId,
    /// The prepared message, exactly as it is sent.
    pub content: Bytes,
    pub recipients: Vec<Recipient>,
    /// What SES-shaped events will say of it, if its configuration
    /// publishes them.
    pub mail: Option<Mail>,
}

impl AcceptMessage {
    /// Prepared content as message `id`, with a delivery for each recipient.
    /// Its body and delivery IDs are drawn from `ids` one after another, so
    /// the deliveries are the first IDs of `ids`'s lane above the body's:
    /// how a report finds the deliveries of the message it names.
    pub fn new(
        id: MessageId,
        content: Bytes,
        recipients: &[Address],
        mail: Option<Mail>,
        ids: &mut IdGenerator,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            body: BodyId(ids.next(now)),
            content,
            mail,
            recipients: recipients
                .iter()
                .map(|address| Recipient {
                    delivery: DeliveryId(ids.next(now)),
                    address: address.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Recipient {
    pub delivery: DeliveryId,
    pub address: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptRefusal {
    NoMessages,
    NoRecipients,
    /// A message has more than [`MAX_RECIPIENTS`].
    TooManyRecipients,
    /// It would expire as soon as it was accepted.
    ExpiresAtAcceptance,
    /// Some of its IDs are taken by something else.
    Conflict,
    /// Policy changed after it was authorised, and no longer allows it.
    Unauthorised(Denial),
    /// Its account has accepted its daily quota of recipients.
    QuotaExceeded,
}

/// The second commit point: a delivery reserved for an attempt. The permit
/// to send it is answered only once the reservation is durable.
#[derive(Clone, Debug)]
pub struct Reserve {
    pub delivery: DeliveryId,
    /// The generation the caller's view of the delivery was taken at.
    pub seen: Generation,
    pub attempt: AttemptId,
    /// The egress it goes out from, which it keeps: the host's own address
    /// when absent.
    pub egress: Option<EgressId>,
    /// The receiver site it goes to, whose budget at an egress with a cap
    /// the reservation counts against. Absent for a delivery
    /// whose route gives it no attempt.
    pub site: Option<Arc<str>>,
    pub now: Timestamp,
}

/// What a reservation committed: a permit to send; or the delivery
/// finished without an attempt, because its recipient is suppressed or its
/// authority was withdrawn; or a hold pauses it, and it is parked until the
/// hold is lifted.
#[derive(Debug)]
pub enum Reservation {
    Permit(DispatchPermit),
    Suppressed,
    Cancelled,
    Paused,
}

#[derive(Debug)]
pub struct Suppress {
    pub account: AccountId,
    pub addresses: Vec<Address>,
    pub reason: Reason,
    pub now: Timestamp,
}

#[derive(Debug)]
pub struct Unsuppress {
    pub account: AccountId,
    pub addresses: Vec<Address>,
}

/// The third commit point: what an attempt did.
#[derive(Debug)]
pub struct RecordOutcome {
    pub permit: DispatchPermit,
    pub disposition: Disposition,
    /// What the receiver last said, if it said anything.
    pub evidence: Option<Evidence>,
    /// A rejection whose reply rules the address out, by the receiver rules:
    /// the recipient is suppressed in the outcome's commit.
    pub suppress: bool,
    /// How its site's cooldown changed with it, kept in the outcome's
    /// commit so a restart keeps it too.
    pub cooled: Option<CooldownChange>,
    /// A report of the attempt its transport already has, recorded in the
    /// outcome's commit after it, for its delivery alone, unless the
    /// outcome is refused: the mailbox simulator's complaint.
    pub feedback: Option<Box<Report>>,
    /// What the receiver's reply showed at its site, for warmup to count:
    /// given for an attempt from an egress capped there.
    pub counted: Option<Counted>,
    pub now: Timestamp,
}

/// A page of a key's scan: how many records of `table` in it are still
/// sealed under the key, and where the next page starts, or none once
/// every table holding personal data is scanned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyHeld {
    pub table: &'static str,
    pub held: u64,
    pub next: Option<Vec<u8>>,
}

/// A key that seals data: its 32 bytes, never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct DataKey(pub [u8; 32]);

impl std::fmt::Debug for DataKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DataKey(..)")
    }
}

/// Warmup's evidence of a UTC day: each (egress, site)'s counts
/// that day, those that counted anything, and how many attempts from a
/// capped egress, reserved before the day ended, are not yet recorded,
/// whose replies may still be of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DayEvidence {
    pub counts: Vec<(EgressId, Arc<str>, Counts)>,
    pub unrecorded: u64,
}

/// What an outcome counts toward warmup's evidence at its site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counted {
    pub site: Arc<str>,
    pub signal: Signal,
    /// When the receiver replied, the day it counts on.
    pub at: Timestamp,
}

/// How an outcome changed its site's cooldown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CooldownChange {
    /// Its reply began or stretched one: the store keeps it, unless it
    /// already keeps one that ends later.
    Kept(SiteCooldown),
    /// The site is done cooling, and the store forgets it: a probe was
    /// delivered after the cooldown ran out, or the site had nothing for
    /// the scheduler's horizon after it did.
    Ended {
        egress: Option<EgressId>,
        site: Arc<str>,
    },
}

/// A site's cooldown, as the store keeps it: from one source, the egress or
/// the host's own address, until a wall-clock time. Once that time passes,
/// the site still takes one probe at a time until one is delivered, so it
/// is kept until then.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteCooldown {
    pub egress: Option<EgressId>,
    pub site: Arc<str>,
    pub until: Timestamp,
    /// Throttles since the site last took mail.
    pub throttles: u32,
    /// What the receiver said when it began.
    pub reply: Option<Evidence>,
}

/// What the scheduler starts from (`Command::Dispatched`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DispatchLedger {
    /// Each (egress, site)'s window of reservations.
    pub windows: Vec<(EgressId, Arc<str>, Window)>,
    /// Every cooldown kept: running, or run out with no probe delivered
    /// since.
    pub cooldowns: Vec<SiteCooldown>,
}

#[derive(Clone, Copy, Debug)]
pub struct Expire {
    pub delivery: DeliveryId,
    pub now: Timestamp,
}

/// A waiting delivery to park as it is to go out from `egress`, which it
/// keeps, `seen` the generation the scheduler read it at.
#[derive(Clone, Copy, Debug)]
pub struct Park {
    pub delivery: DeliveryId,
    pub seen: Generation,
    pub egress: Option<EgressId>,
    pub now: Timestamp,
}

#[derive(Clone, Copy, Debug)]
pub struct Release {
    pub delivery: DeliveryId,
    pub seen: Generation,
}

/// A waiting delivery to put off until `until`, as it is to go out from
/// `egress`, which it keeps, `seen` the generation the scheduler read it at.
#[derive(Clone, Copy, Debug)]
pub struct Postpone {
    pub delivery: DeliveryId,
    pub seen: Generation,
    pub egress: Option<EgressId>,
    pub until: Timestamp,
    pub now: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Id, IdentityId, Lane, Shard};

    #[test]
    fn an_acceptance_has_a_delivery_per_recipient_and_its_lifetime() {
        let mut ids = IdGenerator::new(Shard::new(0), Lane::new(0).unwrap(), None);
        let now = Timestamp::from_micros(1_800_000_000_000_000);
        let id = MessageId(ids.next(now));
        let recipients = [
            Address::parse("a@sink.test").unwrap(),
            Address::parse("b@sink.test").unwrap(),
        ];
        let message = AcceptMessage::new(
            id,
            Bytes::from_static(b"content"),
            &recipients,
            None,
            &mut ids,
            now,
        );
        let authority = Authority {
            account: AccountId(Id::from_u64(1).unwrap()),
            credential: CredentialId(Id::from_u64(3).unwrap()),
            origin: Origin {
                identity: IdentityId(Id::from_u64(2).unwrap()),
                tenant: None,
                configuration: None,
            },
            revision: PolicyRevision(1),
            template: None,
        };
        let accept = Accept::new(
            authority,
            vec![message],
            &mut ids,
            now,
            Duration::from_secs(3600),
        );
        assert_eq!(accept.authority, authority);
        assert_eq!(
            accept.expires_at,
            now.saturating_add(Duration::from_secs(3600))
        );
        let accepted = &accept.messages[0];
        assert_eq!(accepted.id, id);
        let addresses: Vec<&Address> = accepted.recipients.iter().map(|r| &r.address).collect();
        assert_eq!(addresses, recipients.iter().collect::<Vec<_>>());
        let delivery = accept.delivery(accepted, &accepted.recipients[0]).unwrap();
        assert_eq!(delivery.recipient(), &recipients[0]);
    }
}
