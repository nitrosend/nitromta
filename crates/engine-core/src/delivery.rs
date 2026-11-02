//! A delivery: one recipient of one message, and its queue lifecycle.
//!
//! Its state changes only through the transitions here, and each one checks
//! the state it expects. Reservations and outcomes also check the
//! generation the caller last saw, so a stale view (a scheduler's cached
//! window, a worker whose attempt was recovered after a restart) can never
//! overwrite newer state. A refused transition changes nothing.

use crate::address::Address;
use crate::attempt::Evidence;
use crate::id::{AccountId, AttemptId, DeliveryId, EgressId, MessageId};
use crate::policy::Origin;
use crate::time::Timestamp;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    id: DeliveryId,
    message: MessageId,
    account: AccountId,
    /// Its message's, so dispatch checks its authority without reading the
    /// message.
    origin: Origin,
    recipient: Address,
    expires_at: Timestamp,
    generation: Generation,
    state: QueueState,
    attempts: u32,
    uncertain_attempts: u32,
    /// The egress it goes out from, as its last reservation chose:
    /// the host's own address when absent.
    egress: Option<EgressId>,
    /// Where the journal holds what the receiver said when its last attempt
    /// ended without delivering it, with the receiver rules that matched,
    /// so `explain` says why it waits or failed. The
    /// reply stays in its attempt's entry, so the delivery's row grows by
    /// a position, not by the reply. A reservation clears it.
    reply_entry: Option<u64>,
}

/// The version of a delivery's state. It advances with every transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u32);

impl Generation {
    pub const FIRST: Self = Self(0);

    /// Reads a stored generation.
    pub const fn from_u32(generation: u32) -> Self {
        Self(generation)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }

    fn next(self) -> Self {
        Self(
            self.0
                .checked_add(1)
                .expect("a delivery cannot make 2^32 transitions"),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueState {
    /// Waiting for its next attempt, which may start at `due_at`. A waiting
    /// delivery is always due before it expires.
    Ready { due_at: Timestamp },
    /// Reserved for `attempt`, which may be on the wire.
    InFlight {
        attempt: AttemptId,
        since: Timestamp,
    },
    /// Paused by a hold since `since`: no attempt starts until
    /// it is released, when it waits for `due_at` again. It still expires.
    Held { due_at: Timestamp, since: Timestamp },
    /// Finished: nothing will send it again. Feedback can still arrive.
    Finished {
        completion: Completion,
        at: Timestamp,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// The receiver accepted it in `attempt`. That ends the engine's
    /// responsibility for transport, not the possibility of a later bounce
    /// or complaint.
    RemoteAccepted { attempt: AttemptId },
    /// The receiver refused it permanently in `attempt`.
    Rejected { attempt: AttemptId },
    /// No attempt succeeded before its expiry, or its next attempt would
    /// have fallen after it.
    Expired,
    /// Its recipient was suppressed when it fell due, so no attempt was
    /// made.
    Suppressed,
    /// The authority it was sent under was withdrawn before it was sent:
    /// its identity, tenant or configuration was removed, or the tenant's
    /// association with them. No attempt was made.
    Cancelled,
    /// Capture mode took it in `attempt`, in place of delivery:
    /// nothing reached a receiver.
    Captured { attempt: AttemptId },
}

/// What an attempt's outcome means for its delivery, as classified from
/// the receiver's reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// The receiver accepted it.
    Delivered,
    /// The receiver refused it permanently.
    Rejected,
    /// A temporary failure: try again, not before `not_before`.
    Deferred { not_before: Timestamp },
    /// The receiver may or may not have accepted it: for example, the
    /// connection failed after the message was sent and before the final
    /// reply arrived. It is tried again, not before `not_before`, which may
    /// duplicate it, and every such attempt is counted.
    Uncertain { not_before: Timestamp },
    /// Capture mode took it in place of delivery: no receiver
    /// was asked.
    Captured,
}

/// The right to make one attempt for one delivery. Only
/// [`Delivery::reserve`] creates one, it cannot be copied, and recording its
/// outcome consumes it, so each reservation has at most one outcome.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a reserved delivery stays in flight until its attempt's outcome is recorded"]
pub struct DispatchPermit {
    delivery: DeliveryId,
    attempt: AttemptId,
    generation: Generation,
}

impl DispatchPermit {
    pub fn delivery(&self) -> DeliveryId {
        self.delivery
    }

    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }
}

/// A delivery as stored. [`Delivery::from_record`] turns it back into a
/// delivery only if its state is one the transitions could have produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRecord {
    pub id: DeliveryId,
    pub message: MessageId,
    pub account: AccountId,
    pub origin: Origin,
    pub recipient: Address,
    pub expires_at: Timestamp,
    pub generation: Generation,
    pub state: QueueState,
    pub attempts: u32,
    pub uncertain_attempts: u32,
    pub egress: Option<EgressId>,
    pub reply_entry: Option<u64>,
}

/// A stored delivery whose state no sequence of transitions produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImpossibleDelivery;

/// Why a transition was refused. The delivery is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It does not exist: it was never accepted, or it finished and
    /// retention has removed it.
    Gone,
    /// It has finished.
    Finished,
    /// The caller's generation is not the current one: its view is out of
    /// date.
    Stale { current: Generation },
    /// Its next attempt may not start until `due_at`.
    NotDue { due_at: Timestamp },
    /// Its expiry has passed, so the only transition left is to expire it.
    PastExpiry,
    /// Its expiry has not passed.
    NotExpired,
    /// An attempt is in flight.
    InFlight,
    /// A hold pauses it.
    Held,
    /// No hold pauses it.
    NotHeld,
    /// No attempt is in flight.
    NotInFlight,
    /// The permit is not for the attempt in flight.
    WrongAttempt,
    /// Current policy no longer sends its mail from the source it was
    /// placed on: it is placed again.
    Unsourced,
}

impl Delivery {
    /// A newly accepted delivery, ready for its first attempt at `due_at`.
    /// `None` unless it is due before it expires.
    pub fn new(
        id: DeliveryId,
        message: MessageId,
        account: AccountId,
        origin: Origin,
        recipient: Address,
        due_at: Timestamp,
        expires_at: Timestamp,
    ) -> Option<Self> {
        (due_at < expires_at).then_some(Self {
            id,
            message,
            account,
            origin,
            recipient,
            expires_at,
            generation: Generation::FIRST,
            state: QueueState::Ready { due_at },
            attempts: 0,
            uncertain_attempts: 0,
            egress: None,
            reply_entry: None,
        })
    }

    /// A delivery read back from storage.
    pub fn from_record(record: DeliveryRecord) -> Result<Self, ImpossibleDelivery> {
        // Every attempt is reserved once and counted uncertain at most once,
        // and every transition advances the generation.
        let counts_hold =
            record.uncertain_attempts <= record.attempts && record.attempts <= record.generation.0;
        let state_holds = match record.state {
            QueueState::Ready { due_at } | QueueState::Held { due_at, .. } => {
                due_at < record.expires_at
            }
            QueueState::InFlight { .. }
            | QueueState::Finished {
                completion:
                    Completion::RemoteAccepted { .. }
                    | Completion::Rejected { .. }
                    | Completion::Captured { .. },
                ..
            } => record.attempts > 0,
            QueueState::Finished {
                completion: Completion::Expired | Completion::Suppressed | Completion::Cancelled,
                ..
            } => true,
        };
        if !(counts_hold && state_holds) {
            return Err(ImpossibleDelivery);
        }
        Ok(Self {
            id: record.id,
            message: record.message,
            account: record.account,
            origin: record.origin,
            recipient: record.recipient,
            expires_at: record.expires_at,
            generation: record.generation,
            state: record.state,
            attempts: record.attempts,
            uncertain_attempts: record.uncertain_attempts,
            egress: record.egress,
            reply_entry: record.reply_entry,
        })
    }

    /// Keeps where the journal holds what the receiver said as an attempt
    /// ended, at `entry`, unless it delivered: a delivery that waits or
    /// failed says why; one delivered, or whose last attempt heard nothing,
    /// keeps no reply.
    pub fn heard(&mut self, reply: Option<&Evidence>, entry: u64) {
        self.reply_entry = reply.filter(|reply| reply.code / 100 != 2).map(|_| entry);
    }

    /// Reserves the delivery for `attempt`, which may then be sent from
    /// `egress`, which it keeps. `seen` is the generation the caller's view
    /// of the delivery was taken at.
    pub fn reserve(
        &mut self,
        seen: Generation,
        attempt: AttemptId,
        egress: Option<EgressId>,
        now: Timestamp,
    ) -> Result<DispatchPermit, Refusal> {
        let QueueState::Ready { due_at } = self.state else {
            return Err(self.not_ready());
        };
        self.check(seen)?;
        if now >= self.expires_at {
            return Err(Refusal::PastExpiry);
        }
        if now < due_at {
            return Err(Refusal::NotDue { due_at });
        }
        self.state = QueueState::InFlight {
            attempt,
            since: now,
        };
        self.egress = egress;
        // In flight, it no longer waits for the reason its last reply gave.
        self.reply_entry = None;
        self.attempts += 1;
        self.advance();
        Ok(DispatchPermit {
            delivery: self.id,
            attempt,
            generation: self.generation,
        })
    }

    /// Records the outcome of the attempt `permit` allowed.
    pub fn record_outcome(
        &mut self,
        permit: DispatchPermit,
        disposition: Disposition,
        now: Timestamp,
    ) -> Result<(), Refusal> {
        let QueueState::InFlight { attempt, .. } = self.state else {
            return Err(match self.state {
                QueueState::Finished { .. } => Refusal::Finished,
                _ => Refusal::NotInFlight,
            });
        };
        if permit.delivery != self.id || permit.attempt != attempt {
            return Err(Refusal::WrongAttempt);
        }
        self.check(permit.generation)?;
        self.state = match disposition {
            Disposition::Delivered => QueueState::Finished {
                completion: Completion::RemoteAccepted { attempt },
                at: now,
            },
            Disposition::Rejected => QueueState::Finished {
                completion: Completion::Rejected { attempt },
                at: now,
            },
            Disposition::Captured => QueueState::Finished {
                completion: Completion::Captured { attempt },
                at: now,
            },
            Disposition::Deferred { not_before } => self.retry_at(not_before, now),
            Disposition::Uncertain { not_before } => {
                self.uncertain_attempts += 1;
                self.retry_at(not_before, now)
            }
        };
        self.advance();
        Ok(())
    }

    /// Parks a waiting delivery a hold covers, as it was to be
    /// sent from `egress`, which it keeps, as a reservation would. It keeps
    /// when it was due. `seen` is the generation the caller's view of the
    /// delivery was taken at.
    pub fn park(
        &mut self,
        seen: Generation,
        egress: Option<EgressId>,
        now: Timestamp,
    ) -> Result<(), Refusal> {
        let QueueState::Ready { due_at } = self.state else {
            return Err(self.not_ready());
        };
        self.check(seen)?;
        if now >= self.expires_at {
            return Err(Refusal::PastExpiry);
        }
        self.state = QueueState::Held { due_at, since: now };
        self.egress = egress;
        self.advance();
        Ok(())
    }

    /// Puts off a waiting delivery whose egress has no room for it:
    /// it waits until `until`, or until just before it expires if
    /// that is sooner, and never for less than it did, as it is to go out
    /// from `egress`, which it keeps, as a reservation would. `seen` is the
    /// generation the caller's view of the delivery was taken at.
    pub fn postpone(
        &mut self,
        seen: Generation,
        egress: Option<EgressId>,
        until: Timestamp,
        now: Timestamp,
    ) -> Result<(), Refusal> {
        let QueueState::Ready { due_at } = self.state else {
            return Err(self.not_ready());
        };
        self.check(seen)?;
        if now >= self.expires_at {
            return Err(Refusal::PastExpiry);
        }
        let latest = self
            .expires_at
            .saturating_sub(std::time::Duration::from_micros(1));
        self.state = QueueState::Ready {
            due_at: due_at.max(until.min(latest)),
        };
        self.egress = egress;
        self.advance();
        Ok(())
    }

    /// Releases a held delivery once no hold covers it: it waits for when
    /// it was due, which may have passed.
    pub fn release(&mut self, seen: Generation) -> Result<(), Refusal> {
        let QueueState::Held { due_at, .. } = self.state else {
            return Err(match self.state {
                QueueState::Finished { .. } => Refusal::Finished,
                QueueState::InFlight { .. } => Refusal::InFlight,
                _ => Refusal::NotHeld,
            });
        };
        self.check(seen)?;
        self.state = QueueState::Ready { due_at };
        self.advance();
        Ok(())
    }

    /// Expires a waiting or held delivery whose expiry has passed. A
    /// delivery with an attempt in flight waits for that attempt's outcome,
    /// which either delivers it or expires it.
    pub fn expire(&mut self, now: Timestamp) -> Result<(), Refusal> {
        if !matches!(
            self.state,
            QueueState::Ready { .. } | QueueState::Held { .. }
        ) {
            return Err(self.not_ready());
        }
        if now < self.expires_at {
            return Err(Refusal::NotExpired);
        }
        self.state = QueueState::Finished {
            completion: Completion::Expired,
            at: now,
        };
        self.advance();
        Ok(())
    }

    /// Finishes a waiting delivery whose recipient is suppressed, without an
    /// attempt.
    pub fn suppress(&mut self, now: Timestamp) -> Result<(), Refusal> {
        self.finish_unsent(Completion::Suppressed, now)
    }

    /// Finishes a waiting delivery whose authority was withdrawn, without an
    /// attempt.
    pub fn cancel(&mut self, now: Timestamp) -> Result<(), Refusal> {
        self.finish_unsent(Completion::Cancelled, now)
    }

    fn finish_unsent(&mut self, completion: Completion, now: Timestamp) -> Result<(), Refusal> {
        if !matches!(self.state, QueueState::Ready { .. }) {
            return Err(self.not_ready());
        }
        self.state = QueueState::Finished {
            completion,
            at: now,
        };
        self.advance();
        Ok(())
    }

    /// After a restart, returns a delivery whose attempt was in flight to
    /// the queue, not before `not_before`. The attempt may have reached the
    /// receiver, so it is counted as uncertain. Returns the abandoned
    /// attempt, whose own record the caller marks uncertain.
    pub fn recover(&mut self, not_before: Timestamp, now: Timestamp) -> Result<AttemptId, Refusal> {
        let QueueState::InFlight { attempt, .. } = self.state else {
            return Err(match self.state {
                QueueState::Finished { .. } => Refusal::Finished,
                _ => Refusal::NotInFlight,
            });
        };
        self.uncertain_attempts += 1;
        self.state = self.retry_at(not_before, now);
        self.advance();
        Ok(attempt)
    }

    pub fn id(&self) -> DeliveryId {
        self.id
    }

    pub fn message(&self) -> MessageId {
        self.message
    }

    pub fn account(&self) -> AccountId {
        self.account
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    pub fn recipient(&self) -> &Address {
        &self.recipient
    }

    pub fn egress(&self) -> Option<EgressId> {
        self.egress
    }

    /// Where the journal holds the reply that explains why it waits or
    /// failed, if one does.
    pub fn reply_entry(&self) -> Option<u64> {
        self.reply_entry
    }

    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn state(&self) -> QueueState {
        self.state
    }

    /// Attempts reserved so far.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Attempts whose outcome is unknown, each of which may have delivered
    /// a copy.
    pub fn uncertain_attempts(&self) -> u32 {
        self.uncertain_attempts
    }

    /// Ready for another attempt at `not_before`, or expired now if that
    /// would fall at or after its expiry: no further attempt will be made,
    /// so its outcome is known.
    fn retry_at(&self, not_before: Timestamp, now: Timestamp) -> QueueState {
        if not_before < self.expires_at {
            QueueState::Ready { due_at: not_before }
        } else {
            QueueState::Finished {
                completion: Completion::Expired,
                at: now,
            }
        }
    }

    fn not_ready(&self) -> Refusal {
        match self.state {
            QueueState::Finished { .. } => Refusal::Finished,
            QueueState::InFlight { .. } => Refusal::InFlight,
            QueueState::Held { .. } => Refusal::Held,
            QueueState::Ready { .. } => {
                unreachable!("the caller checked the delivery is not ready")
            }
        }
    }

    fn check(&self, seen: Generation) -> Result<(), Refusal> {
        if seen == self.generation {
            Ok(())
        } else {
            Err(Refusal::Stale {
                current: self.generation,
            })
        }
    }

    fn advance(&mut self) {
        self.generation = self.generation.next();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::id::{IdGenerator, IdentityId, Lane, Shard};
    use crate::rng::Rng;

    const START: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);
    const LIFETIME: Duration = Duration::from_secs(3_600);

    struct Fixture {
        ids: IdGenerator,
        delivery: Delivery,
    }

    impl Fixture {
        fn new() -> Self {
            let lane = Lane::new(0).expect("a valid lane");
            let mut ids = IdGenerator::new(Shard::new(1), lane, None);
            let delivery = Delivery::new(
                DeliveryId(ids.next(START)),
                MessageId(ids.next(START)),
                AccountId(ids.next(START)),
                Origin {
                    identity: IdentityId(ids.next(START)),
                    tenant: None,
                    configuration: None,
                },
                Address::parse("rcpt@example.com").expect("a valid address"),
                START,
                START.saturating_add(LIFETIME),
            )
            .expect("due before it expires");
            Self { ids, delivery }
        }

        fn attempt(&mut self, now: Timestamp) -> AttemptId {
            AttemptId(self.ids.next(now))
        }

        fn reserve(&mut self, now: Timestamp) -> Result<DispatchPermit, Refusal> {
            let attempt = self.attempt(now);
            let seen = self.delivery.generation();
            self.delivery.reserve(seen, attempt, None, now)
        }
    }

    fn record_of(delivery: &Delivery) -> DeliveryRecord {
        DeliveryRecord {
            id: delivery.id(),
            message: delivery.message(),
            account: delivery.account(),
            origin: *delivery.origin(),
            recipient: delivery.recipient().clone(),
            expires_at: delivery.expires_at(),
            generation: delivery.generation(),
            state: delivery.state(),
            attempts: delivery.attempts(),
            uncertain_attempts: delivery.uncertain_attempts(),
            egress: delivery.egress(),
            reply_entry: delivery.reply_entry(),
        }
    }

    #[test]
    fn impossible_records_are_refused() {
        let mut fixture = Fixture::new();
        let attempt = fixture.attempt(START);
        let valid = record_of(&fixture.delivery);
        let impossible = [
            DeliveryRecord {
                state: QueueState::Ready {
                    due_at: valid.expires_at,
                },
                ..valid.clone()
            },
            DeliveryRecord {
                state: QueueState::InFlight {
                    attempt,
                    since: START,
                },
                ..valid.clone()
            },
            DeliveryRecord {
                uncertain_attempts: 1,
                ..valid.clone()
            },
            DeliveryRecord {
                attempts: 1,
                uncertain_attempts: 0,
                ..valid.clone()
            },
        ];
        for record in impossible {
            assert_eq!(
                Delivery::from_record(record.clone()),
                Err(ImpossibleDelivery),
                "{record:?}"
            );
        }
        assert_eq!(Delivery::from_record(valid), Ok(fixture.delivery));
    }

    fn later(by_secs: u64) -> Timestamp {
        START.saturating_add(Duration::from_secs(by_secs))
    }

    #[test]
    fn a_delivered_attempt_finishes_it() {
        let mut fixture = Fixture::new();
        let permit = fixture.reserve(later(1)).expect("due");
        let attempt = permit.attempt();
        fixture
            .delivery
            .record_outcome(permit, Disposition::Delivered, later(2))
            .expect("the attempt in flight");
        assert_eq!(
            fixture.delivery.state(),
            QueueState::Finished {
                completion: Completion::RemoteAccepted { attempt },
                at: later(2),
            }
        );
        assert_eq!(fixture.delivery.attempts(), 1);
        assert_eq!(fixture.reserve(later(3)), Err(Refusal::Finished));
    }

    #[test]
    fn a_held_delivery_keeps_its_due_time_and_egress_and_still_expires() {
        let mut fixture = Fixture::new();
        let egress = Some(EgressId(fixture.ids.next(START)));
        let seen = fixture.delivery.generation();
        fixture
            .delivery
            .park(seen, egress, later(1))
            .expect("waiting");
        assert_eq!(
            fixture.delivery.state(),
            QueueState::Held {
                due_at: START,
                since: later(1),
            }
        );
        assert_eq!(fixture.delivery.egress(), egress);
        assert_eq!(fixture.reserve(later(2)), Err(Refusal::Held));
        assert_eq!(
            fixture.delivery.release(seen),
            Err(Refusal::Stale {
                current: fixture.delivery.generation(),
            })
        );
        let parked = fixture.delivery.generation();
        fixture.delivery.release(parked).expect("held");
        assert_eq!(
            fixture.delivery.state(),
            QueueState::Ready { due_at: START }
        );
        assert_eq!(
            fixture.delivery.release(fixture.delivery.generation()),
            Err(Refusal::NotHeld)
        );
        // Held past its expiry, it expires as a waiting one does.
        let seen = fixture.delivery.generation();
        fixture
            .delivery
            .park(seen, egress, later(3))
            .expect("waiting");
        fixture
            .delivery
            .expire(START.saturating_add(LIFETIME))
            .expect("past its expiry");
        assert!(matches!(
            fixture.delivery.state(),
            QueueState::Finished {
                completion: Completion::Expired,
                ..
            }
        ));
        assert_eq!(fixture.delivery.attempts(), 0);
        assert!(Delivery::from_record(record_of(&fixture.delivery)).is_ok());
    }

    #[test]
    fn a_postponed_delivery_waits_keeping_its_egress_and_is_still_due_before_it_expires() {
        let mut fixture = Fixture::new();
        let egress = Some(EgressId(fixture.ids.next(START)));
        let seen = fixture.delivery.generation();
        fixture
            .delivery
            .postpone(seen, egress, later(600), later(1))
            .expect("waiting");
        assert_eq!(
            fixture.delivery.state(),
            QueueState::Ready { due_at: later(600) }
        );
        assert_eq!(fixture.delivery.egress(), egress);
        assert_eq!(
            fixture.reserve(later(2)),
            Err(Refusal::NotDue { due_at: later(600) })
        );
        // A stale view is refused, and an earlier time leaves it as it was.
        assert!(matches!(
            fixture
                .delivery
                .postpone(seen, egress, later(900), later(2)),
            Err(Refusal::Stale { .. })
        ));
        let seen = fixture.delivery.generation();
        fixture
            .delivery
            .postpone(seen, egress, later(300), later(2))
            .expect("waiting");
        assert_eq!(
            fixture.delivery.state(),
            QueueState::Ready { due_at: later(600) }
        );
        // Put off past its expiry, it is due just before it expires.
        let seen = fixture.delivery.generation();
        fixture
            .delivery
            .postpone(seen, egress, later(2 * LIFETIME.as_secs()), later(3))
            .expect("waiting");
        let expires_at = fixture.delivery.expires_at();
        assert!(matches!(
            fixture.delivery.state(),
            QueueState::Ready { due_at } if due_at < expires_at && due_at > later(600)
        ));
        assert!(Delivery::from_record(record_of(&fixture.delivery)).is_ok());
        let seen = fixture.delivery.generation();
        assert_eq!(
            fixture
                .delivery
                .postpone(seen, egress, later(1), expires_at),
            Err(Refusal::PastExpiry)
        );
        assert_eq!(fixture.delivery.attempts(), 0);
    }

    #[test]
    fn a_deferral_waits_for_its_retry_time() {
        let mut fixture = Fixture::new();
        let permit = fixture.reserve(later(1)).expect("due");
        let retry = Disposition::Deferred {
            not_before: later(600),
        };
        fixture
            .delivery
            .record_outcome(permit, retry, later(2))
            .expect("the attempt in flight");
        assert_eq!(
            fixture.reserve(later(599)),
            Err(Refusal::NotDue { due_at: later(600) })
        );
        assert!(fixture.reserve(later(600)).is_ok());
        assert_eq!(fixture.delivery.attempts(), 2);
    }

    #[test]
    fn a_waiting_delivery_keeps_the_reply_that_deferred_it_until_its_next_attempt() {
        let mut fixture = Fixture::new();
        let permit = fixture.reserve(START).expect("due");
        let not_before = START.saturating_add(Duration::from_secs(60));
        fixture
            .delivery
            .record_outcome(permit, Disposition::Deferred { not_before }, START)
            .expect("in flight");
        let reply = Evidence::new(451, "4.7.1 try again later");
        fixture.delivery.heard(Some(&reply), 7);
        assert_eq!(fixture.delivery.reply_entry(), Some(7));
        let _permit = fixture.reserve(not_before).expect("due");
        assert_eq!(
            fixture.delivery.reply_entry(),
            None,
            "in flight, it waits for nothing"
        );
        // A delivered attempt, or one that heard nothing, keeps no reply.
        fixture
            .delivery
            .heard(Some(&Evidence::new(250, "2.0.0 Ok")), 8);
        assert_eq!(fixture.delivery.reply_entry(), None);
        fixture.delivery.heard(None, 9);
        assert_eq!(fixture.delivery.reply_entry(), None);
    }

    #[test]
    fn a_retry_after_expiry_expires_it_now() {
        let mut fixture = Fixture::new();
        let permit = fixture.reserve(later(1)).expect("due");
        let retry = Disposition::Deferred {
            not_before: START.saturating_add(LIFETIME),
        };
        fixture
            .delivery
            .record_outcome(permit, retry, later(2))
            .expect("the attempt in flight");
        assert_eq!(
            fixture.delivery.state(),
            QueueState::Finished {
                completion: Completion::Expired,
                at: later(2),
            }
        );
    }

    #[test]
    fn a_stale_view_cannot_reserve() {
        let mut fixture = Fixture::new();
        let seen = fixture.delivery.generation();
        let permit = fixture.reserve(later(1)).expect("due");
        let retry = Disposition::Deferred {
            not_before: later(2),
        };
        fixture
            .delivery
            .record_outcome(permit, retry, later(1))
            .expect("the attempt in flight");
        let attempt = fixture.attempt(later(3));
        assert_eq!(
            fixture.delivery.reserve(seen, attempt, None, later(3)),
            Err(Refusal::Stale {
                current: fixture.delivery.generation()
            })
        );
    }

    #[test]
    fn a_recovered_attempts_permit_is_refused() {
        let mut fixture = Fixture::new();
        let abandoned = fixture.reserve(later(1)).expect("due");
        let recovered = fixture
            .delivery
            .recover(later(5), later(4))
            .expect("in flight");
        assert_eq!(recovered, abandoned.attempt());
        assert_eq!(fixture.delivery.uncertain_attempts(), 1);
        let current = fixture.reserve(later(5)).expect("due again");
        assert_eq!(
            fixture
                .delivery
                .record_outcome(abandoned, Disposition::Delivered, later(6)),
            Err(Refusal::WrongAttempt)
        );
        assert!(
            fixture
                .delivery
                .record_outcome(current, Disposition::Delivered, later(6))
                .is_ok()
        );
    }

    #[test]
    fn expiry_waits_for_the_attempt_in_flight() {
        let mut fixture = Fixture::new();
        let end = START.saturating_add(LIFETIME);
        assert_eq!(fixture.delivery.expire(later(1)), Err(Refusal::NotExpired));
        let permit = fixture.reserve(later(1)).expect("due");
        assert_eq!(fixture.delivery.expire(end), Err(Refusal::InFlight));
        let retry = Disposition::Deferred {
            not_before: later(2),
        };
        fixture
            .delivery
            .record_outcome(permit, retry, later(1))
            .expect("the attempt in flight");
        assert_eq!(fixture.reserve(end), Err(Refusal::PastExpiry));
        assert!(fixture.delivery.expire(end).is_ok());
    }

    #[test]
    fn a_delivery_must_be_due_before_it_expires() {
        let mut fixture = Fixture::new();
        let address = fixture.delivery.recipient().clone();
        let id = DeliveryId(fixture.ids.next(START));
        let delivery = &fixture.delivery;
        let (message, account, origin) =
            (delivery.message(), delivery.account(), *delivery.origin());
        assert!(Delivery::new(id, message, account, origin, address, START, START).is_none());
    }

    /// A retry time: usually a few minutes on, sometimes exactly at or just
    /// before the expiry, where the retry-or-expire boundary lies.
    fn retry_time(rng: &mut Rng, now: Timestamp, expires_at: Timestamp) -> Timestamp {
        match rng.below(8) {
            0 => expires_at,
            1 => Timestamp::from_micros(expires_at.as_micros() - 1),
            _ => now.saturating_add(Duration::from_secs(rng.below(900))),
        }
    }

    fn disposition_name(disposition: Disposition) -> &'static str {
        match disposition {
            Disposition::Delivered => "delivered",
            Disposition::Rejected => "rejected",
            Disposition::Deferred { .. } => "deferred",
            Disposition::Uncertain { .. } => "uncertain",
            Disposition::Captured => "captured",
        }
    }

    fn result_name(result: Result<(), Refusal>) -> &'static str {
        match result {
            Ok(()) => "accepted",
            Err(Refusal::Gone) => "gone",
            Err(Refusal::Finished) => "finished",
            Err(Refusal::Stale { .. }) => "stale",
            Err(Refusal::NotDue { .. }) => "not due",
            Err(Refusal::PastExpiry) => "past expiry",
            Err(Refusal::NotExpired) => "not expired",
            Err(Refusal::InFlight) => "in flight",
            Err(Refusal::Held) => "held",
            Err(Refusal::NotHeld) => "not held",
            Err(Refusal::NotInFlight) => "not in flight",
            Err(Refusal::WrongAttempt) => "wrong attempt",
            Err(Refusal::Unsourced) => "unsourced",
        }
    }

    /// Every transition and refusal the random test must reach, so it can
    /// never pass by exercising nothing.
    const MUST_EXERCISE: [(&str, &str); 25] = [
        ("reserve", "accepted"),
        ("reserve", "held"),
        ("park", "accepted"),
        ("park", "held"),
        ("park", "in flight"),
        ("release", "accepted"),
        ("release", "not held"),
        ("reserve", "stale"),
        ("reserve", "not due"),
        ("reserve", "past expiry"),
        ("reserve", "in flight"),
        ("reserve", "finished"),
        ("delivered", "accepted"),
        ("rejected", "accepted"),
        ("deferred", "accepted"),
        ("uncertain", "accepted"),
        ("outcome", "wrong attempt"),
        ("outcome", "not in flight"),
        ("outcome", "finished"),
        ("expire", "accepted"),
        ("expire", "not expired"),
        ("expire", "in flight"),
        ("recover", "accepted"),
        ("recover", "not in flight"),
        ("recover", "finished"),
    ];

    /// Random sequences of every transition, including stale views and
    /// stale permits, checking the invariants after each step.
    #[test]
    fn random_transitions_keep_every_invariant() {
        let mut exercised: std::collections::BTreeMap<(&str, &str), u32> = Default::default();
        for seed in 0..3_000 {
            let mut rng = Rng::from_seed(seed);
            let mut fixture = Fixture::new();
            let mut now = START;
            let expires_at = fixture.delivery.expires_at();
            let mut permits: Vec<DispatchPermit> = Vec::new();
            let mut reserved = 0;
            let mut uncertain = 0;
            let mut steps_since_finished = 0;

            for step in 0..64 {
                now = now.saturating_add(Duration::from_secs(rng.below(240)));
                let before = fixture.delivery.clone();
                let (transition, result) = match rng.below(8) {
                    0 | 1 => {
                        let seen = if rng.below(5) == 0 {
                            Generation(u32::try_from(rng.below(8)).expect("small"))
                        } else {
                            fixture.delivery.generation()
                        };
                        let attempt = fixture.attempt(now);
                        let result = fixture.delivery.reserve(seen, attempt, None, now);
                        let result = result.map(|permit| {
                            assert_eq!(seen, before.generation(), "seed {seed} step {step}");
                            assert_eq!(permit.attempt(), attempt);
                            permits.push(permit);
                            reserved += 1;
                        });
                        ("reserve", result)
                    }
                    2 | 3 if !permits.is_empty() => {
                        let index =
                            usize::try_from(rng.below(permits.len() as u64)).expect("an index");
                        let permit = permits.swap_remove(index);
                        let used = (permit.attempt(), permit.generation);
                        let not_before = retry_time(&mut rng, now, expires_at);
                        // Mostly retries, so deliveries live long enough to
                        // be recovered and to collect stale permits.
                        let disposition = match rng.below(8) {
                            0 => Disposition::Delivered,
                            1 => Disposition::Rejected,
                            2..=4 => Disposition::Deferred { not_before },
                            _ => Disposition::Uncertain { not_before },
                        };
                        let result = fixture.delivery.record_outcome(permit, disposition, now);
                        if result.is_ok() {
                            assert!(
                                matches!(
                                    before.state(),
                                    QueueState::InFlight { attempt, .. } if attempt == used.0
                                ),
                                "seed {seed} step {step}: only the attempt in flight has an outcome"
                            );
                            assert_eq!(used.1, before.generation());
                            if matches!(disposition, Disposition::Uncertain { .. }) {
                                uncertain += 1;
                            }
                        }
                        let name = if result.is_ok() {
                            disposition_name(disposition)
                        } else {
                            "outcome"
                        };
                        (name, result)
                    }
                    4 => ("expire", fixture.delivery.expire(now)),
                    5 => {
                        let not_before = retry_time(&mut rng, now, expires_at);
                        let result = fixture.delivery.recover(not_before, now).map(|_| {
                            uncertain += 1;
                        });
                        ("recover", result)
                    }
                    6 => {
                        let seen = fixture.delivery.generation();
                        ("park", fixture.delivery.park(seen, None, now))
                    }
                    _ => {
                        let seen = fixture.delivery.generation();
                        ("release", fixture.delivery.release(seen))
                    }
                };
                *exercised
                    .entry((transition, result_name(result)))
                    .or_default() += 1;
                let accepted = result.is_ok();

                let delivery = &fixture.delivery;
                if accepted {
                    assert_eq!(delivery.generation(), before.generation().next());
                    assert!(
                        !matches!(before.state(), QueueState::Finished { .. }),
                        "seed {seed} step {step}: a finished delivery never changes"
                    );
                } else {
                    assert_eq!(
                        delivery, &before,
                        "seed {seed} step {step}: a refusal changes nothing"
                    );
                }
                assert_eq!(
                    Delivery::from_record(record_of(delivery)).as_ref(),
                    Ok(delivery),
                    "seed {seed} step {step}: every reachable state can be stored and read back"
                );
                assert_eq!(delivery.attempts(), reserved);
                assert_eq!(delivery.uncertain_attempts(), uncertain);
                match delivery.state() {
                    QueueState::Ready { due_at } | QueueState::Held { due_at, .. } => {
                        assert!(due_at < delivery.expires_at());
                    }
                    QueueState::InFlight { attempt, .. } => assert!(
                        permits.iter().any(|permit| permit.attempt() == attempt
                            && permit.generation == delivery.generation()),
                        "seed {seed} step {step}: the attempt in flight has its permit"
                    ),
                    QueueState::Finished { .. } => {
                        // A few more steps check that it stays finished.
                        steps_since_finished += 1;
                        if steps_since_finished > 4 {
                            break;
                        }
                    }
                }
            }
        }
        for case in MUST_EXERCISE {
            let count = exercised.get(&case).copied().unwrap_or(0);
            assert!(
                count >= 50,
                "{case:?} was exercised {count} times: {exercised:#?}"
            );
        }
    }
}
