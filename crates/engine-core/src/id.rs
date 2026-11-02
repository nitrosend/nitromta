//! Identifiers.
//!
//! Every ID is a 63-bit integer, so the store keeps every table in its
//! fastest layout: integer primary keys, appended in order. Every ID also
//! carries when it was issued and the shard that owns it, so retention can
//! work over ID ranges and feedback can find its owning shard from the ID
//! alone.
//!
//! | Bits     | Field |
//! |----------|-------|
//! | 63       | always zero, so IDs stay positive as signed 64-bit integers |
//! | 62 to 21 | milliseconds since 2026-01-01T00:00:00Z: 42 bits, enough until 2165 |
//! | 20 to 13 | the owning shard: 8 bits |
//! | 12 to 9  | the lane, the generator within the shard that issued it: 4 bits |
//! | 8 to 0   | the sequence within the millisecond: 9 bits, 512 IDs per lane |
//!
//! This layout is a persisted format. IDs are the engine's internal form:
//! they reveal issue order and volume, so adapters choose the
//! representation that callers see.

use crate::time::Timestamp;

/// 2026-01-01T00:00:00Z, in milliseconds since the Unix epoch.
const EPOCH_MILLIS: u64 = 1_767_225_600_000;
const SEQUENCE_BITS: u32 = 9;
const LANE_BITS: u32 = 4;
const SHARD_BITS: u32 = 8;
const MILLIS_BITS: u32 = 42;
const LANE_SHIFT: u32 = SEQUENCE_BITS;
const SHARD_SHIFT: u32 = LANE_SHIFT + LANE_BITS;
const MILLIS_SHIFT: u32 = SHARD_SHIFT + SHARD_BITS;
const LANES: u8 = 1 << LANE_BITS;
const SEQUENCES: u16 = 1 << SEQUENCE_BITS;
const MAX_MILLIS: u64 = (1 << MILLIS_BITS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Id(u64);

impl Id {
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Reads a stored ID: `None` if the value is not one, because its top bit
    /// is set.
    pub const fn from_u64(value: u64) -> Option<Self> {
        if value >> (MILLIS_SHIFT + MILLIS_BITS) == 0 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn shard(self) -> Shard {
        Shard((self.0 >> SHARD_SHIFT) as u8)
    }

    pub const fn lane(self) -> Lane {
        Lane(((self.0 >> LANE_SHIFT) as u8) & (LANES - 1))
    }

    /// When it was issued, to the millisecond. An ID issued during a burst
    /// can run a few milliseconds ahead of the clock (see
    /// [`IdGenerator::next`]).
    pub const fn issued_at(self) -> Timestamp {
        Timestamp::from_micros(((self.0 >> MILLIS_SHIFT) + EPOCH_MILLIS) * 1_000)
    }

    /// The first and last IDs of its lane in its millisecond: every ID a
    /// generator of that lane issued then lies between them.
    pub const fn lane_millisecond(self) -> (Self, Self) {
        let sequences = SEQUENCES as u64 - 1;
        let first = self.0 & !sequences;
        (Self(first), Self(first | sequences))
    }

    /// How many IDs one generator issues in a millisecond at most.
    pub const PER_MILLISECOND: usize = SEQUENCES as usize;

    /// The same lane and shard, a millisecond later.
    pub const fn millisecond_after(self) -> Self {
        Self(self.0 + (1 << MILLIS_SHIFT))
    }

    /// The least ID issued at `at` or later. Every ID below it was issued
    /// before `at`, since an ID never runs behind the clock.
    pub const fn first_at(at: Timestamp) -> Self {
        let millis = at.as_millis().saturating_sub(EPOCH_MILLIS);
        let millis = if millis > MAX_MILLIS {
            MAX_MILLIS
        } else {
            millis
        };
        Self(millis << MILLIS_SHIFT)
    }

    const fn millis(self) -> u64 {
        self.0 >> MILLIS_SHIFT
    }
}

/// The shard that owns an ID: a host, its IPs and its own store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shard(u8);

impl Shard {
    pub const fn new(shard: u8) -> Self {
        Self(shard)
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// A generator within a shard. Each component that issues IDs has its own
/// lane, assigned by its driver, so generators never need to coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lane(u8);

impl Lane {
    /// `None` unless `lane` is below 16.
    pub const fn new(lane: u8) -> Option<Self> {
        if lane < LANES { Some(Self(lane)) } else { None }
    }

    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// Issues IDs for one lane of one shard.
#[derive(Debug)]
pub struct IdGenerator {
    shard: Shard,
    lane: Lane,
    millis: u64,
    next_sequence: u16,
}

impl IdGenerator {
    /// A generator whose IDs all sort after `after`, the highest ID the
    /// shard has stored, if any. It starts in the millisecond after that
    /// ID, so a restart never reissues an ID that may be stored, even when
    /// the clock has stepped back. An ID that was issued but never stored
    /// can be reissued safely: nothing outside the process ever saw it.
    pub fn new(shard: Shard, lane: Lane, after: Option<Id>) -> Self {
        Self {
            shard,
            lane,
            millis: after.map_or(0, |id| id.millis() + 1),
            next_sequence: 0,
        }
    }

    /// The next ID. IDs from one generator strictly increase whatever the
    /// clock does: when the clock stands still or steps back, the generator
    /// stays in its current millisecond, and when a millisecond's 512 IDs
    /// are used up, it moves to the next millisecond ahead of the clock.
    pub fn next(&mut self, now: Timestamp) -> Id {
        let millis = now.as_millis().saturating_sub(EPOCH_MILLIS);
        if millis > self.millis {
            self.millis = millis;
            self.next_sequence = 0;
        } else if self.next_sequence == SEQUENCES {
            self.millis += 1;
            self.next_sequence = 0;
        }
        assert!(self.millis <= MAX_MILLIS, "IDs run out in 2165");
        let id = Id((self.millis << MILLIS_SHIFT)
            | (u64::from(self.shard.0) << SHARD_SHIFT)
            | (u64::from(self.lane.0) << LANE_SHIFT)
            | u64::from(self.next_sequence));
        self.next_sequence += 1;
        id
    }
}

macro_rules! typed_ids {
    ($($(#[doc = $doc:literal])* $name:ident,)*) => {$(
        $(#[doc = $doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub Id);
    )*};
}

typed_ids! {
    /// An account: the owner of tenants, identities and credentials, and
    /// the scope of every record.
    AccountId,
    /// A tenant within an account.
    TenantId,
    /// A sending identity: a verified domain or address.
    IdentityId,
    /// A configuration: how a set of messages is sent and reported.
    ConfigurationId,
    /// A credential that may submit for its account.
    CredentialId,
    /// Where events for a configuration's mail are sent: a subscription's
    /// webhook, or an endpoint subscribed to a topic.
    SubscriptionId,
    /// A topic, which SES-shaped event destinations publish to.
    TopicId,
    /// An email template an account keeps, which mail is sent by.
    TemplateId,
    /// Where a configuration's events are published in SES's shape.
    DestinationId,
    /// A named set of egresses, which a configuration's mail goes out from.
    PoolId,
    /// A source address the host sends from.
    EgressId,
    /// A pause of an account's mail, or of a tenant's, configuration's,
    /// identity's or egress's.
    HoldId,
    /// A bounce or complaint report the feedback listener received.
    ReportId,
    /// One accepted request, which may contain several messages.
    SubmissionId,
    /// One distinct, immutable message.
    MessageId,
    /// A prepared message body.
    BodyId,
    /// One recipient of one message.
    DeliveryId,
    /// One transport attempt for a delivery.
    AttemptId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    const SHARD: Shard = Shard::new(201);

    fn lane(lane: u8) -> Lane {
        Lane::new(lane).expect("a valid test lane")
    }

    fn at_millis(millis: u64) -> Timestamp {
        Timestamp::from_micros(millis * 1_000)
    }

    #[test]
    fn the_layout_round_trips() {
        let mut generator = IdGenerator::new(SHARD, lane(13), None);
        let issued = at_millis(EPOCH_MILLIS + 86_400_000);
        let id = generator.next(issued);
        assert_eq!(id.shard(), SHARD);
        assert_eq!(id.lane(), lane(13));
        assert_eq!(id.issued_at(), issued);
        assert_eq!(Id::from_u64(id.as_u64()), Some(id));
        assert_eq!(Id::from_u64(1 << 63), None);
        assert_eq!(Lane::new(16), None);
    }

    #[test]
    fn ids_strictly_increase_whatever_the_clock_does() {
        for seed in 0..200 {
            let mut rng = Rng::from_seed(seed);
            let mut generator = IdGenerator::new(SHARD, lane(3), None);
            let mut millis = EPOCH_MILLIS + 1_000_000;
            let mut previous = generator.next(at_millis(millis));
            for _ in 0..2_000 {
                // Mostly small steps forward, sometimes a stall, a step back
                // or a burst within one millisecond.
                match rng.below(10) {
                    0 => millis = millis.saturating_sub(rng.below(5_000)),
                    1 | 2 => {}
                    _ => millis += rng.below(3),
                }
                let burst = if rng.below(50) == 0 { 700 } else { 1 };
                for _ in 0..burst {
                    let id = generator.next(at_millis(millis));
                    assert!(id > previous, "seed {seed}: {id:?} after {previous:?}");
                    assert_eq!((id.shard(), id.lane()), (SHARD, lane(3)));
                    previous = id;
                }
            }
        }
    }

    #[test]
    fn a_full_millisecond_moves_ahead_of_the_clock() {
        let mut generator = IdGenerator::new(SHARD, lane(0), None);
        let now = at_millis(EPOCH_MILLIS + 50);
        let ids: Vec<Id> = (0..SEQUENCES + 1).map(|_| generator.next(now)).collect();
        assert_eq!(ids[usize::from(SEQUENCES) - 1].issued_at(), now);
        assert_eq!(
            ids[usize::from(SEQUENCES)].issued_at(),
            at_millis(EPOCH_MILLIS + 51)
        );
    }

    #[test]
    fn every_id_below_the_first_at_a_time_was_issued_before_it() {
        let mut generator = IdGenerator::new(SHARD, lane(4), None);
        let earlier = generator.next(at_millis(EPOCH_MILLIS + 999));
        let at = at_millis(EPOCH_MILLIS + 1_000);
        let first = Id::first_at(at);
        assert!(earlier < first);
        assert!(generator.next(at) >= first);
        assert_eq!(first.issued_at(), at);
        assert_eq!(Id::first_at(at_millis(0)).as_u64(), 0, "before the epoch");
    }

    #[test]
    fn a_restarted_generator_sorts_after_what_was_stored() {
        let mut before = IdGenerator::new(SHARD, lane(5), None);
        let now = at_millis(EPOCH_MILLIS + 10_000);
        let stored = (0..10)
            .map(|_| before.next(now))
            .max()
            .expect("ids were issued");

        // The clock has stepped back across the restart.
        let mut after = IdGenerator::new(SHARD, lane(5), Some(stored));
        let resumed = after.next(at_millis(EPOCH_MILLIS + 9_000));
        assert!(resumed > stored);
    }
}
