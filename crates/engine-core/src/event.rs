//! The events the journal's entries make, among which a
//! subscription chooses. Each entry makes one event, of the kind
//! [`EventKind::of`] names.

use crate::attempt::AttemptResult;
use crate::journal::Entry;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventKind {
    /// A message was accepted.
    Accepted,
    /// The receiver accepted a delivery.
    Delivered,
    /// Capture mode took a delivery in place of sending it: no
    /// receiver saw it.
    Captured,
    /// The receiver refused a delivery for now, and it is tried again.
    Deferred,
    /// The receiver refused a delivery for good, or a report said it
    /// bounced after the receiver took it.
    Bounced,
    /// The receiver may have accepted a delivery and its answer was lost, so
    /// it is tried again.
    Uncertain,
    /// A delivery ran out of time before it finished.
    Expired,
    /// A delivery's recipient is suppressed, so it was not sent.
    Suppressed,
    /// A delivery's authority was withdrawn, so it was not sent.
    Cancelled,
    /// A report said a delivery's recipient complained.
    Complained,
}

impl EventKind {
    pub const ALL: [Self; 10] = [
        Self::Accepted,
        Self::Delivered,
        Self::Captured,
        Self::Deferred,
        Self::Bounced,
        Self::Uncertain,
        Self::Expired,
        Self::Suppressed,
        Self::Cancelled,
        Self::Complained,
    ];

    /// The kind of event `entry` makes.
    pub fn of(entry: &Entry) -> Self {
        match entry {
            Entry::Accepted { .. } => Self::Accepted,
            Entry::Attempted { attempt, .. } => match attempt.ended.map(|ended| ended.result) {
                Some(AttemptResult::Delivered) => Self::Delivered,
                Some(AttemptResult::Captured) => Self::Captured,
                Some(AttemptResult::Rejected) => Self::Bounced,
                Some(AttemptResult::Deferred) => Self::Deferred,
                Some(AttemptResult::Uncertain | AttemptResult::Abandoned) | None => Self::Uncertain,
            },
            Entry::Expired { .. } => Self::Expired,
            Entry::Suppressed { .. } => Self::Suppressed,
            Entry::Cancelled { .. } => Self::Cancelled,
            Entry::Bounced { .. } => Self::Bounced,
            Entry::Complained { .. } => Self::Complained,
        }
    }

    /// Its name, as subscriptions and events give it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Delivered => "delivered",
            Self::Captured => "captured",
            Self::Deferred => "deferred",
            Self::Bounced => "bounced",
            Self::Uncertain => "uncertain",
            Self::Expired => "expired",
            Self::Suppressed => "suppressed",
            Self::Cancelled => "cancelled",
            Self::Complained => "complained",
        }
    }

    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_is_found_by_its_name() {
        for kind in EventKind::ALL {
            assert_eq!(EventKind::named(kind.name()), Some(kind));
        }
        assert_eq!(EventKind::named("Delivered"), None);
    }
}
