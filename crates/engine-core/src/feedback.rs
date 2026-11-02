//! Feedback: bounce and complaint reports about the engine's
//! mail, as its feedback listener received them, and what each may change.
//!
//! Correlation is not trust. A report's return path names the message it
//! is about only through a token the engine issued, and its recipients
//! count only when they are that message's own. Even then a report is
//! strongly correlated, not authenticated, unless a reporter the operator
//! enrolled with signed it. The operator names the least of those classes
//! whose reports may suppress and count; a report below it is
//! recorded, and changes nothing else.

use bytes::Bytes;

use crate::address::Address;
use crate::id::{MessageId, ReportId};
use crate::status::Status;
use crate::time::Timestamp;

/// The most bytes of a report kept as its evidence.
pub const MAX_EVIDENCE_BYTES: usize = 64 * 1024;

/// A report to record: what it claims, which the store weighs against the
/// message it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub id: ReportId,
    /// The message its return path's token names, when the token is one
    /// the engine issued.
    pub message: Option<MessageId>,
    pub kind: Kind,
    /// The recipients it names, and what it says of each.
    pub recipients: Vec<Claim>,
    /// What makes it the same report as one received before, whenever it
    /// arrives: its reporter's ID, the message it names and its
    /// kind. With each recipient, it makes the effect on that recipient's
    /// delivery, which happens once however often the report comes.
    pub identity: [u8; 32],
    /// As it arrived, at most [`MAX_EVIDENCE_BYTES`].
    pub evidence: Bytes,
    pub received_at: Timestamp,
    /// It carries a DKIM signature that verified, by a reporter the
    /// operator enrolled with: the marker its events carry.
    pub authenticated: bool,
    /// Its evidence is of a class the operator lets suppress an address
    /// and count toward complaints and warmup.
    pub trusted: bool,
    /// Made by a mailbox simulator for its own address, not received: its
    /// events are recorded and it suppresses nothing, as a simulator's
    /// addresses are never suppressed. Its effects are decided as it is
    /// recorded, so it is not kept.
    pub simulated: bool,
}

/// The classes of evidence a report may be of, from the least:
/// the operator names the least whose reports suppress and count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// Its return path's token is one the engine issued, and it names that
    /// message's own recipients.
    #[default]
    Correlated,
    /// As well, a reporter the operator enrolled with signed it.
    Authenticated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A delivery status notification (RFC 3464).
    DeliveryStatus,
    /// A feedback report (RFC 5965) of this feedback type, in lowercase.
    Feedback(String),
    /// Neither: kept as evidence about its message, if it names one.
    Unrecognised,
}

/// What a report says of one recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub address: Address,
    /// For a delivery status notification: whether delivery to it failed.
    pub failed: bool,
    pub status: Option<Status>,
    /// Whether its status rules the address out, as the intake judged it
    /// by the receiver rules: a permanent failure in a class
    /// that does.
    pub rules_out_address: bool,
    /// The receiver's words, at most 512 bytes.
    pub diagnostic: Option<String>,
}

/// What a report does to one delivery it is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The delivery bounced after the receiver took it: an event, and the
    /// recipient suppressed when the status rules the address out.
    Bounced { suppress: bool },
    /// Its recipient complained: an event, and the recipient suppressed for
    /// a complaint of abuse.
    Complained { suppress: bool },
    /// Nothing but the evidence.
    None,
}

impl Report {
    /// What it does to a delivery whose recipient `claim` names.
    /// A failure suppresses only when its status rules the address
    /// out; a complaint only when it reports abuse; and either
    /// only when the report is trusted. Fraud, virus and other reports are
    /// complaints without a suppression, and a `not-spam` or
    /// `auth-failure` report is not a complaint at all.
    pub fn effect(&self, claim: &Claim) -> Effect {
        let suppresses = self.trusted && !self.simulated;
        match &self.kind {
            Kind::DeliveryStatus if claim.failed => Effect::Bounced {
                suppress: claim.rules_out_address && suppresses,
            },
            Kind::Feedback(feedback_type) => match feedback_type.as_str() {
                "abuse" => Effect::Complained {
                    suppress: suppresses,
                },
                "fraud" | "virus" | "other" => Effect::Complained { suppress: false },
                _ => Effect::None,
            },
            Kind::DeliveryStatus | Kind::Unrecognised => Effect::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::Id;

    fn report(kind: Kind) -> Report {
        Report {
            id: ReportId(Id::from_u64(1).unwrap()),
            message: None,
            kind,
            recipients: Vec::new(),
            identity: [0; 32],
            evidence: Bytes::new(),
            received_at: Timestamp::from_micros(0),
            authenticated: false,
            trusted: true,
            simulated: false,
        }
    }

    fn claim(failed: bool, rules_out_address: bool) -> Claim {
        Claim {
            address: Address::parse("a@example.com").unwrap(),
            failed,
            status: None,
            rules_out_address,
            diagnostic: None,
        }
    }

    #[test]
    fn a_failure_suppresses_only_when_it_rules_the_address_out() {
        let bounce = report(Kind::DeliveryStatus);
        assert_eq!(
            bounce.effect(&claim(true, true)),
            Effect::Bounced { suppress: true }
        );
        assert_eq!(
            bounce.effect(&claim(true, false)),
            Effect::Bounced { suppress: false }
        );
        // A delay, or a relay's notice, is no bounce.
        assert_eq!(bounce.effect(&claim(false, false)), Effect::None);
    }

    #[test]
    fn only_a_complaint_of_abuse_suppresses() {
        let of = |feedback_type: &str| {
            report(Kind::Feedback(feedback_type.to_owned())).effect(&claim(false, false))
        };
        assert_eq!(of("abuse"), Effect::Complained { suppress: true });
        for complaint in ["fraud", "virus", "other"] {
            assert_eq!(of(complaint), Effect::Complained { suppress: false });
        }
        for not_one in ["not-spam", "auth-failure", "anything"] {
            assert_eq!(of(not_one), Effect::None);
        }
        assert_eq!(
            report(Kind::Unrecognised).effect(&claim(true, true)),
            Effect::None
        );
    }

    #[test]
    fn an_untrusted_report_is_its_events_alone() {
        let untrusted = |kind| Report {
            trusted: false,
            ..report(kind)
        };
        assert_eq!(
            untrusted(Kind::DeliveryStatus).effect(&claim(true, true)),
            Effect::Bounced { suppress: false }
        );
        assert_eq!(
            untrusted(Kind::Feedback("abuse".to_owned())).effect(&claim(false, false)),
            Effect::Complained { suppress: false }
        );
    }
}
