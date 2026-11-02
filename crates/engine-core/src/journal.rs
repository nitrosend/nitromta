//! The transition journal: in commit order, an entry for each
//! message accepted, for each attempt or delivery that ends, and for each
//! bounce or complaint a report makes about a delivery. Events are read
//! from it, and it holds each attempt's evidence, so there are no
//! attempt records of their own.

use crate::attempt::{Attempt, Evidence};
use crate::id::{AccountId, ConfigurationId, DeliveryId, MessageId, ReportId};
use crate::status::Status;
use crate::time::Timestamp;

/// Each entry names the configuration its mail was sent under, so a
/// subscription finds the entries it owes without reading their records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A message accepted, with the deliveries it made.
    Accepted {
        message: MessageId,
        account: AccountId,
        configuration: Option<ConfigurationId>,
        deliveries: Vec<DeliveryId>,
        at: Timestamp,
    },
    /// An attempt ended, with how it ended and what the receiver said.
    Attempted {
        attempt: Attempt,
        configuration: Option<ConfigurationId>,
        evidence: Option<Evidence>,
    },
    /// A delivery ran out of time before it finished.
    Expired {
        delivery: DeliveryId,
        account: AccountId,
        configuration: Option<ConfigurationId>,
        at: Timestamp,
    },
    /// A delivery whose recipient was suppressed finished without an
    /// attempt.
    Suppressed {
        delivery: DeliveryId,
        account: AccountId,
        configuration: Option<ConfigurationId>,
        at: Timestamp,
    },
    /// A delivery whose authority was withdrawn finished without an
    /// attempt.
    Cancelled {
        delivery: DeliveryId,
        account: AccountId,
        configuration: Option<ConfigurationId>,
        at: Timestamp,
    },
    /// A report said a delivery bounced after its receiver took it,
    /// with the status the report gave, and whether a reporter the
    /// operator enrolled with signed it.
    Bounced {
        delivery: DeliveryId,
        account: AccountId,
        configuration: Option<ConfigurationId>,
        report: ReportId,
        status: Option<Status>,
        authenticated: bool,
        at: Timestamp,
    },
    /// A report said a delivery's recipient complained, with the report's
    /// feedback type, and whether a reporter the operator enrolled with
    /// signed it.
    Complained {
        delivery: DeliveryId,
        account: AccountId,
        configuration: Option<ConfigurationId>,
        report: ReportId,
        feedback_type: String,
        authenticated: bool,
        at: Timestamp,
    },
}

impl Entry {
    /// The deliveries it is about.
    pub fn deliveries(&self) -> Vec<DeliveryId> {
        match self {
            Self::Accepted { deliveries, .. } => deliveries.clone(),
            Self::Attempted { attempt, .. } => vec![attempt.delivery],
            Self::Expired { delivery, .. }
            | Self::Suppressed { delivery, .. }
            | Self::Cancelled { delivery, .. }
            | Self::Bounced { delivery, .. }
            | Self::Complained { delivery, .. } => vec![*delivery],
        }
    }

    /// When it happened: the acceptance, the attempt's end, or the finish.
    pub fn at(&self) -> Timestamp {
        match self {
            Self::Accepted { at, .. }
            | Self::Expired { at, .. }
            | Self::Suppressed { at, .. }
            | Self::Cancelled { at, .. }
            | Self::Bounced { at, .. }
            | Self::Complained { at, .. } => *at,
            Self::Attempted { attempt, .. } => {
                attempt.ended.map_or(attempt.reserved_at, |ended| ended.at)
            }
        }
    }

    pub fn configuration(&self) -> Option<ConfigurationId> {
        match self {
            Self::Accepted { configuration, .. }
            | Self::Attempted { configuration, .. }
            | Self::Expired { configuration, .. }
            | Self::Suppressed { configuration, .. }
            | Self::Cancelled { configuration, .. }
            | Self::Bounced { configuration, .. }
            | Self::Complained { configuration, .. } => *configuration,
        }
    }
}
