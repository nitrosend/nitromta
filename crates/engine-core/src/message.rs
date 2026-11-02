//! A message: one distinct, immutable message, as it was accepted.

use bytes::Bytes;

use crate::id::{AccountId, BodyId, MessageId, SubmissionId};
use crate::policy::Origin;
use crate::time::Timestamp;

/// What SES-shaped events say of their message: kept with
/// it when its configuration publishes to an SES-shaped destination, and
/// nothing for any other message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mail {
    /// The address it was sent as.
    pub source: String,
    /// Who it was accepted for.
    pub destination: Vec<String>,
    /// Its header block as it was sent, at most [`Mail::MOST_HEADERS`]
    /// bytes, cut at the end of a field.
    pub headers: Bytes,
    /// Whether its header block was longer.
    pub truncated: bool,
    /// Its tags, in order, each a name and its value.
    pub tags: Vec<(String, String)>,
}

impl Mail {
    /// The most of a header block kept, as SES keeps for its events.
    pub const MOST_HEADERS: usize = 10 * 1024;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: MessageId,
    pub submission: SubmissionId,
    pub account: AccountId,
    /// The identity, tenant and configuration it was sent under.
    pub origin: Origin,
    /// Its prepared content, exactly as it is sent.
    pub body: BodyId,
    pub accepted_at: Timestamp,
    /// The policy it was accepted under.
    pub policy_revision: PolicyRevision,
    /// How many recipients it was accepted for, however many of its
    /// deliveries retention has removed since.
    pub recipients: u32,
}

/// A revision of the policy that admission and dispatch enforce (see
/// [`crate::policy`]). It increases with every change, so a decision taken
/// under an older revision can be rechecked. A store with no policy yet is
/// at revision 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRevision(pub u64);
