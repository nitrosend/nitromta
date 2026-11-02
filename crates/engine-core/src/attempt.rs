//! An attempt: one transport attempt for one delivery, kept as evidence of
//! what happened to it.

use crate::delivery::Disposition;
use crate::id::{AccountId, AttemptId, DeliveryId};
use crate::time::Timestamp;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub id: AttemptId,
    pub delivery: DeliveryId,
    pub account: AccountId,
    /// When its delivery was reserved for it.
    pub reserved_at: Timestamp,
    /// How it ended, once it has.
    pub ended: Option<AttemptEnd>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptEnd {
    pub result: AttemptResult,
    pub at: Timestamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptResult {
    Delivered,
    Rejected,
    Deferred,
    /// Its outcome was lost, for example with the receiver's final reply.
    Uncertain,
    /// Its process stopped before its outcome was recorded, so it may have
    /// reached the receiver.
    Abandoned,
    /// Capture mode took it in place of delivery.
    Captured,
}

/// What the receiver last said in an attempt: its reply's code and text,
/// kept to [`Evidence::MAX_TEXT_BYTES`], and the receiver rules it matched;
/// or, with [`Evidence::LOCAL`] for its code, the engine's own account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub code: u16,
    pub text: String,
    /// The names of the receiver rules that matched it,
    /// separated by spaces; empty when none did.
    pub rules: String,
}

impl Evidence {
    /// The most of a reply's text kept, cut at a character's boundary.
    pub const MAX_TEXT_BYTES: usize = 512;

    /// The code of the engine's own account, given when no receiver's
    /// reply says why an attempt went no further: a TLS policy it could
    /// not keep, for one.
    pub const LOCAL: u16 = 0;

    /// The code of the engine's own decision to hold a delivery back before
    /// any connection: a dispatch hook's hold. SES-shaped events call the
    /// delay it causes a sending deferral, not a failure to communicate.
    pub const HELD: u16 = 1;

    /// The engine's own account of why mail went no further.
    pub fn local(text: &str) -> Self {
        Self::new(Self::LOCAL, text)
    }

    /// The engine's own account of why it held a delivery back.
    pub fn held(text: &str) -> Self {
        Self::new(Self::HELD, text)
    }

    /// Whether it is the engine's own account rather than a reply.
    pub fn is_local(&self) -> bool {
        matches!(self.code, Self::LOCAL | Self::HELD)
    }

    pub fn new(code: u16, text: &str) -> Self {
        let mut end = text.len().min(Self::MAX_TEXT_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            code,
            text: text[..end].to_owned(),
            rules: String::new(),
        }
    }
}

impl From<Disposition> for AttemptResult {
    fn from(disposition: Disposition) -> Self {
        match disposition {
            Disposition::Delivered => Self::Delivered,
            Disposition::Rejected => Self::Rejected,
            Disposition::Deferred { .. } => Self::Deferred,
            Disposition::Uncertain { .. } => Self::Uncertain,
            Disposition::Captured => Self::Captured,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_is_kept_to_its_limit_whole_characters_only() {
        let text = format!("{}é", "x".repeat(Evidence::MAX_TEXT_BYTES - 1));
        let kept = Evidence::new(550, &text);
        assert_eq!(kept.text.len(), Evidence::MAX_TEXT_BYTES - 1);
        assert_eq!(Evidence::new(250, "2.0.0 Ok").text, "2.0.0 Ok");
    }
}
