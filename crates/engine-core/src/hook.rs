//! Hook points: where a build's own code decides along the
//! pipeline without changing the core. Admission decides each message once
//! it is prepared and before its acceptance commits; dispatch decides each
//! recipient before its reservation. Anything that only watches reads the
//! events instead.
//!
//! A hook is compiled into a build of its own, which hands it to the shell.
//! The shell asks it outside the commit owner, within the time and the
//! number of calls at once its configuration allows, and answers by the
//! hook's failure policy when it does not decide in time. A hook only
//! refuses or holds: what it lets through still meets authorisation,
//! durability and suppression. With none, nothing is asked.

use std::future::Future;
use std::pin::Pin;

/// A hook's answer, once it comes: a verdict for each of what it was asked
/// about, in order, or why it could not decide.
pub type Answer<V> = Pin<Box<dyn Future<Output = Result<Vec<V>, String>> + Send>>;

/// Why a hook refused or held something, as SMTP replies and the journal
/// carry it: printable ASCII on one line, at most `Reason::MAX` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason(Box<str>);

impl Reason {
    pub const MAX: usize = 200;

    /// `text`, with ASCII whitespace as spaces and anything else but
    /// printable ASCII as `?`, cut to `MAX`.
    pub fn new(text: &str) -> Self {
        let text: String = text
            .chars()
            .map(|c| match c {
                c if c.is_ascii_graphic() => c,
                c if c.is_ascii_whitespace() => ' ',
                _ => '?',
            })
            .take(Self::MAX)
            .collect();
        match text.trim() {
            "" => Self("no reason given".into()),
            text => Self(text.into()),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub mod admission {
    //! The admission hook: each message, once prepared and before its
    //! acceptance commits.

    use std::sync::Arc;

    use bytes::Bytes;

    use super::{Answer, Reason};
    use crate::address::Address;
    use crate::command::Authority;
    use crate::id::MessageId;

    /// A message as admission sees it: prepared and signed, and not yet
    /// accepted.
    #[derive(Clone, Debug)]
    pub struct Message {
        pub id: MessageId,
        /// The account, credential, identity, tenant and configuration it
        /// is sent under.
        pub authority: Authority,
        pub recipients: Vec<Address>,
        /// The message exactly as it is to be sent: a handle on its one
        /// copy, which a hook cannot change.
        pub content: Bytes,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Verdict {
        Accept,
        /// Refused for good: its client is told so, and nothing is kept.
        Reject(Reason),
        /// Refused for now: its client may send it again.
        Defer(Reason),
    }

    impl Verdict {
        /// What its client is told, unless it accepts.
        pub fn refused(self) -> Option<Refused> {
            match self {
                Self::Accept => None,
                Self::Reject(reason) => Some(Refused {
                    permanent: true,
                    reason,
                }),
                Self::Defer(reason) => Some(Refused {
                    permanent: false,
                    reason,
                }),
            }
        }
    }

    /// A message admission refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Refused {
        /// For good, rather than for now.
        pub permanent: bool,
        pub reason: Reason,
    }

    pub trait Hook: Send + Sync + 'static {
        /// Decides each of `messages`: one verdict each, in order.
        fn admit(self: Arc<Self>, messages: Vec<Message>) -> Answer<Verdict>;
    }
}

pub mod dispatch {
    //! The dispatch hook: each recipient, before its reservation, so a
    //! recipient it holds or rejects spends no budget and its body is not
    //! read.

    use std::sync::Arc;

    use super::{Answer, Reason};
    use crate::address::Address;
    use crate::id::{DeliveryId, EgressId, MessageId};
    use crate::policy::Origin;

    /// A recipient about to be reserved for an attempt.
    #[derive(Clone, Debug)]
    pub struct Recipient {
        pub delivery: DeliveryId,
        pub message: MessageId,
        pub address: Address,
        /// The identity, tenant and configuration its message was sent
        /// under.
        pub origin: Origin,
        /// Attempts it has had so far.
        pub attempts: u32,
        /// The receiver site it goes to.
        pub site: Arc<str>,
        /// The egress it goes out from: the host's own address when absent.
        pub egress: Option<EgressId>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Verdict {
        Proceed,
        /// Not now: it waits for its next retry, with the reason as the
        /// engine's own evidence.
        Hold(Reason),
        /// Never: it fails, with the reason as the engine's own evidence.
        Reject(Reason),
    }

    pub trait Hook: Send + Sync + 'static {
        /// Decides each of `recipients`: one verdict each, in order.
        fn decide(self: Arc<Self>, recipients: Vec<Recipient>) -> Answer<Verdict>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_is_one_line_of_printable_ascii_within_its_bound() {
        assert_eq!(Reason::new("virus\r\nfound: é").as_str(), "virus  found: ?");
        assert_eq!(Reason::new(&"x".repeat(500)).as_str().len(), Reason::MAX);
        assert_eq!(Reason::new("  \t ").as_str(), "no reason given");
    }
}
