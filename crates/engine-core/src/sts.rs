//! A domain's MTA-STS policy (RFC 8461), as delivery keeps it.
//! A policy holds for its `max_age` from when it was fetched, and the store
//! keeps it that long, across restarts: an attacker who blocks its lookup
//! or its policy host cannot take it away, which is what the RFC's cache is
//! for (section 10.2).

use std::time::Duration;

use crate::time::Timestamp;

/// How a policy asks to be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Mail goes only to the exchanges it names, over TLS whose certificate
    /// the web PKI trusts for the exchange's name.
    Enforce,
    /// Mail goes as it would without a policy.
    Testing,
    /// The domain has withdrawn its policy.
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The domain it is for, in lowercase.
    pub domain: Box<str>,
    /// The ID the domain's `_mta-sts` record named when it was fetched: a
    /// record naming another announces a new policy.
    pub id: Box<str>,
    pub mode: Mode,
    /// The exchanges it permits, in lowercase: names, and names after `*.`
    /// for any one label in front of them.
    pub mx: Vec<Box<str>>,
    pub max_age: Duration,
    pub fetched_at: Timestamp,
}

impl Policy {
    /// The longest a policy may hold (RFC 8461, 3.2).
    pub const MAX_AGE: Duration = Duration::from_secs(31_557_600);

    pub fn expires_at(&self) -> Timestamp {
        self.fetched_at.saturating_add(self.max_age)
    }

    /// Whether it still holds at `now`.
    pub fn holds(&self, now: Timestamp) -> bool {
        now < self.expires_at()
    }

    /// Whether mail to its domain must keep to it.
    pub fn enforces(&self) -> bool {
        self.mode == Mode::Enforce
    }

    /// Whether it permits mail to `exchange`, a lowercase name (RFC 8461,
    /// 4.1): one of its names, or one label in front of a name after `*.`.
    pub fn permits(&self, exchange: &str) -> bool {
        self.mx
            .iter()
            .any(|pattern| match pattern.strip_prefix("*.") {
                Some(parent) => exchange
                    .split_once('.')
                    .is_some_and(|(label, rest)| !label.is_empty() && rest == parent),
                None => **pattern == *exchange,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mx: &[&str]) -> Policy {
        Policy {
            domain: "example.test".into(),
            id: "1".into(),
            mode: Mode::Enforce,
            mx: mx.iter().map(|&pattern| pattern.into()).collect(),
            max_age: Duration::from_secs(86_400),
            fetched_at: Timestamp::from_micros(1_000_000),
        }
    }

    #[test]
    fn a_wildcard_permits_one_label_in_front_of_its_name_and_no_more() {
        let policy = policy(&["mx.example.test", "*.mail.example.test"]);
        assert!(policy.permits("mx.example.test"));
        assert!(policy.permits("a.mail.example.test"));
        assert!(!policy.permits("mail.example.test"));
        assert!(!policy.permits("a.b.mail.example.test"));
        assert!(!policy.permits("mx2.example.test"));
    }

    #[test]
    fn a_policy_holds_for_its_max_age_from_its_fetch() {
        let policy = policy(&[]);
        assert!(policy.holds(Timestamp::from_micros(86_400_999_999)));
        assert!(!policy.holds(Timestamp::from_micros(86_401_000_000)));
    }
}
