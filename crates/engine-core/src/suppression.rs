//! Suppression: recipients an account sends no more mail to. A
//! delivery whose recipient is suppressed when it falls due finishes without
//! an attempt; as in SES, its message was accepted all the same.

use crate::address::Address;
use crate::id::AccountId;
use crate::time::Timestamp;

/// Why an address is suppressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// A permanent bounce for it.
    Bounce,
    /// A complaint from it.
    Complaint,
    /// Its account's operator added it.
    Operator,
}

/// What a suppression is matched by: the address in lowercase, as SES
/// matches its suppression list. The address itself keeps its case.
pub fn key(address: &Address) -> String {
    address.as_str().to_ascii_lowercase()
}

/// An address on a suppression list, as it was given, why, and since when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suppressed {
    pub address: Address,
    pub reason: Reason,
    pub at: Timestamp,
}

/// A page of an account's suppression list: in the order of its
/// keys, from after `after`, at most `limit` that are of `reasons` (any, if
/// empty) and were suppressed from `from` and before `to`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    pub account: AccountId,
    pub after: Option<String>,
    pub limit: usize,
    pub reasons: Vec<Reason>,
    pub from: Option<Timestamp>,
    pub to: Option<Timestamp>,
}

impl List {
    /// The most rows one page reads, so a filter that matches few of a long
    /// list holds up no commits for long.
    pub const MOST_READ: usize = 5_000;
}

/// What a page found, and the key of the last row it read, which the next
/// page starts after, while more may follow.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    pub suppressed: Vec<Suppressed>,
    pub next: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_matches_whatever_its_case() {
        let one = Address::parse("Jane.Doe@Example.COM").unwrap();
        let other = Address::parse("jane.doe@example.com").unwrap();
        assert_eq!(key(&one), key(&other));
        assert_eq!(one.as_str(), "Jane.Doe@Example.COM");
    }
}
