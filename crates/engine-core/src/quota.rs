//! The acceptance quota: the recipients each account accepted in
//! the last 24 hours, rolling, counted by the minute. A minute leaves the
//! window only once all of it is more than 24 hours old, so no 24 hours
//! ever admit more than the quota.
//!
//! The commit owner holds the ledger, so two acceptances can never both take
//! the last of a quota. Each minute's count is written once for each commit
//! group that changed it, and deleted once it has left the window, so a
//! restart reads at most a day of minutes for each account.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::AccountId;
use crate::time::Timestamp;

/// The minutes the quota counts back over.
pub const WINDOW_MINUTES: u64 = 24 * 60;

/// A minute of acceptances: its account, and the minute since the epoch.
pub type Minute = (AccountId, u64);

#[derive(Debug, Default)]
pub struct Ledger {
    counts: BTreeMap<AccountId, BTreeMap<u64, u64>>,
    totals: BTreeMap<AccountId, u64>,
    /// Minutes changed, and minutes gone from the window, since the last
    /// flush.
    changed: BTreeSet<Minute>,
    gone: BTreeSet<Minute>,
}

/// What changed since the last flush: each changed minute's count, and the
/// minutes to delete.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flushed {
    pub counts: Vec<(Minute, u64)>,
    pub gone: Vec<Minute>,
}

impl Ledger {
    /// The ledger as stored.
    pub fn from_counts(counts: impl IntoIterator<Item = (Minute, u64)>) -> Self {
        let mut ledger = Self::default();
        for ((account, minute), count) in counts {
            *ledger
                .counts
                .entry(account)
                .or_default()
                .entry(minute)
                .or_default() += count;
            *ledger.totals.entry(account).or_default() += count;
        }
        ledger
    }

    /// The recipients `account` accepted in the 24 hours up to `at`.
    pub fn sent(&mut self, account: AccountId, at: Timestamp) -> u64 {
        self.expire(account, at);
        self.totals.get(&account).copied().unwrap_or(0)
    }

    /// Whether `account` may accept `recipients` more at `at` within
    /// `quota`.
    pub fn admits(
        &mut self,
        account: AccountId,
        at: Timestamp,
        recipients: u64,
        quota: u64,
    ) -> bool {
        self.sent(account, at).saturating_add(recipients) <= quota
    }

    /// Counts `recipients` accepted for `account` at `at`.
    pub fn count(&mut self, account: AccountId, at: Timestamp, recipients: u64) {
        self.expire(account, at);
        let minute = minute_of(at);
        *self
            .counts
            .entry(account)
            .or_default()
            .entry(minute)
            .or_default() += recipients;
        *self.totals.entry(account).or_default() += recipients;
        self.gone.remove(&(account, minute));
        self.changed.insert((account, minute));
    }

    /// Forgets every account's minutes that have left the window as of
    /// `at`.
    pub fn expire_all(&mut self, at: Timestamp) {
        let accounts: Vec<AccountId> = self.counts.keys().copied().collect();
        for account in accounts {
            self.expire(account, at);
        }
    }

    /// What changed since the last flush, for the store to write.
    pub fn flush(&mut self) -> Flushed {
        let counts = std::mem::take(&mut self.changed)
            .into_iter()
            .filter_map(|(account, minute)| {
                let count = self.counts.get(&account)?.get(&minute)?;
                Some(((account, minute), *count))
            })
            .collect();
        Flushed {
            counts,
            gone: std::mem::take(&mut self.gone).into_iter().collect(),
        }
    }

    fn expire(&mut self, account: AccountId, at: Timestamp) {
        let Some(minutes) = self.counts.get_mut(&account) else {
            return;
        };
        let first = minute_of(at).saturating_sub(WINDOW_MINUTES);
        let kept = minutes.split_off(&first);
        let gone = std::mem::replace(minutes, kept);
        let total = self.totals.entry(account).or_default();
        for (minute, count) in gone {
            *total -= count;
            self.changed.remove(&(account, minute));
            self.gone.insert((account, minute));
        }
    }
}

fn minute_of(at: Timestamp) -> u64 {
    at.as_micros() / 60_000_000
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::id::Id;

    const ACCOUNT: AccountId = AccountId(Id::from_u64(1).unwrap());
    const OTHER: AccountId = AccountId(Id::from_u64(2).unwrap());
    const START: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);

    fn later(minutes: u64) -> Timestamp {
        START.saturating_add(Duration::from_secs(minutes * 60))
    }

    #[test]
    fn the_quota_counts_the_last_24_hours_rolling() {
        let mut ledger = Ledger::default();
        ledger.count(ACCOUNT, START, 60);
        ledger.count(ACCOUNT, later(600), 30);
        assert!(ledger.admits(ACCOUNT, later(600), 10, 100));
        assert!(!ledger.admits(ACCOUNT, later(600), 11, 100));
        assert!(
            ledger.admits(OTHER, later(600), 100, 100),
            "each account its own"
        );
        assert_eq!(ledger.sent(ACCOUNT, later(WINDOW_MINUTES)), 90);
        assert_eq!(
            ledger.sent(ACCOUNT, later(WINDOW_MINUTES + 1)),
            30,
            "the first minute has left the window"
        );
        assert!(ledger.admits(ACCOUNT, later(WINDOW_MINUTES + 1), 70, 100));
    }

    #[test]
    fn a_minute_stays_until_its_last_recipient_is_a_day_old() {
        let mut ledger = Ledger::default();
        let last_second = START.saturating_add(Duration::from_secs(59));
        ledger.count(ACCOUNT, last_second, 100);
        let a_day_on = last_second.saturating_add(Duration::from_secs(24 * 60 * 60));
        assert!(
            !ledger.admits(ACCOUNT, a_day_on, 1, 100),
            "a day after the minute's last recipient, not before"
        );
        assert!(ledger.admits(
            ACCOUNT,
            a_day_on.saturating_add(Duration::from_secs(1)),
            100,
            100
        ));
    }

    #[test]
    fn a_minute_is_written_once_per_flush_and_deleted_once_it_leaves() {
        let mut ledger = Ledger::default();
        ledger.count(ACCOUNT, START, 1);
        ledger.count(ACCOUNT, START, 2);
        let minute = (ACCOUNT, START.as_micros() / 60_000_000);
        assert_eq!(
            ledger.flush(),
            Flushed {
                counts: vec![(minute, 3)],
                gone: Vec::new(),
            }
        );
        assert_eq!(ledger.flush(), Flushed::default(), "nothing changed since");
        ledger.expire_all(later(WINDOW_MINUTES + 1));
        assert_eq!(ledger.flush().gone, vec![minute]);

        let mut read = Ledger::from_counts([(minute, 3)]);
        assert_eq!(read.sent(ACCOUNT, START), 3);
    }
}
