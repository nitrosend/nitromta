//! Abuse bounds: failed authentications by source address, so a
//! guesser is refused before its credentials are checked. An address with
//! [`Failures::LIMIT`] failures inside [`Failures::WINDOW`] of its first is
//! refused until that window passes. At most [`Failures::MOST_TRACKED`]
//! addresses are tracked; when that many are, those past their window are
//! forgotten first, and a new one is not tracked until there is room.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::time::Monotonic;

#[derive(Debug, Default)]
pub struct Failures {
    /// Each address's failures, and when its window began.
    by_address: BTreeMap<IpAddr, (u32, Monotonic)>,
}

impl Failures {
    pub const LIMIT: u32 = 10;
    pub const WINDOW: Duration = Duration::from_secs(600);
    pub const MOST_TRACKED: usize = 65_536;

    /// Whether `address` may try to authenticate at `now`.
    pub fn allows(&self, address: IpAddr, now: Monotonic) -> bool {
        match self.by_address.get(&address) {
            Some(&(count, since)) => count < Self::LIMIT || Self::passed(since, now),
            None => true,
        }
    }

    /// Counts a failed authentication from `address` at `now`.
    pub fn failed(&mut self, address: IpAddr, now: Monotonic) {
        if !self.by_address.contains_key(&address) && self.by_address.len() >= Self::MOST_TRACKED {
            self.by_address
                .retain(|_, &mut (_, since)| !Self::passed(since, now));
            if self.by_address.len() >= Self::MOST_TRACKED {
                return;
            }
        }
        let (count, since) = self.by_address.entry(address).or_insert((0, now));
        if Self::passed(*since, now) {
            (*count, *since) = (0, now);
        }
        *count = count.saturating_add(1);
    }

    /// Whether no address is tracked, so no authentication need ask.
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    fn passed(since: Monotonic, now: Monotonic) -> bool {
        now.saturating_duration_since(since) >= Self::WINDOW
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> Monotonic {
        Monotonic::from_micros(seconds * 1_000_000)
    }

    #[test]
    fn an_address_is_refused_past_its_failures_until_its_window_passes() {
        let mut failures = Failures::default();
        let guesser: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        for second in 0..Failures::LIMIT {
            assert!(failures.allows(guesser, at(u64::from(second))));
            failures.failed(guesser, at(u64::from(second)));
        }
        assert!(!failures.allows(guesser, at(100)));
        assert!(failures.allows(other, at(100)), "only the guesser");
        assert!(failures.allows(guesser, at(600)), "its window has passed");
        // A failure after the window starts a new one.
        failures.failed(guesser, at(600));
        assert!(failures.allows(guesser, at(601)));
    }

    #[test]
    fn it_tracks_a_bounded_number_of_addresses() {
        let mut failures = Failures::default();
        for n in 0..Failures::MOST_TRACKED as u32 {
            failures.failed(IpAddr::from(n.to_be_bytes()), at(0));
        }
        let late = IpAddr::from([10, 255, 255, 255]);
        failures.failed(late, at(1));
        assert_eq!(failures.by_address.len(), Failures::MOST_TRACKED);
        assert!(!failures.by_address.contains_key(&late), "no room yet");
        // Once the others' windows pass, they make room.
        failures.failed(late, at(600));
        assert_eq!(failures.by_address.len(), 1);
    }
}
