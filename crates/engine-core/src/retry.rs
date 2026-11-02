//! When to try a delivery again after a temporary failure.

use std::time::Duration;

use crate::rng::Rng;
use crate::time::{Timestamp, micros};

/// Backoff that doubles from `first` up to `max`, with jitter. A delivery is
/// retried on this schedule until its absolute expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetrySchedule {
    first: Duration,
    max: Duration,
}

impl RetrySchedule {
    /// `None` unless `0 < first <= max`.
    pub fn new(first: Duration, max: Duration) -> Option<Self> {
        (!first.is_zero() && first <= max).then_some(Self { first, max })
    }

    /// The longest it waits between attempts.
    pub fn max(&self) -> Duration {
        self.max
    }

    /// When to try again after `attempts` attempts have been made: that
    /// attempt's backoff, jittered within its upper half. The jitter spreads
    /// retries out, so deliveries deferred together are not all retried
    /// together.
    pub fn not_before(&self, now: Timestamp, attempts: u32, rng: &mut Rng) -> Timestamp {
        let doublings = attempts.saturating_sub(1).min(31);
        let backoff = micros(self.first.saturating_mul(1 << doublings).min(self.max));
        let jittered = backoff / 2 + rng.below(backoff / 2 + 1);
        now.saturating_add(Duration::from_micros(jittered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_its_cap_with_jitter_in_its_upper_half() {
        let schedule = RetrySchedule::new(Duration::from_secs(60), Duration::from_secs(600))
            .expect("a valid schedule");
        let now = Timestamp::from_micros(1_000_000_000);
        let mut rng = Rng::from_seed(3);
        for (attempts, backoff_secs) in [(1, 60), (2, 120), (3, 240), (4, 480), (5, 600), (40, 600)]
        {
            for _ in 0..1_000 {
                let delay = schedule
                    .not_before(now, attempts, &mut rng)
                    .saturating_duration_since(now);
                let backoff = Duration::from_secs(backoff_secs);
                assert!(
                    delay >= backoff / 2 && delay <= backoff,
                    "{attempts}: {delay:?}"
                );
            }
        }
    }

    #[test]
    fn invalid_schedules_are_refused() {
        assert_eq!(
            RetrySchedule::new(Duration::ZERO, Duration::from_secs(1)),
            None
        );
        assert_eq!(
            RetrySchedule::new(Duration::from_secs(2), Duration::from_secs(1)),
            None
        );
    }
}
