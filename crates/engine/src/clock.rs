//! Time for the components: both system clocks, read together through
//! engine-core's [`Clock`], which holds either one still across a backward
//! step, as the simulator does.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use engine_core::time::{Clock, Monotonic, Now, Timestamp};

pub struct SystemClock {
    origin: Instant,
    clock: Mutex<Clock>,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            clock: Mutex::new(Clock::default()),
        }
    }

    pub fn now(&self) -> Now {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_micros()).unwrap_or(u64::MAX)
            });
        let monotonic = u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observe(
                Timestamp::from_micros(wall),
                Monotonic::from_micros(monotonic),
            )
    }

    /// The instant at which the monotonic clock reads `at`, for a timer.
    pub fn instant(&self, at: Monotonic) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.origin + Duration::from_micros(at.as_micros()))
    }
}
