//! Time as an input. Deterministic code never reads a clock: its driver
//! passes the current time into every call.

use std::time::Duration;

/// Wall-clock time, in microseconds since the Unix epoch. Persisted
/// deadlines (retry times, expiry) use it, so they keep their meaning across
/// restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Timestamp(u64);

/// Monotonic time, in microseconds since an origin its driver chooses. Live
/// timers use it, so a change to the wall clock never fires them early or
/// late.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Monotonic(u64);

/// The current time on both clocks, read together by the driver.
///
/// Within one driver's lifetime neither clock goes backwards: a driver holds
/// the wall clock still rather than pass a backward step through. Across a
/// restart the wall clock may read earlier than timestamps already
/// persisted, and code that compares against stored deadlines tolerates
/// that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    pub wall: Timestamp,
    pub monotonic: Monotonic,
}

/// Turns a driver's raw clock readings into [`Now`], holding either clock
/// still across a backward step. Both drivers read time through it, so they
/// treat clocks the same way.
#[derive(Debug, Default)]
pub struct Clock {
    last: Option<Now>,
}

impl Clock {
    pub fn observe(&mut self, wall: Timestamp, monotonic: Monotonic) -> Now {
        let now = match self.last {
            Some(last) => Now {
                wall: wall.max(last.wall),
                monotonic: monotonic.max(last.monotonic),
            },
            None => Now { wall, monotonic },
        };
        self.last = Some(now);
        now
    }
}

macro_rules! microsecond_clock {
    ($name:ident) => {
        impl $name {
            pub const fn from_micros(micros: u64) -> Self {
                Self(micros)
            }

            pub const fn as_micros(self) -> u64 {
                self.0
            }

            /// This time plus `duration`, saturating at the end of time.
            pub fn saturating_add(self, duration: Duration) -> Self {
                Self(self.0.saturating_add(micros(duration)))
            }

            /// This time less `duration`, saturating at the start of time.
            pub fn saturating_sub(self, duration: Duration) -> Self {
                Self(self.0.saturating_sub(micros(duration)))
            }

            /// The time elapsed since `earlier`, or zero if `earlier` is
            /// later.
            pub fn saturating_duration_since(self, earlier: Self) -> Duration {
                Duration::from_micros(self.0.saturating_sub(earlier.0))
            }
        }
    };
}

microsecond_clock!(Timestamp);
microsecond_clock!(Monotonic);

impl Timestamp {
    /// Milliseconds since the Unix epoch.
    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000
    }

    /// This moment by the UTC calendar.
    pub fn utc(self) -> Utc {
        let seconds = self.0 / 1_000_000;
        let days = seconds / 86_400;
        let of_day = seconds % 86_400;
        // Howard Hinnant's civil_from_days, for days since 1970-01-01.
        let z = days + 719_468;
        let era = z / 146_097;
        let doe = z % 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        Utc {
            year: yoe + era * 400 + u64::from(month <= 2),
            month,
            day: doy - (153 * mp + 2) / 5 + 1,
            weekday: days % 7,
            hour: of_day / 3600,
            minute: of_day % 3600 / 60,
            second: of_day % 60,
            millisecond: self.0 / 1_000 % 1_000,
        }
    }
}

/// A moment by the UTC calendar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utc {
    pub year: u64,
    /// 1 to 12.
    pub month: u64,
    /// 1 to 31.
    pub day: u64,
    /// Days since a Thursday, as 1 January 1970 was: 0 to 6.
    pub weekday: u64,
    pub hour: u64,
    pub minute: u64,
    pub second: u64,
    pub millisecond: u64,
}

/// A duration in whole microseconds, saturating at `u64::MAX`.
pub(crate) fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_saturates() {
        let late = Timestamp::from_micros(u64::MAX - 1);
        assert_eq!(
            late.saturating_add(Duration::from_secs(1)).as_micros(),
            u64::MAX
        );
        let early = Timestamp::from_micros(5);
        assert_eq!(early.saturating_duration_since(late), Duration::ZERO);
        assert_eq!(
            late.saturating_duration_since(early),
            Duration::from_micros(u64::MAX - 6)
        );
        assert_eq!(Timestamp::from_micros(1_234_567).as_millis(), 1_234);
    }

    #[test]
    fn a_moment_reads_by_the_calendar() {
        // 2026-10-27T15:30:05.250Z, a Tuesday.
        let at = Timestamp::from_micros(1_793_115_005_250_000).utc();
        assert_eq!(
            (at.year, at.month, at.day, at.hour, at.minute, at.second),
            (2026, 10, 27, 15, 30, 5)
        );
        assert_eq!((at.weekday, at.millisecond), (5, 250));
        let leap = Timestamp::from_micros(951_782_400_000_000).utc();
        assert_eq!((leap.year, leap.month, leap.day), (2000, 2, 29));
    }

    #[test]
    fn a_clock_holds_still_across_a_backward_step() {
        let mut clock = Clock::default();
        let (wall, monotonic) = (Timestamp::from_micros(100), Monotonic::from_micros(10));
        assert_eq!(clock.observe(wall, monotonic), Now { wall, monotonic });

        let stepped_back = clock.observe(Timestamp::from_micros(40), Monotonic::from_micros(20));
        assert_eq!(stepped_back.wall, wall);
        assert_eq!(stepped_back.monotonic, Monotonic::from_micros(20));

        let caught_up = clock.observe(Timestamp::from_micros(150), Monotonic::from_micros(30));
        assert_eq!(caught_up.wall, Timestamp::from_micros(150));
    }
}
