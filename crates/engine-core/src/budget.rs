//! The dispatch ledger: reservations per (egress, site) over a
//! rolling 24 hours, in ten-minute buckets, which attempt and warmup
//! budgets read. One [`Window`] holds an (egress, site)'s whole day, so the
//! store keeps it as one row. A bucket leaves the window only once all of
//! it is more than 24 hours old, so a budget errs late, by ten minutes at
//! most, and never early. Beside each window, a [`Tally`] keeps warmup's
//! evidence at a capped egress by UTC day.

use std::time::Duration;

use crate::time::Timestamp;

/// How long one bucket covers.
pub const BUCKET: Duration = Duration::from_secs(600);

/// Buckets a window holds: 24 hours of them, and the one partly past that.
pub const BUCKETS: usize = 145;

/// An (egress, site)'s reservations over the last 24 hours.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    /// The period the newest bucket is for: ten-minute periods since the
    /// Unix epoch.
    newest: u64,
    /// By period, each at `period % BUCKETS`.
    counts: [u32; BUCKETS],
}

impl Default for Window {
    fn default() -> Self {
        Self {
            newest: 0,
            counts: [0; BUCKETS],
        }
    }
}

impl Window {
    /// A window as stored: its newest period and its buckets.
    pub fn from_parts(newest: u64, counts: [u32; BUCKETS]) -> Self {
        Self { newest, counts }
    }

    pub fn parts(&self) -> (u64, &[u32; BUCKETS]) {
        (self.newest, &self.counts)
    }

    /// Counts one reservation made at `at`.
    pub fn add(&mut self, at: Timestamp) {
        let period = period(at).max(self.newest);
        self.advance(period);
        let bucket = &mut self.counts[slot(period)];
        *bucket = bucket.saturating_add(1);
    }

    /// Takes back one reservation counted at `at` that was never made: one
    /// the store refused, or never asked for. Nothing, once it has left the
    /// window.
    pub fn remove(&mut self, at: Timestamp) {
        let period = period(at);
        if period <= self.newest && period + BUCKETS as u64 > self.newest {
            let bucket = &mut self.counts[slot(period)];
            *bucket = bucket.saturating_sub(1);
        }
    }

    /// The reservations made in the 24 hours up to `at`.
    pub fn total(&self, at: Timestamp) -> u64 {
        let now = period(at);
        // A clock that stepped back counts everything.
        let first = now.max(self.newest).saturating_sub(BUCKETS as u64 - 1);
        (first..=self.newest)
            .map(|period| u64::from(self.counts[slot(period)]))
            .sum()
    }

    /// When the oldest reservation it counts at `at` leaves it, if it
    /// counts any: when a budget it holds spent has room again, at the
    /// latest.
    pub fn frees_at(&self, at: Timestamp) -> Option<Timestamp> {
        let now = period(at);
        let first = now.max(self.newest).saturating_sub(BUCKETS as u64 - 1);
        let oldest = (first..=self.newest).find(|period| self.counts[slot(*period)] > 0)?;
        let micros = u64::try_from(BUCKET.as_micros()).unwrap_or(u64::MAX);
        Some(Timestamp::from_micros(
            (oldest + BUCKETS as u64).saturating_mul(micros),
        ))
    }

    /// When a budget of `cap` reservations a day, spent as this window
    /// counts at `at`, has room for the `n`th reservation from then
    /// (0-based), each made as soon as there is room: `at` for those it has
    /// room for already, and for the rest as the reservations it counts
    /// leave it, a day later for each time round. Never early, and late by
    /// a bucket a day at most. None for a cap of nothing, which never has
    /// room.
    pub fn room_at(&self, at: Timestamp, cap: u64, n: u64) -> Option<Timestamp> {
        if cap == 0 {
            return None;
        }
        let total = self.total(at);
        let free = cap.saturating_sub(total);
        let (rounds, place) = (n / cap, n % cap);
        let first = period(at)
            .max(self.newest)
            .saturating_sub(BUCKETS as u64 - 1);
        let micros = u64::try_from(BUCKET.as_micros()).unwrap_or(u64::MAX);
        let room = if place < free {
            at
        } else {
            // Past those over the cap, the reservation whose leaving makes
            // room for it.
            let mut index = total.saturating_sub(cap) + (place - free);
            let leaving = (first..=self.newest).find(|period| {
                let count = u64::from(self.counts[slot(*period)]);
                let found = index < count;
                index = index.saturating_sub(count);
                found
            })?;
            Timestamp::from_micros((leaving + BUCKETS as u64).saturating_mul(micros))
        };
        Some(room.saturating_add(Duration::from_micros(
            rounds.saturating_mul(BUCKETS as u64).saturating_mul(micros),
        )))
    }

    /// Whether it counts nothing at `at`, so it need not be kept.
    pub fn is_empty(&self, at: Timestamp) -> bool {
        self.total(at) == 0
    }

    /// Moves the newest bucket on to `period`, emptying those it passes.
    fn advance(&mut self, period: u64) {
        let passed = period.saturating_sub(self.newest).min(BUCKETS as u64);
        for step in 1..=passed {
            self.counts[slot(self.newest + step)] = 0;
        }
        self.newest = period;
    }
}

/// What one outcome or report at an (egress, site) showed, as warmup counts
/// it: only what the receiver said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Delivered,
    /// A temporary refusal.
    Deferred,
    /// A reply the receiver rules call a throttle, temporary or not.
    Throttled,
    /// A permanent refusal, or a bounce reported after delivery.
    Failed,
    Complained,
}

/// An (egress, site)'s signals on one UTC day.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub delivered: u32,
    pub deferred: u32,
    pub throttled: u32,
    pub failed: u32,
    pub complained: u32,
}

impl Counts {
    pub fn count(&mut self, signal: Signal) {
        let count = match signal {
            Signal::Delivered => &mut self.delivered,
            Signal::Deferred => &mut self.deferred,
            Signal::Throttled => &mut self.throttled,
            Signal::Failed => &mut self.failed,
            Signal::Complained => &mut self.complained,
        };
        *count = count.saturating_add(1);
    }

    /// The receiver's replies counted: its sample. A complaint is not one.
    pub fn replies(&self) -> u64 {
        [self.delivered, self.deferred, self.throttled, self.failed]
            .into_iter()
            .map(u64::from)
            .sum()
    }

    pub fn add(&mut self, other: &Self) {
        self.delivered = self.delivered.saturating_add(other.delivered);
        self.deferred = self.deferred.saturating_add(other.deferred);
        self.throttled = self.throttled.saturating_add(other.throttled);
        self.failed = self.failed.saturating_add(other.failed);
        self.complained = self.complained.saturating_add(other.complained);
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// An (egress, site)'s signals on the UTC day under way and the day before:
/// warmup's evidence, kept in the ledger's row beside its
/// window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// The day `today` counts: days since the Unix epoch.
    day: u64,
    today: Counts,
    yesterday: Counts,
}

impl Tally {
    /// A tally as stored.
    pub fn from_parts(day: u64, today: Counts, yesterday: Counts) -> Self {
        Self {
            day,
            today,
            yesterday,
        }
    }

    pub fn parts(&self) -> (u64, Counts, Counts) {
        (self.day, self.today, self.yesterday)
    }

    /// Counts `signal` on the day of `at`, the day it happened on, which
    /// may be the day before the latest seen: an outcome or report that
    /// waited its turn across midnight. One older than either day it keeps
    /// is of a day already judged, and counts nothing.
    pub fn count(&mut self, signal: Signal, at: Timestamp) {
        let on = day(at);
        self.advance(on);
        if on == self.day {
            self.today.count(signal);
        } else if on.checked_add(1) == Some(self.day) {
            self.yesterday.count(signal);
        }
    }

    /// What it counted on `day`: nothing for a day it no longer keeps.
    pub fn on(&self, day: u64) -> Counts {
        if day == self.day {
            self.today
        } else if day.checked_add(1) == Some(self.day) {
            self.yesterday
        } else {
            Counts::default()
        }
    }

    /// Whether it keeps nothing for the day of `at` or the day before, so
    /// it need not be kept.
    pub fn is_empty(&self, at: Timestamp) -> bool {
        let now = day(at).max(self.day);
        self.on(now).is_empty()
            && now
                .checked_sub(1)
                .is_none_or(|before| self.on(before).is_empty())
    }

    fn advance(&mut self, day: u64) {
        if day <= self.day {
            return;
        }
        self.yesterday = if day == self.day + 1 {
            self.today
        } else {
            Counts::default()
        };
        self.today = Counts::default();
        self.day = day;
    }
}

/// The UTC day `at` falls on: days since the Unix epoch.
pub fn day(at: Timestamp) -> u64 {
    at.as_micros() / DAY_MICROS
}

/// When UTC day `day` begins.
pub fn day_start(day: u64) -> Timestamp {
    Timestamp::from_micros(day.saturating_mul(DAY_MICROS))
}

const DAY_MICROS: u64 = 24 * 3_600 * 1_000_000;

fn period(at: Timestamp) -> u64 {
    at.as_micros() / u64::try_from(BUCKET.as_micros()).unwrap_or(u64::MAX)
}

fn slot(period: u64) -> usize {
    (period % BUCKETS as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A moment on a bucket's edge.
    const START: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);

    fn later(seconds: u64) -> Timestamp {
        START.saturating_add(Duration::from_secs(seconds))
    }

    #[test]
    fn a_window_counts_the_last_24_hours_and_lets_a_bucket_go_only_when_all_of_it_is_older() {
        let mut window = Window::default();
        window.add(later(599));
        window.add(later(600));
        window.add(later(3_600));
        assert_eq!(window.total(later(3_600)), 3);
        let day = 24 * 3_600;
        assert_eq!(
            window.total(later(day + 599)),
            3,
            "the first bucket is not all older"
        );
        assert_eq!(window.total(later(day + 600)), 2, "now it is");
        assert_eq!(window.frees_at(later(day)), Some(later(day + 600)));
        assert_eq!(window.total(later(day + 3_600 + 600)), 0);
        assert!(window.is_empty(later(2 * day)));
        assert_eq!(window.frees_at(later(2 * day)), None);
    }

    #[test]
    fn a_spent_budget_has_room_again_as_each_reservation_leaves_and_a_day_later_each_time_round() {
        let mut window = Window::default();
        for seconds in [0, 0, 600, 1_200] {
            window.add(later(seconds));
        }
        let now = later(3_600);
        let day = 24 * 3_600 + 600;
        // A cap of six has room for two now; then the first bucket's two
        // leave, then the next bucket's, and the one after.
        let rooms: Vec<Option<Timestamp>> = (0..8).map(|n| window.room_at(now, 6, n)).collect();
        assert_eq!(
            rooms,
            [
                Some(now),
                Some(now),
                Some(later(day)),
                Some(later(day)),
                Some(later(day + 600)),
                Some(later(day + 1_200)),
                // Round again: those made now leave a day later.
                Some(now.saturating_add(Duration::from_secs(day))),
                Some(now.saturating_add(Duration::from_secs(day))),
            ]
        );
        // A cap lowered below what it counts has room only once the excess
        // has left too.
        assert_eq!(window.room_at(now, 2, 0), Some(later(day + 600)));
        assert_eq!(window.room_at(now, 2, 1), Some(later(day + 1_200)));
        assert_eq!(window.room_at(now, 0, 0), None);
        // An empty window has room for a cap's worth at once.
        let empty = Window::default();
        assert_eq!(empty.room_at(now, 3, 2), Some(now));
        assert_eq!(
            empty.room_at(now, 3, 3),
            Some(now.saturating_add(Duration::from_secs(day)))
        );
    }

    #[test]
    fn a_tally_keeps_the_day_under_way_and_the_day_before_by_utc_day() {
        let day = 24 * 3_600;
        // START is not on a day's edge: the day it falls on, and its edge.
        let today = super::day(START);
        let midnight = Timestamp::from_micros((today + 1) * DAY_MICROS);
        let mut tally = Tally::default();
        tally.count(Signal::Delivered, START);
        tally.count(Signal::Throttled, START);
        tally.count(Signal::Delivered, midnight);
        tally.count(Signal::Complained, midnight);
        let yesterday = tally.on(today);
        assert_eq!((yesterday.delivered, yesterday.throttled), (1, 1));
        assert_eq!(yesterday.replies(), 2);
        let now = tally.on(today + 1);
        assert_eq!((now.delivered, now.complained, now.replies()), (1, 1, 1));
        // What happened before midnight, counted after it, counts on its
        // own day; what happened on a day no longer kept counts nothing.
        tally.count(Signal::Failed, START);
        assert_eq!(tally.on(today).failed, 1);
        assert_eq!(tally.on(today + 1).failed, 0);
        let before = Timestamp::from_micros((today - 1) * DAY_MICROS);
        tally.count(Signal::Failed, before);
        assert_eq!(tally.on(today - 1), Counts::default());
        assert_eq!(tally.on(today).failed, 1);
        assert!(!tally.is_empty(later(day)));
        // Two days on, the day before is the one under way at midnight,
        // and three days on nothing is kept.
        let two = Timestamp::from_micros((today + 2) * DAY_MICROS);
        assert!(!tally.is_empty(two));
        assert!(tally.is_empty(Timestamp::from_micros((today + 3) * DAY_MICROS)));
        tally.count(
            Signal::Deferred,
            Timestamp::from_micros((today + 3) * DAY_MICROS),
        );
        assert!(
            tally.on(today + 2).is_empty(),
            "a day with nothing is empty"
        );
        assert_eq!(tally.on(today + 3).deferred, 1);
        let (stored, now, before) = tally.parts();
        assert_eq!(Tally::from_parts(stored, now, before), tally);
    }

    #[test]
    fn a_window_reads_back_as_it_was_and_counts_on_after_a_long_silence() {
        let mut window = Window::default();
        window.add(START);
        let (newest, counts) = window.parts();
        let mut read = Window::from_parts(newest, *counts);
        assert_eq!(read, window);
        read.add(later(30 * 24 * 3_600));
        assert_eq!(
            read.total(later(30 * 24 * 3_600)),
            1,
            "the old count is gone"
        );
    }
}
