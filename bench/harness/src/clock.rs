//! Wall-clock time as the harness records it: microseconds since the Unix
//! epoch. Every container on one host reads the same kernel clock, so a time
//! taken by the load generator and one taken by the sink can be compared.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_micros()).unwrap_or(i64::MAX)
        })
}

/// `20261027T153000Z`, for naming a run.
pub fn compact_utc(micros: i64) -> String {
    let t = Civil::of(micros);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// `2026-10-27T15:30:00Z`.
pub fn iso_utc(micros: i64) -> String {
    let t = Civil::of(micros);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// `Tue, 27 Oct 2026 15:30:00 +0000`, for a Date header (RFC 5322, 3.3).
pub fn rfc5322(micros: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let t = Civil::of(micros);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        DAYS[t.weekday],
        t.day,
        MONTHS[t.month - 1],
        t.year,
        t.hour,
        t.minute,
        t.second
    )
}

/// A UTC calendar time.
struct Civil {
    year: i64,
    month: usize,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    /// 0 is Sunday.
    weekday: usize,
}

impl Civil {
    /// Howard Hinnant's `civil_from_days`, from days since 1970-01-01.
    fn of(micros: i64) -> Self {
        let seconds = micros.div_euclid(1_000_000);
        let days = seconds.div_euclid(86_400);
        let of_day = seconds.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self {
            year,
            month: usize::try_from(month).unwrap_or(1),
            day,
            hour: of_day / 3600,
            minute: of_day % 3600 / 60,
            second: of_day % 60,
            weekday: usize::try_from((days + 4).rem_euclid(7)).unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_format_as_utc() {
        // 1,700,000,000 seconds after the epoch was a Tuesday.
        let micros = 1_700_000_000 * 1_000_000;
        assert_eq!(iso_utc(micros), "2023-11-14T22:13:20Z");
        assert_eq!(compact_utc(micros), "20231114T221320Z");
        assert_eq!(rfc5322(micros), "Tue, 14 Nov 2023 22:13:20 +0000");
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        // A leap day, and the last second of a year.
        assert_eq!(iso_utc(1_709_164_800 * 1_000_000), "2024-02-29T00:00:00Z");
        assert_eq!(iso_utc(1_798_761_599 * 1_000_000), "2026-12-31T23:59:59Z");
    }
}
