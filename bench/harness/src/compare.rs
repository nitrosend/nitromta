//! A smoke run against the last one on the same machine.
//!
//! The smoke profile does the same work every run, so its costs compare from
//! run to run: CPU and bytes written per message, memory per queued
//! recipient, and p99 latency, each as the median and range of a run's
//! repetitions. A cost is marked changed when its median moved further than
//! the wider of the two runs' ranges, which is as far as the machine alone
//! moves it. A repetition whose work (CPU, bytes written or memory) is more
//! than twice or under half its run's median is named, since one such
//! repetition widens the range enough to hide a change, and may be a fault
//! of its own: on 28 October 2026 one wrote eighteen times the others.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

const MIB: f64 = 1024.0 * 1024.0;

/// What a run must share with an earlier one to be compared with it: the
/// machine, the runtime, the placement and the profile's settings, but not
/// the words describing the profile. What differs is the engine.
fn fingerprint(result: &Value) -> Value {
    let mut settings = result["settings"].clone();
    if let Some(settings) = settings.as_object_mut() {
        settings.remove("summary");
    }
    json!({
        "cpu": result["environment"]["cpu"],
        "memory": result["environment"]["memory_bytes"],
        "runtime": result["environment"]["runtime"],
        "placement": result["placement"],
        "settings": settings,
    })
}

fn last_step(run: &Value) -> &Value {
    run["steps"]
        .as_array()
        .and_then(|steps| steps.last())
        .unwrap_or(&Value::Null)
}

/// Whether a cost is the system's work, which repeats closely, rather than
/// latency or the machine's speed, which move with the machine.
const WORK: [&str; 3] = [
    "CPU ms per message",
    "KiB written per message",
    "bytes of memory per queued recipient",
];

/// Each cost, with its value in every repetition that completed.
fn costs(result: &Value) -> Vec<(&'static str, Vec<f64>)> {
    let runs: Vec<&Value> = result["runs"]
        .as_array()
        .map(|runs| runs.iter().filter(|run| run["error"].is_null()).collect())
        .unwrap_or_default();
    let each = |pick: fn(&Value) -> Option<f64>| -> Vec<f64> {
        runs.iter().filter_map(|run| pick(run)).collect()
    };
    vec![
        (
            "CPU ms per message",
            each(|run| last_step(run)["usage"]["cpu_ms_per_message"].as_f64()),
        ),
        (
            "KiB written per message",
            each(|run| last_step(run)["usage"]["written_kib_per_message"].as_f64()),
        ),
        (
            "bytes of memory per queued recipient",
            each(|run| {
                let backlog = &run["backlog"];
                let queued =
                    backlog["queued_anon_mib"].as_f64()? - backlog["idle_anon_mib"].as_f64()?;
                Some(queued * MIB / backlog["recipients"].as_f64()?)
            }),
        ),
        (
            "submit p99 ms",
            each(|run| last_step(run)["submit_ms"]["p99"].as_f64()),
        ),
        (
            "delivery p99 ms",
            each(|run| last_step(run)["delivery_ms"]["p99"].as_f64()),
        ),
        (
            "CPU gauge, SHA-256 MB/s",
            each(|run| run["probe"]["hash_mb_s"].as_f64()),
        ),
    ]
}

struct Summary {
    median: f64,
    low: f64,
    high: f64,
}

fn summarise(values: &[f64]) -> Option<Summary> {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let (&low, &high) = (sorted.first()?, sorted.last()?);
    let middle = sorted.len() / 2;
    let median = if sorted.len().is_multiple_of(2) {
        f64::midpoint(sorted[middle - 1], sorted[middle])
    } else {
        sorted[middle]
    };
    Some(Summary { median, low, high })
}

fn shown(summary: &Summary) -> String {
    format!(
        "{:.3} ({:.3} to {:.3})",
        summary.median, summary.low, summary.high
    )
}

/// Compares the run in `out` with the latest earlier run of `profile` on
/// the same machine, as lines to print.
pub fn compare(out: &Path, profile: &str, current: &Value) -> Vec<String> {
    let suffix = format!("-{profile}");
    let mut earlier: Vec<_> = out
        .parent()
        .and_then(|parent| fs::read_dir(parent).ok())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path != out
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(&suffix))
        })
        .collect();
    // Each run's directory starts with the time it started.
    earlier.sort();
    let wanted = fingerprint(current);
    let previous = earlier.iter().rev().find_map(|path| {
        let text = fs::read_to_string(path.join("result.json")).ok()?;
        let result: Value = serde_json::from_str(&text).ok()?;
        (fingerprint(&result) == wanted).then_some((path, result))
    });
    let Some((path, previous)) = previous else {
        return vec!["no earlier run of this profile on this machine to compare with".to_owned()];
    };
    let before: BTreeMap<&str, Vec<f64>> = costs(&previous).into_iter().collect();
    let mut lines = vec![format!("against {}:", path.display())];
    for (name, now) in costs(current) {
        let was = before.get(name).and_then(|was| summarise(was));
        let (Some(now), Some(was)) = (summarise(&now), was) else {
            lines.push(format!("  {name:<38} not measured in both runs"));
            continue;
        };
        let moved = now.median - was.median;
        let noise = (now.high - now.low).max(was.high - was.low);
        let verdict = if moved.abs() > noise {
            format!("CHANGED by {:+.1}%", 100.0 * moved / was.median)
        } else {
            "within the machine's spread".to_owned()
        };
        lines.push(format!(
            "  {name:<38} {} now, {} before: {verdict}",
            shown(&now),
            shown(&was)
        ));
    }
    for (name, values) in costs(current) {
        if !WORK.contains(&name) {
            continue;
        }
        let Some(summary) = summarise(&values) else {
            continue;
        };
        for (repetition, value) in values.iter().enumerate() {
            if outlying(*value, summary.median) {
                lines.push(format!(
                    "  repetition {} is an outlier: {name} {value:.3}, against a median of {:.3}",
                    repetition + 1,
                    summary.median
                ));
            }
        }
    }
    lines
}

/// More than twice, or under half, the median.
fn outlying(value: f64, median: f64) -> bool {
    value > 2.0 * median || value < median / 2.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_median_is_the_middle_value_or_the_mean_of_the_two_middle_ones() {
        let odd = summarise(&[3.0, 1.0, 2.0]).expect("values");
        assert_eq!((odd.median, odd.low, odd.high), (2.0, 1.0, 3.0));
        assert_eq!(
            summarise(&[4.0, 1.0, 2.0, 3.0]).expect("values").median,
            2.5
        );
        assert!(summarise(&[]).is_none());
    }

    #[test]
    fn a_value_twice_or_half_the_median_is_an_outlier() {
        assert!(outlying(85.5, 5.0));
        assert!(outlying(2.0, 5.0));
        assert!(!outlying(6.8, 4.6));
    }

    #[test]
    fn a_run_compares_with_one_whose_profile_reads_differently() {
        let run = |summary: &str, rate: f64| json!({"environment": {}, "placement": {}, "settings": {"summary": summary, "rate": rate}});
        assert_eq!(
            fingerprint(&run("before", 2000.0)),
            fingerprint(&run("after", 2000.0))
        );
        assert_ne!(
            fingerprint(&run("same", 2000.0)),
            fingerprint(&run("same", 4000.0))
        );
    }

    #[test]
    fn memory_per_queued_recipient_leaves_out_what_the_system_uses_idle() {
        let result = json!({"runs": [{
            "error": null,
            "backlog": {"recipients": 1024.0, "idle_anon_mib": 10.0, "queued_anon_mib": 11.0},
            "steps": [],
        }]});
        let costs: BTreeMap<_, _> = costs(&result).into_iter().collect();
        assert_eq!(costs["bytes of memory per queued recipient"], [1024.0]);
    }
}
