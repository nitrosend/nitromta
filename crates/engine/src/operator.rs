//! The operator's endpoint: plain HTTP on the `[operator]`
//! address, local by default, for health and metrics.
//!
//! - `/health/live`: the engine is responding.
//! - `/health/accept`: it is safe to accept mail: the store has not failed,
//!   and the engine is not stopping.
//! - `/health/dispatch`: it is safe to dispatch: the scheduler runs too.
//! - `/metrics`: counters and gauges, in Prometheus's text format.
//!
//! Every count is held in memory and added to where the shell already
//! handles a batch or an event, never with a store read or write. A
//! latency is a histogram of fixed buckets, an atomic add or three each
//! time; attempts by site, egress and tenant are one short lock each.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use engine_core::hook::{admission, dispatch};
use engine_core::id::{EgressId, TenantId};
use engine_core::policy::Policy;
use engine_scheduler::Attempted;
use http_body_util::Full;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use crate::capture::Inspector;
use crate::log::Hex;
use crate::policy::Current;
use crate::stop::Stop;

/// A listener whose connections past its most are closed as they come.
#[derive(Clone, Copy, Debug)]
pub enum Listener {
    Submission,
    Ses,
    Feedback,
    Operator,
}

impl Listener {
    const ALL: [Self; 4] = [Self::Submission, Self::Ses, Self::Feedback, Self::Operator];

    pub fn name(self) -> &'static str {
        match self {
            Self::Submission => "submission",
            Self::Ses => "ses",
            Self::Feedback => "feedback",
            Self::Operator => "operator",
        }
    }
}

/// What the engine counts, and the state its health reads.
#[derive(Default)]
pub struct Operations {
    pub messages_accepted: AtomicU64,
    pub recipients_accepted: AtomicU64,
    attempts: [AtomicU64; ATTEMPTED.len()],
    pub deliveries_held: AtomicU64,
    pub body_bytes_held: AtomicU64,
    pub commit_groups: AtomicU64,
    pub commit_micros: AtomicU64,
    pub store_bytes: AtomicU64,
    pub batches_taken: AtomicU64,
    pub batches_refused: AtomicU64,
    pub reports: AtomicU64,
    pub reports_suppressing: AtomicU64,
    /// Reports naming no message the engine sent, taken past the
    /// quarantine's bound and not kept.
    pub reports_unkept: AtomicU64,
    pub authentication_failures: AtomicU64,
    /// Connections each listener closed as they came, with its most open
    /// already, by [`Listener`].
    pub connections_refused: [AtomicU64; Listener::ALL.len()],
    pub store_failed: AtomicBool,
    pub scheduler_failed: AtomicBool,
    /// Free space on the store's disk, and whether it is below the reserve
    /// kept for outcomes, feedback and checkpoints.
    pub store_free_bytes: AtomicU64,
    pub disk_low: AtomicBool,
    /// Bytes of mail accepted and waiting for their commit, and the most
    /// that may before new mail is refused: no limit while 0.
    pub pending_bytes: AtomicU64,
    pub pending_limit: AtomicU64,
    /// Recipients and requests refused for storage's sake, or while the
    /// engine drains.
    pub refused_for_storage: AtomicU64,
    /// The operator's drain: no new mail while the queue is
    /// delivered. An acceptance counts itself in `accepting` before it
    /// reads the flag, until its commit is answered; a drain sets the flag
    /// before it waits for that count to empty. So each acceptance either
    /// sees the drain or is committed, and counted in the queue, before the
    /// drain says what is outstanding.
    pub draining: AtomicBool,
    pub accepting: AtomicU64,
    /// The hooks' verdicts, those their failure policy gave included, and
    /// their calls that failed.
    admission_verdicts: [AtomicU64; ADMISSION_VERDICTS.len()],
    dispatch_verdicts: [AtomicU64; DISPATCH_VERDICTS.len()],
    pub admission_failures: AtomicU64,
    pub dispatch_failures: AtomicU64,
    /// Batches of events parked past their subscription's budget, and
    /// parked batches replayed and taken, and those parked now,
    /// as the store last measured.
    pub events_parked: AtomicU64,
    pub events_replayed: AtomicU64,
    pub events_parked_now: AtomicU64,
    /// Content bytes of messages accepted, against which the disk's writes
    /// give the write amplification.
    pub accepted_bytes: AtomicU64,
    /// Unfinished deliveries by state, as the store keeps them; how long
    /// ago the oldest waiting or held one was accepted; and how late the
    /// earliest waiting one is.
    pub queue_waiting: AtomicU64,
    pub queue_in_flight: AtomicU64,
    pub queue_held: AtomicU64,
    /// The same three as one commit group left them, together, which a
    /// drain reads: read apart, a delivery moving from waiting to
    /// in flight could be counted in neither.
    pub queue: Mutex<Queued>,
    pub queue_oldest_seconds: AtomicU64,
    pub queue_due_lag_seconds: AtomicU64,
    /// How far behind the furthest-behind subscription is: entries past its
    /// cursor, and the age of the first.
    pub event_lag_entries: AtomicU64,
    pub event_lag_seconds: AtomicU64,
    /// How long acceptance took, from a message's content in hand to its
    /// commit; and from a delivery's acceptance to the attempt that
    /// delivered it, or rejected it.
    acceptance: Histogram,
    delivered: Histogram,
    rejected: Histogram,
    /// Outcomes by how they ended, and reports' bounces and complaints, at
    /// each site, egress and tenant.
    counted: Mutex<Breakdown>,
}

/// Unfinished deliveries by state, as one commit group left them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Queued {
    pub waiting: u64,
    pub in_flight: u64,
    pub held: u64,
}

/// Where an outcome went, which it is counted by: its site's provider, if
/// it is a provider's site; the egress it went out from, if not the host's
/// own address; and its message's tenant.
pub struct Counted<'a> {
    pub provider: Option<&'a Arc<str>>,
    pub egress: Option<EgressId>,
    pub tenant: Option<TenantId>,
}

/// The most egresses and tenants counted apart: past them, the rest are
/// counted together, as `other`, so the counts' memory and series stay
/// bounded whatever policy's history.
const COUNTED_APART: usize = 4_096;

/// Outcomes by how they ended, and reports' bounces and complaints.
#[derive(Clone, Copy, Default)]
struct Counts {
    outcomes: [u64; ATTEMPTED.len()],
    bounces: u64,
    complaints: u64,
}

/// Counts by site (`None` for every site no provider claims, so as many as
/// the receiver rules have providers), by egress (`None` for the host's own
/// address) and by tenant, each of the last two with a count more for those
/// past [`COUNTED_APART`], and one for those policy no longer has, which a
/// scrape moves there, so every total only grows.
#[derive(Clone, Default)]
struct Breakdown {
    sites: BTreeMap<Option<Arc<str>>, Counts>,
    egresses: BTreeMap<Option<EgressId>, Counts>,
    tenants: BTreeMap<TenantId, Counts>,
    other_egresses: Counts,
    other_tenants: Counts,
    removed_egresses: Counts,
    removed_tenants: Counts,
}

impl Counts {
    fn add(&mut self, more: &Self) {
        for (count, more) in self.outcomes.iter_mut().zip(more.outcomes) {
            *count += more;
        }
        self.bounces += more.bounces;
        self.complaints += more.complaints;
    }

    fn any(&self) -> bool {
        self.outcomes.iter().any(|count| *count > 0) || self.bounces > 0 || self.complaints > 0
    }
}

impl Breakdown {
    /// Counts by `counted`'s site, when `by_site`, egress and tenant.
    fn add(&mut self, counted: &Counted<'_>, by_site: bool, count: impl Fn(&mut Counts)) {
        if by_site {
            count(self.sites.entry(counted.provider.cloned()).or_default());
        }
        count(apart(
            &mut self.egresses,
            counted.egress,
            &mut self.other_egresses,
        ));
        if let Some(tenant) = counted.tenant {
            count(apart(&mut self.tenants, tenant, &mut self.other_tenants));
        }
    }
}

/// `key`'s counts, or the others' once [`COUNTED_APART`] are apart.
fn apart<'a, K: Ord>(
    counts: &'a mut BTreeMap<K, Counts>,
    key: K,
    others: &'a mut Counts,
) -> &'a mut Counts {
    if counts.len() < COUNTED_APART || counts.contains_key(&key) {
        counts.entry(key).or_default()
    } else {
        others
    }
}

/// The upper bounds of a histogram's buckets, in microseconds; above the
/// last, `+Inf`.
type Bounds = [u64; 12];

/// Acceptance, from a millisecond to ten seconds.
const ACCEPTANCE_BOUNDS: Bounds = [
    1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000,
    10_000_000,
];

/// A delivery's outcome, from a second to five days.
const OUTCOME_BOUNDS: Bounds = {
    const SECOND: u64 = 1_000_000;
    [
        SECOND,
        5 * SECOND,
        15 * SECOND,
        60 * SECOND,
        300 * SECOND,
        900 * SECOND,
        3_600 * SECOND,
        4 * 3_600 * SECOND,
        12 * 3_600 * SECOND,
        86_400 * SECOND,
        3 * 86_400 * SECOND,
        5 * 86_400 * SECOND,
    ]
};

/// Durations in Prometheus's histogram form: a count in each bucket, and
/// their sum. Their number is the buckets' own total, read with them, so
/// `+Inf` and `_count` always agree.
#[derive(Default)]
struct Histogram {
    buckets: [AtomicU64; 13],
    micros: AtomicU64,
}

impl Histogram {
    fn observe(&self, bounds: &Bounds, took: Duration) {
        let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        let bucket = bounds.partition_point(|&bound| bound < micros);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// Its lines, under `labels` (none, or a label and a comma).
    fn write(&self, text: &mut String, name: &str, labels: &str, bounds: &Bounds) {
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .collect();
        let mut below = 0;
        for (bucket, bound) in counts.iter().zip(bounds) {
            below += bucket;
            let seconds = *bound as f64 / 1e6;
            let _ = writeln!(
                text,
                "nitromta_{name}_bucket{{{labels}le=\"{seconds}\"}} {below}"
            );
        }
        below += counts[bounds.len()];
        let _ = writeln!(
            text,
            "nitromta_{name}_bucket{{{labels}le=\"+Inf\"}} {below}"
        );
        let labels = labels.trim_end_matches(',');
        let (open, close) = if labels.is_empty() {
            ("", "")
        } else {
            ("{", "}")
        };
        let seconds = self.micros.load(Ordering::Relaxed) as f64 / 1e6;
        let _ = writeln!(text, "nitromta_{name}_sum{open}{labels}{close} {seconds}");
        let _ = writeln!(text, "nitromta_{name}_count{open}{labels}{close} {below}");
    }
}

/// The process's I/O counts, `/proc/self/io`, opened before the engine
/// stops itself leaving a core dump: that makes `/proc`'s files root's,
/// and this one, its owner's alone, could not be opened after. It is read
/// again at each scrape (Linux).
#[cfg(target_os = "linux")]
static IO: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

/// Opens the process's I/O counts, for the metrics. Called before
/// [`crate::privileges::no_core_dumps`].
pub fn keep_io() {
    #[cfg(target_os = "linux")]
    if let Ok(file) = std::fs::File::open("/proc/self/io") {
        let _ = IO.set(file);
    }
}

/// The process's CPU time and resident memory, under Prometheus's usual
/// names, and the bytes it has had written to disk, read from `/proc` as
/// they are asked for. Linux alone has them.
fn process(text: &mut String) {
    #[cfg(target_os = "linux")]
    {
        // The command, the second field, is in parentheses and may hold
        // anything: the fields after it are counted from its end. User and
        // system CPU time are the fourteenth and fifteenth, in clock ticks.
        let stat = std::fs::read_to_string("/proc/self/stat").ok();
        let ticks = stat.as_deref().and_then(|stat| {
            let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
            let field = |index: usize| fields.get(index)?.parse::<u64>().ok();
            Some(field(11)? + field(12)?)
        });
        if let Some(ticks) = ticks {
            let seconds = ticks as f64 / rustix::param::clock_ticks_per_second() as f64;
            let _ = writeln!(
                text,
                "# HELP process_cpu_seconds_total User and system CPU time spent."
            );
            let _ = writeln!(text, "# TYPE process_cpu_seconds_total counter");
            let _ = writeln!(text, "process_cpu_seconds_total {seconds}");
        }
        let resident = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok());
        if let Some(pages) = resident {
            let bytes = pages * rustix::param::page_size() as u64;
            let _ = writeln!(
                text,
                "# HELP process_resident_memory_bytes Resident memory size."
            );
            let _ = writeln!(text, "# TYPE process_resident_memory_bytes gauge");
            let _ = writeln!(text, "process_resident_memory_bytes {bytes}");
        }
        let written = IO.get().and_then(|io| {
            use std::os::unix::fs::FileExt as _;
            let mut read = [0; 512];
            let length = io.read_at(&mut read, 0).ok()?;
            std::str::from_utf8(&read[..length])
                .ok()?
                .lines()
                .find_map(|line| line.strip_prefix("write_bytes:"))?
                .trim()
                .parse::<u64>()
                .ok()
        });
        if let Some(written) = written {
            metric(
                text,
                "disk_written_bytes_total",
                "counter",
                "Bytes the engine has had written to disk, its store's log, database and checkpoints among them.",
                &[("", written)],
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = text;
}

/// A metric's lines: its help, its type, and each value under its labels.
fn metric(text: &mut String, name: &str, kind: &str, help: &str, values: &[(&str, u64)]) {
    let _ = writeln!(text, "# HELP nitromta_{name} {help}");
    let _ = writeln!(text, "# TYPE nitromta_{name} {kind}");
    for (labels, value) in values {
        let _ = writeln!(text, "nitromta_{name}{labels} {value}");
    }
}

/// A histogram's lines, each series under its labels.
fn histogram(text: &mut String, name: &str, help: &str, series: &[(&str, &Histogram, &Bounds)]) {
    let _ = writeln!(text, "# HELP nitromta_{name} {help}");
    let _ = writeln!(text, "# TYPE nitromta_{name} histogram");
    for (labels, histogram, bounds) in series {
        histogram.write(text, name, labels, bounds);
    }
}

/// `value` as a label's value: its backslashes, quotes and line breaks
/// escaped.
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Why new mail is refused for now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pressure {
    /// The store's disk has less free space than its reserve.
    Disk,
    /// More mail waits for its commit than `[store] pending_mib` allows.
    Pending,
    /// The operator drains the engine.
    Draining,
}

impl Pressure {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Disk => "the store's disk is below its reserve",
            Self::Pending => "more mail waits for its commit than may",
            Self::Draining => "draining: the queue is delivered and no new mail taken",
        }
    }
}

/// Each hook point's verdicts, by their labels.
const ADMISSION_VERDICTS: [&str; 3] = ["accept", "reject", "defer"];
const DISPATCH_VERDICTS: [&str; 3] = ["proceed", "hold", "reject"];

/// Each way an attempt ends, with its label.
const ATTEMPTED: [(Attempted, &str); 7] = [
    (Attempted::Delivered, "delivered"),
    (Attempted::Captured, "captured"),
    (Attempted::Deferred, "deferred"),
    (Attempted::Throttled, "throttled"),
    (Attempted::Rejected, "rejected"),
    (Attempted::Uncertain, "uncertain"),
    (Attempted::NotSent, "not_sent"),
];

impl Operations {
    /// Why new mail is refused for now, if it is: one flag and one count,
    /// read for each recipient or request.
    pub fn pressure(&self) -> Option<Pressure> {
        let limit = self.pending_limit.load(Ordering::Relaxed);
        if self.disk_low.load(Ordering::Relaxed) {
            Some(Pressure::Disk)
        } else if limit > 0 && self.pending_bytes.load(Ordering::Relaxed) >= limit {
            Some(Pressure::Pending)
        } else if self.draining.load(Ordering::Relaxed) {
            Some(Pressure::Draining)
        } else {
            None
        }
    }

    /// Counts the admission hook's verdict on a message.
    pub fn admitted(&self, verdict: &admission::Verdict) {
        let index = match verdict {
            admission::Verdict::Accept => 0,
            admission::Verdict::Reject(_) => 1,
            admission::Verdict::Defer(_) => 2,
        };
        self.admission_verdicts[index].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts the dispatch hook's verdict on a recipient.
    pub fn decided(&self, verdict: &dispatch::Verdict) {
        let index = match verdict {
            dispatch::Verdict::Proceed => 0,
            dispatch::Verdict::Hold(_) => 1,
            dispatch::Verdict::Reject(_) => 2,
        };
        self.dispatch_verdicts[index].fetch_add(1, Ordering::Relaxed);
    }

    /// How `result` is named in the metrics and the logs.
    pub fn label(result: Attempted) -> &'static str {
        ATTEMPTED
            .iter()
            .find_map(|(kind, label)| (*kind == result).then_some(*label))
            .unwrap_or("unknown")
    }

    /// Counts an outcome that ended as `result`, where it went, and, if it
    /// delivered or rejected its mail, `since` its delivery's acceptance.
    pub fn attempted(&self, result: Attempted, counted: &Counted<'_>, since: Duration) {
        let Some(index) = ATTEMPTED.iter().position(|(kind, _)| *kind == result) else {
            return;
        };
        self.attempts[index].fetch_add(1, Ordering::Relaxed);
        match result {
            Attempted::Delivered => self.delivered.observe(&OUTCOME_BOUNDS, since),
            Attempted::Rejected => self.rejected.observe(&OUTCOME_BOUNDS, since),
            _ => {}
        }
        self.breakdown()
            .add(counted, true, |counts| counts.outcomes[index] += 1);
    }

    /// Counts a report the store recorded, and what it did to each
    /// delivery it was about.
    pub fn recorded(&self, recorded: &engine_core::command::FeedbackRecorded) {
        self.reports.fetch_add(1, Ordering::Relaxed);
        self.reports_suppressing
            .fetch_add(u64::from(recorded.suppressed), Ordering::Relaxed);
        self.reports_unkept
            .fetch_add(u64::from(recorded.unkept), Ordering::Relaxed);
        for reported in &recorded.effects {
            self.reported(reported);
        }
    }

    /// Counts a report's first effect on a delivery: a bounce or a
    /// complaint, where the delivery went out from, and for whom. A report
    /// names no site.
    pub fn reported(&self, reported: &engine_core::command::Reported) {
        let counted = Counted {
            provider: None,
            egress: reported.egress,
            tenant: reported.tenant,
        };
        let complaint = reported.complaint;
        self.breakdown().add(&counted, false, |counts| {
            if complaint {
                counts.complaints += 1;
            } else {
                counts.bounces += 1;
            }
        });
    }

    fn breakdown(&self) -> std::sync::MutexGuard<'_, Breakdown> {
        self.counted.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What a drain has outstanding: the queue as the store last measured
    /// it, and the attempts whose outcome was uncertain.
    /// Begins or ends a drain.
    pub fn drain(&self, draining: bool) {
        self.draining.store(draining, Ordering::SeqCst);
    }

    /// Done once every acceptance that read the drain's flag before it was
    /// set has its commit's answer: a few milliseconds, a commit group's.
    pub async fn settled(&self) {
        while self.accepting.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// What a drain has outstanding: the queue as the store counted it at
    /// its last commit.
    pub fn outstanding(&self) -> engine_api::drain::Outstanding {
        let read = |gauge: &AtomicU64| gauge.load(Ordering::Relaxed);
        let uncertain = ATTEMPTED
            .iter()
            .position(|(kind, _)| *kind == Attempted::Uncertain)
            .map_or(0, |index| read(&self.attempts[index]));
        let queued = *self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        engine_api::drain::Outstanding {
            draining: self.draining.load(Ordering::Relaxed),
            waiting: queued.waiting,
            in_flight: queued.in_flight,
            held: queued.held,
            uncertain_attempts: uncertain,
        }
    }

    /// Counts a connection `listener` closed as it came.
    pub fn refused_connection(&self, listener: Listener) {
        self.connections_refused[listener as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a message accepted, `took` from its content in hand.
    pub fn accepted_in(&self, took: Duration) {
        self.acceptance.observe(&ACCEPTANCE_BOUNDS, took);
    }

    /// Why it is not safe to accept, if it is not.
    fn not_accepting(&self, stop: &Stop) -> Option<&'static str> {
        if self.store_failed.load(Ordering::Relaxed) {
            Some("the store failed")
        } else if stop.stopping() {
            Some("stopping")
        } else {
            self.pressure().map(Pressure::reason)
        }
    }

    /// Why it is not safe to dispatch, if it is not: as for accepting, but
    /// that pressure on new mail leaves dispatch running.
    fn not_dispatching(&self, stop: &Stop) -> Option<&'static str> {
        if self.store_failed.load(Ordering::Relaxed) {
            return Some("the store failed");
        }
        if stop.stopping() {
            return Some("stopping");
        }
        self.scheduler_failed
            .load(Ordering::Relaxed)
            .then_some("the scheduler stopped")
    }

    /// Every count, in Prometheus's text format.
    /// The metrics, each tenant named as `policy` names it.
    fn render(&self, stop: &Stop, policy: &Policy) -> String {
        let mut text = String::new();
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        metric(
            &mut text,
            "messages_accepted_total",
            "counter",
            "Messages accepted.",
            &[("", read(&self.messages_accepted))],
        );
        metric(
            &mut text,
            "recipients_accepted_total",
            "counter",
            "Recipients accepted.",
            &[("", read(&self.recipients_accepted))],
        );
        let labels: Vec<String> = ATTEMPTED
            .iter()
            .map(|(_, label)| format!("{{result=\"{label}\"}}"))
            .collect();
        let attempts: Vec<(&str, u64)> = labels
            .iter()
            .zip(&self.attempts)
            .map(|(label, counter)| (label.as_str(), read(counter)))
            .collect();
        metric(
            &mut text,
            "attempts_total",
            "counter",
            "Delivery attempts, by how they ended.",
            &attempts,
        );
        self.write_breakdown(&mut text, policy);
        metric(
            &mut text,
            "deliveries_held",
            "gauge",
            "Deliveries the scheduler holds in memory.",
            &[("", read(&self.deliveries_held))],
        );
        metric(
            &mut text,
            "body_bytes_held",
            "gauge",
            "Bytes of message bodies the scheduler holds in memory.",
            &[("", read(&self.body_bytes_held))],
        );
        metric(
            &mut text,
            "commit_groups_total",
            "counter",
            "Commit groups, each one synchronous commit.",
            &[("", read(&self.commit_groups))],
        );
        metric(
            &mut text,
            "commit_seconds_total",
            "counter",
            "Time spent committing groups.",
            &[("", read(&self.commit_micros) / 1_000_000)],
        );
        metric(
            &mut text,
            "store_bytes",
            "gauge",
            "The store's size on disk, without its write-ahead log.",
            &[("", read(&self.store_bytes))],
        );
        metric(
            &mut text,
            "store_free_bytes",
            "gauge",
            "Free space on the store's disk.",
            &[("", read(&self.store_free_bytes))],
        );
        metric(
            &mut text,
            "accepted_bytes_total",
            "counter",
            "Content bytes of the messages accepted, against which the disk's writes give the write amplification.",
            &[("", read(&self.accepted_bytes))],
        );
        metric(
            &mut text,
            "queue_deliveries",
            "gauge",
            "Unfinished deliveries, by state: waiting for their attempt, in flight, or held.",
            &[
                ("{state=\"waiting\"}", read(&self.queue_waiting)),
                ("{state=\"in_flight\"}", read(&self.queue_in_flight)),
                ("{state=\"held\"}", read(&self.queue_held)),
            ],
        );
        metric(
            &mut text,
            "queue_oldest_seconds",
            "gauge",
            "How long ago the waiting or held delivery nearest its expiry, the oldest, was accepted.",
            &[("", read(&self.queue_oldest_seconds))],
        );
        metric(
            &mut text,
            "queue_due_lag_seconds",
            "gauge",
            "How late the earliest waiting delivery is past its due time.",
            &[("", read(&self.queue_due_lag_seconds))],
        );
        metric(
            &mut text,
            "event_lag_entries",
            "gauge",
            "Journal entries past the furthest-behind subscription's cursor.",
            &[("", read(&self.event_lag_entries))],
        );
        metric(
            &mut text,
            "event_lag_seconds",
            "gauge",
            "How long ago the first journal entry past the furthest-behind subscription's cursor happened.",
            &[("", read(&self.event_lag_seconds))],
        );
        metric(
            &mut text,
            "pending_bytes",
            "gauge",
            "Bytes of mail accepted and waiting for their commit.",
            &[("", read(&self.pending_bytes))],
        );
        metric(
            &mut text,
            "refused_for_storage_total",
            "counter",
            "Recipients and requests refused while the store's disk was below its reserve or too much mail waited for its commit.",
            &[("", read(&self.refused_for_storage))],
        );
        metric(
            &mut text,
            "webhook_batches_total",
            "counter",
            "Event batches posted, by whether the subscriber took them.",
            &[
                ("{result=\"taken\"}", read(&self.batches_taken)),
                ("{result=\"refused\"}", read(&self.batches_refused)),
            ],
        );
        metric(
            &mut text,
            "event_batches_parked_total",
            "counter",
            "Batches of events parked past their subscription's budget, for replay.",
            &[("", read(&self.events_parked))],
        );
        metric(
            &mut text,
            "event_batches_replayed_total",
            "counter",
            "Parked batches of events posted again and taken.",
            &[("", read(&self.events_replayed))],
        );
        metric(
            &mut text,
            "event_batches_parked",
            "gauge",
            "Batches of events parked now, in every subscription, waiting for a replay or the feedback window.",
            &[("", read(&self.events_parked_now))],
        );
        metric(
            &mut text,
            "reports_total",
            "counter",
            "Bounce and complaint reports recorded.",
            &[("", read(&self.reports))],
        );
        metric(
            &mut text,
            "reports_suppressing_total",
            "counter",
            "Recipients reports suppressed.",
            &[("", read(&self.reports_suppressing))],
        );
        metric(
            &mut text,
            "reports_unkept_total",
            "counter",
            "Reports naming no message the engine sent, taken once the quarantine was full and not kept.",
            &[("", read(&self.reports_unkept))],
        );
        metric(
            &mut text,
            "authentication_failures_total",
            "counter",
            "Failed authentications on the submission and SES listeners.",
            &[("", read(&self.authentication_failures))],
        );
        let labels: Vec<String> = Listener::ALL
            .iter()
            .map(|listener| format!("{{listener=\"{}\"}}", listener.name()))
            .collect();
        let refused: Vec<(&str, u64)> = labels
            .iter()
            .zip(&self.connections_refused)
            .map(|(label, counter)| (label.as_str(), read(counter)))
            .collect();
        metric(
            &mut text,
            "connections_refused_total",
            "counter",
            "Connections closed as they came, their listener having its most open already.",
            &refused,
        );
        let labels: Vec<String> = ADMISSION_VERDICTS
            .iter()
            .map(|verdict| format!("{{hook=\"admission\",verdict=\"{verdict}\"}}"))
            .chain(
                DISPATCH_VERDICTS
                    .iter()
                    .map(|verdict| format!("{{hook=\"dispatch\",verdict=\"{verdict}\"}}")),
            )
            .collect();
        let verdicts: Vec<(&str, u64)> = labels
            .iter()
            .zip(
                self.admission_verdicts
                    .iter()
                    .chain(&self.dispatch_verdicts),
            )
            .map(|(label, counter)| (label.as_str(), read(counter)))
            .collect();
        metric(
            &mut text,
            "hook_verdicts_total",
            "counter",
            "The hooks' verdicts, by hook point, those their failure policy gave included.",
            &verdicts,
        );
        metric(
            &mut text,
            "hook_failures_total",
            "counter",
            "Hook calls that failed, panicked or did not decide in time.",
            &[
                ("{hook=\"admission\"}", read(&self.admission_failures)),
                ("{hook=\"dispatch\"}", read(&self.dispatch_failures)),
            ],
        );
        let health = |unsafe_because: Option<&str>| u64::from(unsafe_because.is_none());
        histogram(
            &mut text,
            "acceptance_seconds",
            "Time to accept a message, from its content in hand to its commit's answer.",
            &[("", &self.acceptance, &ACCEPTANCE_BOUNDS)],
        );
        histogram(
            &mut text,
            "outcome_seconds",
            "Time from a delivery's acceptance to the attempt that delivered or rejected it.",
            &[
                ("result=\"delivered\",", &self.delivered, &OUTCOME_BOUNDS),
                ("result=\"rejected\",", &self.rejected, &OUTCOME_BOUNDS),
            ],
        );
        metric(
            &mut text,
            "accepting",
            "gauge",
            "Whether it is safe to accept mail.",
            &[("", health(self.not_accepting(stop)))],
        );
        metric(
            &mut text,
            "store_fenced",
            "gauge",
            "Whether the store was restored and holds the deliveries its copy held until the operator decides.",
            &[(
                "",
                u64::from(policy.fence().is_some_and(|fence| !fence.discarding)),
            )],
        );
        metric(
            &mut text,
            "dispatching",
            "gauge",
            "Whether it is safe to dispatch mail.",
            &[("", health(self.not_dispatching(stop)))],
        );
        process(&mut text);
        text
    }
}

impl Operations {
    /// The outcomes and reports by site, egress and tenant: a provider's
    /// site by its name and every other as `other`; an egress by its
    /// address, the host's own as `host`; a tenant by its account and name;
    /// those past the bound as `other`, and those policy no longer has as
    /// `removed`. Under their lock, the removed ones' counts are moved
    /// there and the counts copied out, to be written after.
    fn write_breakdown(&self, text: &mut String, policy: &Policy) {
        let breakdown = {
            let mut counted = self.breakdown();
            let counted = &mut *counted;
            let mut removed = Counts::default();
            counted.egresses.retain(|egress, counts| {
                let kept = egress.is_none_or(|id| policy.egress(id).is_some());
                if !kept {
                    removed.add(counts);
                }
                kept
            });
            counted.removed_egresses.add(&removed);
            let mut removed = Counts::default();
            counted.tenants.retain(|tenant, counts| {
                let kept = policy.tenant(*tenant).is_some();
                if !kept {
                    removed.add(counts);
                }
                kept
            });
            counted.removed_tenants.add(&removed);
            counted.clone()
        };
        let egress = |egress: &Option<EgressId>| match egress.and_then(|id| policy.egress(id)) {
            Some(egress) => egress.address.to_string(),
            None => "host".to_owned(),
        };
        let tenant = |tenant: &TenantId| match policy.tenant(*tenant) {
            Some(found) => format!(
                "account=\"{}\",tenant=\"{}\"",
                found.account.0.as_u64(),
                label(&found.name)
            ),
            None => format!("tenant=\"{}\"", Hex(tenant.0)),
        };
        let mut by_site: Vec<(String, Counts)> = breakdown
            .sites
            .iter()
            .map(|(site, counts)| {
                let site = label(site.as_deref().unwrap_or("other"));
                (format!("site=\"{site}\""), *counts)
            })
            .collect();
        by_site.sort_by(|(left, _), (right, _)| left.cmp(right));
        let mut by_egress: Vec<(String, Counts)> = breakdown
            .egresses
            .iter()
            .map(|(id, counts)| (format!("egress=\"{}\"", egress(id)), *counts))
            .collect();
        for (name, counts) in [
            ("other", breakdown.other_egresses),
            ("removed", breakdown.removed_egresses),
        ] {
            if counts.any() {
                by_egress.push((format!("egress=\"{name}\""), counts));
            }
        }
        let mut by_tenant: Vec<(String, Counts)> = breakdown
            .tenants
            .iter()
            .map(|(id, counts)| (tenant(id), *counts))
            .collect();
        for (name, counts) in [
            ("other", breakdown.other_tenants),
            ("removed", breakdown.removed_tenants),
        ] {
            if counts.any() {
                by_tenant.push((format!("tenant=\"{name}\""), counts));
            }
        }
        let outcomes = |text: &mut String, name: &str, help: &str, rows: &[(String, Counts)]| {
            let _ = writeln!(text, "# HELP nitromta_{name} {help}");
            let _ = writeln!(text, "# TYPE nitromta_{name} counter");
            for (labels, counts) in rows {
                for ((_, result), count) in ATTEMPTED.iter().zip(counts.outcomes) {
                    let _ = writeln!(
                        text,
                        "nitromta_{name}{{{labels},result=\"{result}\"}} {count}"
                    );
                }
            }
        };
        let reports = |text: &mut String, name: &str, help: &str, rows: &[(String, Counts)]| {
            let _ = writeln!(text, "# HELP nitromta_{name} {help}");
            let _ = writeln!(text, "# TYPE nitromta_{name} counter");
            for (labels, counts) in rows {
                for (kind, count) in [("bounce", counts.bounces), ("complaint", counts.complaints)]
                {
                    let _ = writeln!(text, "nitromta_{name}{{{labels},kind=\"{kind}\"}} {count}");
                }
            }
        };
        outcomes(
            text,
            "attempts_by_site_total",
            "Delivery outcomes by the receiver site's provider, or other, and how they ended.",
            &by_site,
        );
        outcomes(
            text,
            "attempts_by_egress_total",
            "Delivery outcomes by the egress they went out from, or the host's own address, and how they ended.",
            &by_egress,
        );
        outcomes(
            text,
            "attempts_by_tenant_total",
            "Delivery outcomes by their message's account and tenant, and how they ended.",
            &by_tenant,
        );
        reports(
            text,
            "reports_by_egress_total",
            "Bounces and complaints reports made, by the egress their delivery went out from.",
            &by_egress,
        );
        reports(
            text,
            "reports_by_tenant_total",
            "Bounces and complaints reports made, by their message's account and tenant.",
            &by_tenant,
        );
    }
}

/// How long a request's header may take to arrive.
const HEADER: Duration = Duration::from_secs(10);

/// Serves the endpoint on `listener`, its connections bounded as every
/// listener's are.
pub async fn serve(
    listener: TcpListener,
    operations: Arc<Operations>,
    stop: Arc<Stop>,
    policy: Arc<Current>,
    inspector: Option<Arc<Inspector>>,
) -> Result<(), String> {
    let most = crate::listen::MOST_OPEN;
    let counted = Arc::clone(&operations);
    crate::listen::accept(listener, Listener::Operator, most, &counted, |tcp| {
        let (operations, stop) = (Arc::clone(&operations), Arc::clone(&stop));
        let policy = Arc::clone(&policy);
        let inspector = inspector.clone();
        async move {
            let service = hyper::service::service_fn(move |request| {
                let path = request.uri().path().to_owned();
                // Capture mode's inspector answers under /capture,
                // the rest at once.
                let reply = match inspector
                    .as_ref()
                    .filter(|_| path == "/capture" || path.starts_with("/capture/"))
                {
                    Some(inspector) => Reply::Inspecting(Arc::clone(inspector)),
                    None => {
                        let policy = policy.load();
                        Reply::Ready(answer(&path, &operations, &stop, policy.policy()))
                    }
                };
                async move {
                    Ok::<_, Infallible>(match reply {
                        Reply::Ready(answered) => answered,
                        Reply::Inspecting(inspector) => inspector.page(&path).await,
                    })
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER)
                .serve_connection(TokioIo::new(tcp), service)
                .await;
        }
    })
    .await
}

/// An operator request's reply: made at once, or the inspector's to make.
enum Reply {
    Ready(http::Response<Full<Bytes>>),
    Inspecting(Arc<Inspector>),
}

fn answer(
    path: &str,
    operations: &Operations,
    stop: &Stop,
    policy: &Policy,
) -> http::Response<Full<Bytes>> {
    let health = |unsafe_because: Option<&str>| match unsafe_because {
        None => (200, "ok\n".to_owned()),
        Some(reason) => (503, format!("{reason}\n")),
    };
    let (status, body) = match path {
        "/health/live" => (200, "ok\n".to_owned()),
        "/health/accept" => health(operations.not_accepting(stop)),
        "/health/dispatch" => health(operations.not_dispatching(stop)),
        "/metrics" => (200, operations.render(stop, policy)),
        _ => (404, "not found\n".to_owned()),
    };
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(body)))
        .expect("a response always builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_follows_the_store_the_scheduler_and_the_stop() {
        let (operations, stop) = (Operations::default(), Stop::default());
        let policy = Policy::default();
        let status = |path| answer(path, &operations, &stop, &policy).status().as_u16();
        assert_eq!(
            (status("/health/accept"), status("/health/dispatch")),
            (200, 200)
        );
        // Pressure on storage refuses new mail and leaves dispatch running.
        operations.disk_low.store(true, Ordering::Relaxed);
        assert_eq!(
            (status("/health/accept"), status("/health/dispatch")),
            (503, 200)
        );
        operations.disk_low.store(false, Ordering::Relaxed);
        operations.pending_limit.store(100, Ordering::Relaxed);
        operations.pending_bytes.store(100, Ordering::Relaxed);
        assert_eq!(operations.pressure(), Some(Pressure::Pending));
        operations.pending_bytes.store(99, Ordering::Relaxed);
        assert_eq!(operations.pressure(), None);
        operations.scheduler_failed.store(true, Ordering::Relaxed);
        assert_eq!(
            (status("/health/accept"), status("/health/dispatch")),
            (200, 503)
        );
        stop.start();
        assert_eq!(status("/health/accept"), 503);
        assert_eq!(status("/health/live"), 200);
        assert_eq!(status("/elsewhere"), 404);
    }

    #[test]
    fn egresses_and_tenants_past_the_bound_are_counted_together() {
        let (mut counts, mut others) = (BTreeMap::new(), Counts::default());
        for key in 0..=COUNTED_APART {
            apart(&mut counts, key, &mut others).bounces += 1;
        }
        assert_eq!((counts.len(), others.bounces), (COUNTED_APART, 1));
        // One already apart is still counted apart.
        apart(&mut counts, 0, &mut others).bounces += 1;
        assert_eq!((counts[&0].bounces, others.bounces), (2, 1));
    }

    #[test]
    fn metrics_are_in_prometheus_text() {
        let (operations, stop) = (Operations::default(), Stop::default());
        operations.messages_accepted.fetch_add(3, Ordering::Relaxed);
        let nowhere = Counted {
            provider: None,
            egress: None,
            tenant: None,
        };
        operations.attempted(Attempted::Deferred, &nowhere, Duration::from_secs(1));
        // Policy with an egress, and a tenant of one name in two accounts.
        use engine_core::id::{AccountId, EgressId, Id};
        use engine_core::policy::{Account, Change, Limits};
        let id = |value: u64| Id::from_u64(value).unwrap();
        let (egress, removed) = (EgressId(id(30)), EgressId(id(31)));
        let tenants = [TenantId(id(40)), TenantId(id(41))];
        let mut policy = Policy::default();
        for account in [1, 2] {
            let account = Account {
                id: AccountId(id(account)),
                limits: Limits::default(),
                daily_quota: None,
            };
            policy.apply(Change::Account(account)).unwrap();
        }
        let egress_change = |id, address: &str| Change::Egress {
            id,
            account: AccountId(Id::from_u64(1).unwrap()),
            address: address.parse().unwrap(),
            helo: "mx.example.test".to_owned(),
            pool: None,
            daily_cap: None,
        };
        policy.apply(egress_change(egress, "192.0.2.1")).unwrap();
        policy.apply(egress_change(removed, "192.0.2.2")).unwrap();
        for (account, tenant) in [1, 2].into_iter().zip(tenants) {
            policy
                .apply(Change::Tenant {
                    id: tenant,
                    account: AccountId(id(account)),
                    name: "production".to_owned(),
                    identities: Vec::new(),
                    configurations: Vec::new(),
                    limits: Limits::default(),
                })
                .unwrap();
        }
        // Delivered three seconds after its acceptance, at a provider's
        // site, from an egress, for each account's tenant; and one more from
        // an egress policy then removes.
        let google: Arc<str> = Arc::from("Google");
        for tenant in tenants {
            let counted = Counted {
                provider: Some(&google),
                egress: Some(egress),
                tenant: Some(tenant),
            };
            operations.attempted(Attempted::Delivered, &counted, Duration::from_secs(3));
        }
        let gone = Counted {
            provider: None,
            egress: Some(removed),
            tenant: None,
        };
        operations.attempted(Attempted::Rejected, &gone, Duration::from_secs(3));
        policy
            .apply(Change::Remove(engine_core::policy::Target::Egress(
                "192.0.2.2".parse().unwrap(),
            )))
            .unwrap();
        // A bounce reported later.
        operations.reported(&engine_core::command::Reported {
            complaint: false,
            egress: Some(egress),
            tenant: Some(tenants[1]),
        });
        operations.accepted_in(Duration::from_millis(3));
        operations.decided(&dispatch::Verdict::Hold(engine_core::hook::Reason::new(
            "later",
        )));
        let text = operations.render(&stop, &policy);
        assert!(text.contains(
            "# TYPE nitromta_messages_accepted_total counter\nnitromta_messages_accepted_total 3\n"
        ));
        assert!(text.contains("nitromta_attempts_total{result=\"deferred\"} 1\n"));
        for line in [
            "nitromta_attempts_by_site_total{site=\"other\",result=\"deferred\"} 1\n",
            "nitromta_attempts_by_site_total{site=\"Google\",result=\"delivered\"} 2\n",
            "nitromta_attempts_by_egress_total{egress=\"host\",result=\"deferred\"} 1\n",
            "nitromta_attempts_by_egress_total{egress=\"192.0.2.1\",result=\"delivered\"} 2\n",
            "nitromta_attempts_by_tenant_total{account=\"1\",tenant=\"production\",result=\"delivered\"} 1\n",
            "nitromta_attempts_by_tenant_total{account=\"2\",tenant=\"production\",result=\"delivered\"} 1\n",
            "nitromta_reports_by_egress_total{egress=\"192.0.2.1\",kind=\"bounce\"} 1\n",
            "nitromta_reports_by_tenant_total{account=\"2\",tenant=\"production\",kind=\"bounce\"} 1\n",
            "# TYPE nitromta_outcome_seconds histogram\n",
            "nitromta_outcome_seconds_bucket{result=\"delivered\",le=\"1\"} 0\n",
            "nitromta_outcome_seconds_bucket{result=\"delivered\",le=\"5\"} 2\n",
            "nitromta_outcome_seconds_bucket{result=\"delivered\",le=\"+Inf\"} 2\n",
            "nitromta_outcome_seconds_sum{result=\"delivered\"} 6\n",
            "nitromta_outcome_seconds_count{result=\"rejected\"} 1\n",
            "nitromta_acceptance_seconds_bucket{le=\"0.0025\"} 0\n",
            "nitromta_acceptance_seconds_bucket{le=\"0.005\"} 1\n",
            "nitromta_acceptance_seconds_count 1\n",
        ] {
            assert!(text.contains(line), "{line} in {text}");
        }
        // A deferral is no outcome's latency; the egress policy removed is
        // counted as removed, and a report on its mail after the removal
        // there too, at the next scrape.
        assert!(text.contains("nitromta_outcome_seconds_count{result=\"delivered\"} 2\n"));
        assert!(!text.contains("192.0.2.2"), "{text}");
        let removed_line =
            "nitromta_attempts_by_egress_total{egress=\"removed\",result=\"rejected\"} 1\n";
        assert!(text.contains(removed_line), "{text}");
        operations.reported(&engine_core::command::Reported {
            complaint: true,
            egress: Some(removed),
            tenant: None,
        });
        let text = operations.render(&stop, &policy);
        assert!(text.contains(removed_line), "{text}");
        assert!(
            text.contains(
                "nitromta_reports_by_egress_total{egress=\"removed\",kind=\"complaint\"} 1\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("nitromta_hook_verdicts_total{hook=\"dispatch\",verdict=\"hold\"} 1\n")
        );
        assert!(text.contains("nitromta_accepting 1\n"));
        assert!(text.contains("nitromta_store_fenced 0\n"));
    }
}
