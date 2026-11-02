//! The operator's `explain` and `queue` on the admin socket:
//!
//! - `{"op":"explain","delivery":"<hex>"}` or `{"op":"explain","message":"<hex>"}`:
//!   each delivery as the store holds it, and, if the scheduler holds it,
//!   where it waits and why.
//! - `{"op":"queue"}`, or with `"most"`: the scheduler's queues, those with
//!   the most waiting first.

use engine_core::attempt::Evidence;
use engine_core::budget::Signal;
use engine_core::command::{Inspect, Inspected};
use engine_core::delivery::{Completion, QueueState};
use engine_core::id::{DeliveryId, Id, MessageId};
use engine_core::policy::{self, Judgment, Target, Verdict};
use engine_core::time::Timestamp;
use engine_scheduler::{Capped, Cooling, Hold, QueueReport, Report};
use serde::{Deserialize, Serialize};

use crate::native::{Reply, error, line};

/// The queues shown when a request names no number.
const QUEUES_SHOWN: usize = 50;

/// What an inspection request asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asked {
    /// The store's records, then where the scheduler holds them.
    Explain(Inspect),
    Queue {
        most: usize,
    },
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Explain {
        delivery: Option<String>,
        message: Option<String>,
    },
    Queue {
        most: Option<usize>,
    },
}

#[derive(Deserialize)]
struct Op<'a> {
    op: &'a str,
}

/// The inspection `line` asks for, or `None` if it asks for something else.
/// An inspection it cannot read is refused with its reply line.
pub fn asked(line: &[u8]) -> Option<Result<Asked, Vec<u8>>> {
    let op: Op = serde_json::from_slice(line).ok()?;
    if !matches!(op.op, "explain" | "queue") {
        return None;
    }
    let refused = |message: String| error("malformed", message);
    let request: Request = match serde_json::from_slice(line) {
        Ok(request) => request,
        Err(problem) => return Some(Err(refused(problem.to_string()))),
    };
    let hex = |text: &str| u64::from_str_radix(text, 16).ok().and_then(Id::from_u64);
    Some(match request {
        Request::Explain {
            delivery: Some(delivery),
            message: None,
        } => hex(&delivery)
            .map(|id| Asked::Explain(Inspect::Delivery(DeliveryId(id))))
            .ok_or_else(|| refused("delivery is an ID in hex".to_owned())),
        Request::Explain {
            delivery: None,
            message: Some(message),
        } => hex(&message)
            .map(|id| Asked::Explain(Inspect::Message(MessageId(id))))
            .ok_or_else(|| refused("message is an ID in hex".to_owned())),
        Request::Explain { .. } => Err(refused(
            "explain names a delivery or a message, not both".to_owned(),
        )),
        Request::Queue { most } => Ok(Asked::Queue {
            most: most.unwrap_or(QUEUES_SHOWN),
        }),
    })
}

#[derive(Serialize)]
struct Explained {
    deliveries: Vec<Explanation>,
}

#[derive(Serialize)]
struct Explanation {
    delivery: String,
    message: String,
    recipient: String,
    /// `waiting`, `paused`, `in_flight` or `finished`.
    state: &'static str,
    /// When a waiting delivery's next attempt is due, a hold paused it, an
    /// attempt in flight began, or a delivery finished.
    at: String,
    /// How a finished delivery finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    completion: Option<&'static str>,
    expires: String,
    attempts: u32,
    uncertain_attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress: Option<String>,
    /// What the receiver said when its last attempt ended without
    /// delivering it.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_reply: Option<LastReply>,
    /// Where the scheduler holds it, if it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    held: Option<Held>,
    /// The restored store's fence, if it covers it.
    #[serde(skip_serializing_if = "Option::is_none")]
    fenced: Option<Fenced>,
    /// The hold that pauses it. One paused by a hold lifted since
    /// has none, and waits for the pass that releases it.
    #[serde(skip_serializing_if = "Option::is_none")]
    paused: Option<PausedBy>,
}

/// The hold that pauses a delivery: its ID, what it is on as `release`
/// names it, and why.
#[derive(Serialize)]
struct PausedBy {
    hold: String,
    account: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    configuration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress: Option<String>,
    reason: String,
    /// Whether new mail the hold covers is still accepted, to wait.
    accepting: bool,
}

impl PausedBy {
    fn of(hold: &policy::Hold, on: &Target) -> Self {
        let mut paused = Self {
            hold: hex(hold.id.0),
            account: hold.account.0.as_u64(),
            tenant: None,
            configuration: None,
            identity: None,
            egress: None,
            reason: hold.reason.clone(),
            accepting: hold.accepting,
        };
        match on {
            Target::Tenant { name, .. } => paused.tenant = Some(name.clone()),
            Target::Configuration { name, .. } => paused.configuration = Some(name.clone()),
            Target::Identity { name, .. } => paused.identity = Some(name.clone()),
            Target::Egress(address) => paused.egress = Some(address.to_string()),
            _ => {}
        }
        paused
    }
}

#[derive(Serialize)]
struct LastReply {
    reply: String,
    /// The receiver rules it matched.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<String>,
}

#[derive(Serialize)]
struct Held {
    /// `routing`, `unplaced`, `queued`, `consulting`, `starting` or
    /// `in_flight`.
    r#where: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    site: Option<String>,
    /// Its queue's exchanges, when its site is a provider's.
    #[serde(skip_serializing_if = "Option::is_none")]
    exchanges: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ahead: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cooling: Option<Cooled>,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_frees: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warmup: Option<Warmup>,
}

/// An egress's cap at a site, and the judgment that set it.
#[derive(Serialize)]
struct Warmup {
    cap: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    judged: Option<Judged>,
}

/// One of warmup's judgments: of which UTC day, what it did, the signal
/// that held or lowered the cap, and the day's counts.
#[derive(Serialize)]
pub(crate) struct Judged {
    day: String,
    verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    by: Option<&'static str>,
    delivered: u32,
    deferred: u32,
    throttled: u32,
    failed: u32,
    complained: u32,
}

pub(crate) fn judged(day: u64, judgment: &Judgment) -> Judged {
    let signal = |signal| match signal {
        Signal::Delivered => "delivered",
        Signal::Deferred => "deferred",
        Signal::Throttled => "throttled",
        Signal::Failed => "failed",
        Signal::Complained => "complained",
    };
    let (verdict, by) = match judgment.verdict {
        Verdict::Raised => ("raised", None),
        Verdict::Untested => ("untested", None),
        Verdict::Held(by) => ("held", Some(signal(by))),
        Verdict::Lowered(by) => ("lowered", Some(signal(by))),
        Verdict::Set => ("set by the operator", None),
    };
    let counts = judgment.counts;
    Judged {
        day: day_text(day),
        verdict,
        by,
        delivered: counts.delivered,
        deferred: counts.deferred,
        throttled: counts.throttled,
        failed: counts.failed,
        complained: counts.complained,
    }
}

fn warmup(capped: &Capped) -> Warmup {
    Warmup {
        cap: capped.cap,
        judged: capped
            .judged
            .as_ref()
            .map(|(day, judgment)| judged(*day, judgment)),
    }
}

#[derive(Serialize)]
struct Cooled {
    until: String,
    throttles: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply: Option<String>,
}

#[derive(Serialize)]
struct Queues {
    stored: Stored,
    queues: Vec<Queue>,
}

/// The unfinished deliveries the store holds, by state: those the
/// scheduler holds in memory, which `queues` shows, and those waiting for a
/// later time, a retry's or a cap's, which it does not.
#[derive(Clone, Copy, Serialize)]
pub struct Stored {
    pub waiting: u64,
    pub in_flight: u64,
    pub held: u64,
}

#[derive(Serialize)]
struct Queue {
    site: String,
    /// The queue's exchanges, when its site is a provider's.
    #[serde(skip_serializing_if = "Option::is_none")]
    exchanges: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress: Option<String>,
    waiting: usize,
    /// Put off in the store until the egress's cap has room for them.
    put_off: u64,
    active: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    cooling: Option<Cooled>,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_frees: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warmup: Option<Warmup>,
}

/// The line answering `explain`: `deliveries` as the store holds them, with
/// the replies that explain why they wait or failed, and where `report`
/// says the scheduler holds them.
pub fn explained(deliveries: &[Inspected], report: &Report) -> Vec<u8> {
    let holds = match report {
        Report::Holds(holds) => holds.as_slice(),
        Report::Queues(_) => &[],
    };
    let deliveries = deliveries
        .iter()
        .map(
            |Inspected {
                 delivery,
                 reply,
                 hold,
                 fence,
             }| {
                let (state, at, completion) = match delivery.state() {
                    QueueState::Ready { due_at } => ("waiting", due_at, None),
                    QueueState::Held { since, .. } => ("paused", since, None),
                    QueueState::InFlight { since, .. } => ("in_flight", since, None),
                    QueueState::Finished { completion, at } => {
                        let completion = match completion {
                            Completion::RemoteAccepted { .. } => "delivered",
                            Completion::Rejected { .. } => "rejected",
                            Completion::Expired => "expired",
                            Completion::Suppressed => "suppressed",
                            Completion::Cancelled => "cancelled",
                            Completion::Captured { .. } => "captured",
                        };
                        ("finished", at, Some(completion))
                    }
                };
                Explanation {
                    delivery: hex(delivery.id().0),
                    message: hex(delivery.message().0),
                    recipient: delivery.recipient().as_str().to_owned(),
                    state,
                    at: rfc3339(at),
                    completion,
                    expires: rfc3339(delivery.expires_at()),
                    attempts: delivery.attempts(),
                    uncertain_attempts: delivery.uncertain_attempts(),
                    egress: delivery.egress().map(|egress| hex(egress.0)),
                    last_reply: reply.as_ref().map(|reply| LastReply {
                        reply: said(reply),
                        rules: reply.rules.split_whitespace().map(str::to_owned).collect(),
                    }),
                    held: holds
                        .iter()
                        .find(|(id, _)| *id == delivery.id())
                        .map(|(_, hold)| held(hold)),
                    paused: hold.as_ref().map(|(hold, on)| PausedBy::of(hold, on)),
                    fenced: fence.map(|fence| Fenced {
                        taken: rfc3339(fence.taken),
                        discarding: fence.discarding,
                    }),
                }
            },
        )
        .collect();
    line(&Reply::Ok(Explained { deliveries }))
}

/// A restored store's fence, as it covers a delivery: since a copy taken
/// when, and whether the decision was to discard what it covers.
#[derive(Serialize)]
struct Fenced {
    taken: String,
    discarding: bool,
}

/// The line answering `queue`: what the store holds, and the queues the
/// scheduler holds in memory.
pub fn queued(report: &Report, stored: Stored) -> Vec<u8> {
    let queues = match report {
        Report::Queues(queues) => queues.iter().map(queue).collect(),
        Report::Holds(_) => Vec::new(),
    };
    line(&Reply::Ok(Queues { stored, queues }))
}

fn held(hold: &Hold) -> Held {
    let nothing = Held {
        r#where: "",
        domain: None,
        site: None,
        exchanges: None,
        egress: None,
        ahead: None,
        cooling: None,
        budget_frees: None,
        warmup: None,
    };
    match hold {
        Hold::Routing { domain } => Held {
            r#where: "routing",
            domain: Some(domain.to_string()),
            ..nothing
        },
        Hold::Unplaced => Held {
            r#where: "unplaced",
            ..nothing
        },
        Hold::Queued {
            site,
            queue,
            egress,
            ahead,
            cooling,
            budget_frees,
            warmup: capped,
        } => Held {
            r#where: "queued",
            site: Some(site.to_string()),
            exchanges: exchanges_of(site, queue),
            egress: egress.map(|egress| hex(egress.0)),
            ahead: Some(*ahead),
            cooling: cooling.as_ref().map(cooled),
            budget_frees: budget_frees.map(rfc3339),
            warmup: capped.as_ref().map(warmup),
            ..nothing
        },
        Hold::Consulting { site, egress }
        | Hold::Starting { site, egress }
        | Hold::InFlight { site, egress } => Held {
            r#where: match hold {
                Hold::Consulting { .. } => "consulting",
                Hold::Starting { .. } => "starting",
                _ => "in_flight",
            },
            site: Some(site.to_string()),
            egress: egress.map(|egress| hex(egress.0)),
            ..nothing
        },
    }
}

fn queue(report: &QueueReport) -> Queue {
    Queue {
        site: report.site.to_string(),
        exchanges: exchanges_of(&report.site, &report.queue),
        egress: report.egress.map(|egress| hex(egress.0)),
        waiting: report.waiting,
        put_off: report.put_off,
        active: report.active,
        cooling: report.cooling.as_ref().map(cooled),
        budget_frees: report.budget_frees.map(rfc3339),
        warmup: report.warmup.as_ref().map(warmup),
    }
}

fn cooled(cooling: &Cooling) -> Cooled {
    Cooled {
        until: rfc3339(cooling.until),
        throttles: cooling.throttles,
        reply: cooling.reply.as_ref().map(said),
    }
}

/// What a reply said, or the engine's own account as it is.
fn said(evidence: &Evidence) -> String {
    if evidence.is_local() {
        evidence.text.clone()
    } else {
        format!("{} {}", evidence.code, evidence.text)
    }
}

/// A queue's exchanges, when they are not its site's name: the site is a
/// provider's.
fn exchanges_of(site: &str, queue: &str) -> Option<String> {
    (site != queue).then(|| queue.to_owned())
}

pub(crate) fn hex(id: Id) -> String {
    format!("{:016x}", id.as_u64())
}

/// `2026-10-27`, for a UTC day as days since the Unix epoch.
pub fn day_text(day: u64) -> String {
    let at = Timestamp::from_micros(day.saturating_mul(86_400_000_000)).utc();
    format!("{:04}-{:02}-{:02}", at.year, at.month, at.day)
}

/// `2026-10-27T15:30:05.250Z`.
pub fn rfc3339(at: Timestamp) -> String {
    let at = at.utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year, at.month, at.day, at.hour, at.minute, at.second, at.millisecond
    )
}

#[cfg(test)]
mod tests {
    use engine_core::id::HoldId;
    use engine_core::policy::Paused;

    use super::*;

    #[test]
    fn inspections_are_read_and_others_left_alone() {
        assert_eq!(
            asked(br#"{"op":"explain","delivery":"00000100000000a1"}"#),
            Some(Ok(Asked::Explain(Inspect::Delivery(DeliveryId(
                Id::from_u64(0x100_0000_00a1).unwrap()
            )))))
        );
        assert_eq!(
            asked(br#"{"op":"queue"}"#),
            Some(Ok(Asked::Queue { most: QUEUES_SHOWN }))
        );
        assert!(matches!(
            asked(br#"{"op":"explain","delivery":"1","message":"2"}"#),
            Some(Err(_))
        ));
        assert!(matches!(
            asked(br#"{"op":"explain","delivery":"zz"}"#),
            Some(Err(_))
        ));
        assert_eq!(asked(br#"{"op":"suppress","account":7}"#), None);
        assert_eq!(asked(b"not json"), None);
    }

    #[test]
    fn a_deferred_delivery_says_what_its_receiver_said_and_the_rules_it_matched() {
        use engine_core::address::Address;
        use engine_core::attempt::Evidence;
        use engine_core::delivery::{Delivery, Disposition};
        use engine_core::id::{AccountId, AttemptId, IdentityId};
        use engine_core::policy::Origin;
        let id = |value: u64| Id::from_u64(value).unwrap();
        let at = Timestamp::from_micros(1_800_000_000_000_000);
        let mut delivery = Delivery::new(
            DeliveryId(id(1)),
            MessageId(id(2)),
            AccountId(id(3)),
            Origin {
                identity: IdentityId(id(4)),
                tenant: None,
                configuration: None,
            },
            Address::parse("r@example.net").unwrap(),
            at,
            at.saturating_add(std::time::Duration::from_secs(3600)),
        )
        .unwrap();
        let permit = delivery
            .reserve(delivery.generation(), AttemptId(id(5)), None, at)
            .unwrap();
        let not_before = at.saturating_add(std::time::Duration::from_secs(600));
        delivery
            .record_outcome(permit, Disposition::Deferred { not_before }, at)
            .unwrap();
        let mut reply = Evidence::new(451, "4.7.1 slow down please");
        reply.rules = "refused Throttled/slow".to_owned();
        delivery.heard(Some(&reply), 9);
        let inspected = Inspected {
            delivery: delivery.clone(),
            reply: Some(reply.clone()),
            hold: None,
            fence: None,
        };
        let text = String::from_utf8(explained(&[inspected], &Report::Holds(Vec::new()))).unwrap();
        assert!(
            text.contains(
                r#""last_reply":{"reply":"451 4.7.1 slow down please","rules":["refused","Throttled/slow"]}"#
            ),
            "{text}"
        );
        // Paused, it says by what hold, and why.
        delivery.park(delivery.generation(), None, at).unwrap();
        let hold = policy::Hold {
            id: HoldId(id(6)),
            account: delivery.account(),
            paused: Paused::Account,
            accepting: true,
            reason: "billing".to_owned(),
        };
        let on = Target::Account(hold.account);
        let inspected = Inspected {
            delivery,
            reply: Some(reply),
            hold: Some((hold, on)),
            fence: None,
        };
        let text = String::from_utf8(explained(&[inspected], &Report::Holds(Vec::new()))).unwrap();
        assert!(text.contains(r#""state":"paused""#), "{text}");
        assert!(
            text.contains(r#""reason":"billing","accepting":true}"#),
            "{text}"
        );
        assert!(text.contains(r#""paused":{"hold":"#), "{text}");
    }

    const STORED: Stored = Stored {
        waiting: 12,
        in_flight: 1,
        held: 0,
    };

    #[test]
    fn a_queue_is_shown_with_its_cooldown_and_the_reply_that_began_it() {
        let report = Report::Queues(vec![QueueReport {
            site: "mx.example.net".into(),
            queue: "mx.example.net".into(),
            egress: None,
            waiting: 12,
            active: 1,
            cooling: Some(Cooling {
                until: Timestamp::from_micros(1_800_000_000_000_000),
                throttles: 2,
                reply: Some(engine_core::attempt::Evidence::new(421, "4.7.0 Try later")),
            }),
            budget_frees: None,
            warmup: None,
            put_off: 0,
        }]);
        let text = String::from_utf8(queued(&report, STORED)).unwrap();
        assert_eq!(
            text,
            "{\"ok\":{\"stored\":{\"waiting\":12,\"in_flight\":1,\"held\":0},\"queues\":[{\"site\":\"mx.example.net\",\"waiting\":12,\"put_off\":0,\"active\":1,\"cooling\":{\"until\":\"2027-01-15T08:00:00.000Z\",\"throttles\":2,\"reply\":\"421 4.7.0 Try later\"}}]}}\n"
        );
    }

    #[test]
    fn a_capped_queue_shows_its_cap_the_judgment_that_set_it_and_what_it_put_off() {
        let counts = engine_core::budget::Counts {
            delivered: 480,
            throttled: 9,
            ..Default::default()
        };
        // The site's own row, all its mail put off.
        let report = Report::Queues(vec![QueueReport {
            site: "Microsoft".into(),
            queue: "Microsoft".into(),
            egress: None,
            waiting: 0,
            put_off: 40,
            active: 0,
            cooling: None,
            budget_frees: Some(Timestamp::from_micros(1_800_000_000_000_000)),
            warmup: Some(Capped {
                cap: 500,
                judged: Some((
                    20_391,
                    Judgment {
                        counts,
                        verdict: Verdict::Lowered(Signal::Throttled),
                    },
                )),
            }),
        }]);
        let text = String::from_utf8(queued(&report, STORED)).unwrap();
        assert!(
            text.contains(r#"{"site":"Microsoft","waiting":0,"put_off":40,"active":0,"#),
            "{text}"
        );
        assert!(
            text.contains(r#""budget_frees":"2027-01-15T08:00:00.000Z","warmup":{"cap":500,"judged":{"day":"2025-10-30","verdict":"lowered","by":"throttled","delivered":480,"deferred":0,"throttled":9,"failed":0,"complained":0}}"#),
            "{text}"
        );
    }
}
