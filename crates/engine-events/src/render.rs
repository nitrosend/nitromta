//! A batch's body: the events a subscription owes from part of the journal,
//! as JSON, within a bound on its bytes. An event names its
//! message and recipients, never the message's body. A replay's batch says
//! it is one.

use engine_core::command::Owed;
use engine_core::event::EventKind;
use engine_core::id::Id;
use engine_core::journal::Entry;
use engine_core::policy::Subscription;
use engine_core::time::Timestamp;
use serde::Serialize;

#[derive(Serialize)]
struct Event<'a> {
    /// Its position in the journal and its kind, the same however often it
    /// is sent.
    id: String,
    #[serde(rename = "type")]
    kind: &'static str,
    at: String,
    /// Its message's ID, as `SendEmail` answered it. Absent only if the
    /// delivery's record is gone.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// An accepted message's recipients.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    recipients: Vec<&'a str>,
    /// Any other event's recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<String>,
    /// What the receiver last said in the attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    reply: Option<Reply<'a>>,
    /// The bounce or complaint report it came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<String>,
    /// A reported bounce's status code, as its report gave it.
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    /// A complaint's feedback type.
    #[serde(skip_serializing_if = "Option::is_none")]
    feedback: Option<&'a str>,
    /// Whether a bounce's or complaint's report was signed by a reporter
    /// the operator enrolled with, so a consumer can weigh it.
    #[serde(skip_serializing_if = "Option::is_none")]
    authenticated: Option<bool>,
}

#[derive(Serialize)]
struct Reply<'a> {
    code: u16,
    text: &'a str,
    /// The receiver rules it matched.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<&'a str>,
}

/// The body of the batch holding the events `owed` holds, as many as fit
/// in `bytes` and at least one, and the position of the last entry it
/// covers: `owed`'s last if every event fits, else its last event's. A
/// replay's says so.
pub fn bounded(
    subscription: &Subscription,
    owed: &Owed,
    bytes: usize,
    replay: bool,
) -> (Vec<u8>, u64) {
    let name = serde_json::to_string(&subscription.name).expect("a name always serialises");
    let mut body = format!("{{\"subscription\":{name},");
    if replay {
        body.push_str("\"replay\":true,");
    }
    body.push_str("\"events\":[");
    let mut body = body.into_bytes();
    let mut through = owed.through;
    for (index, (position, entry)) in owed.entries.iter().enumerate() {
        let event =
            serde_json::to_vec(&event(*position, entry, owed)).expect("an event always serialises");
        // A comma before it, and the closing bracket and brace after.
        let after = body.len() + usize::from(index > 0) + event.len() + 2;
        if index > 0 && after > bytes {
            through = owed.entries[index - 1].0;
            break;
        }
        if index > 0 {
            body.push(b',');
        }
        body.extend_from_slice(&event);
    }
    body.extend_from_slice(b"]}");
    (body, through)
}

fn event<'a>(position: u64, entry: &'a Entry, owed: &'a Owed) -> Event<'a> {
    let kind = EventKind::of(entry);
    let delivered = |delivery| owed.deliveries.get(delivery);
    let mut event = Event {
        id: format!("{position:016x}-{}", kind.name()),
        kind: kind.name(),
        at: String::new(),
        message: None,
        recipients: Vec::new(),
        recipient: None,
        attempt: None,
        reply: None,
        report: None,
        status: None,
        feedback: None,
        authenticated: None,
    };
    let (at, delivery) = match entry {
        Entry::Accepted {
            message,
            deliveries,
            at,
            ..
        } => {
            event.message = Some(hex(message.0));
            event.recipients = deliveries
                .iter()
                .filter_map(&delivered)
                .map(|(_, recipient)| recipient.as_str())
                .collect();
            (*at, None)
        }
        Entry::Attempted {
            attempt, evidence, ..
        } => {
            event.attempt = Some(hex(attempt.id.0));
            event.reply = evidence.as_ref().map(|evidence| Reply {
                code: evidence.code,
                text: &evidence.text,
                rules: evidence.rules.split_whitespace().collect(),
            });
            let at = attempt.ended.map_or(attempt.reserved_at, |ended| ended.at);
            (at, Some(&attempt.delivery))
        }
        Entry::Expired { delivery, at, .. }
        | Entry::Suppressed { delivery, at, .. }
        | Entry::Cancelled { delivery, at, .. } => (*at, Some(delivery)),
        Entry::Bounced {
            delivery,
            report,
            status,
            authenticated,
            at,
            ..
        } => {
            event.report = Some(hex(report.0));
            event.status = status.map(|status| status.to_string());
            event.authenticated = Some(*authenticated);
            (*at, Some(delivery))
        }
        Entry::Complained {
            delivery,
            report,
            feedback_type,
            authenticated,
            at,
            ..
        } => {
            event.report = Some(hex(report.0));
            event.feedback = Some(feedback_type);
            event.authenticated = Some(*authenticated);
            (*at, Some(delivery))
        }
    };
    if let Some((message, recipient)) = delivery.and_then(delivered) {
        event.message = Some(hex(message.0));
        event.recipient = Some(recipient.as_str());
    }
    event.at = rfc3339(at);
    event
}

pub(crate) fn hex(id: Id) -> String {
    format!("{:016x}", id.as_u64())
}

/// `2026-10-27T15:30:05.250Z`.
pub(crate) fn rfc3339(at: Timestamp) -> String {
    let at = at.utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year, at.month, at.day, at.hour, at.minute, at.second, at.millisecond
    )
}

#[cfg(test)]
mod tests {
    use engine_core::attempt::Attempt;
    use engine_core::id::{AccountId, AttemptId, DeliveryId, ReportId};

    use super::*;

    #[test]
    fn a_complaint_says_whether_its_report_was_authenticated_and_an_attempt_says_nothing() {
        let id = |value| Id::from_u64(value).unwrap();
        let complained = |authenticated| Entry::Complained {
            delivery: DeliveryId(id(1 << 40)),
            account: AccountId(id(1)),
            configuration: None,
            report: ReportId(id(2 << 40)),
            feedback_type: "abuse".to_owned(),
            authenticated,
            at: Timestamp::from_micros(1_800_000_000_000_000),
        };
        let owed = Owed::default();
        for authenticated in [true, false] {
            let entry = complained(authenticated);
            let event = serde_json::to_value(event(9, &entry, &owed)).unwrap();
            assert_eq!(event["type"], "complained");
            assert_eq!(event["authenticated"], authenticated, "{event}");
        }
        let attempted = Entry::Attempted {
            attempt: Attempt {
                id: AttemptId(id(3 << 40)),
                delivery: DeliveryId(id(1 << 40)),
                account: AccountId(id(1)),
                reserved_at: Timestamp::from_micros(1_800_000_000_000_000),
                ended: None,
            },
            configuration: None,
            evidence: None,
        };
        let event = serde_json::to_value(event(9, &attempted, &owed)).unwrap();
        assert!(event.get("authenticated").is_none(), "{event}");
    }
}
