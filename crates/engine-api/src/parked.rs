//! The operator's parked events on the admin socket:
//!
//! - `{"op":"parked","account":1,"subscription":"hooks"}`: the
//!   subscription's parked batches, or a topic subscriber's, named by its
//!   subscription ARN, oldest first: each one's `batch` (its
//!   first event's journal position, which `replay` names), the last
//!   position it covers, when it was parked, its posts and why the last
//!   failed. At most `PAGE` a page: one that is not the last says `next`,
//!   which `"from"` asks for.
//! - `{"op":"replay","account":1,"subscription":"hooks"}`, or with
//!   `"batch"`: its parked batches, or that one, posted again, marked as
//!   replays. The answer says how many will be; each one taken leaves
//!   `parked`.

use engine_core::command::{Answer, ParkedEvents};
use engine_core::id::{AccountId, Id, SubscriptionId};
use serde::{Deserialize, Serialize};

use crate::inspect::{hex, rfc3339};
use crate::native::{Reply, error, line};

/// The most parked batches a `parked` answer lists.
pub const PAGE: usize = 1000;

/// What a parked-events request asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asked {
    Parked {
        account: AccountId,
        subscription: String,
        from: Option<u64>,
    },
    Replay {
        account: AccountId,
        subscription: String,
        batch: Option<u64>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Parked {
        account: u64,
        subscription: String,
        from: Option<u64>,
    },
    Replay {
        account: u64,
        subscription: String,
        batch: Option<u64>,
    },
}

#[derive(Deserialize)]
struct Op<'a> {
    op: &'a str,
}

/// The request `line` makes of parked events, or `None` if it asks for
/// something else. One it cannot read is refused with its reply line.
pub fn asked(line: &[u8]) -> Option<Result<Asked, Vec<u8>>> {
    let op: Op = serde_json::from_slice(line).ok()?;
    if !matches!(op.op, "parked" | "replay") {
        return None;
    }
    let refused = |message: String| error("malformed", message);
    let request: Request = match serde_json::from_slice(line) {
        Ok(request) => request,
        Err(problem) => return Some(Err(refused(problem.to_string()))),
    };
    let account = |account| {
        Id::from_u64(account)
            .map(AccountId)
            .ok_or_else(|| error("invalid_account", format!("{account} is not an account")))
    };
    Some(match request {
        Request::Parked {
            account: id,
            subscription,
            from,
        } => account(id).map(|account| Asked::Parked {
            account,
            subscription,
            from,
        }),
        Request::Replay {
            account: id,
            subscription,
            batch,
        } => account(id).map(|account| Asked::Replay {
            account,
            subscription,
            batch,
        }),
    })
}

#[derive(Serialize)]
struct Listed {
    subscription: String,
    parked: Vec<Batch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<u64>,
}

#[derive(Serialize)]
struct Batch {
    batch: u64,
    through: u64,
    parked_at: String,
    attempts: u32,
    failure: String,
}

#[derive(Serialize)]
struct Replaying {
    replaying: usize,
}

/// The line answering `parked`, from the store's answer to a read of a
/// page and one more: none if the store did not answer.
pub fn listed(answer: Option<Answer>) -> Vec<u8> {
    match answer {
        Some(Answer::ParkedEvents(Ok(Some((subscription, parked))))) => {
            listing(subscription, &parked)
        }
        Some(Answer::ParkedEvents(Ok(None))) => {
            error("unknown", "no such subscription in the account".to_owned())
        }
        _ => error("unavailable", "the store did not answer".to_owned()),
    }
}

fn listing(subscription: SubscriptionId, parked: &[ParkedEvents]) -> Vec<u8> {
    let next = parked.get(PAGE).map(|batch| batch.first);
    let parked = parked
        .iter()
        .take(PAGE)
        .map(|batch| Batch {
            batch: batch.first,
            through: batch.through,
            parked_at: rfc3339(batch.at),
            attempts: batch.attempts,
            failure: batch.failure.clone(),
        })
        .collect();
    line(&Reply::Ok(Listed {
        subscription: hex(subscription.0),
        parked,
        next,
    }))
}

/// The line answering `replay`: how many parked batches will be posted
/// again, or why none; none if event delivery did not answer.
pub fn replaying(outcome: Option<Result<usize, String>>) -> Vec<u8> {
    match outcome {
        Some(Ok(replaying)) => line(&Reply::Ok(Replaying { replaying })),
        Some(Err(why)) => error("unknown", why),
        None => error("unavailable", "event delivery did not answer".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use engine_core::time::Timestamp;

    use super::*;

    #[test]
    fn parked_events_are_asked_for_by_subscription_and_listed_with_their_failure() {
        assert_eq!(
            asked(br#"{"op":"replay","account":1,"subscription":"hooks","batch":7}"#),
            Some(Ok(Asked::Replay {
                account: AccountId(Id::from_u64(1).unwrap()),
                subscription: "hooks".to_owned(),
                batch: Some(7),
            }))
        );
        assert!(asked(br#"{"op":"explain","delivery":"1"}"#).is_none());
        assert!(matches!(
            asked(br#"{"op":"parked","account":1}"#),
            Some(Err(_))
        ));
        let subscription = SubscriptionId(Id::from_u64(9).unwrap());
        let parked = ParkedEvents {
            subscription,
            first: 7,
            through: 12,
            at: Timestamp::from_micros(1_800_000_000_000_000),
            attempts: 9,
            failure: "answered 503".to_owned(),
        };
        let found = Answer::ParkedEvents(Ok(Some((subscription, vec![parked.clone()]))));
        let text = String::from_utf8(listed(Some(found))).unwrap();
        assert_eq!(
            text,
            "{\"ok\":{\"subscription\":\"0000000000000009\",\"parked\":[{\"batch\":7,\"through\":12,\"parked_at\":\"2027-01-15T08:00:00.000Z\",\"attempts\":9,\"failure\":\"answered 503\"}]}}\n"
        );
        // More than a page: the page, and where the next starts.
        let many = (0..=PAGE as u64)
            .map(|first| ParkedEvents {
                first,
                through: first,
                ..parked.clone()
            })
            .collect();
        let text = String::from_utf8(listed(Some(Answer::ParkedEvents(Ok(Some((
            subscription,
            many,
        )))))))
        .unwrap();
        assert_eq!(text.matches("\"batch\"").count(), PAGE);
        assert!(text.ends_with(&format!(",\"next\":{PAGE}}}}}\n")), "{text}");
        assert_eq!(
            asked(br#"{"op":"parked","account":1,"subscription":"hooks","from":1000}"#),
            Some(Ok(Asked::Parked {
                account: AccountId(Id::from_u64(1).unwrap()),
                subscription: "hooks".to_owned(),
                from: Some(1000),
            }))
        );
    }
}
