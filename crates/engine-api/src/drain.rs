//! The operator's drain on the admin socket:
//! `{"op":"drain"}` refuses new mail while the queue is delivered, and
//! `{"op":"undrain"}` takes it again. Each answers what is outstanding:
//! deliveries waiting, in flight and held, as the store last measured
//! them, and attempts whose outcome was uncertain since the engine started.
//! A drain is the running engine's alone: a restart takes mail again.

use serde::{Deserialize, Serialize};

use crate::native::{Reply, error, line};

/// What a drain request asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asked {
    Drain,
    Undrain,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Drain {},
    Undrain {},
}

#[derive(Deserialize)]
struct Op<'a> {
    op: &'a str,
}

/// What is outstanding as a drain goes on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Outstanding {
    pub draining: bool,
    pub waiting: u64,
    pub in_flight: u64,
    pub held: u64,
    pub uncertain_attempts: u64,
}

/// The drain request `line` makes, or `None` if it asks for something
/// else. One it cannot read is refused with its reply line.
pub fn asked(line: &[u8]) -> Option<Result<Asked, Vec<u8>>> {
    let op: Op = serde_json::from_slice(line).ok()?;
    if !matches!(op.op, "drain" | "undrain") {
        return None;
    }
    Some(match serde_json::from_slice(line) {
        Ok(Request::Drain {}) => Ok(Asked::Drain),
        Ok(Request::Undrain {}) => Ok(Asked::Undrain),
        Err(problem) => Err(error("malformed", problem.to_string())),
    })
}

/// The line answering a drain request.
pub fn answered(outstanding: &Outstanding) -> Vec<u8> {
    line(&Reply::Ok(outstanding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_drain_is_asked_and_answered_with_what_is_outstanding() {
        assert_eq!(asked(br#"{"op":"drain"}"#), Some(Ok(Asked::Drain)));
        assert_eq!(asked(br#"{"op":"undrain"}"#), Some(Ok(Asked::Undrain)));
        assert!(matches!(
            asked(br#"{"op":"drain","now":true}"#),
            Some(Err(_))
        ));
        assert!(asked(br#"{"op":"queue"}"#).is_none());
        let outstanding = Outstanding {
            draining: true,
            waiting: 3,
            ..Outstanding::default()
        };
        assert_eq!(
            String::from_utf8(answered(&outstanding)).unwrap(),
            "{\"ok\":{\"draining\":true,\"waiting\":3,\"in_flight\":0,\"held\":0,\"uncertain_attempts\":0}}\n"
        );
    }
}
