//! Which installation key the running engine seals with, on
//! the admin socket: `{"op":"keys"}` answers `{"sealing": <id>, "keys":
//! <path>, "store": <path>}`, the keys file it holds and the store it seals,
//! as their full paths. Every start seals every secret in policy under the
//! newest key it loads, and every new secret is sealed under it, so as far
//! as secrets go the keys before it may go once a start has used it; mail
//! sealed under a key keeps needing it until that mail is gone, which
//! `{"op":"key_held","key":<id>,"from":<token>}` says a page at a time:
//! `{"table": <name>, "held": <records>, "next": <token>}`, the records of
//! one table still sealed under it and where the next page starts, `next`
//! null once every table is read.

use engine_core::command::KeyHeld;
use serde::{Deserialize, Serialize};

use crate::native::{Reply, error, line};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Keys {},
    KeyHeld { key: u8, from: Option<String> },
}

#[derive(Deserialize)]
struct Op<'a> {
    op: &'a str,
}

/// What is asked of the keys.
#[derive(Debug, PartialEq, Eq)]
pub enum Asked {
    Keys,
    KeyHeld { key: u8, from: Option<Vec<u8>> },
}

#[derive(Serialize)]
struct Sealing<'a> {
    sealing: u8,
    keys: &'a str,
    store: &'a str,
}

#[derive(Serialize)]
struct Held<'a> {
    table: &'a str,
    held: u64,
    next: Option<String>,
}

/// What `line` asks of the keys: `None` if it asks for something else, and
/// its reply line if it cannot be read.
pub fn asked(line: &[u8]) -> Option<Result<Asked, Vec<u8>>> {
    let op: Op = serde_json::from_slice(line).ok()?;
    if op.op != "keys" && op.op != "key_held" {
        return None;
    }
    let malformed = |problem: String| error("malformed", problem);
    Some(match serde_json::from_slice(line) {
        Ok(Request::Keys {}) => Ok(Asked::Keys),
        Ok(Request::KeyHeld { key, from }) => match from.map(|from| unhex(&from)) {
            Some(None) => Err(malformed("`from` is a token a page gave".to_owned())),
            from => Ok(Asked::KeyHeld {
                key,
                from: from.flatten(),
            }),
        },
        Err(problem) => Err(malformed(problem.to_string())),
    })
}

/// The line answering `keys`: the key every secret is sealed under, in the
/// store and keys file at the paths given.
pub fn answered(sealing: u8, keys: &str, store: &str) -> Vec<u8> {
    line(&Reply::Ok(Sealing {
        sealing,
        keys,
        store,
    }))
}

/// The line answering `key_held` with `page`.
pub fn held(page: &KeyHeld) -> Vec<u8> {
    line(&Reply::Ok(Held {
        table: page.table,
        held: page.held,
        next: page
            .next
            .as_ref()
            .map(|next| next.iter().map(|byte| format!("{byte:02x}")).collect()),
    }))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_sealing_and_what_a_key_holds_are_asked_and_answered() {
        assert_eq!(asked(br#"{"op":"keys"}"#), Some(Ok(Asked::Keys)));
        assert!(matches!(asked(br#"{"op":"keys","id":1}"#), Some(Err(_))));
        assert!(asked(br#"{"op":"queue"}"#).is_none());
        assert_eq!(
            String::from_utf8(answered(3, "/etc/keys", "/var/store.db")).unwrap(),
            "{\"ok\":{\"sealing\":3,\"keys\":\"/etc/keys\",\"store\":\"/var/store.db\"}}\n"
        );
        assert_eq!(
            asked(br#"{"op":"key_held","key":2}"#),
            Some(Ok(Asked::KeyHeld { key: 2, from: None }))
        );
        assert_eq!(
            asked(br#"{"op":"key_held","key":2,"from":"03ff"}"#),
            Some(Ok(Asked::KeyHeld {
                key: 2,
                from: Some(vec![3, 255])
            }))
        );
        assert!(matches!(
            asked(br#"{"op":"key_held","key":2,"from":"3"}"#),
            Some(Err(_))
        ));
        let page = KeyHeld {
            table: "journal",
            held: 4,
            next: Some(vec![3, 255]),
        };
        assert_eq!(
            String::from_utf8(held(&page)).unwrap(),
            "{\"ok\":{\"table\":\"journal\",\"held\":4,\"next\":\"03ff\"}}\n"
        );
    }
}
