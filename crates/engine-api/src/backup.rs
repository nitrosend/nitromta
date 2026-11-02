//! Backups and a restored store's fence on the admin socket.
//!
//! `{"op":"backup","to":<path>}` copies the store to a file at a full path
//! the engine may write, and answers where, how large and when it was
//! taken. `{"op":"fence"}` answers the store's fence: `null` unless it was
//! restored and no decision lifted it, or else when the copy was taken and
//! restored, whether its deliveries are being discarded, and how many it
//! covers that are unfinished. `{"op":"fence_release"}` sends them, and
//! `{"op":"fence_discard"}` cancels each as it falls due; each answers the
//! fence as it then is.

use engine_core::policy::Fence;
use engine_core::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::inspect::rfc3339;
use crate::native::{Reply, error, line};

/// What a backup or fence request asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asked {
    Backup { to: String },
    Fence,
    Release,
    Discard,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Backup { to: String },
    Fence {},
    FenceRelease {},
    FenceDiscard {},
}

#[derive(Deserialize)]
struct Op<'a> {
    op: &'a str,
}

/// The request `line` makes, or `None` if it asks for something else. One
/// it cannot read, or a backup to a path that is not a full one, is refused
/// with its reply line.
pub fn asked(line: &[u8]) -> Option<Result<Asked, Vec<u8>>> {
    let op: Op = serde_json::from_slice(line).ok()?;
    if !matches!(
        op.op,
        "backup" | "fence" | "fence_release" | "fence_discard"
    ) {
        return None;
    }
    Some(match serde_json::from_slice(line) {
        Ok(Request::Backup { to }) if !to.starts_with('/') => Err(error(
            "malformed",
            "a backup's destination is a full path, as the engine finds it".to_owned(),
        )),
        Ok(Request::Backup { to }) => Ok(Asked::Backup { to }),
        Ok(Request::Fence {}) => Ok(Asked::Fence),
        Ok(Request::FenceRelease {}) => Ok(Asked::Release),
        Ok(Request::FenceDiscard {}) => Ok(Asked::Discard),
        Err(problem) => Err(error("malformed", problem.to_string())),
    })
}

#[derive(Serialize)]
struct Copied<'a> {
    to: &'a str,
    bytes: u64,
    taken: String,
}

/// The line answering a backup: the copy, in place.
pub fn copied(to: &str, bytes: u64, taken: Timestamp) -> Vec<u8> {
    line(&Reply::Ok(Copied {
        to,
        bytes,
        taken: rfc3339(taken),
    }))
}

/// The line answering a backup that failed.
pub fn not_copied(why: &str) -> Vec<u8> {
    error("backup_failed", why.to_owned())
}

#[derive(Serialize)]
struct Fenced {
    fence: Option<Shown>,
}

#[derive(Serialize)]
struct Shown {
    taken: String,
    restored: String,
    discarding: bool,
    unfinished: u64,
}

/// The line answering a fence request: the fence as it is, and the
/// unfinished deliveries it covers, or `null` if there is none.
pub fn fenced(fence: Option<(Fence, u64)>) -> Vec<u8> {
    line(&Reply::Ok(Fenced {
        fence: fence.map(|(fence, unfinished)| Shown {
            taken: rfc3339(fence.taken),
            restored: rfc3339(fence.restored),
            discarding: fence.discarding,
            unfinished,
        }),
    }))
}

/// The line answering a decision on a store with no fence.
pub fn unfenced() -> Vec<u8> {
    error(
        "not_fenced",
        "the store is not fenced: only a restored store is, until a decision lifts it".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use engine_core::id::Id;

    use super::*;

    #[test]
    fn backups_and_fences_are_asked_and_answered() {
        assert_eq!(
            asked(br#"{"op":"backup","to":"/var/lib/nitromta/copy.db"}"#),
            Some(Ok(Asked::Backup {
                to: "/var/lib/nitromta/copy.db".to_owned()
            }))
        );
        assert!(matches!(
            asked(br#"{"op":"backup","to":"copy.db"}"#),
            Some(Err(_))
        ));
        assert_eq!(asked(br#"{"op":"fence"}"#), Some(Ok(Asked::Fence)));
        assert_eq!(
            asked(br#"{"op":"fence_release"}"#),
            Some(Ok(Asked::Release))
        );
        assert_eq!(
            asked(br#"{"op":"fence_discard"}"#),
            Some(Ok(Asked::Discard))
        );
        assert!(matches!(asked(br#"{"op":"fence","all":1}"#), Some(Err(_))));
        assert!(asked(br#"{"op":"queue"}"#).is_none());
        let at = Timestamp::from_micros(1_800_000_000_000_000);
        assert_eq!(
            String::from_utf8(fenced(None)).unwrap(),
            "{\"ok\":{\"fence\":null}}\n"
        );
        let fence = Fence {
            below: Id::from_u64(9).unwrap(),
            taken: at,
            restored: at,
            discarding: true,
        };
        assert_eq!(
            String::from_utf8(fenced(Some((fence, 4)))).unwrap(),
            format!(
                "{{\"ok\":{{\"fence\":{{\"taken\":\"{t}\",\"restored\":\"{t}\",\"discarding\":true,\"unfinished\":4}}}}}}\n",
                t = rfc3339(at)
            )
        );
    }
}
