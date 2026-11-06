//! What the store holds free, on the admin socket: `{"op":"space"}`, which
//! `nitromta doctor` asks of a running engine, whose store only it may open.

use serde::{Deserialize, Serialize};

use crate::native::{Reply, error, line};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Space {},
}

#[derive(Deserialize)]
struct Op<'a> {
    op: &'a str,
}

#[derive(Serialize)]
struct Space {
    reusable_bytes: u64,
}

/// Whether `line` asks for the store's space, or `None` if it asks for
/// something else. One it cannot read is refused with its reply line.
pub fn asked(line: &[u8]) -> Option<Result<(), Vec<u8>>> {
    let op: Op = serde_json::from_slice(line).ok()?;
    if op.op != "space" {
        return None;
    }
    Some(match serde_json::from_slice(line) {
        Ok(Request::Space {}) => Ok(()),
        Err(problem) => Err(error("malformed", problem.to_string())),
    })
}

/// The line answering it.
pub fn answered(reusable_bytes: u64) -> Vec<u8> {
    line(&Reply::Ok(Space { reusable_bytes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_is_asked_for_by_its_op_alone() {
        assert_eq!(asked(br#"{"op":"space"}"#), Some(Ok(())));
        assert_eq!(asked(br#"{"op":"keys"}"#), None);
        assert!(matches!(asked(br#"{"op":"space","x":1}"#), Some(Err(_))));
        let answer = String::from_utf8(answered(4096)).unwrap();
        assert!(answer.contains(r#""reusable_bytes":4096"#), "{answer}");
    }
}
