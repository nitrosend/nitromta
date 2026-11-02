//! Golden fixtures for the persisted formats: rows and schemas as the
//! release that added each wrote them, under `fixtures/formats`, written
//! once by `cargo xtask fixtures` and never again. The tests read every one
//! with this build, so a field whose number or meaning changed, or a
//! published schema step edited, fails them, while a layout that only grew
//! passes.

#![allow(clippy::disallowed_methods)]

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::PathBuf;

/// Set by `cargo xtask fixtures`: a case without its fixture is given one.
/// One already written is never rewritten.
const WRITING: &str = "NITROMTA_WRITE_FIXTURES";

/// The bytes a record's fixture holds, for its test to read: `kind`'s
/// layout at `version`, in the case `case` names. `fresh` is how this
/// build encodes it, written as the fixture when the case has none yet.
pub fn record(kind: &str, version: u8, case: &str, fresh: &[u8]) -> Vec<u8> {
    let name = format!("{kind}-{version}-{case}.hex");
    let kept = fixture(&name, || {
        let mut text = String::with_capacity(fresh.len() * 2 + 1);
        for byte in fresh {
            let _ = write!(text, "{byte:02x}");
        }
        text.push('\n');
        text
    });
    let kept = kept.trim();
    (0..kept.len())
        .step_by(2)
        .map(|at| {
            kept.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .unwrap_or_else(|| panic!("{name} is not hex"))
        })
        .collect()
}

/// The text a fixture named `name` holds, which `fresh` is when it has
/// none yet.
pub fn text(name: &str, fresh: &str) -> String {
    fixture(name, || fresh.to_owned())
}

fn fixture(name: &str, fresh: impl FnOnce() -> String) -> String {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/formats");
    let path = directory.join(name);
    match std::fs::read_to_string(&path) {
        Ok(kept) => kept,
        Err(error)
            if error.kind() == ErrorKind::NotFound && std::env::var_os(WRITING).is_some() =>
        {
            let fresh = fresh();
            std::fs::create_dir_all(&directory).expect("the fixtures' directory");
            std::fs::write(&path, &fresh).expect("a fixture written");
            fresh
        }
        Err(error) => panic!(
            "fixtures/formats/{name}: {error}; a new case or schema step is published with its fixture, which `cargo xtask fixtures` writes"
        ),
    }
}
