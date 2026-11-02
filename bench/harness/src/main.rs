//! The benchmark harness: the load generator, the sink, the
//! durability probe, the observer, and the runner that measures each system
//! under test with them.
//!
//! One binary with a subcommand per role. `run` drives a comparison from the
//! host through the container runtime; the others run inside the containers it
//! starts. Nothing here depends on an engine crate, so a bug in the engine
//! cannot be mirrored by the code that judges it.

mod api;
mod args;
mod clock;
mod compare;
mod dkim;
mod docker;
mod hooks;
mod load;
mod observe;
mod probe;
mod recipe;
mod records;
mod run;
mod sink;
mod smtp;
mod tls;

use std::process::ExitCode;

const USAGE: &str = "usage: harness <command>
  run <profile>       measure the systems a profile names (on the host)
  sink                the reference sink (in its container)
  sink-ctl take|stats read the sink's arrivals or counters (in its container)
  hooks               the event receiver (in its container)
  hooks-ctl stats|secret  read its counts, or give it the secret (in its container)
  load                the load generator (in its container)
  probe               the durability probe (in a container on the queue volume)";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = argv
        .split_first()
        .map_or(("", &[][..]), |(command, rest)| (command.as_str(), rest));
    let result = match command {
        "run" => run::main(rest),
        "sink" => sink::main(rest),
        "sink-ctl" => sink::control(rest),
        "hooks" => hooks::main(rest),
        "hooks-ctl" => hooks::control(rest),
        "load" => load::main(rest),
        "probe" => probe::main(rest),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("harness: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The multi-threaded runtime the sink and the load generator run on.
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the async runtime: {error}"))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
