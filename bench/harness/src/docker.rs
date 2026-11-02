//! The container runtime, driven through its command line. The `docker`
//! commands used here are the ones every supported runtime provides (Podman
//! answers to them too), so the harness needs nothing else on the host.

use std::process::{Command, Stdio};

pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Runs a command and captures its output; a failure carries its error
/// output.
pub fn run(args: &[&str]) -> Result<Output, String> {
    let output = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            format!("docker: {error}; the harness needs a container runtime's `docker` command")
        })?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(format!(
            "`docker {}` failed: {}",
            shown(args),
            stderr.trim()
        ));
    }
    Ok(Output {
        stdout: output.stdout,
        stderr,
    })
}

/// Runs a command and returns its standard output as trimmed text.
pub fn text(args: &[&str]) -> Result<String, String> {
    run(args).map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Runs a command with its output shown, for builds that take a while.
pub fn shown_run(args: &[&str]) -> Result<(), String> {
    let status = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| format!("docker: {error}"))?;
    if !status.success() {
        return Err(format!("`docker {}` failed", shown(args)));
    }
    Ok(())
}

/// Runs a command whose failure is expected and harmless, such as removing
/// something that may not exist.
pub fn quietly(args: &[&str]) {
    let _ = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// The command as it would be typed, without the long arguments that would
/// bury the error.
fn shown(args: &[&str]) -> String {
    args.iter()
        .map(|arg| if arg.len() > 80 { "…" } else { arg })
        .collect::<Vec<_>>()
        .join(" ")
}
