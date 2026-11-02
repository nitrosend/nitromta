//! The repository's checks. `cargo xtask check` is the one gate: contributors,
//! CI and releases run the same command on any machine, and it stops at the
//! first failure. `cargo xtask check structure` runs only the structure check.
//!
//! Generated crates are checked by regeneration instead of by the source
//! rules: `cargo xtask generate` rewrites them from their recipes, and
//! `cargo xtask check generated` fails if a committed one differs. Both run
//! the recipes in a container.
//!
//! `cargo xtask fixtures` writes the golden fixtures of a persisted format's
//! case or schema step that has none, under `fixtures/formats`; one written
//! is never rewritten, and the gate reads every one.
//!
//! `cargo xtask sdk` installs the SDKs `sdk/` pins, from their lockfiles,
//! and runs them against the engine: the release's matrix
//! runs it, and it needs Node, Python and Ruby, which the gate does not.

mod architecture;
mod structure;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use architecture::Architecture;
use structure::Workspace;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let root = root();
    let outcome = match arguments.as_slice() {
        ["check"] => check(&root),
        ["check", "structure"] => check_structure(&root),
        ["check", "generated"] => check_generated(&root),
        ["generate"] => generate(&root),
        ["fixtures"] => fixtures(&root),
        ["sdk"] => sdk(&root),
        ["fuzz"] => fuzz(&root, FUZZ_SECONDS),
        ["fuzz", seconds] => seconds
            .parse()
            .map_err(|_| format!("fuzz: {seconds} is not a number of seconds"))
            .and_then(|seconds| fuzz(&root, seconds)),
        _ => Err(
            "usage: cargo xtask check [structure|generated] | cargo xtask generate | cargo xtask fixtures | cargo xtask sdk | cargo xtask fuzz [seconds]"
                .to_owned(),
        ),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// The repository root: xtask lives one directory below it.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives inside the repository")
        .to_path_buf()
}

/// A cargo command at the repository root, run by the same cargo that runs
/// xtask. `CLIPPY_CONF_DIR` is removed so Clippy always reads the
/// repository's own configuration.
fn cargo(root: &Path) -> Command {
    let program = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(program);
    command.current_dir(root).env_remove("CLIPPY_CONF_DIR");
    command
}

fn check(root: &Path) -> Result<(), String> {
    check_structure(root)?;
    step("format", cargo(root).args(["fmt", "--all", "--check"]))?;
    step(
        "clippy",
        cargo(root).args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ]),
    )?;
    let deny_installed = cargo(root)
        .args(["deny", "--version"])
        .output()
        .is_ok_and(|output| output.status.success());
    if !deny_installed {
        return Err(
            "deny: cargo-deny is not installed; install it with `cargo install --locked cargo-deny`"
                .to_owned(),
        );
    }
    step("deny", cargo(root).args(["deny", "--locked", "check"]))?;
    step(
        "test",
        cargo(root).args(["test", "--workspace", "--all-features", "--locked"]),
    )?;
    work_counts(root);
    Ok(())
}

/// What changed in the engine's work since the last run, as the simulator's
/// work counts recorded it. Their budgets are checked by the
/// tests; this shows the changes within them.
fn work_counts(root: &Path) {
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let directory = target.join("tmp");
    if let Ok(changes) = std::fs::read_to_string(directory.join("work-counts.changes")) {
        println!("==> work counts");
        print!("{changes}");
        println!(
            "every count: {}",
            directory.join("work-counts.txt").display()
        );
    }
}

/// Installs each SDK as its lockfile pins it, then runs the scenario
/// through each against the engine.
fn sdk(root: &Path) -> Result<(), String> {
    let sdk = root.join("sdk");
    let javascript = sdk.join("javascript");
    step(
        "sdk: javascript",
        Command::new("npm")
            .args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])
            .current_dir(&javascript),
    )?;
    let python = sdk.join("python");
    if !python.join(".venv").exists() {
        step(
            "sdk: python's environment",
            Command::new("python3")
                .args(["-m", "venv", ".venv"])
                .current_dir(&python),
        )?;
    }
    step(
        "sdk: python",
        Command::new(python.join(".venv/bin/pip"))
            .args([
                "install",
                "--quiet",
                "--require-hashes",
                "--no-deps",
                "-r",
                "requirements.txt",
            ])
            .current_dir(&python),
    )?;
    step(
        "sdk: ruby",
        Command::new("bundle")
            .arg("install")
            .current_dir(sdk.join("ruby"))
            .env("BUNDLE_PATH", "vendor/bundle")
            .env("BUNDLE_FROZEN", "true"),
    )?;
    step(
        "sdk: the scenario",
        cargo(root).args([
            "test",
            "-p",
            "engine",
            "--test",
            "sdk",
            "--locked",
            "--",
            "--ignored",
        ]),
    )
}

/// How long `cargo xtask fuzz` runs each target, unless told otherwise.
const FUZZ_SECONDS: u64 = 60;

/// Runs each fuzz target under libFuzzer, through cargo-fuzz on the nightly
/// toolchain, for `seconds` from its corpus and the same seed each time.
/// What it finds goes to a copy of the corpus under `target/fuzz`, never to
/// the corpus kept; an input that fails is left in `target/fuzz/artifacts`,
/// to be added to its target's corpus once it is fixed.
/// Runs the store's tests with fixtures written where a version has none.
fn fixtures(root: &Path) -> Result<(), String> {
    step(
        "fixtures",
        cargo(root)
            .args(["test", "--locked", "-p", "engine-store", "--lib"])
            .env("NITROMTA_WRITE_FIXTURES", "1"),
    )
}

fn fuzz(root: &Path, seconds: u64) -> Result<(), String> {
    let kept = root.join("fuzz/corpus");
    let work = root.join("target/fuzz");
    let mut targets: Vec<String> = std::fs::read_dir(root.join("fuzz/fuzz_targets"))
        .map_err(|error| format!("fuzz/fuzz_targets: {error}"))?
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            name.strip_suffix(".rs").map(str::to_owned)
        })
        .collect();
    targets.sort();
    for target in targets {
        let corpus = work.join("corpus").join(&target);
        let artifacts = work.join("artifacts").join(&target);
        for directory in [&corpus, &artifacts] {
            std::fs::create_dir_all(directory)
                .map_err(|error| format!("{}: {error}", directory.display()))?;
        }
        for input in std::fs::read_dir(kept.join(&target))
            .map_err(|error| format!("{target}'s corpus: {error}"))?
            .flatten()
        {
            std::fs::copy(input.path(), corpus.join(input.file_name()))
                .map_err(|error| format!("{}: {error}", input.path().display()))?;
        }
        step(
            &format!("fuzz: {target}, {seconds} seconds"),
            Command::new("cargo")
                .args(["+nightly", "fuzz", "run", "--fuzz-dir", "fuzz"])
                // Safe Rust: what it looks for is a panic, an overflow or a
                // hang, which need no sanitizer.
                .args(["--sanitizer", "none", "--debug-assertions", &target])
                .arg(&corpus)
                .arg("--")
                .arg(format!("-max_total_time={seconds}"))
                .args(["-seed=1", "-timeout=10", "-rss_limit_mb=2048"])
                .arg(format!("-artifact_prefix={}/", artifacts.display()))
                .current_dir(root),
        )?;
    }
    Ok(())
}

fn check_structure(root: &Path) -> Result<(), String> {
    println!("==> structure");
    let architecture = Architecture::load(root)?;
    let workspace = Workspace::gather(root, &architecture)?;
    let violations = structure::violations(&architecture, &workspace);
    if violations.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = violations
        .iter()
        .map(|violation| format!("  - {violation}"))
        .collect();
    Err(format!(
        "structure: the repository disagrees with architecture.toml:\n{}",
        list.join("\n")
    ))
}

fn step(name: &str, command: &mut Command) -> Result<(), String> {
    println!("==> {name}");
    let status = command
        .status()
        .map_err(|error| format!("{name}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{name} failed"))
    }
}

/// Runs each generated crate's recipe into `target/generated/<crate>`, and
/// returns each crate's committed directory with its fresh one.
fn regenerate(root: &Path) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let architecture = Architecture::load(root)?;
    let mut generated = Vec::new();
    for (name, recipe) in architecture.generated() {
        let committed = root.join(
            architecture
                .path_of(name)
                .ok_or_else(|| format!("{name}: no path"))?,
        );
        let fresh = root.join("target/generated").join(name);
        if fresh.exists() {
            std::fs::remove_dir_all(&fresh)
                .map_err(|error| format!("{}: {error}", fresh.display()))?;
        }
        std::fs::create_dir_all(&fresh).map_err(|error| format!("{}: {error}", fresh.display()))?;
        let image = format!("{name}-generator");
        let mut build = Command::new("docker");
        build
            .current_dir(root)
            .args(["build", "--quiet", "--tag", &image, "--file", recipe, "."]);
        step(&format!("build the generator for {name}"), &mut build)?;
        let mut run = Command::new("docker");
        run.args([
            "run",
            "--rm",
            "--volume",
            &format!("{}:/out", fresh.display()),
            &image,
        ]);
        step(&format!("generate {name}"), &mut run)?;
        generated.push((committed, fresh));
    }
    Ok(generated)
}

fn generate(root: &Path) -> Result<(), String> {
    for (committed, fresh) in regenerate(root)? {
        if committed.exists() {
            std::fs::remove_dir_all(&committed)
                .map_err(|error| format!("{}: {error}", committed.display()))?;
        }
        copy_tree(&fresh, &committed)?;
        println!("wrote {}", committed.display());
    }
    Ok(())
}

fn check_generated(root: &Path) -> Result<(), String> {
    let mut differences = Vec::new();
    for (committed, fresh) in regenerate(root)? {
        let (before, after) = (files(&committed)?, files(&fresh)?);
        for (path, contents) in &after {
            match before.get(path) {
                None => {
                    differences.push(format!("  - {}: missing", committed.join(path).display()))
                }
                Some(old) if old != contents => {
                    differences.push(format!("  - {}: differs", committed.join(path).display()));
                }
                Some(_) => {}
            }
        }
        for path in before.keys().filter(|path| !after.contains_key(*path)) {
            differences.push(format!(
                "  - {}: not generated",
                committed.join(path).display()
            ));
        }
    }
    if differences.is_empty() {
        return Ok(());
    }
    Err(format!(
        "generated: committed code differs from what its recipe generates; run `cargo xtask generate`:\n{}",
        differences.join("\n")
    ))
}

/// Every file under `dir`, by its path within it.
fn files(dir: &Path) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>, String> {
    let mut found = std::collections::BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let contents =
                    std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
                let relative = path
                    .strip_prefix(dir)
                    .map_err(|error| error.to_string())?
                    .to_path_buf();
                found.insert(relative, contents);
            }
        }
    }
    Ok(found)
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    for (path, contents) in files(from)? {
        let target = to.join(&path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        std::fs::write(&target, contents)
            .map_err(|error| format!("{}: {error}", target.display()))?;
    }
    Ok(())
}
