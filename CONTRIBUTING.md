# Contributing

Thank you for helping. Issues and pull requests are welcome on GitHub.

## Before you open a pull request

Run the Rust gate and SDK matrix, which CI and releases require:

```sh
cargo xtask check
cargo xtask sdk
```

[The gate](#the-gate), below, says what it checks and what it needs. A
change to the repository's structure, a crate's ownership or its
dependencies edits [`architecture.toml`](architecture.toml) in the same
commit, or the gate fails.

The store's formats only grow, so an upgrade keeps an operator's store. A
record's field keeps its number and meaning for good, and a new field is
optional, so a row an earlier release wrote reads as it did; a new table,
column or index is a schema step after the last. Anything else, such as a
field whose meaning changes, is a one-time rewrite of the store in the
release that needs it, never a reader for the old format. `cargo xtask
fixtures` writes the golden fixtures for a new case or step, and the gate
reads every fixture an earlier release kept
([`fixtures/formats`](fixtures/formats/README.md)).

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
`fix(scheduler): ...`, `feat(api): ...`.

## The gate

`cargo xtask check` runs the Rust gate. Contributors and CI run the same
command, and it stops at the first failure:

1. **structure:** the repository matches `architecture.toml`, which declares
   every crate, what each owns and must not own, and its dependencies;
2. **format:** `cargo fmt`;
3. **clippy:** with warnings as errors, and the determinism rules for the
   deterministic crates;
4. **deny:** the licenses, sources and advisories allowed in `deny.toml`;
5. **test:** every test in the workspace, among them the deterministic
   simulator's power-loss runs, the persisted formats' golden fixtures and
   every fuzz target's corpus;
6. **work counts:** the simulator's exact counts of every write the engine
   makes, checked against the store's budget and set beside the last run's.

It needs rustup, which installs the toolchain `rust-toolchain.toml` names,
cargo-deny (`cargo install --locked cargo-deny`), and libclang, with which the
simulator's tests build SQLite's preupdate hook (Xcode's command line tools
on macOS, `libclang-dev` on Debian).

`cargo xtask sdk` separately runs the pinned [SDK matrix](sdk/README.md).
CI requires both commands, including at the exact tag before a release builds.

The engine's core is deterministic: its state machines receive time,
randomness and I/O results from their driver, so the same code runs under
the production shell and under the simulator, and any simulated run replays
exactly from its seed.

Generated code is checked by regenerating it: `cargo xtask check generated`
runs each generated crate's recipe in a container and fails if the committed
crate differs, and `cargo xtask generate` rewrites it.
[`models/README.md`](models/README.md) says what is generated from what.

Every parser has a fuzz target in [`fuzz`](fuzz), and `cargo xtask fuzz`
runs each under libFuzzer, with the nightly toolchain and cargo-fuzz. The
store's formats only grow, and every row and schema an earlier release kept
in [`fixtures/formats`](fixtures/formats) is read by the gate;
`cargo xtask fixtures` writes those for a new case or step.

## Sign your work

Every commit carries a Developer Certificate of Origin sign-off, which says
you wrote the change, or have the right to submit it, under the project's
license ([DCO 1.1](https://developercertificate.org/)):

```text
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it. Contributions are licensed under Apache-2.0, as the
project is.

## Maintainers

auscaster is the maintainer and release authority. Security reports go to
security@nitrosend.com, as [SECURITY.md](SECURITY.md) says.
