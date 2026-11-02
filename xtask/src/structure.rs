//! The structure check: the repository must match `architecture.toml`.
//!
//! Facts about the repository are gathered once into a [`Workspace`], so the
//! rules in [`violations`] are pure and are tested without a repository.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::architecture::Architecture;

/// Lints that only a declared exception may switch off: `unsafe_code`, the
/// determinism lints, and the groups and switches that would include them.
pub const CONTROLLED_LINTS: [&str; 7] = [
    "unsafe_code",
    "clippy::disallowed_methods",
    "clippy::disallowed_types",
    "clippy::disallowed_macros",
    "clippy::style",
    "clippy::all",
    "warnings",
];

/// What the structure check knows about the repository.
#[derive(Default)]
pub struct Workspace {
    /// Entries at the repository root, tracked or untracked but not ignored.
    pub root_entries: BTreeSet<String>,
    /// Paths of declared crates that contain a manifest.
    pub crate_dirs: BTreeSet<String>,
    pub members: Vec<Member>,
}

/// One workspace member.
#[derive(Default)]
pub struct Member {
    pub name: String,
    /// The crate's directory, relative to the repository root.
    pub path: String,
    pub manifest: toml::Table,
    /// Workspace crates it depends on, through any kind of dependency.
    pub internal: BTreeSet<String>,
    /// Third-party crates it depends on directly, through any kind of dependency.
    pub external: BTreeSet<String>,
    /// Every package reachable through normal dependencies.
    pub closure: BTreeSet<String>,
    /// The Clippy configuration Clippy reads for this crate.
    pub clippy: Option<String>,
    /// Each Rust source file, by its path within the crate, with the
    /// controlled lints its attributes name.
    pub sources: BTreeMap<String, BTreeSet<String>>,
}

impl Workspace {
    pub fn gather(root: &Path, architecture: &Architecture) -> Result<Self, String> {
        let root = root
            .canonicalize()
            .map_err(|error| format!("{}: {error}", root.display()))?;
        let output = run(crate::cargo(&root).args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
        ]))?;
        let metadata: Metadata =
            serde_json::from_slice(&output).map_err(|error| format!("cargo metadata: {error}"))?;

        let names: BTreeMap<&str, &str> = metadata
            .packages
            .iter()
            .map(|package| (package.id.as_str(), package.name.as_str()))
            .collect();
        let edges = metadata.resolve.normal_edges();
        let members: Vec<&Package> = metadata
            .packages
            .iter()
            .filter(|package| metadata.workspace_members.contains(&package.id))
            .collect();

        let mut gathered = Vec::new();
        for package in members {
            let dir = package
                .manifest_path
                .parent()
                .and_then(|dir| dir.canonicalize().ok())
                .ok_or_else(|| format!("{}: no crate directory", package.name))?;
            let manifest = read(&package.manifest_path)?
                .parse::<toml::Table>()
                .map_err(|error| format!("{}: {error}", package.manifest_path.display()))?;
            let (internal, external) = package
                .dependencies
                .iter()
                .map(|dependency| dependency.name.clone())
                .partition(|name| architecture.crates.contains_key(name));
            gathered.push(Member {
                name: package.name.clone(),
                path: relative(&root, &dir)?,
                manifest,
                internal,
                external,
                closure: closure(&edges, &package.id, &names),
                clippy: governing_clippy(&root, &dir),
                sources: sources(&dir)?,
            });
        }

        let crate_dirs = architecture
            .crates
            .keys()
            .filter_map(|name| architecture.path_of(name))
            .filter(|path| root.join(path).join("Cargo.toml").is_file())
            .collect();
        Ok(Self {
            root_entries: root_entries(&root)?,
            crate_dirs,
            members: gathered,
        })
    }
}

/// Every way the repository disagrees with the architecture file.
pub fn violations(architecture: &Architecture, workspace: &Workspace) -> Vec<String> {
    let mut found = Vec::new();
    declarations(architecture, &mut found);
    for entry in &workspace.root_entries {
        if !architecture.root.contains_key(entry) {
            found.push(format!(
                "`{entry}` at the repository root is not declared in [root]"
            ));
        }
    }
    let members: BTreeSet<&str> = workspace
        .members
        .iter()
        .map(|member| member.name.as_str())
        .collect();
    for (name, declared) in &architecture.crates {
        let Some(path) = architecture.path_of(name) else {
            continue;
        };
        if !workspace.crate_dirs.contains(&path) {
            continue;
        }
        // Cargo lints every workspace member it builds, even as another
        // crate's dependency, so generated code stays out of the workspace:
        // it is checked by regeneration, never by the gate's lints.
        let generated = architecture
            .kinds
            .get(&declared.kind)
            .is_some_and(|kind| kind.generated);
        match (generated, members.contains(name.as_str())) {
            (false, false) => found.push(format!(
                "{name}: `{path}` exists but is not a workspace member"
            )),
            (true, true) => found.push(format!(
                "{name}: a generated crate stays out of the workspace; add `{path}` to its `exclude`"
            )),
            _ => {}
        }
    }
    for member in &workspace.members {
        member_rules(architecture, member, &mut found);
    }
    found
}

/// The architecture file must be complete and consistent with itself.
fn declarations(architecture: &Architecture, found: &mut Vec<String>) {
    for (entry, purpose) in &architecture.root {
        if purpose.trim().is_empty() {
            found.push(format!("[root] `{entry}` needs its purpose"));
        }
    }
    for (name, group) in &architecture.groups {
        if group.summary.trim().is_empty() || group.crates.is_empty() {
            found.push(format!("[groups.{name}] needs a summary and its crates"));
        }
        if !architecture
            .kinds
            .values()
            .any(|kind| kind.forbidden.contains(name))
        {
            found.push(format!("[groups.{name}] is not used by any kind"));
        }
    }
    for (name, kind) in &architecture.kinds {
        if kind.summary.trim().is_empty() {
            found.push(format!("[kinds.{name}] needs a summary"));
        }
        if kind.under != "." && !architecture.root.contains_key(&kind.under) {
            found.push(format!(
                "[kinds.{name}] lives under `{}`, which [root] does not declare",
                kind.under
            ));
        }
        for other in &kind.may_depend_on {
            if !architecture.kinds.contains_key(other) {
                found.push(format!(
                    "[kinds.{name}] may depend on `{other}`, which is not a kind"
                ));
            }
        }
        for group in &kind.forbidden {
            if !architecture.groups.contains_key(group) {
                found.push(format!(
                    "[kinds.{name}] forbids `{group}`, which is not a group"
                ));
            }
        }
    }
    for (name, declared) in &architecture.crates {
        let Some(kind) = architecture.kinds.get(&declared.kind) else {
            found.push(format!("{name}: kind `{}` is not declared", declared.kind));
            continue;
        };
        match (kind.generated, &declared.recipe) {
            (true, None) => found.push(format!("{name}: a generated crate needs its `recipe`")),
            (false, Some(_)) => {
                found.push(format!("{name}: only a generated crate has a `recipe`"))
            }
            _ => {}
        }
        if declared.owns.trim().is_empty() || declared.must_not_own.trim().is_empty() {
            found.push(format!("{name}: needs `owns` and `must_not_own`"));
        }
        for dependency in &declared.internal {
            match architecture.crates.get(dependency) {
                None => found.push(format!(
                    "{name}: depends on `{dependency}`, which is not a declared crate"
                )),
                Some(_) if dependency == name => {
                    found.push(format!("{name}: depends on itself"));
                }
                Some(other) if !kind.may_depend_on.contains(&other.kind) => {
                    found.push(format!(
                        "{name}: a {} crate may not depend on `{dependency}`, a {} crate",
                        declared.kind, other.kind
                    ));
                }
                Some(_) => {}
            }
        }
        for (file, exception) in &declared.exceptions {
            if exception.reason.trim().is_empty() || exception.allow.is_empty() {
                found.push(format!(
                    "{name}: the exception for `{file}` needs what it allows and why"
                ));
            }
            for lint in &exception.allow {
                if !CONTROLLED_LINTS.contains(&lint.as_str()) {
                    found.push(format!(
                        "{name}: the exception for `{file}` allows `{lint}`, which is not a controlled lint"
                    ));
                }
            }
        }
    }
}

/// An existing crate must match its declaration exactly.
fn member_rules(architecture: &Architecture, member: &Member, found: &mut Vec<String>) {
    let name = &member.name;
    let Some(declared) = architecture.crates.get(name) else {
        found.push(format!(
            "{name}: `{}` is not declared in architecture.toml",
            member.path
        ));
        return;
    };
    // An undeclared kind is reported with the declarations.
    let Some(kind) = architecture.kinds.get(&declared.kind) else {
        return;
    };
    let expected = architecture.path_of(name).unwrap_or_default();
    if member.path != expected {
        found.push(format!(
            "{name}: lives at `{}`, but a {} crate lives at `{expected}`",
            member.path, declared.kind
        ));
    }
    compare(name, &declared.internal, &member.internal, found);
    if kind.generated {
        return;
    }

    manifest_rules(name, &member.manifest, found);
    match &declared.external {
        Some(external) => compare(name, external, &member.external, found),
        None => found.push(format!(
            "{name}: exists, so architecture.toml must list its `external` dependencies"
        )),
    }
    for package in &member.closure {
        for group in &kind.forbidden {
            let forbidden = architecture
                .groups
                .get(group)
                .is_some_and(|group| group.crates.iter().any(|pattern| matches(pattern, package)));
            if forbidden {
                found.push(format!(
                    "{name}: its dependencies include `{package}` ({group}), which a {} crate may never use",
                    declared.kind
                ));
            }
        }
    }
    if let Some(clippy) = &kind.clippy
        && member.clippy.as_ref() != Some(clippy)
    {
        found.push(format!(
            "{name}: must be governed by `{clippy}`, but Clippy reads {}",
            member
                .clippy
                .as_deref()
                .map_or("its defaults".to_owned(), |path| format!("`{path}`"))
        ));
    }
    for (file, lints) in &member.sources {
        let allowed = declared
            .exceptions
            .get(file)
            .map(|exception| &exception.allow);
        for lint in lints {
            if !allowed.is_some_and(|allowed| allowed.contains(lint)) {
                found.push(format!(
                    "{name}: `{file}` switches off `{lint}` without an exception in architecture.toml"
                ));
            }
        }
    }
    for (file, exception) in &declared.exceptions {
        let used = member.sources.get(file);
        for lint in &exception.allow {
            if !used.is_some_and(|lints| lints.contains(lint)) {
                found.push(format!(
                    "{name}: the exception for `{file}` allows `{lint}`, which the file no longer uses"
                ));
            }
        }
    }
}

/// The manifest inherits the workspace's package fields, lints and
/// dependency versions.
fn manifest_rules(name: &str, manifest: &toml::Table, found: &mut Vec<String>) {
    let package = manifest.get("package").and_then(toml::Value::as_table);
    for field in ["version", "edition", "license", "publish"] {
        if !package
            .and_then(|package| package.get(field))
            .is_some_and(inherits_workspace)
        {
            found.push(format!(
                "{name}: must take `{field}` from the workspace (`{field}.workspace = true`)"
            ));
        }
    }
    if !manifest.get("lints").is_some_and(inherits_workspace) {
        found.push(format!(
            "{name}: must take its lints from the workspace (`[lints] workspace = true`)"
        ));
    }
    let targets = manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|targets| targets.values())
        .filter_map(toml::Value::as_table);
    for table in std::iter::once(manifest).chain(targets) {
        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let entries = table.get(section).and_then(toml::Value::as_table);
            for (dependency, entry) in entries.into_iter().flatten() {
                let from_workspace = entry.as_table().is_some_and(|entry| {
                    entry.get("workspace").and_then(toml::Value::as_bool) == Some(true)
                        && entry.keys().all(|key| {
                            ["workspace", "features", "optional"].contains(&key.as_str())
                        })
                });
                if !from_workspace {
                    found.push(format!(
                        "{name}: `{dependency}` must use the workspace's version (`{dependency}.workspace = true`)"
                    ));
                }
            }
        }
    }
}

fn inherits_workspace(value: &toml::Value) -> bool {
    value.as_table().is_some_and(|table| {
        table.len() == 1 && table.get("workspace").and_then(toml::Value::as_bool) == Some(true)
    })
}

fn compare(name: &str, declared: &[String], actual: &BTreeSet<String>, found: &mut Vec<String>) {
    for dependency in actual
        .iter()
        .filter(|dependency| !declared.contains(dependency))
    {
        found.push(format!(
            "{name}: depends on `{dependency}`, which architecture.toml does not list"
        ));
    }
    for dependency in declared
        .iter()
        .filter(|dependency| !actual.contains(*dependency))
    {
        found.push(format!(
            "{name}: architecture.toml lists `{dependency}`, which it does not depend on"
        ));
    }
}

fn matches(pattern: &str, package: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => package.starts_with(prefix),
        None => package == pattern,
    }
}

/// The controlled lints named by `allow`, `expect` or `cfg_attr` attributes.
/// Attributes are read where rustfmt puts them, at the start of a line, so
/// text inside string literals is not mistaken for one.
pub fn controlled_lints(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
        let rest = &source[offset + indent..];
        offset += line.len();
        let Some(body) = rest.strip_prefix("#![").or_else(|| rest.strip_prefix("#[")) else {
            continue;
        };
        let Some(end) = closing_bracket(body) else {
            continue;
        };
        let attribute = &body[..end];
        let name = attribute.trim_start();
        if !["allow", "expect", "cfg_attr"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        found.extend(
            attribute
                .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                .filter(|token| CONTROLLED_LINTS.contains(token))
                .map(str::to_owned),
        );
    }
    found
}

fn closing_bracket(text: &str) -> Option<usize> {
    let mut depth = 0_usize;
    for (index, character) in text.char_indices() {
        match character {
            '[' => depth += 1,
            ']' if depth == 0 => return Some(index),
            ']' => depth -= 1,
            _ => {}
        }
    }
    None
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
    resolve: Resolve,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    manifest_path: PathBuf,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    name: String,
}

#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    id: String,
    deps: Vec<NodeDependency>,
}

#[derive(Deserialize)]
struct NodeDependency {
    pkg: String,
    dep_kinds: Vec<DependencyKind>,
}

#[derive(Deserialize)]
struct DependencyKind {
    /// `None` for a normal dependency, otherwise `dev` or `build`.
    kind: Option<String>,
}

impl Resolve {
    /// Each package's normal (not dev or build) dependencies.
    fn normal_edges(&self) -> BTreeMap<&str, Vec<&str>> {
        self.nodes
            .iter()
            .map(|node| {
                let normal = node
                    .deps
                    .iter()
                    .filter(|dependency| {
                        dependency.dep_kinds.iter().any(|kind| kind.kind.is_none())
                    })
                    .map(|dependency| dependency.pkg.as_str())
                    .collect();
                (node.id.as_str(), normal)
            })
            .collect()
    }
}

/// The names of every package reachable from `start` through normal
/// dependencies.
fn closure(
    edges: &BTreeMap<&str, Vec<&str>>,
    start: &str,
    names: &BTreeMap<&str, &str>,
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![start];
    while let Some(id) = pending.pop() {
        for &next in edges.get(id).into_iter().flatten() {
            if seen.insert(next) {
                pending.push(next);
            }
        }
    }
    seen.into_iter()
        .filter_map(|id| names.get(id))
        .map(|name| (*name).to_owned())
        .collect()
}

/// Entries at the root that git tracks or would track.
fn root_entries(root: &Path) -> Result<BTreeSet<String>, String> {
    let output = run(Command::new("git").current_dir(root).args([
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ]))?;
    let listing = String::from_utf8(output).map_err(|_| "git ls-files: a path is not UTF-8")?;
    Ok(listing
        .split('\0')
        .filter_map(|path| path.split('/').next())
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect())
}

/// The nearest Clippy configuration at or above the crate, within the
/// repository, as Clippy itself finds it.
fn governing_clippy(root: &Path, dir: &Path) -> Option<String> {
    dir.ancestors()
        .take_while(|ancestor| ancestor.starts_with(root))
        .flat_map(|ancestor| ["clippy.toml", ".clippy.toml"].map(|file| ancestor.join(file)))
        .find(|candidate| candidate.is_file())
        .and_then(|config| relative(root, &config).ok())
}

fn sources(dir: &Path) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut found = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = std::fs::read_dir(&current)
            .map_err(|error| format!("{}: {error}", current.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("{}: {error}", current.display()))?
                .path();
            if path.is_dir() {
                if path.file_name() != Some(OsStr::new("target")) {
                    pending.push(path);
                }
            } else if path.extension() == Some(OsStr::new("rs")) {
                found.insert(relative(dir, &path)?, controlled_lints(&read(&path)?));
            }
        }
    }
    Ok(found)
}

fn relative(base: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(base)
        .ok()
        .and_then(Path::to_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is outside {}", path.display(), base.display()))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn run(command: &mut Command) -> Result<Vec<u8>, String> {
    let output = command
        .output()
        .map_err(|error| format!("{command:?}: {error}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "{command:?} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCHITECTURE: &str = r#"
        [root]
        "Cargo.toml" = "the workspace"
        crates = "the crates"

        [groups.io]
        summary = "I/O"
        crates = ["tokio", "hyper*"]

        [kinds.pure]
        summary = "deterministic"
        under = "crates"
        may_depend_on = ["pure"]
        clippy = "crates/clippy.toml"
        forbidden = ["io"]

        [kinds.shell]
        summary = "the shell"
        under = "crates"
        may_depend_on = ["pure"]

        [crates.core]
        kind = "pure"
        owns = "records"
        must_not_own = "sockets"
        external = ["bytes"]

        [crates.core.exceptions."src/vfs.rs"]
        allow = ["unsafe_code"]
        reason = "a C interface"

        [crates.app]
        kind = "shell"
        owns = "I/O"
        must_not_own = "decisions"
        internal = ["core"]
        external = []

        [crates.later]
        kind = "pure"
        owns = "planned work"
        must_not_own = "anything else"
    "#;

    #[test]
    fn generated_crates_have_recipes_and_others_do_not() {
        let text = ARCHITECTURE.to_owned()
            + r#"
            [kinds.generated]
            summary = "generated"
            under = "crates"
            generated = true

            [crates.api]
            kind = "generated"
            owns = "generated code"
            must_not_own = "anything written by hand"
        "#;
        let mut architecture = Architecture::parse(&text).expect("parses");
        let found = |architecture: &Architecture| {
            let mut found = Vec::new();
            declarations(architecture, &mut found);
            found
        };
        assert_eq!(
            found(&architecture),
            ["api: a generated crate needs its `recipe`"]
        );
        architecture.crates.get_mut("api").expect("declared").recipe = Some("recipe".to_owned());
        assert!(found(&architecture).is_empty());
        architecture
            .crates
            .get_mut("core")
            .expect("declared")
            .recipe = Some("recipe".to_owned());
        assert_eq!(
            found(&architecture),
            ["core: only a generated crate has a `recipe`"]
        );
    }

    #[test]
    fn a_generated_crate_stays_out_of_the_workspace() {
        let text = ARCHITECTURE.to_owned()
            + r#"
            [kinds.generated]
            summary = "generated"
            under = "crates"
            generated = true

            [crates.api]
            kind = "generated"
            owns = "generated code"
            must_not_own = "anything written by hand"
            recipe = "recipe"
        "#;
        let architecture = Architecture::parse(&text).expect("parses");
        let (_, mut workspace) = matching();
        workspace.crate_dirs.insert("crates/api".into());
        assert_eq!(violations(&architecture, &workspace), Vec::<String>::new());
        workspace.members.push(Member {
            name: "api".into(),
            path: "crates/api".into(),
            ..Member::default()
        });
        assert_eq!(
            violations(&architecture, &workspace),
            [
                "api: a generated crate stays out of the workspace; add `crates/api` to its `exclude`"
            ]
        );
    }

    fn set<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
        items.map(str::to_owned).into()
    }

    fn manifest(dependencies: &str) -> toml::Table {
        format!(
            "[package]\nname = \"x\"\nversion.workspace = true\nedition.workspace = true\nlicense.workspace = true\npublish.workspace = true\n\n[lints]\nworkspace = true\n\n[dependencies]\n{dependencies}\n"
        )
        .parse()
        .expect("the test manifest parses")
    }

    fn matching() -> (Architecture, Workspace) {
        let architecture = Architecture::parse(ARCHITECTURE).expect("the test architecture parses");
        let core = Member {
            name: "core".into(),
            path: "crates/core".into(),
            manifest: manifest("bytes.workspace = true"),
            external: set(["bytes"]),
            closure: set(["bytes"]),
            clippy: Some("crates/clippy.toml".into()),
            sources: [
                ("src/lib.rs".to_owned(), set([])),
                ("src/vfs.rs".to_owned(), set(["unsafe_code"])),
            ]
            .into(),
            ..Member::default()
        };
        let app = Member {
            name: "app".into(),
            path: "crates/app".into(),
            manifest: manifest("core.workspace = true"),
            internal: set(["core"]),
            closure: set(["core", "bytes", "tokio"]),
            sources: [("src/main.rs".to_owned(), set([]))].into(),
            ..Member::default()
        };
        let workspace = Workspace {
            root_entries: set(["Cargo.toml", "crates"]),
            crate_dirs: set(["crates/core", "crates/app"]),
            members: vec![core, app],
        };
        (architecture, workspace)
    }

    fn member<'a>(workspace: &'a mut Workspace, name: &str) -> &'a mut Member {
        workspace
            .members
            .iter_mut()
            .find(|member| member.name == name)
            .expect("the test member exists")
    }

    #[test]
    fn a_matching_repository_passes() {
        let (architecture, workspace) = matching();
        assert_eq!(violations(&architecture, &workspace), Vec::<String>::new());
    }

    #[test]
    fn each_rule_reports_its_violation() {
        let (mut architecture, mut workspace) = matching();
        let mut expected = Vec::new();

        workspace.root_entries.insert("scripts".into());
        expected.push("`scripts` at the repository root is not declared");

        workspace.crate_dirs.insert("crates/later".into());
        expected.push("later: `crates/later` exists but is not a workspace member");

        workspace.members.push(Member {
            name: "stray".into(),
            path: "crates/stray".into(),
            ..Member::default()
        });
        expected.push("stray: `crates/stray` is not declared");

        let core = member(&mut workspace, "core");
        core.external.insert("serde".into());
        expected.push("core: depends on `serde`, which architecture.toml does not list");
        core.closure.insert("hyper-util".into());
        expected.push("core: its dependencies include `hyper-util` (io)");
        core.clippy = None;
        expected.push("core: must be governed by `crates/clippy.toml`");
        core.sources
            .insert("src/lib.rs".into(), set(["clippy::disallowed_types"]));
        expected.push("core: `src/lib.rs` switches off `clippy::disallowed_types`");
        core.sources.insert("src/vfs.rs".into(), set([]));
        expected.push("which the file no longer uses");

        let app = member(&mut workspace, "app");
        app.manifest =
            "[package]\nedition = \"2024\"\n[dependencies]\ncore = { path = \"../core\" }\n"
                .parse()
                .expect("the test manifest parses");
        expected.push("app: must take `version` from the workspace");
        expected.push("app: must take `edition` from the workspace");
        expected.push("app: must take its lints from the workspace");
        expected.push("app: `core` must use the workspace's version");

        let declared = architecture.crates.get_mut("app").expect("app is declared");
        declared.external = None;
        expected.push("app: exists, so architecture.toml must list its `external` dependencies");

        let declared = architecture
            .crates
            .get_mut("core")
            .expect("core is declared");
        declared.internal.push("app".into());
        expected.push("core: a pure crate may not depend on `app`, a shell crate");

        let found = violations(&architecture, &workspace);
        for fragment in expected {
            assert!(
                found.iter().any(|violation| violation.contains(fragment)),
                "expected a violation containing {fragment:?}, found:\n{}",
                found.join("\n")
            );
        }
    }

    #[test]
    fn controlled_lints_are_read_from_attributes_only() {
        let source = concat!(
            "#![allow(unsafe_code)]\n",
            "    #[expect(\n",
            "        clippy::disallowed_types,\n",
            "        reason = \"a test\"\n",
            "    )]\n",
            "#[cfg_attr(test, allow(clippy::style))]\n",
            "#[allow(dead_code)]\n",
            "let text = \"#[allow(warnings)]\";\n",
        );
        assert_eq!(
            controlled_lints(source),
            set(["unsafe_code", "clippy::disallowed_types", "clippy::style"])
        );
    }
}
