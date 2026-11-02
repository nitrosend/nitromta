//! `architecture.toml`: the single home for what the repository contains,
//! what each crate owns, and what each crate may depend on.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Architecture {
    /// Every entry allowed at the repository root, with its purpose.
    pub root: BTreeMap<String, String>,
    pub groups: BTreeMap<String, Group>,
    pub kinds: BTreeMap<String, Kind>,
    pub crates: BTreeMap<String, Crate>,
}

/// Third-party crates that kinds forbid. A trailing `*` matches a prefix.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub summary: String,
    pub crates: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kind {
    pub summary: String,
    /// The directory the kind's crates live in; `.` is the repository root.
    pub under: String,
    #[serde(default)]
    pub may_depend_on: Vec<String>,
    /// Groups that may never appear in a crate's normal dependency closure.
    #[serde(default)]
    pub forbidden: Vec<String>,
    /// The Clippy configuration that must govern the kind's crates.
    pub clippy: Option<String>,
    /// Generated crates are checked by regenerating them, not by the
    /// manifest, dependency and source rules.
    #[serde(default)]
    pub generated: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crate {
    pub kind: String,
    pub owns: String,
    pub must_not_own: String,
    #[serde(default)]
    pub internal: Vec<String>,
    /// Required once the crate exists, unless it is generated.
    pub external: Option<Vec<String>>,
    /// Files allowed to switch off controlled lints, keyed by their path
    /// within the crate.
    #[serde(default)]
    pub exceptions: BTreeMap<String, Exception>,
    /// A generated crate's container recipe, relative to the repository
    /// root: `cargo xtask generate` builds and runs it to write the crate.
    pub recipe: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub allow: Vec<String>,
    pub reason: String,
}

impl Architecture {
    pub fn load(root: &Path) -> Result<Self, String> {
        let path = root.join("architecture.toml");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|error| format!("architecture.toml: {error}"))
    }

    /// Where a declared crate lives, relative to the repository root.
    pub fn path_of(&self, name: &str) -> Option<String> {
        let kind = self.kinds.get(&self.crates.get(name)?.kind)?;
        Some(if kind.under == "." {
            name.to_owned()
        } else {
            format!("{}/{name}", kind.under)
        })
    }
}

impl Architecture {
    /// The generated crates, with their recipes.
    pub fn generated(&self) -> impl Iterator<Item = (&str, &str)> {
        self.crates
            .iter()
            .filter_map(|(name, declared)| Some((name.as_str(), declared.recipe.as_deref()?)))
    }
}
