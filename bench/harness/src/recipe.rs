//! The recipe, which says what the harness builds and runs, and the profiles,
//! which say how hard and for how long it measures: `recipe.toml` and
//! `profiles/*.toml` beside this crate's manifest.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::api::Ingress;

/// The images every run needs besides the systems under test.
pub const TOOLS: [&str; 3] = ["harness", "unbound", "ceilings"];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub base: Base,
    pub sources: BTreeMap<String, Source>,
    pub images: BTreeMap<String, Image>,
    pub systems: BTreeMap<String, System>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    /// The image every build stage starts from.
    pub build: String,
    /// The image every runtime stage starts from.
    pub runtime: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub url: String,
    pub tag: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    #[serde(default)]
    pub sources: Vec<String>,
    /// Built from the whole repository rather than its own directory.
    #[serde(default)]
    pub repository: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct System {
    pub summary: String,
    pub image: String,
    pub durability: Durability,
    /// How messages reach it: SMTP submission unless an API is named.
    #[serde(default)]
    pub ingress: Ingress,
    /// The port its ingress listens on.
    pub port: u16,
    /// Where the system keeps its queue: the measured volume is mounted here.
    pub spool: String,
    /// A log file to keep with the result, for diagnosis.
    pub log: Option<String>,
    /// A file in its container where a system that issues its own secrets
    /// writes them, as `{"smtp": {"user", "password"}, "ses": {"user",
    /// "password"}, "hooks"}`, the last its event subscription's secret. A
    /// system without one takes the harness's password.
    pub credentials: Option<String>,
    /// Whether it runs production-shaped unless that is ablated:
    /// its mail from a pool of two egresses, under a configuration
    /// with a tenant and a subscription the harness's event receiver
    /// takes, against a million suppressions.
    #[serde(default)]
    pub production: bool,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// When a system acknowledges a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Durability {
    /// After a durable write.
    Sync,
    /// Before one: a separately labelled run.
    Async,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub summary: String,
    pub systems: Vec<String>,
    pub repetitions: usize,
    pub placement: Placement,
    pub workload: Workload,
    #[serde(default)]
    pub delivery: Delivery,
    /// What every system runs without, as a labelled ablation that shows
    /// what that part costs.
    #[serde(default)]
    pub without: Vec<Ablation>,
    /// One more receiver that throttles, for the throttled-destination
    /// profile.
    pub throttle: Option<Throttle>,
    /// A deferred backlog to build and measure, in place of the search.
    pub backlog: Option<Backlog>,
    /// A fixed offered load, after any backlog and in place of the search.
    pub fixed: Option<Fixed>,
    /// A crash test on LazyFS, in place of the search.
    pub crash: Option<Crash>,
    /// Whether the session measures the component ceilings,
    /// which a regression check of one system against itself leaves out,
    /// with the build they need.
    #[serde(default = "measured")]
    pub ceilings: bool,
    pub search: Search,
    pub budgets: Budgets,
}

fn measured() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub sut_cpus: usize,
    pub sut_memory_mib: u64,
    /// The fewest CPUs the tools may share.
    pub tool_cpus: usize,
    pub tool_memory_mib: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub message_bytes: usize,
    pub connections: usize,
    /// How many domains the sink's recipients are spread across, every one
    /// served by the sink.
    #[serde(default = "Workload::one")]
    pub domains: usize,
    /// Recipients per message, which share its body.
    #[serde(default = "Workload::one")]
    pub recipients: u16,
    /// Receiver sites the domains are spread over, each with an exchange of
    /// its own, all served by the sink.
    #[serde(default = "Workload::one")]
    pub sites: usize,
    /// How long the sink takes over each exchange, as a receiver at a
    /// distance does: one round trip.
    #[serde(default)]
    pub round_trip_ms: u64,
}

impl Workload {
    fn one<T: From<u8>>() -> T {
        T::from(1)
    }
}

/// A part every system runs without, to measure what it costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ablation {
    /// No DKIM signature.
    Signing,
    /// Delivery in plaintext: the sink offers no STARTTLS. Submission keeps
    /// its TLS, since authentication needs it.
    Tls,
    /// The slice: a production-shaped system without its production shape.
    Production,
}

impl Ablation {
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "signing" => Ok(Self::Signing),
            "tls" => Ok(Self::Tls),
            "production" => Ok(Self::Production),
            _ => Err(format!(
                "`--without {name}`: only signing, tls and production can be left out"
            )),
        }
    }
}

/// How every system delivers: at most this many connections to a
/// receiver site, and one retry schedule, first after `retry_first_seconds`,
/// doubling, at most `retry_max_seconds` apart. The harness hands these to
/// each system's configuration, so they are equal by construction.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Delivery {
    pub connections: usize,
    pub retry_first_seconds: u64,
    pub retry_max_seconds: u64,
}

impl Default for Delivery {
    fn default() -> Self {
        Self {
            connections: 64,
            retry_first_seconds: 10,
            retry_max_seconds: 60,
        }
    }
}

/// A deferred backlog. It is built while the sink
/// refuses every session, so every system queues every recipient. Then its
/// memory is read, the system is stopped and started again, and the sink
/// opens: every recipient must arrive once.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backlog {
    /// Messages submitted into it, each with the workload's recipients.
    pub messages: u64,
    /// How long a system rests before its memory is read.
    pub settle_seconds: f64,
    /// How long every recipient has to arrive once the sink opens.
    pub drain_seconds: f64,
    /// Whether the sink opens only once every delivery waits at the longest
    /// retry interval, so drains compare between systems. The
    /// smoke profile, which compares a system only with itself, opens it at
    /// once.
    #[serde(default = "Backlog::yes")]
    pub open_at_longest_retry: bool,
}

impl Backlog {
    fn yes() -> bool {
        true
    }
}

/// A crash test. With `power`, the system runs on LazyFS, which
/// keeps every write not yet synced in its own memory, and part way through
/// a steady load the container is killed, losing those writes as a power
/// failure would. Without, it is killed on its own volume, which keeps
/// them, as when the process alone is lost. The system starts again on what
/// is there, and every recipient it acknowledged must arrive.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crash {
    /// Whether the power fails with it, losing what it had not synced.
    #[serde(default = "power")]
    pub power: bool,
    /// Messages offered a second, and for how long.
    pub rate: f64,
    pub seconds: f64,
    /// When, into the load, the container is killed.
    pub after_seconds: f64,
    /// While the load runs, the sink takes this many messages a second over
    /// this many sessions, and refuses the rest for now, so much of what the
    /// system acknowledged is still queued when it is killed. The limit lifts
    /// once the system accepts again.
    pub sink_rate: f64,
    pub sink_connections: usize,
    /// How long every acknowledged recipient has to arrive after the start.
    pub drain_seconds: f64,
}

fn power() -> bool {
    true
}

/// A fixed offered load in place of the search: the smoke profile
/// does the same work every run, so its costs compare from run to run.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixed {
    /// Messages offered a second, well below the system's saturation.
    pub rate: f64,
    pub seconds: f64,
}

/// A receiver that limits what it takes, as a large provider does, and
/// answers 421 and closes the connection beyond that. Its messages may wait
/// while it throttles, but none may be lost: once the search is over, the
/// throttle is lifted and every held message must arrive.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Throttle {
    /// The share of recipients it receives.
    pub share: f64,
    /// Messages a second it accepts, across every session.
    pub rate: f64,
    /// Sessions it allows at once.
    pub connections: usize,
    /// How long every held message has to arrive once the throttle lifts.
    pub release_seconds: f64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Search {
    pub warmup_rate: f64,
    pub warmup_seconds: f64,
    pub start_rate: f64,
    pub step_seconds: f64,
    pub bisections: u32,
    /// How long accepted messages may take to reach the sink after a step.
    pub drain_seconds: f64,
    pub headroom_seconds: f64,
    /// How many times the offered rate the tools must be able to carry.
    pub headroom: f64,
    /// An idle pause before each system's run but the first, so a machine
    /// that slows under sustained load recovers between systems.
    #[serde(default)]
    pub cooldown_seconds: f64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub submit_p99_ms: f64,
    pub delivery_p99_ms: f64,
    /// The share of the offered load that must be accepted.
    pub accepted_share: f64,
    /// The most anonymous memory a backlog may hold queued, and once the
    /// system has started again on it.
    #[serde(default)]
    pub backlog_anon_mib: Option<f64>,
}

pub fn load<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

impl Recipe {
    /// Every name the systems use resolves.
    pub fn check(&self, systems: &[String]) -> Result<(), String> {
        for tool in TOOLS {
            if !self.images.contains_key(tool) {
                return Err(format!("the recipe has no `{tool}` image"));
            }
        }
        for (name, image) in &self.images {
            for source in &image.sources {
                if !self.sources.contains_key(source) {
                    return Err(format!(
                        "image `{name}` needs source `{source}`, which the recipe does not name"
                    ));
                }
            }
        }
        for (name, system) in &self.systems {
            if !self.images.contains_key(&system.image) {
                return Err(format!(
                    "system `{name}` runs image `{}`, which the recipe does not build",
                    system.image
                ));
            }
        }
        for name in systems {
            if !self.systems.contains_key(name) {
                let known: Vec<&str> = self.systems.keys().map(String::as_str).collect();
                return Err(format!(
                    "no system `{name}`; the recipe has {}",
                    known.join(", ")
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recipe_and_every_profile_are_consistent() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let recipe: Recipe = load(&dir.join("recipe.toml")).unwrap();
        for entry in fs::read_dir(dir.join("profiles")).unwrap() {
            let path = entry.unwrap().path();
            let profile: Profile = load(&path).unwrap();
            recipe
                .check(&profile.systems)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        }
        for name in recipe.images.keys() {
            assert!(
                dir.join("images").join(name).join("Dockerfile").is_file(),
                "{name} has no Dockerfile"
            );
        }
    }
}
