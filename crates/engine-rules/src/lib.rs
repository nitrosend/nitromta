//! The receiver rule bundle: which sites are the providers'
//! that matter, the limits kept to at each site, the replies that mean a
//! site refuses an egress for now, and what each enhanced status code says
//! of a failure. The bundle is data, `rules/receivers.toml`, built in and
//! overridden field by field in configuration. This crate reads it, checks
//! it, and applies it.
//!
//! A site is what a receiver's limits apply to: a provider's,
//! when every one of the exchanges a domain names is the provider's, or else
//! that set of exchanges. A provider's name starts with a capital, which no
//! exchange's name has, so a provider's site never shares a name with a set
//! of exchanges.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use engine_core::attempt::Evidence;
use engine_core::status::Status;
use regex::RegexSet;
use serde::Deserialize;

/// The bundle as it ships.
const SHIPPED: &str = include_str!("../../../rules/receivers.toml");

/// The name under which the defaults are overridden.
pub const DEFAULTS: &str = "defaults";

/// A provider's entry, or the defaults', as the bundle and an operator's
/// overrides write it. A field an override leaves out keeps the bundle's.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The suffixes of the provider's exchanges' names, each from a dot.
    pub exchanges: Option<Vec<String>>,
    /// Connections from one egress at most, shared by a provider's sites.
    pub connections: Option<usize>,
    /// Transactions one connection carries before it closes.
    pub transactions_per_connection: Option<usize>,
    /// Mail goes to it only over TLS, whatever `[delivery] require_tls`
    /// says.
    pub require_tls: Option<bool>,
    pub throttles: Option<Vec<ThrottleEntry>>,
    pub warmup: Option<WarmupEntry>,
}

/// Warmup's ladder and thresholds, as the bundle and an
/// operator's overrides write them, field by field.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmupEntry {
    /// Daily caps, rung by rung, each above the one before.
    pub ladder: Option<Vec<u64>>,
    /// The fewest replies in a day that judge a site on its own.
    pub sample: Option<u64>,
    /// Each signal's thresholds to hold and to lower a cap, in basis
    /// points of its denominator.
    pub complaints: Option<[u32; 2]>,
    pub failures: Option<[u32; 2]>,
    pub deferrals: Option<[u32; 2]>,
    pub throttles: Option<[u32; 2]>,
}

/// Warmup's ladder and thresholds at a site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warmup {
    pub ladder: Arc<[u64]>,
    pub sample: u64,
    /// Of deliveries.
    pub complaints: Threshold,
    /// Of replies.
    pub failures: Threshold,
    /// Of replies.
    pub deferrals: Threshold,
    /// Of replies.
    pub throttles: Threshold,
}

/// Rates, in basis points, at which a signal holds a cap and lowers it. A
/// count of none is under every threshold, so one of 0 means any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threshold {
    pub hold: u32,
    pub lower: u32,
}

impl Threshold {
    /// How far `count` of `of` reaches: to hold, to lower, or neither.
    pub fn reached(&self, count: u32, of: u64) -> Option<Reached> {
        if count == 0 {
            return None;
        }
        let at = |basis_points: u32| {
            u128::from(count) * 10_000 >= u128::from(basis_points) * u128::from(of)
        };
        if at(self.lower) {
            Some(Reached::Lower)
        } else if at(self.hold) {
            Some(Reached::Hold)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reached {
    Hold,
    Lower,
}

/// A reply that refuses an egress for now.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrottleEntry {
    pub name: String,
    /// Matched against the reply's text.
    pub pattern: String,
    /// The cooldown's minimum; the retry schedule's when 0.
    #[serde(default)]
    pub cooldown_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    revision: u32,
    defaults: Entry,
    #[serde(default)]
    receivers: BTreeMap<String, Entry>,
    #[serde(default)]
    statuses: BTreeMap<String, ClassEntry>,
    #[serde(default)]
    tests: Vec<Test>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassEntry {
    /// Each `subject.detail`, whatever the class.
    codes: Vec<String>,
    scope: Scope,
    #[serde(default)]
    rules_out_address: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Test {
    #[allow(dead_code, reason = "read by people: where the reply came from")]
    source: String,
    exchanges: Vec<String>,
    reply: String,
    site: String,
    class: Option<String>,
    #[serde(default)]
    rules_out_address: bool,
    throttle_seconds: Option<u64>,
    rules: Vec<String>,
}

/// What a failure is about.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Recipient,
    Message,
    Sender,
    Egress,
    Site,
}

/// What an enhanced status code says of a failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    pub name: Arc<str>,
    pub scope: Scope,
    /// A permanent failure in it means the address can never be delivered
    /// to, so it may suppress the address.
    pub rules_out_address: bool,
}

/// What a site keeps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub connections: usize,
    pub transactions_per_connection: usize,
    /// Its mail goes only over TLS.
    pub require_tls: bool,
}

/// A reply's verdict at its site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// Its enhanced status code's class, if the bundle registers it.
    pub class: Option<Class>,
    /// It is a permanent failure whose class rules the address out.
    pub rules_out_address: bool,
    /// The site refuses its egress for now: it cools down for at least
    /// this long, beyond the retry schedule's cooldown.
    pub throttle: Option<Duration>,
    /// The rules that matched, by name: the class, then the throttle
    /// replies, the defaults' first.
    pub rules: Vec<Arc<str>>,
}

/// The bundle, overridden, checked and compiled.
#[derive(Debug)]
pub struct Rules {
    revision: u32,
    defaults: Arc<Shaping>,
    providers: Vec<Provider>,
    statuses: Arc<Statuses>,
}

#[derive(Debug)]
struct Provider {
    name: Arc<str>,
    suffixes: Vec<String>,
    shaping: Arc<Shaping>,
}

/// The limits, throttle replies and warmup of a provider, or of the
/// defaults.
#[derive(Debug)]
struct Shaping {
    limits: Limits,
    patterns: RegexSet,
    /// Each pattern's rule name and the cooldown's minimum.
    throttles: Vec<(Arc<str>, Duration)>,
    warmup: Warmup,
}

#[derive(Debug)]
struct Statuses {
    classes: Vec<Class>,
    /// Each `(subject, detail)`'s class.
    by_code: BTreeMap<(u16, u16), usize>,
}

/// A site, and what applies there.
#[derive(Clone, Debug)]
pub struct Site(Arc<SiteRules>);

#[derive(Debug)]
struct SiteRules {
    name: Arc<str>,
    shaping: Arc<Shaping>,
    statuses: Arc<Statuses>,
}

impl Rules {
    /// The shipped bundle, with `overrides` from configuration, keyed by a
    /// provider's name or [`DEFAULTS`].
    pub fn new(overrides: &BTreeMap<String, Entry>) -> Result<Self, String> {
        Self::from_bundle(SHIPPED, overrides)
    }

    fn from_bundle(text: &str, overrides: &BTreeMap<String, Entry>) -> Result<Self, String> {
        let bundle: Bundle = toml::from_str(text).map_err(|error| format!("receivers: {error}"))?;
        let mut defaults = bundle.defaults;
        let mut receivers = bundle.receivers;
        for (name, entry) in overrides {
            let base = if name == DEFAULTS {
                &mut defaults
            } else {
                receivers.entry(name.clone()).or_default()
            };
            merge(base, entry);
        }
        if defaults.exchanges.is_some() {
            return Err("receivers.defaults: the defaults claim no exchanges".to_owned());
        }
        let limits = Limits {
            connections: defaults
                .connections
                .ok_or("receivers.defaults: connections is missing")?,
            transactions_per_connection: defaults
                .transactions_per_connection
                .ok_or("receivers.defaults: transactions_per_connection is missing")?,
            require_tls: defaults.require_tls.unwrap_or(false),
        };
        let shared = defaults.throttles.unwrap_or_default();
        let warmup_entry = defaults.warmup.unwrap_or_default();
        let base_warmup = warmup(DEFAULTS, &warmup_entry, None)?;
        let defaults = Arc::new(shaping(
            DEFAULTS,
            limits,
            &shared,
            &[],
            base_warmup.clone(),
        )?);
        let mut providers: Vec<Provider> = Vec::new();
        for (name, entry) in receivers {
            if !name.starts_with(|c: char| c.is_ascii_uppercase())
                || !name.chars().all(|c| c.is_ascii_alphanumeric())
            {
                return Err(format!(
                    "receivers.{name}: a provider's name is letters and digits from a capital"
                ));
            }
            let suffixes = entry.exchanges.unwrap_or_default();
            if suffixes.is_empty() {
                return Err(format!("receivers.{name}: exchanges is missing"));
            }
            for suffix in &suffixes {
                let suffix_ok = suffix.starts_with('.')
                    && suffix.len() > 1
                    && !suffix.ends_with('.')
                    && *suffix == suffix.to_ascii_lowercase();
                if !suffix_ok {
                    return Err(format!(
                        "receivers.{name}: {suffix:?} is not a lowercase suffix from a dot"
                    ));
                }
                // One exchange is never two providers'.
                if let Some(other) = providers.iter().find(|other| {
                    other.suffixes.iter().any(|theirs| {
                        theirs.ends_with(suffix.as_str()) || suffix.ends_with(theirs.as_str())
                    })
                }) {
                    return Err(format!(
                        "receivers.{name}: {suffix:?} overlaps {}'s exchanges",
                        other.name
                    ));
                }
            }
            let limits = Limits {
                connections: entry.connections.unwrap_or(limits.connections),
                transactions_per_connection: entry
                    .transactions_per_connection
                    .unwrap_or(limits.transactions_per_connection),
                require_tls: entry.require_tls.unwrap_or(limits.require_tls),
            };
            let own = entry.throttles.unwrap_or_default();
            let warmup = match &entry.warmup {
                Some(own) => warmup(&name, own, Some(&base_warmup))?,
                None => base_warmup.clone(),
            };
            providers.push(Provider {
                shaping: Arc::new(shaping(&name, limits, &shared, &own, warmup)?),
                name: name.into(),
                suffixes,
            });
        }
        let rules = Self {
            revision: bundle.revision,
            defaults,
            providers,
            statuses: Arc::new(statuses(bundle.statuses)?),
        };
        // An operator's overrides may change what the shipped tests expect,
        // so they are checked only for the bundle as shipped.
        if overrides.is_empty() {
            rules.check(&bundle.tests)?;
        }
        Ok(rules)
    }

    pub fn revision(&self) -> u32 {
        self.revision
    }

    /// The site the exchanges a domain names make, most preferred first.
    pub fn site(&self, exchanges: &[String]) -> Site {
        let provider = self.providers.iter().find(|provider| {
            !exchanges.is_empty()
                && exchanges.iter().all(|exchange| {
                    provider
                        .suffixes
                        .iter()
                        .any(|suffix| exchange.ends_with(suffix.as_str()))
                })
        });
        let (name, shaping) = match provider {
            Some(provider) => (Arc::clone(&provider.name), Arc::clone(&provider.shaping)),
            None => (exchange_set(exchanges).into(), Arc::clone(&self.defaults)),
        };
        Site(Arc::new(SiteRules {
            name,
            shaping,
            statuses: Arc::clone(&self.statuses),
        }))
    }

    /// The limits of the site named `name`: its provider's, or, for a set
    /// of exchanges, the defaults.
    pub fn limits_of(&self, name: &str) -> Limits {
        self.providers
            .iter()
            .find(|provider| &*provider.name == name)
            .map_or(self.defaults.limits, |provider| provider.shaping.limits)
    }

    /// Warmup's ladder and thresholds at the site named `name`: its
    /// provider's, or, for a set of exchanges, the defaults.
    pub fn warmup_of(&self, name: &str) -> &Warmup {
        self.providers
            .iter()
            .find(|provider| &*provider.name == name)
            .map_or(&self.defaults.warmup, |provider| &provider.shaping.warmup)
    }

    /// The defaults' warmup, which an egress's own cap climbs and the sites
    /// pooled under it are judged by.
    pub fn default_warmup(&self) -> &Warmup {
        &self.defaults.warmup
    }

    /// The class of `status`, as a delivery status notification gives it.
    pub fn class(&self, status: Status) -> Option<&Class> {
        self.statuses.class(status)
    }

    /// Whether `status`, as a delivery status notification gives it, says
    /// the address can never be delivered to.
    pub fn rules_out_address(&self, status: Status) -> bool {
        status.is_permanent()
            && self
                .class(status)
                .is_some_and(|class| class.rules_out_address)
    }

    /// Checks every test against these rules.
    fn check(&self, tests: &[Test]) -> Result<(), String> {
        for test in tests {
            let site = self.site(&test.exchanges);
            let (code, text) = split_reply(&test.reply)
                .ok_or_else(|| format!("receivers test {:?}: no reply code", test.reply))?;
            let verdict = site.verdict(code, text);
            let got = (
                site.name().to_string(),
                verdict.class.as_ref().map(|class| class.name.to_string()),
                verdict.rules_out_address,
                verdict.throttle.map(|minimum| minimum.as_secs()),
                verdict
                    .rules
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            );
            let want = (
                test.site.clone(),
                test.class.clone(),
                test.rules_out_address,
                test.throttle_seconds,
                test.rules.clone(),
            );
            if got != want {
                return Err(format!(
                    "receivers test {:?}: got {got:?}, expected {want:?}",
                    test.reply
                ));
            }
        }
        Ok(())
    }
}

impl Site {
    /// Its name: a provider's, or its exchanges', sorted and joined.
    pub fn name(&self) -> &Arc<str> {
        &self.0.name
    }

    /// The provider's name, if it is a provider's site.
    pub fn provider(&self) -> Option<&Arc<str>> {
        self.0
            .name
            .starts_with(|first: char| first.is_ascii_uppercase())
            .then_some(&self.0.name)
    }

    pub fn limits(&self) -> Limits {
        self.0.shaping.limits
    }

    /// A reply from this site, `code` and its whole `text`: the evidence
    /// kept of it, with the rules it matched, and its verdict, `None` for a
    /// 2xx reply, which is not judged. The whole text is judged, though the
    /// evidence keeps only [`Evidence::MAX_TEXT_BYTES`] of it.
    pub fn judged(&self, code: u16, text: &str) -> (Evidence, Option<Verdict>) {
        let mut evidence = Evidence::new(code, text);
        if code / 100 == 2 {
            return (evidence, None);
        }
        let verdict = self.verdict(code, text);
        evidence.rules = verdict
            .rules
            .iter()
            .map(|rule| &**rule)
            .collect::<Vec<_>>()
            .join(" ");
        (evidence, Some(verdict))
    }

    /// The verdict on a reply other than 2xx from this site: its class, by
    /// the enhanced status code its text begins with; whether it rules the
    /// address out; and whether it throttles, as any 421 does by SMTP
    /// itself and any reply the bundle names, whatever its code.
    pub fn verdict(&self, code: u16, text: &str) -> Verdict {
        let class = Status::parse(text).and_then(|status| self.0.statuses.class(status));
        let mut rules: Vec<Arc<str>> = class.iter().map(|class| Arc::clone(&class.name)).collect();
        let mut throttle = (code == 421).then_some(Duration::ZERO);
        let shaping = &self.0.shaping;
        for index in shaping.patterns.matches(text).iter() {
            let (name, minimum) = &shaping.throttles[index];
            rules.push(Arc::clone(name));
            throttle = Some(throttle.unwrap_or_default().max(*minimum));
        }
        Verdict {
            rules_out_address: code / 100 == 5
                && class.is_some_and(|class| class.rules_out_address),
            class: class.cloned(),
            throttle,
            rules,
        }
    }
}

impl Statuses {
    fn class(&self, status: Status) -> Option<&Class> {
        if !matches!(status.class, 4 | 5) {
            return None;
        }
        let index = self.by_code.get(&(status.subject, status.detail))?;
        self.classes.get(*index)
    }
}

/// The name of a set of exchanges: sorted, without repeats, and joined.
/// Domains whose exchanges make the same set share their queue, and, when
/// no provider claims the set, it is their site's name too.
pub fn exchange_set(exchanges: &[String]) -> String {
    let mut sorted = exchanges.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted.join(",")
}

/// Replaces each of `base`'s fields that `entry` gives.
fn merge(base: &mut Entry, entry: &Entry) {
    if let Some(exchanges) = &entry.exchanges {
        base.exchanges = Some(exchanges.clone());
    }
    if let Some(connections) = entry.connections {
        base.connections = Some(connections);
    }
    if let Some(transactions) = entry.transactions_per_connection {
        base.transactions_per_connection = Some(transactions);
    }
    if let Some(required) = entry.require_tls {
        base.require_tls = Some(required);
    }
    if let Some(throttles) = &entry.throttles {
        base.throttles = Some(throttles.clone());
    }
    if let Some(warmup) = &entry.warmup {
        let into = base.warmup.get_or_insert_with(WarmupEntry::default);
        let fields = [
            (&mut into.complaints, warmup.complaints),
            (&mut into.failures, warmup.failures),
            (&mut into.deferrals, warmup.deferrals),
            (&mut into.throttles, warmup.throttles),
        ];
        for (field, value) in fields {
            if value.is_some() {
                *field = value;
            }
        }
        if let Some(ladder) = &warmup.ladder {
            into.ladder = Some(ladder.clone());
        }
        if let Some(sample) = warmup.sample {
            into.sample = Some(sample);
        }
    }
}

/// A provider's warmup, or the defaults', checked: what `entry` leaves out
/// is `base`'s, the defaults'.
fn warmup(owner: &str, entry: &WarmupEntry, base: Option<&Warmup>) -> Result<Warmup, String> {
    let missing = |field| format!("receivers.{owner}.warmup: {field} is missing");
    let ladder: Arc<[u64]> = match (&entry.ladder, base) {
        (Some(ladder), _) => ladder.as_slice().into(),
        (None, Some(base)) => Arc::clone(&base.ladder),
        (None, None) => return Err(missing("ladder")),
    };
    if ladder.is_empty() || ladder[0] == 0 || ladder.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!(
            "receivers.{owner}.warmup: a ladder climbs from above 0, each rung above the one before"
        ));
    }
    let sample = entry
        .sample
        .or(base.map(|base| base.sample))
        .ok_or_else(|| missing("sample"))?;
    if sample == 0 {
        return Err(format!(
            "receivers.{owner}.warmup: a sample of 0 judges nothing"
        ));
    }
    let threshold = |name, own: Option<[u32; 2]>, base: Option<Threshold>| {
        let threshold = match (own, base) {
            (Some([hold, lower]), _) => Threshold { hold, lower },
            (None, Some(base)) => base,
            (None, None) => return Err(missing(name)),
        };
        if threshold.hold > threshold.lower || threshold.lower > 10_000 {
            return Err(format!(
                "receivers.{owner}.warmup: {name} holds at or below where it lowers, at most 10000"
            ));
        }
        Ok(threshold)
    };
    Ok(Warmup {
        ladder,
        sample,
        complaints: threshold(
            "complaints",
            entry.complaints,
            base.map(|base| base.complaints),
        )?,
        failures: threshold("failures", entry.failures, base.map(|base| base.failures))?,
        deferrals: threshold(
            "deferrals",
            entry.deferrals,
            base.map(|base| base.deferrals),
        )?,
        throttles: threshold(
            "throttles",
            entry.throttles,
            base.map(|base| base.throttles),
        )?,
    })
}

/// A provider's shaping, or the defaults': the defaults' throttle replies,
/// then its own.
fn shaping(
    owner: &str,
    limits: Limits,
    shared: &[ThrottleEntry],
    own: &[ThrottleEntry],
    warmup: Warmup,
) -> Result<Shaping, String> {
    if limits.connections == 0 || limits.transactions_per_connection == 0 {
        return Err(format!("receivers.{owner}: a limit of 0 sends nothing"));
    }
    let entries: Vec<(&str, &ThrottleEntry)> = shared
        .iter()
        .map(|entry| (DEFAULTS, entry))
        .chain(own.iter().map(|entry| (owner, entry)))
        .collect();
    let mut throttles = Vec::with_capacity(entries.len());
    for (from, entry) in &entries {
        if entry.name.is_empty() || entry.name.contains(char::is_whitespace) {
            return Err(format!(
                "receivers.{from}: a throttle's name {:?} is one word",
                entry.name
            ));
        }
        let name: Arc<str> = format!("{from}/{}", entry.name).into();
        if throttles.iter().any(|(other, _)| *other == name) {
            return Err(format!("receivers.{from}: two throttles are named {name}"));
        }
        throttles.push((name, Duration::from_secs(entry.cooldown_seconds)));
    }
    let patterns = RegexSet::new(entries.iter().map(|(_, entry)| entry.pattern.as_str()))
        .map_err(|error| format!("receivers.{owner}: a throttle's pattern: {error}"))?;
    Ok(Shaping {
        limits,
        patterns,
        throttles,
        warmup,
    })
}

fn statuses(entries: BTreeMap<String, ClassEntry>) -> Result<Statuses, String> {
    let mut classes = Vec::with_capacity(entries.len());
    let mut by_code = BTreeMap::new();
    for (name, entry) in entries {
        if name.contains(['/', ' ']) {
            return Err(format!(
                "receivers.statuses.{name}: a class's name has no / or space"
            ));
        }
        for code in &entry.codes {
            let pair = code
                .split_once('.')
                .and_then(|(subject, detail)| Some((subject.parse().ok()?, detail.parse().ok()?)))
                .ok_or_else(|| {
                    format!("receivers.statuses.{name}: {code:?} is not subject.detail")
                })?;
            if by_code.insert(pair, classes.len()).is_some() {
                return Err(format!(
                    "receivers.statuses.{name}: {code} is in two classes"
                ));
            }
        }
        classes.push(Class {
            name: name.into(),
            scope: entry.scope,
            rules_out_address: entry.rules_out_address,
        });
    }
    Ok(Statuses { classes, by_code })
}

/// A test's reply as the wire writes it: its code, then its text.
fn split_reply(reply: &str) -> Option<(u16, &str)> {
    let (code, text) = reply.split_once(' ')?;
    Some((code.parse().ok()?, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> BTreeMap<String, Entry> {
        BTreeMap::new()
    }

    #[test]
    fn the_shipped_bundle_passes_every_one_of_its_tests() {
        let rules = Rules::new(&none()).unwrap();
        assert_eq!(rules.revision(), 1);
    }

    #[test]
    fn a_providers_domains_share_its_site_and_others_keep_their_own() {
        let rules = Rules::new(&none()).unwrap();
        let workspace = rules.site(&["aspmx.l.google.com".to_owned()]);
        let gmail = rules.site(&[
            "gmail-smtp-in.l.google.com".to_owned(),
            "alt1.gmail-smtp-in.l.google.com".to_owned(),
        ]);
        assert_eq!((&**workspace.name(), &**gmail.name()), ("Google", "Google"));
        assert_eq!(workspace.limits().connections, 5);
        let other = rules.site(&["mx2.example.net".to_owned(), "mx1.example.net".to_owned()]);
        assert_eq!(rules.limits_of("Google"), workspace.limits());
        assert_eq!(
            rules
                .limits_of("mx1.example.net,mx2.example.net")
                .connections,
            10
        );
        assert_eq!(&**other.name(), "mx1.example.net,mx2.example.net");
        assert_eq!(other.limits().connections, 10);
        // The same exchanges in another order make the same set.
        let reordered = rules.site(&["mx1.example.net".to_owned(), "mx2.example.net".to_owned()]);
        assert_eq!(reordered.name(), other.name());
        assert_ne!(
            exchange_set(&["mx1.example.net".to_owned()]),
            exchange_set(&["mx1.example.net".to_owned(), "mx2.example.net".to_owned()])
        );
        // A suffix matches whole labels only.
        assert_eq!(
            &**rules.site(&["notgoogle.com".to_owned()]).name(),
            "notgoogle.com"
        );
    }

    #[test]
    fn warmup_climbs_the_bundles_ladder_and_an_override_changes_the_fields_it_gives() {
        let rules = Rules::new(&none()).unwrap();
        let shipped = rules.default_warmup();
        assert_eq!(shipped.ladder.first(), Some(&50));
        assert_eq!(shipped.sample, 100);
        assert_eq!(rules.warmup_of("Google"), shipped, "it falls through");
        assert_eq!(rules.warmup_of("mx1.example.net"), shipped);
        // Outlook's own, half the pace to 10,000, and the rest falls through.
        let rungs_to = |ladder: &[u64]| ladder.iter().position(|rung| *rung == 10_000);
        let slower = rules.warmup_of("Outlook");
        assert_eq!(rungs_to(&shipped.ladder), Some(7));
        assert_eq!(rungs_to(&slower.ladder), Some(14));
        assert_eq!(
            slower.deferrals,
            Threshold {
                hold: 50,
                lower: 2_000
            }
        );
        assert_eq!(slower.throttles, shipped.throttles);
        let overrides: BTreeMap<String, Entry> = toml::from_str(
            r#"
            [defaults.warmup]
            sample = 40

            [Outlook.warmup]
            ladder = [20, 60, 180]
            throttles = [50, 200]
            "#,
        )
        .unwrap();
        let overridden = Rules::new(&overrides).unwrap();
        let defaults = overridden.default_warmup();
        assert_eq!((defaults.sample, &defaults.ladder), (40, &shipped.ladder));
        let outlook = overridden.warmup_of("Outlook");
        assert_eq!(&*outlook.ladder, &[20, 60, 180]);
        assert_eq!(
            outlook.throttles,
            Threshold {
                hold: 50,
                lower: 200
            }
        );
        assert_eq!(
            (outlook.sample, outlook.complaints),
            (40, shipped.complaints),
            "what it leaves out is the defaults'"
        );
        for (bad, why) in [
            ("[defaults.warmup]\nladder = [100, 100]", "climbs"),
            ("[defaults.warmup]\nladder = []", "climbs"),
            ("[defaults.warmup]\nsample = 0", "judges nothing"),
            ("[Yahoo.warmup]\nfailures = [600, 500]", "holds at or below"),
        ] {
            let overrides: BTreeMap<String, Entry> = toml::from_str(bad).unwrap();
            let error = Rules::new(&overrides).unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    #[test]
    fn a_threshold_holds_then_lowers_and_a_count_of_none_reaches_neither() {
        let complaints = Threshold {
            hold: 10,
            lower: 30,
        };
        assert_eq!(complaints.reached(0, 1_000), None);
        assert_eq!(complaints.reached(1, 1_001), None, "under 0.1%");
        assert_eq!(complaints.reached(1, 1_000), Some(Reached::Hold), "at 0.1%");
        assert_eq!(
            complaints.reached(3, 1_000),
            Some(Reached::Lower),
            "at 0.3%"
        );
        let any = Threshold {
            hold: 0,
            lower: 100,
        };
        assert_eq!(any.reached(0, 10), None);
        assert_eq!(any.reached(1, 1_000_000), Some(Reached::Hold), "any holds");
        assert_eq!(any.reached(1, 100), Some(Reached::Lower), "1% lowers");
    }

    #[test]
    fn an_override_replaces_the_fields_it_gives_and_may_add_a_provider() {
        let overrides: BTreeMap<String, Entry> = toml::from_str(
            r#"
            [defaults]
            connections = 64

            [Google]
            transactions_per_connection = 10

            [Sink]
            exchanges = [".sink.test"]
            "#,
        )
        .unwrap();
        let rules = Rules::new(&overrides).unwrap();
        let google = rules.site(&["aspmx.l.google.com".to_owned()]).limits();
        assert_eq!(
            (
                google.connections,
                google.transactions_per_connection,
                google.require_tls
            ),
            (5, 10, true),
            "the bundle's, overridden field by field"
        );
        let sink = rules.site(&["mx.sink.test".to_owned()]);
        assert_eq!(&**sink.name(), "Sink");
        assert_eq!(sink.limits().connections, 64, "the defaults', overridden");
        assert!(!sink.limits().require_tls, "the defaults'");
    }

    #[test]
    fn faults_are_refused_at_start() {
        let refused = |text: &str| {
            let overrides: BTreeMap<String, Entry> = toml::from_str(text).unwrap();
            Rules::new(&overrides).unwrap_err()
        };
        assert!(refused("[lowercase]\nexchanges = ['.x.test']").contains("capital"));
        assert!(refused("[Nowhere]\nconnections = 1").contains("exchanges is missing"));
        assert!(refused("[Mail]\nexchanges = ['.l.google.com']").contains("overlaps"));
        assert!(refused("[defaults]\nconnections = 0").contains("sends nothing"));
        assert!(refused("[[Google.throttles]]\nname = 'x'\npattern = '('").contains("pattern"));
    }

    #[test]
    fn a_wrong_expectation_fails_the_bundles_tests() {
        let wrong = SHIPPED.replace(
            "site = \"Google\"\nclass = \"no-such-mailbox\"",
            "site = \"Google\"\nclass = \"mailbox-full\"",
        );
        assert_ne!(wrong, SHIPPED);
        assert!(
            Rules::from_bundle(&wrong, &none())
                .unwrap_err()
                .contains("expected")
        );
    }

    #[test]
    fn judging_a_reply_records_the_rules_it_matched_and_a_2xx_is_not_judged() {
        let rules = Rules::new(&none()).unwrap();
        let yahoo = rules.site(&["mta5.am0.yahoodns.net".to_owned()]);
        let (evidence, verdict) = yahoo.judged(
            421,
            "4.7.0 [TSS04] Messages from 192.0.2.1 temporarily deferred",
        );
        assert_eq!(verdict.unwrap().throttle, Some(Duration::from_secs(7200)));
        assert_eq!(
            evidence.rules,
            "refused defaults/ip-temporarily-deferred Yahoo/TSS04"
        );
        let (delivered, verdict) = yahoo.judged(250, "2.0.0 Ok");
        assert_eq!((verdict, delivered.rules.as_str()), (None, ""));
        // A marker past what the evidence keeps is still judged.
        let long = format!("4.7.0 {} [TSS04]", "x".repeat(Evidence::MAX_TEXT_BYTES));
        let (evidence, verdict) = yahoo.judged(451, &long);
        assert_eq!(verdict.unwrap().throttle, Some(Duration::from_secs(7200)));
        assert!(evidence.text.len() <= Evidence::MAX_TEXT_BYTES);
    }

    #[test]
    fn a_reports_status_is_classified_by_the_same_table() {
        let rules = Rules::new(&none()).unwrap();
        let status = |text| Status::parse(text).unwrap();
        assert!(rules.rules_out_address(status("5.1.1")));
        assert!(!rules.rules_out_address(status("4.1.1")), "temporary");
        assert!(!rules.rules_out_address(status("5.2.2")), "a full mailbox");
        assert_eq!(rules.class(status("5.7.26")).unwrap().scope, Scope::Sender);
    }
}
