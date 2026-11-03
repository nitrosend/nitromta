//! The engine's configuration, read from one TOML file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub store: Store,
    pub submission: Submission,
    /// The SES v2 API; the engine serves none when this is absent.
    pub ses: Option<Ses>,
    /// The SNS subset, served on the SES API's listener, which SES-shaped
    /// events are published through; none when this is absent.
    pub sns: Option<Sns>,
    /// The admin service; the engine serves none when this is absent.
    /// Identities, tenants, configurations and credentials are policy, set
    /// through it, not here.
    pub admin: Option<Admin>,
    /// The feedback listener; the engine takes no bounce or complaint
    /// reports when this is absent.
    pub feedback: Option<Feedback>,
    pub delivery: Delivery,
    #[serde(default)]
    pub outbound: Outbound,
    /// The certificate authorities verified TLS trusts.
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub scheduler: Scheduler,
    #[serde(default)]
    pub log: Log,
    /// The operator's endpoint, for health and metrics; the engine serves
    /// none when this is absent.
    pub operator: Option<Operator>,
    /// Capture mode: every delivery is captured into a directory
    /// in place of being sent, and nothing reaches a receiver.
    pub capture: Option<Capture>,
    /// Overrides of the receiver rule bundle, field by field:
    /// `[receivers.defaults]` for the sites no provider claims, and
    /// `[receivers.<Provider>]` for a provider, which a new name adds.
    #[serde(default)]
    pub receivers: BTreeMap<String, engine_rules::Entry>,
    /// How the hooks a build carries are run.
    #[serde(default)]
    pub hooks: Hooks,
    /// Each event subscription's budget.
    #[serde(default)]
    pub events: Events,
    #[serde(default)]
    pub warmup: Warmup,
}

/// Warmup's schedule and promotion.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Warmup {
    /// Whether the engine judges each capped egress once a day and sets its
    /// caps. Off, caps change only by the operator's command, by hand or
    /// from the operator's own system.
    pub automatic: bool,
}

impl Default for Warmup {
    fn default() -> Self {
        Self { automatic: true }
    }
}

/// Each event subscription's budget: its own, so a subscriber
/// that fails holds back only its own events. Any setting left out takes
/// its default.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Events {
    /// The most events in a batch.
    pub batch_events: usize,
    /// The most bytes a batch's body holds, unless its one event holds more.
    pub batch_bytes: usize,
    /// How long a batch is posted again from its first failure before it is
    /// parked, for `replay` to post again, and its subscription's later
    /// events go on.
    pub park_after_seconds: u64,
}

impl Default for Events {
    fn default() -> Self {
        Self {
            batch_events: 1000,
            batch_bytes: 1 << 20,
            park_after_seconds: 86_400,
        }
    }
}

/// Each hook point's settings, for the hook the build carries there. A
/// section for a hook the build does not carry stops the engine at its
/// start; a hook with no section runs with the defaults.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hooks {
    pub admission: Option<Hook>,
    pub dispatch: Option<Hook>,
}

/// Any setting left out takes its default.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Hook {
    /// How long a call may take, waiting for its place among those under
    /// way included, before its failure policy decides.
    pub timeout_ms: u64,
    /// Calls under way at once at most.
    pub concurrency: usize,
    /// What a call that fails, panics or does not decide in time comes to.
    pub on_failure: OnFailure,
}

impl Default for Hook {
    fn default() -> Self {
        Self {
            timeout_ms: 1000,
            concurrency: 64,
            on_failure: OnFailure::Closed,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnFailure {
    /// The mail waits: admission refuses it for now, and dispatch holds it
    /// for its next retry.
    #[default]
    Closed,
    /// The mail goes on as if the hook had let it.
    Open,
}

/// The operator's endpoint: plain HTTP, so it belongs on a
/// local or private address.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    pub listen: String,
}

/// Capture mode, for trying the engine and testing applications:
/// mail is accepted, signed and stored as ever, and each transaction is
/// written to `directory`, which the operator endpoint's `/capture` shows,
/// in place of delivery. Nothing is looked up in the DNS, and nothing
/// reaches a receiver.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub directory: PathBuf,
}

/// The engine's logs.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    pub level: LogLevel,
    pub format: LogFormat,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    /// Also a line for each transaction, which `info` leaves to the
    /// journal.
    Debug,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object a line.
    #[default]
    Json,
    Text,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Store {
    /// The SQLite database. Its directory holds the write-ahead log too.
    pub path: PathBuf,
    /// The installation's keys, which seal the secrets in policy:
    /// a file of its own, apart from the store and its backups, which
    /// only its owner may read. `nitromta key --to <file>` writes one.
    pub keys: PathBuf,
    /// This store's shard, which every ID it issues carries.
    #[serde(default)]
    pub shard: u8,
    /// Pages the write-ahead log may hold before it is checkpointed; the
    /// store's measured default when absent.
    pub checkpoint_pages: Option<u32>,
    /// How long finished mail is kept for the bounces and complaints that
    /// arrive after it; 7 days when absent.
    pub feedback_window_seconds: Option<u64>,
    /// Free space kept on the store's disk for outcomes, feedback and
    /// checkpoints: below it, new mail is refused for now.
    #[serde(default = "Store::default_reserve_mib")]
    pub reserve_mib: u64,
    /// Mail accepted and waiting for its commit, at most, before new mail
    /// is refused for now.
    #[serde(default = "Store::default_pending_mib")]
    pub pending_mib: u64,
    /// Whether personal data is sealed: `off`, by default, when
    /// the operator relies on full-disk encryption; `installation`, under
    /// the keys file's newest key; or `tenant`, each tenant's mail under a
    /// key of its own, in `<keys>.tenants/`, so removing the tenant erases
    /// it. What was sealed under any of them still reads.
    #[serde(default)]
    pub encryption: Encryption,
}

/// How personal data is sealed, as configuration names it.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Encryption {
    #[default]
    Off,
    Installation,
    Tenant,
}

impl Store {
    /// The store's options, as the engine and a restore open it with.
    pub fn options(&self) -> engine_store::store::StoreOptions {
        let mut options = engine_store::store::StoreOptions::default();
        if let Some(pages) = self.checkpoint_pages {
            options.checkpoint_pages = pages;
        }
        if let Some(seconds) = self.feedback_window_seconds {
            options.feedback_window = std::time::Duration::from_secs(seconds);
        }
        options.encryption = match self.encryption {
            Encryption::Off => engine_store::store::Encryption::Off,
            Encryption::Installation => engine_store::store::Encryption::Installation,
            Encryption::Tenant => engine_store::store::Encryption::Tenant,
        };
        options
    }

    fn default_reserve_mib() -> u64 {
        1024
    }

    fn default_pending_mib() -> u64 {
        512
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub listen: String,
    pub hostname: String,
    pub certificate: PathBuf,
    pub key: PathBuf,
    /// SES's limit, 40 MB, by default.
    #[serde(default = "Submission::default_max_message_bytes")]
    pub max_message_bytes: usize,
    /// SES's limit of 50 recipients by default.
    #[serde(default = "Submission::default_max_recipients")]
    pub max_recipients: usize,
    /// RFC 5321's five minutes by default.
    #[serde(default = "Submission::default_idle_seconds")]
    pub idle_seconds: u64,
    /// How long an accepted message is tried before it expires; three days by
    /// default.
    #[serde(default = "Submission::default_lifetime_seconds")]
    pub lifetime_seconds: u64,
    /// Threads that prepare and sign messages; one per CPU by default.
    pub preparation_threads: Option<usize>,
}

impl Submission {
    fn default_max_message_bytes() -> usize {
        40_000_000
    }

    fn default_max_recipients() -> usize {
        50
    }

    fn default_idle_seconds() -> u64 {
        300
    }

    fn default_lifetime_seconds() -> u64 {
        3 * 24 * 3600
    }
}

/// The SES v2 API's HTTPS listener. Its messages are held to submission's
/// limits, lifetime and preparation pool, like any submitted message.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ses {
    pub listen: String,
    pub certificate: PathBuf,
    pub key: PathBuf,
    /// The region its clients sign requests for, such as `us-east-1`.
    pub region: String,
}

/// The SNS subset: what its messages are signed with, and where
/// consumers reach it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sns {
    /// The HTTPS origin consumers reach the SES API's listener at, such as
    /// `https://ses.example.com`: its `SubscribeURL`s, `UnsubscribeURL`s and
    /// certificates are under it.
    pub url: String,
    /// The RSA key messages are signed with, in PEM, read again on SIGHUP.
    pub key: PathBuf,
    /// The key's certificate, which consumers verify messages with.
    pub certificate: PathBuf,
    /// Certificates of keys used before, served while messages signed with
    /// them may still be checked.
    #[serde(default)]
    pub previous_certificates: Vec<PathBuf>,
}

/// The admin service: the native API on a local socket, which only the
/// engine's own user, or root, may use.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    pub socket: PathBuf,
}

/// The feedback listener: bounce and complaint reports, by SMTP,
/// for the return paths at `[delivery] return_path_domain` and the
/// complaint loops' addresses.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feedback {
    /// Port 25, where the return path domain's MX points.
    pub listen: String,
    /// The name it greets with: the MX's own.
    pub hostname: String,
    pub certificate: PathBuf,
    pub key: PathBuf,
    /// The addresses complaint loops send their reports to.
    #[serde(default)]
    pub loops: Vec<String>,
    /// The largest report taken. What is kept of one is its first 64 KiB.
    #[serde(default = "Feedback::default_max_report_bytes")]
    pub max_report_bytes: usize,
    /// How long it waits for a reporter before closing.
    #[serde(default = "Feedback::default_idle_seconds")]
    pub idle_seconds: u64,
    /// The reporters the operator enrolled with, by the domain that signs
    /// their reports: a report with a DKIM signature that
    /// verifies, by one of these or a domain under it, is authenticated.
    /// None by default, when nothing is looked up.
    #[serde(default)]
    pub reporters: Vec<String>,
    /// The least class of report whose bounces and complaints suppress an
    /// address and count: `correlated`, by default, or `authenticated`.
    #[serde(default)]
    pub trusted: Trusted,
}

/// A class of report evidence, as configuration names it.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Trusted {
    #[default]
    Correlated,
    Authenticated,
}

impl Feedback {
    fn default_max_report_bytes() -> usize {
        1024 * 1024
    }

    fn default_idle_seconds() -> u64 {
        60
    }
}

/// The outbound network policy, for delivery and webhooks alike.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outbound {
    /// Private and link-local destinations are refused unless this is set,
    /// for a test against local receivers.
    #[serde(default)]
    pub allow_private_destinations: bool,
}

impl Outbound {
    pub fn policy(&self) -> engine_core::outbound::Outbound {
        engine_core::outbound::Outbound {
            private_allowed: self.allow_private_destinations,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tls {
    /// The certificate authorities that MTA-STS's policy hosts and
    /// exchanges, and event subscribers over `https`, must chain to, as a
    /// PEM bundle; the system's when absent.
    pub authorities: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub helo: String,
    /// Where bounces go: each message's envelope sender is its correlation
    /// token at this domain.
    pub return_path_domain: String,
    /// The secret the tokens are made with, in hex: 32 bytes or more, kept
    /// as long as bounces may still arrive for mail sent under it.
    pub return_path_key: String,
    /// The secrets tokens were made with before a rotation, in hex:
    /// a bounce to one is still taken, for as long as mail sent under it
    /// may still bounce (`[store] feedback_window_seconds`), and then it may
    /// go. New return paths are made with `return_path_key` alone.
    #[serde(default)]
    pub previous_return_path_keys: Vec<String>,
    /// Deliver only over STARTTLS, with no weaker fallback.
    #[serde(default = "Delivery::default_require_tls")]
    pub require_tls: bool,
    /// Recipients of one message that share a transaction to their site at
    /// most.
    #[serde(default = "Delivery::default_recipients_per_transaction")]
    pub recipients_per_transaction: usize,
    /// How long an idle connection stays open for reuse.
    #[serde(default = "Delivery::default_idle_seconds")]
    pub idle_seconds: u64,
    /// The port every receiver is reached on: SMTP's 25. Another suits
    /// only a receiver that listens on it, such as a test's, as all mail
    /// goes there.
    #[serde(default = "Delivery::default_port")]
    pub port: u16,
    /// The recursive resolver lookups go to: in production a local one,
    /// which can validate DNSSEC and which blocklists answer.
    /// When absent, the nameservers the system's resolv.conf lists. An
    /// address alone is at port 53; `address:port` names another.
    #[serde(default, deserialize_with = "Delivery::resolver")]
    pub resolver: Option<std::net::SocketAddr>,
    /// Honour MTA-STS (RFC 8461): a domain's enforced policy keeps its mail
    /// to the exchanges it names, over TLS the web PKI verifies.
    #[serde(default = "Delivery::yes")]
    pub mta_sts: bool,
    /// The port MTA-STS policy hosts are fetched from: RFC 8461's 443, and
    /// another only for testing.
    #[serde(default = "Delivery::default_mta_sts_port")]
    pub mta_sts_port: u16,
    /// Honour DANE (RFC 7672): every lookup's DNSSEC is validated, which
    /// the resolver must pass through, so an exchange's secure TLSA records
    /// bind its certificate. A lookup that fails validation
    /// fails.
    #[serde(default = "Delivery::yes")]
    pub dane: bool,
    /// DNSSEC's trust anchors, as DNSKEY records in a file; the root's,
    /// built in, when absent.
    pub trust_anchor: Option<PathBuf>,
}

impl Delivery {
    fn resolver<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<std::net::SocketAddr>, D::Error> {
        let Some(text) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };
        text.parse()
            .or_else(|_| {
                text.parse::<std::net::IpAddr>()
                    .map(|ip| std::net::SocketAddr::new(ip, 53))
            })
            .map(Some)
            .map_err(|_| serde::de::Error::custom(format!("{text:?} is not an address")))
    }

    fn default_require_tls() -> bool {
        true
    }

    fn yes() -> bool {
        true
    }

    fn default_mta_sts_port() -> u16 {
        443
    }

    /// The most a receiver must accept (RFC 5321, 4.5.3.1.8).
    fn default_recipients_per_transaction() -> usize {
        100
    }

    fn default_idle_seconds() -> u64 {
        30
    }

    fn default_port() -> u16 {
        25
    }
}

/// Any setting left out takes its default.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scheduler {
    /// Deliveries held in memory at most.
    pub window: usize,
    /// Mebibytes of their bodies held in memory at most; past it, a delivery
    /// waits without its body and reads it back when it is due.
    pub window_mib: usize,
    pub scan_seconds: u64,
    pub scan_page: usize,
    pub retry_first_seconds: u64,
    pub retry_max_seconds: u64,
    /// How long a domain's route is kept at most, whatever its records
    /// allow.
    pub route_ttl_seconds: u64,
    /// How long a stop waits for the attempts under way to finish.
    /// One cut off is recovered as abandoned at the next start.
    pub drain_seconds: u64,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self {
            window: 100_000,
            window_mib: 256,
            scan_seconds: 1,
            scan_page: 1000,
            retry_first_seconds: 60,
            retry_max_seconds: 3600,
            route_ttl_seconds: 3600,
            drain_seconds: 20,
        }
    }
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    toml::from_str(&text).map_err(|error| format!("{}: {}", path.display(), vetted(&error, &text)))
}

/// A configuration error by its line and column, and what kind of fault it
/// is, in the engine's own words and its settings' names alone: never the
/// configuration's text, nor anything of it the parser quotes, since a line
/// of it, a value in the wrong place, or a name where a setting should be
/// may be a secret, such as the return path's key.
fn vetted(error: &toml::de::Error, text: &str) -> String {
    let message = error.message();
    // What a setting takes, or a table has, as the engine's own types name
    // them: the last such clause, after anything the parser quoted.
    let expected = message
        .rsplit_once(", expected ")
        .map_or(String::new(), |(_, expected)| {
            format!(": it takes {expected}")
        });
    let fault = if text.parse::<toml::Table>().is_err() {
        "this is not TOML: a string, table or value is not closed, or not written as TOML writes it"
            .to_owned()
    } else if let Some(name) = message
        .strip_prefix("missing field `")
        .and_then(|rest| rest.strip_suffix('`'))
    {
        format!("the setting `{name}` is needed")
    } else if message.starts_with("unknown field") {
        let has = message
            .rsplit_once(", expected ")
            .map_or(String::new(), |(_, settings)| {
                format!(": it has {settings}")
            });
        format!("a setting this table does not have{has}")
    } else if [
        "unknown variant",
        "invalid type",
        "invalid value",
        "invalid length",
    ]
    .iter()
    .any(|kind| message.starts_with(kind))
    {
        format!("a value this setting does not take{expected}")
    } else {
        "a value this setting does not take".to_owned()
    };
    match error.span() {
        Some(span) => {
            let before = text.get(..span.start).unwrap_or(text);
            let line = before.matches('\n').count() + 1;
            let column = before.chars().rev().take_while(|c| *c != '\n').count() + 1;
            format!("line {line}, column {column}: {fault}")
        }
        None => fault,
    }
}

/// Decodes hex, as configuration writes digests.
pub fn hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configuration_error_says_where_and_never_shows_a_secret() {
        let secret = "5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7";
        let path = std::env::temp_dir().join(format!("nitromta-config-{}", std::process::id()));
        for (text, fault) in [
            // A syntax error on the secret's own line.
            (
                format!("[delivery]\nreturn_path_key = \"{secret}\" junk\n"),
                "this is not TOML",
            ),
            // A secret where a number goes, and with a quote inside it.
            (
                format!("[store]\nreserve_mib = \"{secret}\"\n"),
                "a value this setting does not take: it takes u64",
            ),
            (
                format!("[store]\nreserve_mib = \"x\\\" {secret}\"\n"),
                "a value this setting does not take",
            ),
            // A secret where a word from a list goes.
            (
                format!("[log]\nlevel = \"{secret}\"\n"),
                "a value this setting does not take: it takes one of",
            ),
            // A secret pasted alone, where a setting's name goes.
            (
                format!("[delivery]\n{secret} = 1\n"),
                "a setting this table does not have: it has one of `helo`",
            ),
        ] {
            std::fs::write(&path, &text).unwrap();
            let error = load(&path).err().unwrap();
            assert!(!error.contains("5ec7e"), "{error}");
            assert!(error.contains("line 2, column "), "{error}");
            assert!(error.contains(fault), "{fault} in {error}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_minimal_configuration_takes_the_defaults() {
        let config: Config = toml::from_str(
            r#"
            [store]
            path = "/var/spool/engine/store.db"
            keys = "/etc/engine/keys"

            [submission]
            listen = "0.0.0.0:587"
            hostname = "mta.test"
            certificate = "/etc/engine/tls.crt"
            key = "/etc/engine/tls.key"

            [delivery]
            helo = "mta.test"
            return_path_domain = "bounces.example.test"
            return_path_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "#,
        )
        .unwrap();
        assert_eq!(config.submission.max_recipients, 50);
        assert!(config.admin.is_none());
        assert!(config.delivery.require_tls && !config.outbound.allow_private_destinations);
        assert_eq!(config.scheduler.window, 100_000);
        assert!(config.receivers.is_empty());
        assert!(config.hooks.admission.is_none() && config.hooks.dispatch.is_none());
    }

    #[test]
    fn a_hooks_section_takes_the_defaults_it_leaves_out() {
        let hooks: Hooks = toml::from_str(
            r#"
            [admission]
            [dispatch]
            timeout_ms = 50
            on_failure = "open"
            "#,
        )
        .unwrap();
        let admission = hooks.admission.unwrap();
        assert_eq!(
            (
                admission.timeout_ms,
                admission.concurrency,
                admission.on_failure
            ),
            (1000, 64, OnFailure::Closed)
        );
        let dispatch = hooks.dispatch.unwrap();
        assert_eq!(
            (dispatch.timeout_ms, dispatch.on_failure),
            (50, OnFailure::Open)
        );
        assert!(toml::from_str::<Hooks>("[admission]\non_failure = \"maybe\"").is_err());
    }

    #[test]
    fn the_receiver_rules_are_overridden_under_receivers() {
        let config: Config = toml::from_str(
            r#"
            [store]
            path = "store.db"
            keys = "keys"

            [submission]
            listen = "0.0.0.0:587"
            hostname = "mta.test"
            certificate = "tls.crt"
            key = "tls.key"

            [delivery]
            helo = "mta.test"
            return_path_domain = "bounces.example.test"
            return_path_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            resolver = "127.0.0.1:5354"

            [receivers.defaults]
            connections = 64

            [receivers.Google]
            transactions_per_connection = 20
            "#,
        )
        .unwrap();
        assert_eq!(
            config.delivery.resolver,
            Some("127.0.0.1:5354".parse().unwrap())
        );
        let rules = engine_rules::Rules::new(&config.receivers).unwrap();
        let other = rules.site(&["mx.example.net".to_owned()]).limits();
        let google = rules.site(&["aspmx.l.google.com".to_owned()]).limits();
        assert_eq!(
            (other.connections, google.transactions_per_connection),
            (64, 20)
        );
    }

    #[test]
    fn a_resolver_is_at_port_53_unless_it_names_another() {
        #[derive(Deserialize)]
        struct Only {
            #[serde(default, deserialize_with = "Delivery::resolver")]
            resolver: Option<std::net::SocketAddr>,
        }
        let at = |text: &str| toml::from_str::<Only>(text).map(|only| only.resolver);
        assert_eq!(
            at("resolver = \"10.0.0.1\"").unwrap(),
            Some("10.0.0.1:53".parse().unwrap())
        );
        assert_eq!(
            at("resolver = \"[::1]:5354\"").unwrap(),
            Some("[::1]:5354".parse().unwrap())
        );
        assert!(at("resolver = \"nowhere\"").is_err());
        assert_eq!(at("").unwrap(), None);
    }

    #[test]
    fn hex_decodes_pairs_only() {
        assert_eq!(hex("00ff7A"), Some(vec![0, 255, 122]));
        assert_eq!(hex("abc"), None);
        assert_eq!(hex("zz"), None);
    }
}
