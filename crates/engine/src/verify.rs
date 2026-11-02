//! Identity verification: whether an identity's DKIM record
//! publishes its key, the one test `doctor` and the verifier make, and the
//! verifier itself, which checks every identity created through SES's API,
//! and every MAIL FROM domain put through it, on its schedule, and records
//! each change of status as one policy change.
//!
//! A pending check runs at once, then after one minute, two, four and so on,
//! at most every fifteen; a verified one daily; a temporarily failing one
//! hourly; a failed one never, until a new key or domain is put. When each
//! is due is kept in memory alone, so a start checks every one again. At
//! most [`AT_ONCE`] lookups run at once, on the verifier's own task.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use engine_core::command::{Answer, Command, Commit};
use engine_core::id::IdentityId;
use engine_core::policy::{Amendment, Change, Check, Identity, Verification};
use engine_core::time::Timestamp;
use engine_message::dkim::Signer;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::clock::SystemClock;
use crate::policy::Current;
use crate::store::Store;

/// Lookups at most at once.
const AT_ONCE: usize = 16;
/// How long a pending check waits after its first, doubling each time to
/// at most [`LONGEST_WAIT`].
const FIRST_WAIT: Duration = Duration::from_secs(60);
const LONGEST_WAIT: Duration = Duration::from_secs(15 * 60);
const RECHECK: Duration = Duration::from_secs(24 * 3600);
const LAPSING_RECHECK: Duration = Duration::from_secs(3600);
/// How long a key may go unfound, before it is first found or once it is
/// no longer, before its check fails, as SES's does.
const GIVE_UP: Duration = Duration::from_secs(72 * 3600);
/// How often the verifier looks for checks due and policy changed.
const TICK: Duration = Duration::from_secs(1);

/// What a lookup found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Found {
    Ours,
    Not,
    /// No answer: a timeout or a server failure.
    NoAnswer,
}

/// What the verifier checks of an identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Subject {
    /// That its DKIM record publishes the key `key`, at `selector`.
    Dkim { selector: String, key: String },
    /// That its MAIL FROM domain's MX names the bounce host.
    MailFrom(Arc<str>),
}

/// Which of an identity's checks: one of each at most.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Dkim,
    MailFrom,
}

impl Subject {
    fn kind(&self) -> Kind {
        match self {
            Self::Dkim { .. } => Kind::Dkim,
            Self::MailFrom(_) => Kind::MailFrom,
        }
    }
}

/// Where a check of `kind` stands after a lookup at `now` found `found`:
/// found, it is verified; not found, a verified key lapses, and a verified
/// MAIL FROM domain fails at once, so no bounce goes astray; and one pending
/// or lapsing fails once [`GIVE_UP`] has passed, answered or not.
fn next(kind: Kind, check: Check, found: Found, now: Timestamp) -> Check {
    let since = |status| Check { status, since: now };
    let overdue = now.saturating_duration_since(check.since) >= GIVE_UP;
    match (check.status, found) {
        (Verification::Success, Found::Ours) | (Verification::Failed, _) => check,
        (_, Found::Ours) => since(Verification::Success),
        (Verification::Success, Found::Not) => since(match kind {
            Kind::Dkim => Verification::TemporaryFailure,
            Kind::MailFrom => Verification::Failed,
        }),
        (Verification::Success, Found::NoAnswer) => check,
        (Verification::Pending | Verification::TemporaryFailure, _) if overdue => {
            since(Verification::Failed)
        }
        (Verification::Pending | Verification::TemporaryFailure, _) => check,
    }
}

/// When the check after one that left `check` is due, and the wait after
/// that for one still pending: none once it has failed.
fn after(check: Check, wait: Duration) -> Option<(Duration, Duration)> {
    match check.status {
        Verification::Pending => Some((wait, (wait * 2).min(LONGEST_WAIT))),
        Verification::Success => Some((RECHECK, FIRST_WAIT)),
        Verification::TemporaryFailure => Some((LAPSING_RECHECK, FIRST_WAIT)),
        Verification::Failed => None,
    }
}

pub struct Verifier {
    pub policy: Arc<Current>,
    pub store: Store,
    /// As receivers see the DNS.
    pub resolver: TokioResolver,
    pub clock: Arc<SystemClock>,
    /// Where bounces arrive, which a MAIL FROM domain's MX must name: none
    /// if the installation takes none, when none is checked.
    pub bounce_host: Option<String>,
    /// In capture mode, which reaches nothing outside the host:
    /// nothing is looked up, and every record is taken as found, so its
    /// mail is captured as it would be sent.
    pub capture: bool,
}

/// One check's next run.
struct Due {
    /// What it checks and where it stood as last seen: a change to either
    /// starts its schedule again.
    seen: (Subject, Check),
    at: Instant,
    wait: Duration,
}

/// A check done: of which identity, of what it saw, and where it stands
/// now, if that was recorded.
struct Done {
    identity: IdentityId,
    seen: (Subject, Check),
    recorded: Option<Check>,
}

impl Verifier {
    pub async fn run(self: Arc<Self>) {
        let mut due: HashMap<(IdentityId, Kind), Due> = HashMap::new();
        let mut running: HashSet<(IdentityId, Kind)> = HashSet::new();
        let mut checks: JoinSet<Done> = JoinSet::new();
        let mut revision = None;
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                Some(Ok(done)) = checks.join_next(), if !checks.is_empty() => {
                    let key = (done.identity, done.seen.0.kind());
                    running.remove(&key);
                    let Some(entry) = due.get_mut(&key) else {
                        continue;
                    };
                    // Changed since it began: the next look schedules it.
                    if entry.seen != done.seen {
                        continue;
                    }
                    let check = done.recorded.unwrap_or(done.seen.1);
                    entry.seen.1 = check;
                    match after(check, entry.wait) {
                        Some((wait, next)) => {
                            entry.at = Instant::now() + wait;
                            entry.wait = next;
                        }
                        None => {
                            due.remove(&key);
                        }
                    }
                    continue;
                }
            }
            let snapshot = self.policy.load();
            let policy = snapshot.policy();
            if revision != Some(policy.revision()) {
                revision = Some(policy.revision());
                let mut checked = HashSet::new();
                for identity in policy.identities() {
                    for seen in self.checkable(identity) {
                        let key = (identity.id, seen.0.kind());
                        checked.insert(key);
                        if due.get(&key).is_none_or(|entry| entry.seen != seen) {
                            due.insert(
                                key,
                                Due {
                                    seen,
                                    at: Instant::now(),
                                    wait: FIRST_WAIT,
                                },
                            );
                        }
                    }
                }
                due.retain(|key, _| checked.contains(key));
            }
            let now = Instant::now();
            for (key, entry) in &due {
                if running.len() >= AT_ONCE {
                    break;
                }
                if entry.at > now || running.contains(key) {
                    continue;
                }
                let Some(identity) = policy.identity(key.0) else {
                    continue;
                };
                running.insert(*key);
                let verifier = Arc::clone(&self);
                let identity = identity.clone();
                let seen = entry.seen.clone();
                checks.spawn(async move { verifier.check(identity, seen).await });
            }
        }
    }

    /// What the verifier checks of `identity`: its key, if it was created
    /// through SES's API, and its MAIL FROM domain, each with its check,
    /// while that has not failed.
    fn checkable(&self, identity: &Identity) -> Vec<(Subject, Check)> {
        let dkim = identity
            .verification
            .zip(identity.signing.as_ref())
            .map(|(check, signing)| {
                let subject = Subject::Dkim {
                    selector: signing.selector.clone(),
                    key: signing.key.clone(),
                };
                (subject, check)
            });
        let mail_from = identity
            .mail_from
            .as_ref()
            .filter(|_| self.bounce_host.is_some())
            .map(|own| (Subject::MailFrom(Arc::clone(&own.domain)), own.check));
        [dkim, mail_from]
            .into_iter()
            .flatten()
            .filter(|(_, check)| check.status != Verification::Failed)
            .collect()
    }

    /// Looks up what `seen` checks of `identity`, and records where its
    /// check stands if that changed.
    async fn check(&self, identity: Identity, seen: (Subject, Check)) -> Done {
        let (subject, check) = &seen;
        let (owner, found) = match subject {
            _ if self.capture => (identity.domain().to_owned(), Found::Ours),
            Subject::Dkim { selector, key } => {
                let owner = format!("{selector}._domainkey.{}", identity.domain());
                let ours = Signer::from_pem(key, identity.domain(), selector, &[])
                    .map(|signer| signer.public_key());
                let found = match (txt(&self.resolver, &owner).await, ours) {
                    (Err(NoAnswer), _) => Found::NoAnswer,
                    (Ok(records), Ok(ours)) => match dkim(&records, &ours) {
                        Dkim::Ours => Found::Ours,
                        Dkim::Not(_) => Found::Not,
                    },
                    // Checked before a change carries it.
                    (Ok(_), Err(_)) => Found::Not,
                };
                (owner, found)
            }
            Subject::MailFrom(domain) => {
                let host = self.bounce_host.as_deref().unwrap_or_default();
                let found = match exchanges(&self.resolver, domain).await {
                    Err(NoAnswer) => Found::NoAnswer,
                    Ok(names) if names.iter().any(|name| name.eq_ignore_ascii_case(host)) => {
                        Found::Ours
                    }
                    Ok(_) => Found::Not,
                };
                (domain.to_string(), found)
            }
        };
        let now = self.clock.now().wall;
        let updated = next(subject.kind(), *check, found, now);
        let mut done = Done {
            identity: identity.id,
            seen: seen.clone(),
            recorded: None,
        };
        if updated == *check {
            return done;
        }
        let amendment = match subject {
            Subject::Dkim { selector, key } => Amendment::Checked {
                identity: identity.id,
                selector: selector.clone(),
                key: key.clone(),
                from: *check,
                check: updated,
            },
            Subject::MailFrom(domain) => Amendment::MailFromChecked {
                identity: identity.id,
                domain: domain.to_string(),
                from: *check,
                check: updated,
            },
        };
        let change = Change::Amend {
            account: identity.account,
            name: identity.name.clone(),
            amendment,
        };
        if let Some(Answer::Policy(Commit::Committed(_))) =
            self.store.ask(Command::ChangePolicy(change)).await
        {
            tracing::info!(
                identity = %identity.name,
                check = ?subject.kind(),
                from = ?check.status,
                to = ?updated.status,
                %owner,
                "an identity's check changed"
            );
            done.recorded = Some(updated);
        }
        done
    }
}

/// The exchanges `domain`'s MX records name, its CNAMEs followed, each
/// without its final dot: none when the name or its records are not there.
async fn exchanges(resolver: &TokioResolver, domain: &str) -> Result<Vec<String>, NoAnswer> {
    match resolver.mx_lookup(format!("{domain}.")).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::MX(mx) => Some(mx.exchange.to_ascii().trim_end_matches('.').to_owned()),
                _ => None,
            })
            .collect()),
        Err(error) if error.is_nx_domain() || error.is_no_records_found() => Ok(Vec::new()),
        Err(_) => Err(NoAnswer),
    }
}

/// A lookup that got no answer: a timeout or a server failure, as opposed
/// to a name or record that is not there.
#[derive(Debug, PartialEq, Eq)]
pub struct NoAnswer;

/// The TXT records of `owner`, each its strings joined: none when the name
/// or its records are not there.
pub async fn txt(resolver: &TokioResolver, owner: &str) -> Result<Vec<String>, NoAnswer> {
    match resolver.txt_lookup(format!("{owner}.")).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part).into_owned())
                        .collect(),
                ),
                _ => None,
            })
            .collect()),
        Err(error) if error.is_nx_domain() || error.is_no_records_found() => Ok(Vec::new()),
        Err(_) => Err(NoAnswer),
    }
}

/// What a selector's records say of an identity's key.
pub enum Dkim {
    /// One of them is its key, for RSA and SHA-256 email signatures.
    Ours,
    /// None is, and why not.
    Not(String),
}

/// Whether one of the `published` TXT records is a DKIM key record (RFC
/// 6376, 3.6.1) for `ours`, a SubjectPublicKeyInfo in base64: the same RSA
/// key, however encoded, as SubjectPublicKeyInfo or as RSAPublicKey, for
/// email, RSA, and SHA-256.
pub fn dkim(published: &[String], ours: &str) -> Dkim {
    let parse = |encoded: &str| {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .ok()
            .and_then(|der: Vec<u8>| aws_lc_rs::rsa::PublicKey::from_der(&der).ok())
    };
    let Some(ours) = parse(ours) else {
        return Dkim::Not("cannot be compared: the engine's key does not decode".to_owned());
    };
    let mut why = None;
    for record in published {
        let Some(tags) = tags(record) else {
            why = Some(
                "publishes a DKIM record that is not a tag list: a tag twice, or one without its value"
                    .to_owned(),
            );
            continue;
        };
        let value = |name: &str| {
            tags.iter()
                .find(|(tag, _)| tag == name)
                .map(|(_, value)| value.as_str())
        };
        // A v= is the record's first tag, and says DKIM1.
        if value("v").is_some()
            && tags
                .first()
                .is_none_or(|(tag, value)| tag != "v" || value != "DKIM1")
        {
            continue;
        }
        let Some(key) = value("p") else {
            continue;
        };
        let listed = |name: &str, wanted: &[&str]| {
            value(name).is_none_or(|list| list.split(':').any(|item| wanted.contains(&item)))
        };
        why = Some(if key.is_empty() {
            "publishes its key as revoked (p= is empty)".to_owned()
        } else if value("k").is_some_and(|kind| kind != "rsa") {
            format!(
                "publishes a key for another algorithm (k={})",
                value("k").unwrap_or_default()
            )
        } else if !listed("h", &["sha256"]) {
            format!(
                "limits its key to other hashes (h={})",
                value("h").unwrap_or_default()
            )
        } else if !listed("s", &["*", "email"]) {
            format!(
                "limits its key to other services (s={})",
                value("s").unwrap_or_default()
            )
        } else if parse(key).is_some_and(|theirs| theirs.as_ref() == ours.as_ref()) {
            return Dkim::Ours;
        } else {
            "publishes another DKIM key".to_owned()
        });
    }
    Dkim::Not(why.unwrap_or_else(|| "publishes no DKIM key".to_owned()))
}

/// A tag list's tags (RFC 6376 3.2), in order, each value's whitespace
/// taken out: none if it is not one, with a tag twice, a part that is not a
/// tag and its value, or a tag's name that is not a name.
fn tags(record: &str) -> Option<Vec<(String, String)>> {
    let mut tags: Vec<(String, String)> = Vec::new();
    for part in record
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (tag, value) = part.split_once('=')?;
        let tag = tag.trim();
        let named = tag.starts_with(|c: char| c.is_ascii_alphabetic())
            && tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !named || tags.iter().any(|(seen, _)| seen == tag) {
            return None;
        }
        tags.push((tag.to_owned(), value.split_whitespace().collect()));
    }
    Some(tags)
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::KeyPair as _;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    #[test]
    fn a_key_is_verified_when_found_lapses_when_not_and_fails_after_three_days() {
        let next = |check, found, now| next(Kind::Dkim, check, found, now);
        let hours = |count: u64| Timestamp::from_micros(count * 3_600_000_000);
        let check = |status, since| Check { status, since };
        let pending = check(Verification::Pending, hours(0));
        assert_eq!(
            next(pending, Found::Ours, hours(1)),
            check(Verification::Success, hours(1))
        );
        for found in [Found::Not, Found::NoAnswer] {
            assert_eq!(next(pending, found, hours(71)), pending);
            assert_eq!(
                next(pending, found, hours(72)),
                check(Verification::Failed, hours(72))
            );
        }
        let verified = check(Verification::Success, hours(1));
        assert_eq!(next(verified, Found::Ours, hours(30)), verified);
        assert_eq!(next(verified, Found::NoAnswer, hours(30)), verified);
        let lapsing = check(Verification::TemporaryFailure, hours(30));
        assert_eq!(next(verified, Found::Not, hours(30)), lapsing);
        assert_eq!(next(lapsing, Found::Not, hours(101)), lapsing);
        assert_eq!(
            next(lapsing, Found::Ours, hours(40)),
            check(Verification::Success, hours(40))
        );
        assert_eq!(
            next(lapsing, Found::Not, hours(102)),
            check(Verification::Failed, hours(102))
        );
        // A failed check stays failed until a new key is put.
        let failed = check(Verification::Failed, hours(72));
        assert_eq!(next(failed, Found::Ours, hours(80)), failed);
    }

    #[test]
    fn a_mail_from_domain_that_no_longer_points_at_the_bounce_host_fails_at_once() {
        let hours = |count: u64| Timestamp::from_micros(count * 3_600_000_000);
        let check = |status, since| Check { status, since };
        let next = |check, found, now| next(Kind::MailFrom, check, found, now);
        let verified = check(Verification::Success, hours(1));
        assert_eq!(
            next(verified, Found::Not, hours(30)),
            check(Verification::Failed, hours(30))
        );
        assert_eq!(next(verified, Found::NoAnswer, hours(30)), verified);
        let pending = check(Verification::Pending, hours(0));
        assert_eq!(
            next(pending, Found::Ours, hours(1)),
            check(Verification::Success, hours(1))
        );
        assert_eq!(next(pending, Found::Not, hours(71)), pending);
    }

    #[test]
    fn a_pending_check_waits_longer_each_time_and_a_failed_one_is_not_checked() {
        let check = |status| Check {
            status,
            since: Timestamp::from_micros(0),
        };
        let minutes = |count: u64| Duration::from_secs(count * 60);
        let mut wait = FIRST_WAIT;
        let mut waits = Vec::new();
        for _ in 0..6 {
            let (now, next) = after(check(Verification::Pending), wait).unwrap();
            waits.push(now);
            wait = next;
        }
        assert_eq!(
            waits,
            [1, 2, 4, 8, 15, 15].map(minutes),
            "doubling to a quarter hour"
        );
        assert_eq!(
            after(check(Verification::Success), wait),
            Some((RECHECK, FIRST_WAIT))
        );
        assert_eq!(
            after(check(Verification::TemporaryFailure), wait),
            Some((LAPSING_RECHECK, FIRST_WAIT))
        );
        assert_eq!(after(check(Verification::Failed), wait), None);
    }

    #[test]
    fn tags_are_read_in_order_whatever_their_whitespace_and_only_once_each() {
        assert_eq!(
            tags("v=DKIM1; k=rsa; p=AB CD\tEF;"),
            Some(
                [("v", "DKIM1"), ("k", "rsa"), ("p", "ABCDEF")]
                    .map(|(tag, value)| (tag.to_owned(), value.to_owned()))
                    .to_vec()
            )
        );
        assert_eq!(tags("v=DKIM1; p=A; p="), None);
        assert_eq!(tags("v=DKIM1; rsa; p=A"), None);
        assert_eq!(tags("v=DKIM1; 1k=rsa; p=A"), None);
    }

    #[test]
    fn a_dkim_record_holds_the_key_however_encoded_and_only_for_its_use() {
        let key = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let spki = key.public_key().as_der().unwrap();
        let ours = STANDARD.encode(spki.as_ref());
        // The same key as an RSAPublicKey: the SubjectPublicKeyInfo after
        // its header, which is the same for every 2048-bit RSA key.
        let pkcs1 = STANDARD.encode(&spki.as_ref()[24..]);
        let other = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let theirs = STANDARD.encode(other.public_key().as_der().unwrap().as_ref());
        let found = |records: &[String]| match dkim(records, &ours) {
            Dkim::Ours => "ours".to_owned(),
            Dkim::Not(why) => why,
        };
        let one = |record: String| found(&[record]);
        assert_eq!(one(format!("v=DKIM1; k=rsa; p={ours}")), "ours");
        assert_eq!(one(format!("p={pkcs1}")), "ours");
        assert_eq!(one(format!("v=DKIM1; h=sha1:sha256; p={pkcs1}")), "ours");
        assert_eq!(
            one(format!("v=DKIM1; k=ed25519; p={ours}")),
            "publishes a key for another algorithm (k=ed25519)"
        );
        assert_eq!(
            one(format!("v=DKIM1; k=rsa:ed25519; p={ours}")),
            "publishes a key for another algorithm (k=rsa:ed25519)"
        );
        assert_eq!(
            one(format!("v=DKIM1; p={ours}; p=")),
            "publishes a DKIM record that is not a tag list: a tag twice, or one without its value"
        );
        assert_eq!(
            one(format!("v=DKIM1; h=sha1; p={ours}")),
            "limits its key to other hashes (h=sha1)"
        );
        assert_eq!(
            one("v=DKIM1; k=rsa; p=".to_owned()),
            "publishes its key as revoked (p= is empty)"
        );
        assert_eq!(
            one(format!("v=DKIM1; p={theirs}")),
            "publishes another DKIM key"
        );
        // A v= anywhere but first, or another version, is not a key record.
        assert_eq!(
            one(format!("k=rsa; v=DKIM1; p={ours}")),
            "publishes no DKIM key"
        );
        assert_eq!(found(&[]), "publishes no DKIM key");
        // One record of several being the key is enough.
        assert_eq!(
            found(&[format!("v=DKIM1; p={theirs}"), format!("v=DKIM1; p={ours}")]),
            "ours"
        );
    }
}
