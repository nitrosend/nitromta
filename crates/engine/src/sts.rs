//! MTA-STS for delivery: each domain's policy, looked up as its
//! route is, fetched from its policy host over verified TLS when its record
//! names a new one or a refresh is due, and kept in memory and in the store
//! until it runs out, so neither a blocked lookup nor a restart takes it
//! away. What a record and a policy file mean is decided in
//! `engine_smtp::sts`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use engine_core::command::{Answer, Command};
use engine_core::outbound::Outbound;
use engine_core::sts::Policy;
use engine_core::time::Timestamp;
use engine_smtp::sts::{self, Plan, Record};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::clock::SystemClock;
use crate::store::Store;

/// How long a policy fetch may take, from the lookup of its host to the
/// last byte (RFC 8461, 3.3, asks for a bound).
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Policies kept in memory at most: past them, those kept there
/// longest are forgotten, and read back from the store when next needed.
pub const MOST_KEPT: usize = 10_000;

/// The policies kept in memory, by domain, each with when it was kept
/// there, and the order they were: at most [`MOST_KEPT`], and the order at
/// most twice as long, those kept again since or removed among it.
#[derive(Default)]
struct Kept {
    policies: BTreeMap<Box<str>, (Arc<Policy>, u64)>,
    order: VecDeque<(u64, Box<str>)>,
    next: u64,
    /// Whether every policy the store keeps is kept here too: none was
    /// ever forgotten for room, so one not here is in the store neither.
    whole: bool,
}

impl Kept {
    fn get(&self, domain: &str) -> Option<Arc<Policy>> {
        self.policies
            .get(domain)
            .map(|(policy, _)| Arc::clone(policy))
    }

    fn insert(&mut self, policy: Arc<Policy>) {
        let domain = policy.domain.clone();
        self.next += 1;
        self.order.push_back((self.next, domain.clone()));
        self.policies.insert(domain, (policy, self.next));
        while self.policies.len() > MOST_KEPT {
            let Some((kept, domain)) = self.order.pop_front() else {
                break;
            };
            // Kept again since, it is not the one kept longest.
            if self
                .policies
                .get(&domain)
                .is_some_and(|(_, at)| *at == kept)
            {
                self.policies.remove(&domain);
                self.whole = false;
            }
        }
        if self.order.len() > 2 * MOST_KEPT {
            let policies = &self.policies;
            self.order
                .retain(|(kept, domain)| policies.get(domain).is_some_and(|(_, at)| at == kept));
        }
    }

    fn remove(&mut self, domain: &str) {
        self.policies.remove(domain);
    }
}

pub struct Policies {
    resolver: TokioResolver,
    /// Verifies a policy host's certificate for its name.
    tls: TlsConnector,
    /// Where policy hosts serve: 443, RFC 8461's.
    port: u16,
    outbound: Outbound,
    clock: Arc<SystemClock>,
    store: Store,
    /// Each domain's policy, as last fetched, while it may still hold: those
    /// the store read last, and those fetched or read back since.
    kept: Mutex<Kept>,
    /// When each domain's last fetch failed, while it may be retried.
    failed: Mutex<BTreeMap<Box<str>, Timestamp>>,
}

impl Policies {
    /// Starts from the policies the store kept, which still hold: those
    /// fetched last, at most one more than [`MOST_KEPT`], which tells
    /// whether there are more.
    pub fn new(
        resolver: TokioResolver,
        tls: Arc<ClientConfig>,
        port: u16,
        outbound: Outbound,
        clock: Arc<SystemClock>,
        store: Store,
        kept: Vec<Policy>,
    ) -> Self {
        let mut held = Kept {
            whole: kept.len() <= MOST_KEPT,
            ..Kept::default()
        };
        // Fetched last first: those fetched longest ago are forgotten.
        for policy in kept.into_iter().take(MOST_KEPT).rev() {
            held.insert(Arc::new(policy));
        }
        let kept = held;
        Self {
            resolver,
            tls: TlsConnector::from(tls),
            port,
            outbound,
            clock,
            store,
            kept: Mutex::new(kept),
            failed: Mutex::default(),
        }
    }

    /// The policy that holds for `domain` now, enforcing or not, once its
    /// record has been looked up and whatever that asks for fetched.
    pub async fn policy(&self, domain: &str) -> Option<Arc<Policy>> {
        let record = self.record(domain).await;
        let now = self.clock.now().wall;
        let kept = self.kept(domain, now).await;
        let failed = lock(&self.failed).get(domain).copied();
        match sts::plan(kept.as_deref(), &record, failed, now) {
            Plan::Keep => kept,
            Plan::None => {
                if kept.is_some() {
                    lock(&self.kept).remove(domain);
                }
                None
            }
            Plan::Fetch => {
                let Record::Id(id) = &record else {
                    return kept.filter(|policy| policy.holds(now));
                };
                match self.fetch(domain, id, now).await {
                    Ok(policy) => {
                        lock(&self.failed).remove(domain);
                        let policy = Arc::new(policy);
                        lock(&self.kept).insert(Arc::clone(&policy));
                        // The store keeps it too, so a restart does; the
                        // answer is not waited for.
                        let _ = self.store.submit(Command::KeepSts(Policy::clone(&policy)));
                        Some(policy)
                    }
                    Err(error) => {
                        // Forgotten once retried; a domain asked for no more
                        // is forgotten with the oldest.
                        let mut failed = lock(&self.failed);
                        failed.retain(|_, at| now.saturating_duration_since(*at) < sts::RETRY);
                        failed.insert(domain.into(), now);
                        drop(failed);
                        tracing::warn!(
                            domain,
                            %error,
                            "an MTA-STS policy could not be fetched; the one kept, if any, stands"
                        );
                        kept.filter(|policy| policy.holds(now))
                    }
                }
            }
        }
    }

    /// The policy kept for `domain`: in memory, or, if one may have been
    /// forgotten there for room, read back from the store.
    async fn kept(&self, domain: &str, now: Timestamp) -> Option<Arc<Policy>> {
        {
            let kept = lock(&self.kept);
            if let Some(policy) = kept.get(domain) {
                return Some(policy);
            }
            if kept.whole {
                return None;
            }
        }
        let read = Command::StsPolicies {
            now,
            domain: Some(domain.into()),
            limit: 1,
        };
        let Some(Answer::StsPolicies(Ok(mut found))) = self.store.ask(read).await else {
            return None;
        };
        let policy = Arc::new(found.pop()?);
        lock(&self.kept).insert(Arc::clone(&policy));
        Some(policy)
    }

    /// The domain's `_mta-sts` record (RFC 8461, 3.1).
    async fn record(&self, domain: &str) -> Record {
        match self
            .resolver
            .txt_lookup(format!("_mta-sts.{domain}."))
            .await
        {
            Ok(lookup) => {
                let records: Vec<String> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::TXT(txt) => Some(
                            txt.txt_data
                                .iter()
                                .map(|part| String::from_utf8_lossy(part))
                                .collect(),
                        ),
                        _ => None,
                    })
                    .collect();
                sts::record(&records)
            }
            Err(error) if error.is_no_records_found() => Record::Absent,
            Err(_) => Record::Failed,
        }
    }

    /// Fetches the policy `domain`'s record named as `id` (RFC 8461, 3.3):
    /// from its policy host over HTTPS, whose certificate must be valid for
    /// that host's name; a redirect, another status or another media type
    /// is no policy.
    async fn fetch(&self, domain: &str, id: &str, now: Timestamp) -> Result<Policy, String> {
        let host = format!("mta-sts.{domain}");
        let text = tokio::time::timeout(FETCH_TIMEOUT, self.get(&host))
            .await
            .map_err(|_| format!("{host} took too long"))??;
        sts::parse(domain, id, &text, now)
    }

    async fn get(&self, host: &str) -> Result<String, String> {
        let addresses = self
            .resolver
            .lookup_ip(format!("{host}."))
            .await
            .map_err(|error| format!("{host}: {error}"))?;
        let address = addresses
            .iter()
            .find(|ip| self.outbound.permits(*ip))
            .ok_or_else(|| format!("{host} has no address the outbound policy permits"))?;
        let tcp = TcpStream::connect((address, self.port))
            .await
            .map_err(|error| format!("{host}: {error}"))?;
        let name = ServerName::try_from(host.to_owned()).map_err(|error| error.to_string())?;
        let tls = self
            .tls
            .connect(name, tcp)
            .await
            .map_err(|error| format!("{host}: {error}"))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|error| format!("{host}: {error}"))?;
        tokio::spawn(connection);
        let request = http::Request::get("/.well-known/mta-sts.txt")
            .header(http::header::HOST, host)
            .body(Empty::<Bytes>::new())
            .map_err(|error| error.to_string())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| format!("{host}: {error}"))?;
        if response.status() != http::StatusCode::OK {
            return Err(format!("{host} answered {}", response.status()));
        }
        let plain = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/plain"));
        if !plain {
            return Err(format!("{host} served its policy as other than text/plain"));
        }
        let body = Limited::new(response.into_body(), sts::MAX_POLICY_BYTES)
            .collect()
            .await
            .map_err(|error| format!("{host}: {error}"))?
            .to_bytes();
        String::from_utf8(body.to_vec()).map_err(|_| format!("{host}'s policy is not UTF-8"))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use engine_core::sts::Mode;

    use super::*;

    fn policy(domain: &str) -> Arc<Policy> {
        Arc::new(Policy {
            domain: domain.into(),
            id: "1".into(),
            mode: Mode::Enforce,
            mx: vec![format!("mx.{domain}").into()],
            max_age: Duration::from_secs(86_400),
            fetched_at: Timestamp::from_micros(1_800_000_000_000_000),
        })
    }

    #[test]
    fn past_the_most_kept_the_policy_kept_longest_is_forgotten_and_the_store_asked_after() {
        let mut kept = Kept {
            whole: true,
            ..Kept::default()
        };
        kept.insert(policy("first.test"));
        kept.insert(policy("second.test"));
        // Kept again, the first is no longer the one kept longest.
        kept.insert(policy("first.test"));
        for n in 0..MOST_KEPT - 1 {
            kept.insert(policy(&format!("d{n}.test")));
        }
        assert_eq!(kept.policies.len(), MOST_KEPT);
        assert!(kept.get("second.test").is_none());
        assert!(kept.get("first.test").is_some());
        assert!(!kept.whole, "one not here may be in the store");
        assert_eq!(kept.order.len(), MOST_KEPT);
        // Kept again and again, one domain's order stays bounded.
        for _ in 0..3 * MOST_KEPT {
            kept.insert(policy("first.test"));
        }
        assert!(kept.order.len() <= 2 * MOST_KEPT, "{}", kept.order.len());
        assert_eq!(kept.policies.len(), MOST_KEPT);
    }
}
