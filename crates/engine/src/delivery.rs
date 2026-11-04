//! Delivery: for each receiver site, from each egress, the transactions
//! reserved for it and up to its rules' number of connections.
//! A site's queues share them: each connection goes to one queue's
//! exchanges, runs a client session that takes that queue's next
//! transaction whenever it is ready, and closes after its rules' number of
//! transactions, after a reply that throttles the site, or after standing
//! idle. When the site has no room for another and a transaction waits for
//! exchanges no connection goes to, an idle connection gives its place up.
//!
//! Every reply other than 2xx is judged by the site's rules here, as it is
//! read, and the verdict goes to the scheduler with the outcome.
//!
//! A connection tries its queue's exchanges in order of preference until
//! one is ready for an attempt: an exchange refused, unreachable, or whose
//! TLS could not prove what its route asks, makes way for the next (RFC
//! 5321, 5.1), unless a refusal throttles the site. What TLS must prove
//! comes with the route: an exchange with secure TLSA records is verified
//! by them (DANE), else, where an MTA-STS policy enforces, by the web PKI
//! for its name, and otherwise encryption is opportunistic; nothing falls
//! back to less after a failure.
//!
//! It also looks domains' routes up for the scheduler, through the
//! resolver, which says what DNSSEC proved of each answer while DANE is
//! honoured and it is on this host, with each domain's MTA-STS policy; what
//! they mean is decided in `engine_smtp::route`.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::attempt::Evidence;
use engine_core::component::Component;
use engine_core::delivery::DispatchPermit;
use engine_core::id::{EgressId, Id, MessageId};
use engine_core::outbound::Outbound;
use engine_core::policy::Egress;
use engine_core::time::Timestamp;
use engine_feedback::token;
use engine_scheduler::{Attempted, Dispatch, Tls};
use engine_smtp::client::{self, Failure, Input, Job, Outcome, Output, Session};
use engine_smtp::dane::{self, Requirement, Tlsa};
use engine_smtp::reply::Reply;
use engine_smtp::route::{self, Answer};
use engine_store::keys::Unopened;

use crate::sealing::Sealer;
use futures_core::Stream;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, DnsHandle, NetError, NoRecords};
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::op::{DnsRequest, DnsResponse, Message};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use hickory_resolver::{ConnectionProvider, PoolContext, TokioResolver};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::Notify;
use tokio::sync::mpsc::UnboundedSender;
use tokio_rustls::TlsConnector;

use crate::clock::SystemClock;
use crate::config;
use crate::stream::{self, Read};
use crate::sts::Policies;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a receiver may take to complete STARTTLS's handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long an empty answer holds when it gives no negative TTL.
const NEGATIVE_TTL: Duration = Duration::from_secs(60);
/// The most aliases a name's chain may hold before it counts as broken.
const MAX_ALIASES: usize = 8;

#[derive(Clone)]
pub struct Deliverer {
    inner: Arc<Inner>,
}

struct Inner {
    session: client::Config,
    idle: Duration,
    outbound: Outbound,
    port: u16,
    return_path_domain: String,
    return_path_key: token::Key,
    resolver: Resolver,
    /// Whether DANE is honoured, so what an answer proved counts.
    dane: bool,
    /// Each domain's MTA-STS policy, when MTA-STS is honoured.
    policies: Option<Arc<Policies>>,
    /// Encrypts without verifying.
    tls: TlsConnector,
    /// Verifies a certificate by the web PKI for the exchange's name, when
    /// MTA-STS is honoured.
    verified: Option<TlsConnector>,
    scheduler: UnboundedSender<engine_scheduler::Input>,
    clock: Arc<SystemClock>,
    sites: Mutex<BTreeMap<SiteKey, Arc<Site>>>,
    /// Opens a body sealed under any key, whether or not
    /// encryption is on now.
    sealer: Arc<Sealer>,
}

/// An (egress, site), whose connections its queues share from one egress:
/// the host's own address when the egress is absent.
type SiteKey = (Option<EgressId>, Arc<str>);

struct Site {
    /// Its limits, and its verdicts on replies.
    rules: engine_rules::Site,
    /// The egress its connections go out from, as the latest dispatch has
    /// it: the address they are bound to, and the name they greet with.
    egress: Mutex<Option<Arc<Egress>>>,
    /// Whether binding to its egress's address has failed and been
    /// reported, so it is reported once.
    unbound: AtomicBool,
    lines: Mutex<Lines>,
}

/// A site's transactions and connections, changed together under one lock,
/// so a waiting transaction is never missed. A dispatch touches its own
/// queue's line alone.
#[derive(Default)]
struct Lines {
    /// Each queue's, by its name, while it has anything.
    queues: BTreeMap<Arc<str>, Line>,
    /// Open connections, from all the site's queues.
    connections: usize,
    /// How many transactions have come: each waiting one's place in the
    /// order they came.
    arrived: u64,
    /// A reply throttled the site: its waiting transactions went back to
    /// the scheduler, and it takes none until its connections have closed.
    throttled: bool,
}

/// One queue's transactions and connections at its site.
struct Line {
    exchanges: Arc<[String]>,
    /// What its connections' TLS must prove.
    tls: Tls,
    /// The domain its mail is for, on a DANE route.
    next_hop: Option<Arc<str>>,
    /// Transactions waiting for a connection, oldest first, each with its
    /// place in the order the site's came.
    waiting: VecDeque<(u64, Job<DispatchPermit>)>,
    /// Connections open to its exchanges.
    open: usize,
    /// Those standing idle, each with what wakes it.
    idle: Vec<Arc<Notify>>,
}

/// One connection's own state.
struct Connection {
    /// The queue whose exchanges it goes to.
    queue: Arc<str>,
    /// Transactions it has taken.
    taken: usize,
    /// A reply on it throttled its site: it takes no more.
    throttled: bool,
}

impl Lines {
    /// The queue whose transaction has waited longest with no connection
    /// open to its exchanges, if one waits so.
    fn unserved(&self) -> Option<&Arc<str>> {
        self.queues
            .iter()
            .filter(|(_, line)| line.open == 0)
            .filter_map(|(queue, line)| Some((line.waiting.front()?.0, queue)))
            .min_by_key(|(arrived, _)| *arrived)
            .map(|(_, queue)| queue)
    }

    /// Takes the oldest transaction waiting for `queue`'s exchanges.
    fn take(&mut self, queue: &str) -> Option<Job<DispatchPermit>> {
        self.queues
            .get_mut(queue)?
            .waiting
            .pop_front()
            .map(|(_, job)| job)
    }

    /// Takes every transaction waiting at the site.
    fn take_all(&mut self) -> Vec<Job<DispatchPermit>> {
        self.queues
            .values_mut()
            .flat_map(|line| line.waiting.drain(..).map(|(_, job)| job))
            .collect()
    }

    /// Forgets the lines that hold nothing.
    fn tidy(&mut self) {
        self.queues
            .retain(|_, line| line.open > 0 || !line.waiting.is_empty() || !line.idle.is_empty());
    }
}

/// Delivery's resolver: hickory's, over connections that ask what DNSSEC
/// proved of each answer.
pub type Resolver = hickory_resolver::Resolver<Asking>;

/// The resolver delivery's lookups go through: the one the configuration
/// names, or the system's, as they are now; and its nameservers not on this
/// host. It asks for DNSSEC's verdict while DANE is honoured and there are
/// none.
pub fn resolver(config: &config::Delivery) -> Result<(Resolver, Vec<IpAddr>), String> {
    let nameservers = resolver_config(config)?;
    let remote = elsewhere(&nameservers);
    let asking = Asking {
        ask: config.dane && remote.is_empty(),
        runtime: TokioRuntimeProvider::default(),
    };
    let resolver = Resolver::builder_with_config(nameservers, asking)
        .build()
        .map_err(|error| format!("the resolver: {error}"))?;
    Ok((resolver, remote))
}

/// The same resolver as receivers see the DNS, for `doctor`'s checks and
/// identities' verification: never through this host's own hosts file, and
/// asking nothing of DNSSEC, which none of those records needs; a
/// validating resolver still refuses a bogus answer.
pub fn public_resolver(config: &config::Delivery) -> Result<TokioResolver, String> {
    let mut builder = TokioResolver::builder_with_config(
        resolver_config(config)?,
        TokioRuntimeProvider::default(),
    );
    builder.options_mut().use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
    builder
        .build()
        .map_err(|error| format!("the resolver: {error}"))
}

/// Connections to delivery's resolver. While they ask, each query sets
/// the AD bit, which asks for the resolver's verdict without its DNSSEC
/// records (RFC 6840, 5.7), and a reply with the AD bit set proves its
/// answer and authority records secure, the sections that bit speaks for
/// (RFC 4035, 3.2.3). It asks only a resolver on this host: the AD bit of
/// one across a network proves nothing, its path unprotected (RFC 4035,
/// 4.9.3). Unproved, an answer is insecure, so DANE is not used for it and
/// its mail goes as it would without DANE, never held. Validating is that
/// resolver's work, as it is for Postfix: the engine validates nothing, and
/// takes the resolver at its word, so it must validate DNSSEC itself, not
/// pass on another's verdict as a forwarder may.
#[derive(Clone)]
pub struct Asking {
    ask: bool,
    runtime: TokioRuntimeProvider,
}

/// hickory's own connection to a nameserver.
type Exchange = <TokioRuntimeProvider as ConnectionProvider>::Conn;

impl ConnectionProvider for Asking {
    type Conn = Asked;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Asked, NetError>> + Send>>;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let connecting = self.runtime.new_connection(ip, config, cx)?;
        let ask = self.ask;
        Ok(Box::pin(async move {
            Ok(Asked {
                exchange: connecting.await?,
                ask,
            })
        }))
    }

    fn runtime_provider(&self) -> &TokioRuntimeProvider {
        &self.runtime
    }
}

/// One connection to a nameserver of delivery's resolver.
#[derive(Clone)]
pub struct Asked {
    exchange: Exchange,
    ask: bool,
}

impl DnsHandle for Asked {
    type Response = Proved;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, mut request: DnsRequest) -> Proved {
        if self.ask {
            request.metadata.authentic_data = true;
        }
        Proved {
            replies: self.exchange.send(request),
            ask: self.ask,
        }
    }
}

/// A query's replies, each with what it proved.
pub struct Proved {
    replies: <Exchange as DnsHandle>::Response,
    ask: bool,
}

impl Stream for Proved {
    type Item = Result<DnsResponse, NetError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let ask = self.ask;
        Pin::new(&mut self.replies)
            .poll_next(context)
            .map_ok(|mut reply| {
                prove(&mut reply, ask);
                reply
            })
    }
}

/// Marks a reply's answer and authority records secure when it was
/// `asked` for the resolver's verdict and its AD bit says the resolver
/// validated them.
fn prove(reply: &mut Message, asked: bool) {
    if !asked || !reply.metadata.authentic_data {
        return;
    }
    for record in reply.answers.iter_mut().chain(&mut reply.authorities) {
        record.proof = Proof::Secure;
    }
}

/// The nameservers among `nameservers` not on this host, whose word on
/// DNSSEC is not taken.
fn elsewhere(nameservers: &ResolverConfig) -> Vec<IpAddr> {
    nameservers
        .name_servers()
        .iter()
        .map(|server| server.ip)
        .filter(|ip| !ip.to_canonical().is_loopback())
        .collect()
}

/// The nameservers delivery's lookups go to: the one the configuration
/// names, or the system's.
pub fn resolver_config(config: &config::Delivery) -> Result<ResolverConfig, String> {
    let nameservers = match config.resolver {
        Some(address) => vec![address],
        None => system_nameservers()?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 53))
            .collect(),
    };
    let servers = nameservers
        .into_iter()
        .map(|address| {
            let connection = |mut connection: ConnectionConfig| {
                connection.port = address.port();
                connection
            };
            NameServerConfig::new(
                address.ip(),
                true,
                vec![
                    connection(ConnectionConfig::udp()),
                    connection(ConnectionConfig::tcp()),
                ],
            )
        })
        .collect();
    Ok(ResolverConfig::from_name_servers(servers))
}

/// While DANE is honoured, says in the log whether it is in effect, and
/// again whenever that changes: never while `remote`, nameservers of
/// delivery's resolver, are not on this host, and otherwise as the resolver
/// answers for the root's keys, asked each minute. While it is not, mail
/// goes as it would without DANE.
pub fn check_dane(resolver: Resolver, remote: &[IpAddr]) {
    if !remote.is_empty() {
        tracing::warn!("{}", not_local(remote));
        return;
    }
    tokio::spawn(async move {
        let mut said = None;
        loop {
            let validated = validates(&resolver).await;
            let now = validated.as_ref().copied().map_err(|_| ());
            if said != Some(now) {
                if now == Ok(true) {
                    tracing::info!("{}", verdict(&validated));
                } else {
                    tracing::warn!("{}", verdict(&validated));
                }
                said = Some(now);
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

/// Whether `resolver` validates DNSSEC, asked afresh: whether it says the
/// root's keys are validated, or why it gave no answer.
pub async fn validates(resolver: &Resolver) -> Result<bool, String> {
    resolver.clear_lookup_cache(Name::root(), RecordType::DNSKEY);
    match resolver.lookup(Name::root(), RecordType::DNSKEY).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .any(|record| matches!(record.data, RData::DNSSEC(_)) && record.proof.is_secure())),
        Err(error) if no_records(&error).is_some() => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

/// What [`validates`] found, as the log and `doctor` say it.
pub fn verdict(validated: &Result<bool, String>) -> String {
    match validated {
        Ok(true) => {
            "DANE is in effect: the resolver says it validated the root's keys".to_owned()
        }
        Ok(false) => "DANE is not in effect: the resolver does not validate DNSSEC, so mail goes as it would without DANE; point [delivery] resolver at one on this host that does, such as unbound".to_owned(),
        Err(error) => format!(
            "whether DANE is in effect is not known: the resolver did not answer for the root's keys ({error})"
        ),
    }
}

/// Why DANE is not in effect when `remote`, nameservers of delivery's
/// resolver, are not on this host.
pub fn not_local(remote: &[IpAddr]) -> String {
    let remote: Vec<String> = remote.iter().map(IpAddr::to_string).collect();
    format!(
        "DANE is not in effect: the resolver at {} is not on this host, so its word on DNSSEC is not taken, and mail goes as it would without DANE; run a resolver that validates DNSSEC here, such as unbound, and name it as [delivery] resolver",
        remote.join(", ")
    )
}

/// The key return paths are made with, from configuration, checked once so
/// every return path made with it is valid.
pub fn return_path_key(config: &config::Delivery) -> Result<token::Key, String> {
    let key = config::hex(&config.return_path_key)
        .filter(|key| key.len() >= 32)
        .ok_or("delivery's return_path_key must be 32 bytes or more, in hex")?;
    let key = token::Key::new(&key);
    Address::parse(&return_path(
        &key,
        &config.return_path_domain,
        MessageId(Id::from_u64(1).expect("an ID")),
    ))
    .map_err(|error| format!("delivery's return_path_domain: {error:?}"))?;
    Ok(key)
}

/// Every key a bounce's return path may have been made with: the current
/// first, then those from before a rotation.
pub fn return_path_keys(config: &config::Delivery) -> Result<Vec<token::Key>, String> {
    let mut keys = vec![return_path_key(config)?];
    for previous in &config.previous_return_path_keys {
        let key = config::hex(previous).filter(|key| key.len() >= 32).ok_or(
            "each of delivery's previous_return_path_keys must be 32 bytes or more, in hex",
        )?;
        keys.push(token::Key::new(&key));
    }
    Ok(keys)
}

/// Why a sealed body did not open, in the engine's own words.
pub fn unopened_body(unopened: Unopened) -> String {
    match unopened {
        Unopened::NoKey(id) => {
            format!("its body is sealed under key {id}, which the keys file does not hold")
        }
        Unopened::Erased => "its body is erased: its tenant's key is gone".to_owned(),
        Unopened::Damaged => "its body is damaged: it does not open".to_owned(),
    }
}

/// A message's return path: its correlation token, at the bounce domain or
/// its identity's MAIL FROM domain.
pub fn return_path(key: &token::Key, domain: &str, message: MessageId) -> String {
    format!("{}@{domain}", token::local_part(key, message))
}

impl Deliverer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &config::Delivery,
        resolver: Resolver,
        policies: Option<Arc<Policies>>,
        verified: Option<Arc<ClientConfig>>,
        outbound: Outbound,
        scheduler: UnboundedSender<engine_scheduler::Input>,
        clock: Arc<SystemClock>,
        sealer: Arc<Sealer>,
    ) -> Result<Self, String> {
        let return_path_key = return_path_key(config)?;
        Ok(Self {
            inner: Arc::new(Inner {
                session: client::Config {
                    helo: config.helo.clone(),
                    require_tls: config.require_tls,
                    // RFC 5321, 4.5.3.2: five minutes for the envelope's
                    // replies, ten for the reply to the content.
                    reply_timeout: Duration::from_secs(300),
                    final_timeout: Duration::from_secs(600),
                },
                idle: Duration::from_secs(config.idle_seconds),
                outbound,
                port: config.port,
                return_path_domain: config.return_path_domain.clone(),
                return_path_key,
                resolver,
                dane: config.dane,
                policies,
                tls: TlsConnector::from(crate::tls::client()?),
                verified: verified.map(TlsConnector::from),
                scheduler,
                clock,
                sites: Mutex::new(BTreeMap::new()),
                sealer,
            }),
        })
    }

    /// Looks up where a domain's mail goes, with its MTA-STS policy, and
    /// tells the scheduler.
    pub fn resolve(&self, domain: Box<str>) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let policy = async {
                match &inner.policies {
                    Some(policies) => policies.policy(&domain).await,
                    None => None,
                }
            };
            let (lookup, policy) =
                tokio::join!(inner.resolver.mx_lookup(format!("{domain}.")), policy);
            let (answer, secure, ttl) = match lookup {
                Ok(lookup) => {
                    let mut secure = inner.dane;
                    let mut owners = Vec::new();
                    let records: Vec<(u16, String)> = lookup
                        .answers()
                        .iter()
                        .filter_map(|record| match &record.data {
                            RData::MX(mx) => {
                                secure &= record.proof.is_secure();
                                owners.push(lowercase(&record.name));
                                Some((mx.preference, mx.exchange.to_ascii()))
                            }
                            _ => None,
                        })
                        .collect();
                    // MX records another name holds came through the
                    // domain's aliases, each of which must be secure too
                    // (RFC 7672, 2.2.1), walked link by link.
                    if secure && owners.iter().any(|owner| **owner != *domain) {
                        secure = match inner.aliases(&domain).await {
                            Ok((aliases, end)) => {
                                aliases.iter().all(|(_, secure)| *secure)
                                    && owners.iter().all(|owner| *owner == end)
                            }
                            Err(_) => false,
                        };
                    }
                    let ttl = lookup
                        .valid_until()
                        .saturating_duration_since(std::time::Instant::now());
                    (Answer::Records(records), secure, ttl)
                }
                Err(error) => match no_records(&error) {
                    // An empty answer holds for its negative TTL. Proved
                    // empty, its denial and its zone's SOA are secure,
                    // which DANE applies to (RFC 7672, 2.2.2).
                    Some(none) => {
                        // Given no negative TTL, the SOA's gives it (RFC
                        // 2308, 5).
                        let ttl = none
                            .negative_ttl
                            .or_else(|| none.soa.as_ref().map(|soa| soa.ttl.min(soa.data.minimum)))
                            .map_or(NEGATIVE_TTL, |ttl| Duration::from_secs(u64::from(ttl)));
                        let proof: Vec<_> = none
                            .authorities
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .filter(|record| record.record_type() != RecordType::RRSIG)
                            .collect();
                        let mut secure = inner.dane
                            && !proof.is_empty()
                            && proof.iter().all(|record| record.proof.is_secure());
                        // A denial another name holds came through the
                        // domain's aliases, which must be secure too.
                        let denied = lowercase(none.query.name());
                        if secure && denied != *domain {
                            secure = match inner.aliases(&domain).await {
                                Ok((aliases, end)) => {
                                    aliases.iter().all(|(_, secure)| *secure) && end == denied
                                }
                                Err(_) => false,
                            };
                        }
                        if error.is_nx_domain() {
                            (Answer::NoSuchDomain, false, ttl)
                        } else {
                            (Answer::NoRecords, secure, ttl)
                        }
                    }
                    None => (Answer::Failed(error.to_string()), false, Duration::ZERO),
                },
            };
            // A route its policy shaped is looked up again once the policy
            // is due a refresh (RFC 8461, 3.2).
            let ttl = policy.as_ref().map_or(ttl, |policy| {
                ttl.min(engine_smtp::sts::holds_for(policy, inner.clock.now().wall))
            });
            let route = route::route(&domain, answer, secure, policy.as_deref());
            let _ = inner
                .scheduler
                .send(engine_scheduler::Input::Resolved { domain, route, ttl });
        });
    }

    /// Queues a reserved transaction at its site, from its egress.
    pub fn dispatch(&self, dispatch: Dispatch) {
        let inner = &self.inner;
        let site = inner.site(&dispatch.site, dispatch.egress);
        // At the identity's own MAIL FROM domain, while that is verified.
        let at = |domain: &str| {
            Address::parse(&return_path(
                &inner.return_path_key,
                domain,
                dispatch.message,
            ))
        };
        // Policy bounds a MAIL FROM domain so its return path is an address;
        // should one not be, the installation's, checked at the start, is
        // used, never a delivery lost.
        let sender = dispatch
            .return_domain
            .as_deref()
            .and_then(|domain| at(domain).ok())
            .unwrap_or_else(|| {
                at(&inner.return_path_domain)
                    .expect("the installation's return path is checked at the start")
            });
        let job = Job {
            sender: Some(sender),
            recipients: dispatch.recipients,
            content: dispatch.content,
        };
        let mut lines = lock(&site.lines);
        // A throttled site takes nothing until its connections have closed:
        // the scheduler cools it down.
        if lines.throttled {
            drop(lines);
            for (permit, _) in job.recipients {
                inner.finished(permit, Attempted::Throttled, (None, None), None);
            }
            return;
        }
        let arrived = lines.arrived;
        lines.arrived += 1;
        let line = lines
            .queues
            .entry(Arc::clone(&dispatch.queue))
            .or_insert_with(|| Line {
                exchanges: Arc::clone(&dispatch.exchanges),
                tls: dispatch.tls,
                next_hop: dispatch.next_hop.clone(),
                waiting: VecDeque::new(),
                open: 0,
                idle: Vec::new(),
            });
        // Domains naming the same exchanges may prefer them in another
        // order: the latest is followed.
        line.exchanges = dispatch.exchanges;
        line.waiting.push_back((arrived, job));
        let (idle, served) = (line.idle.pop(), line.open > 0);
        // An idle connection to its exchanges takes it; else another opens
        // to them, if the site has room; else, when none goes to them, an
        // idle connection to other exchanges gives its place up.
        if let Some(wake) = idle {
            wake.notify_one();
        } else if lines.connections < site.rules.limits().connections {
            inner.open(&site, &mut lines, &dispatch.queue);
        } else if !served
            && let Some(wake) = lines.queues.values_mut().find_map(|line| line.idle.pop())
        {
            wake.notify_one();
        }
    }
}

impl Inner {
    fn site(&self, rules: &engine_rules::Site, egress: Option<Arc<Egress>>) -> Arc<Site> {
        let mut sites = lock(&self.sites);
        let key = (
            egress.as_ref().map(|egress| egress.id),
            Arc::clone(rules.name()),
        );
        let site = sites.entry(key).or_insert_with(|| {
            Arc::new(Site {
                rules: rules.clone(),
                egress: Mutex::new(None),
                unbound: AtomicBool::new(false),
                lines: Mutex::new(Lines::default()),
            })
        });
        // An egress's name may change: the latest is followed.
        *lock(&site.egress) = egress;
        Arc::clone(site)
    }

    /// Opens a connection to `queue`'s exchanges, which the site has room
    /// for.
    fn open(self: &Arc<Self>, site: &Arc<Site>, lines: &mut Lines, queue: &Arc<str>) {
        let Some(line) = lines.queues.get_mut(queue) else {
            return;
        };
        line.open += 1;
        let (exchanges, tls) = (Arc::clone(&line.exchanges), line.tls);
        let next_hop = line.next_hop.clone();
        lines.connections += 1;
        tokio::spawn(Arc::clone(self).connection(
            Arc::clone(site),
            Arc::clone(queue),
            exchanges,
            tls,
            next_hop,
        ));
    }

    async fn connection(
        self: Arc<Self>,
        site: Arc<Site>,
        queue: Arc<str>,
        exchanges: Arc<[String]>,
        tls: Tls,
        next_hop: Option<Arc<str>>,
    ) {
        let mut connection = Connection {
            queue,
            taken: 0,
            throttled: false,
        };
        let egress = lock(&site.egress).clone();
        let source = egress.as_ref().map(|egress| egress.id);
        let helo = egress.as_ref().map(|egress| egress.helo.clone());
        // Its exchanges in order of preference, until one is ready for an
        // attempt. Short of that, a refusal that throttles the site ends
        // the search; anything else moves on to the next exchange, and the
        // last one's failure is the connection's.
        let mut ended = Ended::default();
        for host in exchanges.iter() {
            let tried = match self
                .reach(host, tls, next_hop.as_deref(), egress.as_deref(), &site)
                .await
            {
                Ok((tcp, requirement)) => {
                    self.run(
                        &site,
                        &mut connection,
                        tcp,
                        host,
                        helo.clone(),
                        &requirement,
                    )
                    .await
                }
                Err(Unreached::Unbound) => {
                    ended = Ended::default();
                    break;
                }
                Err(Unreached::Failed(why)) => Ended {
                    why: Some(why),
                    ..Ended::default()
                },
            };
            let throttles = tried.throttled
                || connection.throttled
                || tried.refusal.as_ref().is_some_and(|reply| {
                    site.rules
                        .judged(reply.code, &reply.text())
                        .1
                        .is_some_and(|verdict| verdict.throttle.is_some())
                });
            ended = tried;
            if ended.ready || throttles {
                break;
            }
        }
        // A connection that never became ready for an attempt (no exchange
        // answered, or each refused or failed before it was ready) failed
        // for its queue.
        let failure = (!ended.ready).then_some(Attempted::NotSent);
        let throttled = ended.throttled || connection.throttled;
        // A refusal of the session itself is no attempt's reply: it is
        // judged here, for the site and for the transactions it refuses.
        // Without one, the engine's own account of the failure stands.
        let (evidence, verdict) = match &ended.refusal {
            Some(reply) => {
                let (evidence, verdict) = site.rules.judged(reply.code, &reply.text());
                (Some(evidence), verdict)
            }
            None => (ended.why.clone().filter(|_| !ended.ready), None),
        };
        // A refusal that throttles cools the site, whether or not any of its
        // transactions waited to carry the verdict.
        if let Some(minimum) = verdict.as_ref().and_then(|verdict| verdict.throttle) {
            let _ = self.scheduler.send(engine_scheduler::Input::SiteThrottled {
                site: site.rules.clone(),
                egress: source,
                reply: evidence.clone(),
                minimum,
            });
        }
        let throttled = throttled
            || verdict
                .as_ref()
                .is_some_and(|verdict| verdict.throttle.is_some());
        let mut lines = lock(&site.lines);
        lines.connections -= 1;
        let open = lines.queues.get_mut(&connection.queue).map_or(0, |line| {
            line.open -= 1;
            line.open
        });
        // A receiver that throttled refuses the site's other transactions as
        // well: they go back to the scheduler, which cools the site down.
        let refused: Vec<Job<DispatchPermit>> = if throttled {
            lines.throttled = true;
            lines.take_all()
        } else if failure.is_some() && open == 0 {
            // The queue's transactions wait for a retry, unless another
            // connection is carrying them.
            let mut refused = Vec::new();
            while let Some(job) = lines.take(&connection.queue) {
                refused.push(job);
            }
            refused
        } else {
            Vec::new()
        };
        // With its last connection closed, a throttled site's episode is
        // over: the scheduler's cooldown holds its mail from here.
        if lines.connections == 0 {
            lines.throttled = false;
        }
        lines.tidy();
        // Its place goes to transactions no connection goes to, which
        // waited for it, or which queued while it closed.
        if let Some(queue) = lines.unserved().cloned() {
            self.open(&site, &mut lines, &queue);
        }
        drop(lines);
        let result = if throttled {
            Attempted::Throttled
        } else {
            failure.unwrap_or(Attempted::NotSent)
        };
        // A session's refusal is one reply, counted with the first
        // transaction it refused alone, as the session it ended ends.
        let mut replied = ended.refusal.is_some().then(|| self.clock.now().wall);
        for (permit, _) in refused.into_iter().flat_map(|job| job.recipients) {
            let reply = (evidence.clone(), verdict.clone());
            self.finished(permit, result, reply, replied.take());
        }
    }

    /// A connection to `host`, from `egress`'s address when there is one,
    /// to an address of the same family, and what its TLS must prove,
    /// decided by `engine_smtp::dane` from what the address and TLSA
    /// lookups proved: a TLSA lookup that fails leaves the host unusable,
    /// never unverified.
    async fn reach(
        &self,
        host: &str,
        tls: Tls,
        next_hop: Option<&str>,
        egress: Option<&Egress>,
        site: &Site,
    ) -> Result<(TcpStream, Requirement), Unreached> {
        let failed = |why: String| Unreached::Failed(Evidence::local(&why));
        let addresses = self
            .resolver
            .lookup_ip(format!("{host}."))
            .await
            .map_err(|error| failed(format!("{host} has no address: {error}")))?;
        let proved = self
            .proved(host, tls, addresses.as_lookup().answers())
            .await
            .map_err(failed)?;
        let requirement = self
            .requirement(host, tls, next_hop, &proved)
            .await
            .map_err(failed)?;
        let source = egress.map(|egress| SocketAddr::new(egress.address, 0));
        let mut why = format!("{host} has no address delivery may connect to");
        for ip in addresses.iter() {
            if !self.outbound.permits(ip)
                || source.is_some_and(|source| source.is_ipv4() != ip.is_ipv4())
            {
                continue;
            }
            let socket = match socket(ip, source) {
                Ok(socket) => socket,
                // The host does not hold the egress's address: its mail
                // waits for a retry, and never goes out from another.
                Err(error) if source.is_some() => {
                    if !site.unbound.swap(true, Ordering::SeqCst) {
                        tracing::error!(
                            source = %egress.map_or(ip, |egress| egress.address),
                            %error,
                            "the host cannot send from an egress's address; its mail waits"
                        );
                    }
                    return Err(Unreached::Unbound);
                }
                Err(_) => continue,
            };
            let attempt = socket.connect(SocketAddr::new(ip, self.port));
            match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
                Ok(Ok(tcp)) => {
                    let _ = tcp.set_nodelay(true);
                    return Ok((tcp, requirement));
                }
                Ok(Err(error)) => why = format!("{host} at {ip}: {error}"),
                Err(_) => why = format!("{host} at {ip} did not answer in time"),
            }
        }
        Err(failed(why))
    }

    /// What TLS to `host` must prove on a route that asks `tls`: the TLSA
    /// records at the first of its candidate base domains to have a secure
    /// set (RFC 7672, 2.2.3), else what the route asks without them. A
    /// DANE-TA certificate may then be valid for its base, or for the next
    /// hop, the domain the mail is for, or that domain's secure expansion.
    async fn requirement(
        &self,
        host: &str,
        tls: Tls,
        next_hop: Option<&str>,
        addresses: &dane::Addresses,
    ) -> Result<Requirement, String> {
        for base in dane::candidates(host, tls, addresses) {
            let lookup = self.tlsa(&base).await;
            match dane::decide(tls, &base, lookup) {
                Some(Ok(Requirement::Dane { records, base, .. })) => {
                    let expanded = match next_hop {
                        Some(domain) => self.expanded(domain).await?,
                        None => None,
                    };
                    let names = dane::reference_identifiers(&base, next_hop, expanded.as_deref());
                    return Ok(Requirement::Dane {
                        records,
                        base,
                        names,
                    });
                }
                Some(decided) => return decided,
                None => {}
            }
        }
        Ok(dane::without_records(tls))
    }

    /// `domain` as its aliases expand, if they do and every link is secure.
    async fn expanded(&self, domain: &str) -> Result<Option<String>, String> {
        let (aliases, end) = self.aliases(domain).await?;
        Ok((!aliases.is_empty() && aliases.iter().all(|(_, secure)| *secure)).then_some(end))
    }

    /// What the TLSA lookup for SMTP at `base`, on the port delivery
    /// connects to, proved. Its records are secure only if every alias in
    /// front of them is too, each link looked up on its own, since a cached
    /// answer may leave links out; aliases that loop or go on too long
    /// fail the lookup.
    async fn tlsa(&self, base: &str) -> dane::Lookup {
        let name = format!("_{}._tcp.{base}", self.port);
        let (aliases, end) = match self.aliases(&name).await {
            Ok(chain) => chain,
            Err(why) => return dane::Lookup::Failed(why),
        };
        let chain = aliases.iter().all(|(_, secure)| *secure);
        match self.resolver.tlsa_lookup(format!("{end}.")).await {
            Ok(lookup) => {
                let mut secure = chain;
                let mut records = Vec::new();
                for record in lookup.answers() {
                    if let RData::TLSA(tlsa) = &record.data {
                        secure &= record.proof.is_secure() && owned_by(record, &end);
                        records.push(Tlsa {
                            usage: tlsa.cert_usage.into(),
                            selector: tlsa.selector.into(),
                            matching: tlsa.matching.into(),
                            data: tlsa.cert_data.clone(),
                        });
                    }
                }
                if secure {
                    dane::Lookup::Secure(records)
                } else {
                    dane::Lookup::Insecure
                }
            }
            Err(error) if no_records(&error).is_some() => dane::Lookup::Absent,
            Err(error) => dane::Lookup::Failed(error.to_string()),
        }
    }

    /// `name`'s chain of aliases, followed one link at a time, each link's
    /// own record looked up: each alias's target and whether its record
    /// was secure, and the name the chain ends at.
    async fn aliases(&self, name: &str) -> Result<(Vec<(String, bool)>, String), String> {
        let mut aliases: Vec<(String, bool)> = Vec::new();
        let mut current = name.to_ascii_lowercase();
        for _ in 0..=MAX_ALIASES {
            let link = match self
                .resolver
                .lookup(format!("{current}."), RecordType::CNAME)
                .await
            {
                Ok(lookup) => lookup
                    .answers()
                    .iter()
                    .find_map(|record| match &record.data {
                        RData::CNAME(target) if owned_by(record, &current) => {
                            Some((lowercase(&target.0), record.proof.is_secure()))
                        }
                        _ => None,
                    }),
                Err(error) if no_records(&error).is_some() => None,
                Err(error) => {
                    return Err(format!("the alias lookup for {current} failed: {error}"));
                }
            };
            let Some((target, secure)) = link else {
                return Ok((aliases, current));
            };
            if target == name || aliases.iter().any(|(seen, _)| *seen == target) {
                return Err(format!("{name}'s aliases loop"));
            }
            aliases.push((target.clone(), secure));
            current = target;
        }
        Err(format!("{name}'s aliases go on too long"))
    }

    /// What an exchange's address lookup proved, for DANE: the alias chain
    /// it followed, walked link by link when its records are another
    /// name's, and whether its address records were secure.
    async fn proved(
        &self,
        host: &str,
        tls: Tls,
        answers: &[hickory_resolver::proto::rr::Record],
    ) -> Result<dane::Addresses, String> {
        let addresses: Vec<_> = answers
            .iter()
            .filter(|record| matches!(record.data, RData::A(_) | RData::AAAA(_)))
            .collect();
        let owned = |name: &str| addresses.iter().all(|record| owned_by(record, name));
        let secure =
            !addresses.is_empty() && addresses.iter().all(|record| record.proof.is_secure());
        if !tls.dane || owned(host) {
            return Ok(dane::Addresses {
                aliases: Vec::new(),
                secure,
            });
        }
        let (aliases, end) = self.aliases(host).await?;
        Ok(dane::Addresses {
            secure: secure && owned(&end),
            aliases,
        })
    }

    /// Runs a session on a new connection to `host`, to its end, greeting
    /// as `helo` when its egress names one, with TLS that proves what
    /// `requirement` asks.
    async fn run(
        &self,
        site: &Site,
        connection: &mut Connection,
        tcp: TcpStream,
        host: &str,
        helo: Option<String>,
        requirement: &Requirement,
    ) -> Ended {
        let mut config = self.session.clone();
        if let Some(helo) = helo {
            config.helo = helo;
        }
        // Whatever verifies TLS requires it, as the site's rules may.
        config.require_tls |=
            site.rules.limits().require_tls || !matches!(requirement, Requirement::Opportunistic);
        let mut session = Session::new(config);
        let mut ready = false;
        let Some(tcp) = self
            .drive(&mut session, site, connection, tcp, &mut ready)
            .await
        else {
            return ended(&session, ready, host, None);
        };
        let failed = |error: &str| handshake_failed(requirement, host, error);
        // A DANE session names its TLSA base domain (RFC 7672, 8.1).
        let (connector, name) = match requirement {
            Requirement::Opportunistic | Requirement::Required => {
                (Ok(self.tls.clone()), host.to_owned())
            }
            Requirement::Verified => (
                self.verified
                    .clone()
                    .ok_or_else(|| "no certificate authorities to verify by".to_owned()),
                host.to_owned(),
            ),
            Requirement::Dane {
                records,
                base,
                names,
            } => (
                crate::tls::dane(records.clone(), names.clone()).map(TlsConnector::from),
                base.clone(),
            ),
        };
        let handshake = match (connector, ServerName::try_from(name)) {
            (Ok(connector), Ok(name)) => {
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(name, tcp)).await {
                    Ok(tls) => tls.map_err(|error| failed(&error.to_string())),
                    Err(_) => Err(failed("the TLS handshake took too long")),
                }
            }
            (Err(error), _) => Err(failed(&error)),
            (_, Err(error)) => Err(failed(&error.to_string())),
        };
        let why = match handshake {
            Ok(tls) => {
                session.handle(self.clock.now(), Input::TlsStarted);
                let _ = self
                    .drive(&mut session, site, connection, tls, &mut ready)
                    .await;
                None
            }
            Err(why) => {
                session.handle(self.clock.now(), Input::Lost);
                let mut out = Vec::new();
                session.poll(self.clock.now(), &mut out);
                for output in out {
                    if let Output::Finished {
                        tag,
                        outcome,
                        at,
                        own,
                    } = output
                    {
                        self.report(site, connection, tag, &outcome, (at, own));
                    }
                }
                Some(why)
            }
        };
        ended(&session, ready, host, why)
    }

    /// Runs the session over `stream` until it closes, or until it asks for
    /// TLS, when the stream comes back for the handshake.
    async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        session: &mut Session<DispatchPermit>,
        site: &Site,
        connection: &mut Connection,
        mut stream: S,
        ready: &mut bool,
    ) -> Option<S> {
        let mut out = Vec::new();
        let mut pending: Vec<Bytes> = Vec::new();
        let mut buffer = Vec::new();
        loop {
            let deadline = session.poll(self.clock.now(), &mut out);
            let mut acted = false;
            for output in out.drain(..) {
                match output {
                    Output::Send(bytes) => pending.push(Bytes::from(bytes)),
                    Output::SendContent(bytes) => pending.push(bytes),
                    Output::StartTls => {
                        return stream::write(&mut stream, &mut pending)
                            .await
                            .ok()
                            .map(|()| stream);
                    }
                    Output::Finished {
                        tag,
                        outcome,
                        at,
                        own,
                    } => {
                        self.report(site, connection, tag, &outcome, (at, own));
                    }
                    Output::Ready => {
                        *ready = true;
                        if stream::write(&mut stream, &mut pending).await.is_err() {
                            session.handle(self.clock.now(), Input::Lost);
                        } else {
                            let next = self.next(site, connection).await;
                            let input = next.map_or(Input::Quit, Input::Deliver);
                            session.handle(self.clock.now(), input);
                        }
                        acted = true;
                    }
                    Output::Close => {
                        let _ = stream::write(&mut stream, &mut pending).await;
                        stream::close(&mut stream).await;
                        return None;
                    }
                }
            }
            if stream::write(&mut stream, &mut pending).await.is_err() {
                session.handle(self.clock.now(), Input::Lost);
                continue;
            }
            if acted {
                continue;
            }
            if session.is_closed() {
                return None;
            }
            match stream::read(&mut stream, &mut buffer, deadline, &self.clock).await {
                Ok(Read::Bytes(bytes)) => session.handle(self.clock.now(), Input::Received(bytes)),
                Ok(Read::Deadline) => {}
                Ok(Read::Closed) | Err(_) => session.handle(self.clock.now(), Input::Lost),
            }
        }
    }

    /// The connection's next transaction, waiting for one as long as it
    /// stands open idle: none once it has carried its rules' number, once
    /// a reply on it throttled its site, or when it gives its place up to
    /// a transaction for other exchanges.
    async fn next(&self, site: &Site, connection: &mut Connection) -> Option<Job<DispatchPermit>> {
        loop {
            let job = self.taken(site, connection).await?;
            if let Some(job) = self.opened(job) {
                return Some(job);
            }
        }
    }

    /// The next job `next` gives, as the store kept it.
    async fn taken(&self, site: &Site, connection: &mut Connection) -> Option<Job<DispatchPermit>> {
        if connection.throttled
            || connection.taken >= site.rules.limits().transactions_per_connection
        {
            return None;
        }
        loop {
            let wake = {
                let mut lines = lock(&site.lines);
                if lines.throttled {
                    return None;
                }
                if let Some(job) = lines.take(&connection.queue) {
                    connection.taken += 1;
                    return Some(job);
                }
                if lines.unserved().is_some()
                    && lines.connections >= site.rules.limits().connections
                {
                    return None;
                }
                let wake = Arc::new(Notify::new());
                let line = lines.queues.get_mut(&connection.queue)?;
                line.idle.push(Arc::clone(&wake));
                wake
            };
            let woken = tokio::time::timeout(self.idle, wake.notified())
                .await
                .is_ok();
            if !woken {
                let mut lines = lock(&site.lines);
                if let Some(line) = lines.queues.get_mut(&connection.queue) {
                    line.idle.retain(|other| !Arc::ptr_eq(other, &wake));
                }
                let job = lines.take(&connection.queue);
                connection.taken += usize::from(job.is_some());
                return job;
            }
        }
    }

    /// `job` with its body opened, if it was sealed, on the
    /// connection's task, never the scheduler's. One that does not open is
    /// finished as not sent, in the engine's own words, and none is given.
    fn opened(&self, mut job: Job<DispatchPermit>) -> Option<Job<DispatchPermit>> {
        match self.sealer.open_body(&job.content) {
            Ok(None) => Some(job),
            Ok(Some(content)) => {
                job.content = Bytes::from(content);
                Some(job)
            }
            Err(unopened) => {
                let why = unopened_body(unopened);
                tracing::warn!(why = %why, "a body could not be opened");
                for (permit, _) in job.recipients {
                    let evidence = Some(Evidence::local(&why));
                    self.finished(permit, Attempted::NotSent, (evidence, None), None);
                }
                None
            }
        }
    }

    /// Reports an attempt's outcome with the site's verdict on its whole
    /// reply. A reply that throttles the site ends the connection's work,
    /// and sends the site's waiting transactions back to the scheduler at
    /// once, so no other connection starts one during the cooldown.
    fn report(
        &self,
        site: &Site,
        connection: &mut Connection,
        permit: DispatchPermit,
        outcome: &Outcome,
        (at, own): (Timestamp, bool),
    ) {
        let (evidence, verdict) = match reply(outcome) {
            Some(reply) => {
                let (evidence, mut verdict) = site.rules.judged(reply.code, &reply.text());
                // Only the recipient's own reply can rule its address out:
                // one refusing the sender or the message, whatever its
                // words, never suppresses it.
                if let Some(verdict) = verdict.as_mut().filter(|_| !own) {
                    verdict.rules_out_address = false;
                }
                (Some(evidence), verdict)
            }
            None => (None, None),
        };
        let throttles = verdict
            .as_ref()
            .is_some_and(|verdict| verdict.throttle.is_some());
        let result = match attempted(outcome) {
            Attempted::Deferred if throttles => Attempted::Throttled,
            result => result,
        };
        // Its reply, read at `at`, counts on that day.
        let replied = evidence.is_some().then_some(at);
        self.finished(permit, result, (evidence, verdict), replied);
        if throttles {
            connection.throttled = true;
            let refused = {
                let mut lines = lock(&site.lines);
                lines.throttled = true;
                lines.take_all()
            };
            for (permit, _) in refused.into_iter().flat_map(|job| job.recipients) {
                self.finished(permit, Attempted::Throttled, (None, None), None);
            }
        }
    }

    /// Reports an attempt's end to the scheduler, which records it, and
    /// counts and logs it as it does every outcome; `replied`, when the
    /// reply came, if `evidence` is the receiver's reply to it, counted
    /// toward warmup on that day.
    fn finished(
        &self,
        permit: DispatchPermit,
        result: Attempted,
        (evidence, verdict): (Option<Evidence>, Option<engine_rules::Verdict>),
        replied: Option<Timestamp>,
    ) {
        let _ = self.scheduler.send(engine_scheduler::Input::Finished {
            permit,
            result,
            evidence,
            verdict,
            feedback: None,
            replied,
        });
    }
}

/// How a session ended.
#[derive(Default)]
struct Ended {
    /// It became ready for an attempt.
    ready: bool,
    /// The receiver answered 421 (`Session::throttled`).
    throttled: bool,
    /// What the server said when it refused the session itself
    /// (`Session::refusal`).
    refusal: Option<Reply>,
    /// The engine's own account of why it ended before it was ready, when
    /// no refusal says.
    why: Option<Evidence>,
}

/// How `session`, to `host`, ended: `why` is a TLS failure's account, if
/// one ended it.
fn ended<T>(session: &Session<T>, ready: bool, host: &str, why: Option<Evidence>) -> Ended {
    let why = why.or_else(|| {
        let why = match session.unready()? {
            Failure::NoTls => format!("TLS is required, and {host} does not offer STARTTLS"),
            Failure::Lost => format!("{host} closed the connection before it was ready"),
            Failure::TimedOut => format!("{host} did not answer in time"),
            Failure::Protocol => format!("{host}'s replies broke the protocol"),
            Failure::Refused(_) => return None,
        };
        Some(Evidence::local(&why))
    });
    Ended {
        ready,
        throttled: session.throttled(),
        refusal: session.refusal().cloned(),
        why,
    }
}

/// Why an exchange was not reached.
enum Unreached {
    /// The host does not hold the egress's address, which no other
    /// exchange changes.
    Unbound,
    /// This exchange was not reached, or what its TLS must prove could not
    /// be learned: the engine's account.
    Failed(Evidence),
}

/// The engine's account of a handshake that failed under `requirement`.
fn handshake_failed(requirement: &Requirement, host: &str, error: &str) -> Evidence {
    let what = match requirement {
        Requirement::Opportunistic | Requirement::Required => "TLS",
        Requirement::Verified => "MTA-STS",
        Requirement::Dane { .. } => "DANE",
    };
    Evidence::local(&format!(
        "{what}: the TLS handshake with {host} failed: {error}"
    ))
}

/// Whether `record` is `name`'s own.
fn owned_by(record: &hickory_resolver::proto::rr::Record, name: &str) -> bool {
    lowercase(&record.name) == name
}

/// A name in lowercase, without its final dot.
fn lowercase(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

/// A lookup's empty answer, if that is what it got.
fn no_records(error: &NetError) -> Option<&NoRecords> {
    match error {
        NetError::Dns(DnsError::NoRecordsFound(none)) => Some(none),
        _ => None,
    }
}

fn attempted(outcome: &Outcome) -> Attempted {
    if outcome.throttled() {
        return Attempted::Throttled;
    }
    match outcome {
        Outcome::Delivered(_) => Attempted::Delivered,
        Outcome::Rejected(_) => Attempted::Rejected,
        Outcome::Deferred(_) => Attempted::Deferred,
        Outcome::NotSent(_) => Attempted::NotSent,
        Outcome::Uncertain => Attempted::Uncertain,
    }
}

/// A socket to connect to `ip`, bound to `source`, an egress's address,
/// when there is one.
fn socket(ip: IpAddr, source: Option<SocketAddr>) -> std::io::Result<TcpSocket> {
    let socket = if ip.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(source) = source {
        socket.bind(source)?;
    }
    Ok(socket)
}

/// What the receiver said of an attempt, if it said anything.
fn reply(outcome: &Outcome) -> Option<&Reply> {
    match outcome {
        Outcome::Delivered(reply)
        | Outcome::Rejected(reply)
        | Outcome::Deferred(reply)
        | Outcome::NotSent(Failure::Refused(reply)) => Some(reply),
        Outcome::NotSent(_) | Outcome::Uncertain => None,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where the system resolver's nameservers are listed.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The system resolver's nameservers, for development; production names
/// its own. Only `nameserver` lines are read, since every lookup
/// is of a fully qualified name. A line whose address cannot be used, such
/// as the link-local IPv6 address with an interface that macOS lists for
/// some networks, is reported and skipped rather than stopping the engine.
fn system_nameservers() -> Result<Vec<IpAddr>, String> {
    let text =
        std::fs::read_to_string(RESOLV_CONF).map_err(|error| format!("{RESOLV_CONF}: {error}"))?;
    let (usable, skipped) = nameservers(&text);
    for address in skipped {
        tracing::warn!(file = RESOLV_CONF, nameserver = %address, "skipped a nameserver that cannot be used");
    }
    if usable.is_empty() {
        return Err(format!(
            "{RESOLV_CONF} lists no usable nameserver; name one as delivery's resolver"
        ));
    }
    Ok(usable)
}

/// Each `nameserver` line's address, and the ones that are not addresses
/// alone.
fn nameservers(text: &str) -> (Vec<IpAddr>, Vec<&str>) {
    let mut usable = Vec::new();
    let mut skipped = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = words.next() else {
            continue;
        };
        match address.parse() {
            Ok(address) => usable.push(address),
            Err(_) => skipped.push(address),
        }
    }
    (usable, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transaction for one recipient, reserved.
    fn job(n: u64) -> Job<DispatchPermit> {
        use engine_core::delivery::Delivery;
        use engine_core::id::{AccountId, AttemptId, DeliveryId, IdentityId};
        use engine_core::policy::Origin;
        use engine_core::time::Timestamp;
        let id = |value: u64| Id::from_u64(value).unwrap();
        let at = Timestamp::from_micros(1_800_000_000_000_000);
        let mut delivery = Delivery::new(
            DeliveryId(id(n)),
            MessageId(id(1000 + n)),
            AccountId(id(1)),
            Origin {
                identity: IdentityId(id(2)),
                tenant: None,
                configuration: None,
            },
            Address::parse("r@example.net").unwrap(),
            at,
            at.saturating_add(Duration::from_secs(60)),
        )
        .unwrap();
        let permit = delivery
            .reserve(delivery.generation(), AttemptId(id(2000 + n)), None, at)
            .unwrap();
        Job {
            sender: None,
            recipients: vec![(permit, Address::parse("r@example.net").unwrap())],
            content: Bytes::new(),
        }
    }

    #[test]
    fn a_freed_place_goes_to_the_queue_whose_transaction_waited_longest() {
        let line = |open, waiting: Vec<u64>| Line {
            exchanges: Arc::from([]),
            tls: Tls::default(),
            next_hop: None,
            waiting: waiting
                .into_iter()
                .map(|arrived| (arrived, job(arrived)))
                .collect(),
            open,
            idle: Vec::new(),
        };
        let mut lines = Lines {
            queues: BTreeMap::from([
                (Arc::from("a"), line(0, vec![5, 6])),
                (Arc::from("b"), line(0, vec![2])),
                (Arc::from("c"), line(1, vec![1])),
                (Arc::from("d"), line(0, vec![])),
            ]),
            connections: 1,
            arrived: 7,
            throttled: false,
        };
        // c has a connection; of the rest, b's waited longest, though a
        // comes first by name.
        assert_eq!(lines.unserved().map(|queue| &**queue), Some("b"));
        assert!(lines.take("b").is_some());
        assert_eq!(lines.unserved().map(|queue| &**queue), Some("a"));
        assert_eq!(lines.take_all().len(), 3);
        assert_eq!(lines.unserved(), None);
    }

    #[test]
    fn a_reply_proves_its_answers_and_authorities_only_when_asked_and_validated() {
        use hickory_resolver::proto::op::OpCode;
        use hickory_resolver::proto::rr::Record;
        use hickory_resolver::proto::rr::rdata::A;
        let record = |owner: &str| {
            Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                60,
                RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
            )
        };
        let reply = |validated| {
            let mut reply = Message::response(1, OpCode::Query);
            reply.metadata.authentic_data = validated;
            reply.add_answers([record("a.example.")]);
            reply.add_authorities([record("b.example.")]);
            reply.add_additionals([record("c.example.")]);
            reply
        };
        let mut validated = reply(true);
        prove(&mut validated, true);
        assert!(validated.answers[0].proof.is_secure());
        assert!(validated.authorities[0].proof.is_secure());
        assert!(
            !validated.additionals[0].proof.is_secure(),
            "the AD bit speaks for no additional record"
        );
        let mut unvalidated = reply(false);
        prove(&mut unvalidated, true);
        assert!(!unvalidated.answers[0].proof.is_secure());
        assert!(!unvalidated.authorities[0].proof.is_secure());
        let mut unasked = reply(true);
        prove(&mut unasked, false);
        assert!(
            !unasked.answers[0].proof.is_secure(),
            "a resolver not asked, its AD bit is not taken"
        );
    }

    #[test]
    fn only_nameservers_on_this_host_are_asked_about_dnssec() {
        let nameservers = |addresses: &[&str]| {
            ResolverConfig::from_name_servers(
                addresses
                    .iter()
                    .map(|address| NameServerConfig::udp_and_tcp(address.parse().unwrap()))
                    .collect(),
            )
        };
        assert!(
            elsewhere(&nameservers(&[
                "127.0.0.1",
                "127.0.0.53",
                "::1",
                "::ffff:127.0.0.1"
            ]))
            .is_empty()
        );
        assert_eq!(
            elsewhere(&nameservers(&["127.0.0.1", "192.0.2.53"])),
            ["192.0.2.53".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn nameservers_are_read_and_unusable_ones_set_aside() {
        let text = "# generated\nsearch lan\nnameserver fe80::6448:42ff:fe22:cc64%en0\nnameserver 172.20.10.1\nnameserver 2001:db8::1\noptions ndots:1\n";
        let (usable, skipped) = nameservers(text);
        assert_eq!(
            usable,
            vec![
                "172.20.10.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        assert_eq!(skipped, vec!["fe80::6448:42ff:fe22:cc64%en0"]);
    }

    #[tokio::test]
    async fn a_connection_goes_out_from_its_egress_and_only_from_one_the_host_holds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let to = listener.local_addr().unwrap();
        let from = SocketAddr::new(to.ip(), 0);
        let stream = socket(to.ip(), Some(from))
            .unwrap()
            .connect(to)
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(
            peer,
            stream.local_addr().unwrap(),
            "from the address it was bound to"
        );
        let elsewhere = SocketAddr::new("203.0.113.9".parse().unwrap(), 0);
        assert!(
            socket(to.ip(), Some(elsewhere)).is_err(),
            "an address the host does not hold"
        );
    }
}
