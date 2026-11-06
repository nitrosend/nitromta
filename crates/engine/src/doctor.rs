//! `nitromta doctor`: the installation checked with what the
//! engine itself uses: its configuration, its resolver and certificates,
//! and, through the running engine's admin socket, its identities and
//! egresses. Each check prints `ok`, `warn` or `fail` with what it found,
//! and a failure says what to change, the DNS record to publish among
//! them. The command fails if any check does. It reads and connects, and
//! changes nothing.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use mail_auth::{MessageAuthenticator, SpfResult, spf::verify::SpfParameters};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, UnixTime};
use serde_json::Value;
use tokio::io::AsyncReadExt as _;

use crate::config::Config;
use crate::{delivery, keys, tls, verify};

/// The time server the clock is checked against, unless the command names
/// another.
pub const TIME_SERVER: &str = "time.cloudflare.com:123";
/// The SMTP server port 25 is checked against: a large receiver's, which
/// answers from anywhere.
pub const PROBE: &str = "gmail-smtp-in.l.google.com:25";

/// The blocklists each egress's address is looked up in.
const BLOCKLISTS: [&str; 3] = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
];

/// How long a certificate must stay valid before it is a warning.
const RENEW_WITHIN: Duration = Duration::from_secs(14 * 86_400);

/// How long any one probe waits.
const PATIENCE: Duration = Duration::from_secs(10);

/// What the checks reach out to.
pub struct Probes {
    pub time_server: String,
    pub port25: String,
}

/// What the running engine says of its policy, for the checks of its
/// identities and egresses: `None` when it is not running.
pub struct Running {
    pub identities: Vec<Value>,
    pub egresses: Vec<Value>,
    /// The key it seals every secret under.
    pub sealing: u8,
    /// Each key older than that, with what still needs it, by where it is
    /// kept: none once it may be retired; or why that could not
    /// be read.
    pub older: Vec<(u8, Result<Kept, String>)>,
    /// Its store's fence, as the admin socket gives it: null if it has none.
    pub fence: Value,
    /// What its store holds free.
    pub reusable: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Default)]
struct Report {
    found: Vec<(Level, String)>,
}

impl Report {
    fn ok(&mut self, what: impl Into<String>) {
        self.found.push((Level::Ok, what.into()));
    }

    fn warn(&mut self, what: impl Into<String>) {
        self.found.push((Level::Warn, what.into()));
    }

    fn fail(&mut self, what: impl Into<String>) {
        self.found.push((Level::Fail, what.into()));
    }

    /// Prints each finding and a summary, and returns whether none failed.
    fn print(&self) -> bool {
        let mut counts = [0; 3];
        for (level, what) in &self.found {
            let (label, index) = match level {
                Level::Ok => ("ok  ", 0),
                Level::Warn => ("warn", 1),
                Level::Fail => ("fail", 2),
            };
            counts[index] += 1;
            println!("{label}  {what}");
        }
        println!(
            "\n{} failed, {} to look at, {} passed",
            counts[2], counts[1], counts[0]
        );
        counts[2] == 0
    }
}

/// Runs every check, and returns whether none failed.
pub fn run(config: &Config, running: Option<&Running>, probes: &Probes) -> Result<bool, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the runtime: {error}"))?;
    let mut report = Report::default();
    store(config, running, &mut report);
    certificates(config, &mut report);
    runtime.block_on(async {
        clock(&probes.time_server, &mut report).await;
        dane(config, &mut report).await?;
        let resolver = delivery::public_resolver(&config.delivery)?;
        match running {
            Some(running) => {
                let mut options = hickory_resolver::config::ResolverOpts::default();
                options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
                let authenticator =
                    MessageAuthenticator::new(delivery::resolver_config(&config.delivery)?, options)
                .map_err(|error| format!("the resolver for SPF: {error}"))?;
                egresses(config, running, &resolver, &authenticator, probes, &mut report).await;
                identities(config, running, &resolver, &authenticator, &mut report).await;
            }
            None => {
                report.warn(
                    "policy: the engine is not running, so its identities and egresses are not checked; start it and run doctor again",
                );
                port25(None, &probes.port25, &mut report).await;
            }
        }
        bounces(config, &resolver, &mut report).await;
        Ok::<(), String>(())
    })?;
    Ok(report.print())
}

/// The store's disk and health, and the installation's keys.
fn store(config: &Config, running: Option<&Running>, report: &mut Report) {
    let store = &config.store;
    let directory = store
        .path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let reserve = store.reserve_mib << 20;
    let reusable = running.map_or_else(
        || crate::store::reusable(&store.path).unwrap_or(0),
        |running| running.reusable,
    );
    match rustix::fs::statvfs(directory) {
        Ok(stat) => {
            let free = stat.f_bavail.saturating_mul(stat.f_frsize);
            let inside = match reusable >> 20 {
                0 => String::new(),
                mib => format!(" and {mib} MiB free in the store"),
            };
            let said = format!(
                "store: {} MiB free on its disk{inside}, against a reserve of {} MiB",
                free >> 20,
                reserve >> 20
            );
            if crate::store::below_reserve(free, reusable, reserve) {
                report.fail(format!("{said}: new mail is refused until space is freed"));
            } else if free.saturating_add(reusable) > reserve.saturating_mul(4) {
                report.ok(said);
            } else {
                report.warn(format!(
                    "{said}: new mail is refused once it reaches the reserve"
                ));
            }
        }
        Err(error) => report.fail(format!(
            "store: its disk at {}: {error}",
            directory.display()
        )),
    }
    if let Some(running) = running {
        report.ok("store: the running engine holds it, and checked it as it started");
        let fence = &running.fence;
        if fence.is_object() && fence["discarding"] != true {
            report.fail(format!(
                "store: restored from a copy taken at {}, it is fenced: {} deliveries the copy held wait for a decision: `nitromta fence release` sends them, `nitromta fence discard` cancels them",
                fence["taken"].as_str().unwrap_or_default(),
                fence["unfinished"]
            ));
        }
    } else if !store.path.exists() {
        report.ok(format!(
            "store: {} is not made yet; the engine makes it as it first starts",
            store.path.display()
        ));
    } else {
        match crate::store::quick_check(&store.path) {
            Ok(()) => report.ok(format!(
                "store: {} passes SQLite's quick check",
                store.path.display()
            )),
            Err(why) => report.fail(why),
        }
    }
    match keys::ids(&store.keys) {
        Ok(ids) => {
            let listed = ids.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
            report.ok(format!(
                "keys: {} holds key {listed}, its owner's alone",
                store.keys.display()
            ));
            if let Some(running) = running
                && ids.last() != Some(&running.sealing)
            {
                report.warn(format!(
                    "keys: the engine seals every secret under key {}, not the newest; a restart seals them under it",
                    running.sealing
                ));
            }
            for (id, kept) in running
                .map(|running| &running.older[..])
                .unwrap_or_default()
            {
                match kept {
                    Ok(kept) if kept.is_empty() => report.ok(format!(
                        "keys: key {id} seals nothing kept any longer: `nitromta key retire --id {id}` removes it"
                    )),
                    Ok(kept) => report.ok(format!(
                        "keys: key {id} still seals {}, and is needed until they are gone",
                        held(kept)
                    )),
                    Err(why) => report.warn(format!(
                        "keys: what key {id} still seals could not be read: {why}"
                    )),
                }
            }
        }
        Err(why) => report.fail(why),
    }
}

/// What still needs a key, by where it is kept: how many records of each
/// table, or capture's files.
pub type Kept = Vec<(String, u64)>;

/// What still needs a key, as `doctor` and `key retire` say it: "4 records
/// (journal 3, cooldowns 1)".
pub fn held(kept: &[(String, u64)]) -> String {
    let total: u64 = kept.iter().map(|(_, count)| count).sum();
    let each: Vec<String> = kept
        .iter()
        .map(|(table, count)| format!("{table} {count}"))
        .collect();
    let records = if total == 1 { "record" } else { "records" };
    format!("{total} {records} ({})", each.join(", "))
}

/// Each listener's certificate and key: loaded as the engine loads them,
/// so the key is the certificate's; chained to the authorities the engine
/// trusts; and valid for the name it greets with, now and for two weeks
/// more.
fn certificates(config: &Config, report: &mut Report) {
    let roots = match tls::authorities(config.tls.authorities.as_deref()) {
        Ok(roots) => roots,
        Err(why) => return report.fail(format!("certificates: {why}")),
    };
    let anchors = &roots.roots;
    let mut check = |listener: &str, path: &Path, key: &Path, name: Option<&str>| {
        if let Err(why) = tls::server(path, key) {
            return report.fail(format!(
                "{listener}: the engine cannot serve its certificate and key ({why}): give it the certificate and the key it was issued for"
            ));
        }
        let chain: Vec<CertificateDer<'static>> = match CertificateDer::pem_file_iter(path)
            .and_then(|certificates| certificates.collect::<Result<Vec<_>, _>>())
        {
            Ok(chain) if !chain.is_empty() => chain,
            Ok(_) => {
                return report.fail(format!(
                    "{listener}: {} holds no certificate",
                    path.display()
                ));
            }
            Err(error) => return report.fail(format!("{listener}: {}: {error}", path.display())),
        };
        let verify = |at: SystemTime| -> Result<(), String> {
            let end =
                webpki::EndEntityCert::try_from(&chain[0]).map_err(|error| error.to_string())?;
            let time =
                UnixTime::since_unix_epoch(at.duration_since(UNIX_EPOCH).unwrap_or_default());
            end.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                anchors,
                &chain[1..],
                time,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|error| error.to_string())?;
            if let Some(name) = name {
                let name = rustls::pki_types::ServerName::try_from(name.to_owned())
                    .map_err(|error| error.to_string())?;
                end.verify_is_valid_for_subject_name(&name)
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        };
        let named = name.map_or(String::new(), |name| format!(" for {name}"));
        let now = SystemTime::now();
        match (verify(now), verify(now + RENEW_WITHIN)) {
            (Ok(()), Ok(())) => report.ok(format!("{listener}: its certificate is valid{named}, past two weeks")),
            (Ok(()), Err(_)) => report.warn(format!(
                "{listener}: its certificate{named} expires within two weeks: renew it"
            )),
            (Err(why), _) => report.fail(format!(
                "{listener}: its certificate{named} is not one clients accept ({why}): use one from a certificate authority, valid for the name clients reach it by"
            )),
        }
    };
    let submission = &config.submission;
    check(
        "submission",
        &submission.certificate,
        &submission.key,
        Some(&submission.hostname),
    );
    if let Some(ses) = &config.ses {
        check("SES API", &ses.certificate, &ses.key, None);
    }
    if let Some(feedback) = &config.feedback {
        check(
            "feedback",
            &feedback.certificate,
            &feedback.key,
            Some(&feedback.hostname),
        );
    }
}

/// The clock against a time server, by SNTP (RFC 4330): signed requests are
/// refused five minutes off, and receivers distrust a skewed date.
async fn clock(server: &str, report: &mut Report) {
    match tokio::time::timeout(PATIENCE, offset(server)).await {
        Ok(Ok(offset)) => {
            let said = format!("clock: {:.3} s from {server}", offset);
            if offset.abs() < 0.5 {
                report.ok(said);
            } else if offset.abs() < 5.0 {
                report.warn(format!("{said}: keep it synchronised, with NTP"));
            } else {
                report.fail(format!(
                    "{said}: synchronise it, with NTP; SigV4 refuses requests five minutes off"
                ));
            }
        }
        Ok(Err(why)) => report.warn(format!(
            "clock: {server} did not answer ({why}), so the clock is not checked"
        )),
        Err(_) => report.warn(format!(
            "clock: {server} did not answer in time, so the clock is not checked"
        )),
    }
}

/// How far the clock is from `server`'s, in seconds: positive when it is
/// behind.
async fn offset(server: &str) -> Result<f64, String> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect(server)
        .await
        .map_err(|error| error.to_string())?;
    let mut request = [0u8; 48];
    // No leap warning, version 4, a client, and when it was sent, which the
    // server's answer echoes.
    request[0] = 0b0010_0011;
    let sent = SystemTime::now();
    let transmitted = ntp(sent);
    request[40..48].copy_from_slice(&transmitted);
    socket
        .send(&request)
        .await
        .map_err(|error| error.to_string())?;
    let mut answer = [0u8; 48];
    let length = socket
        .recv(&mut answer)
        .await
        .map_err(|error| error.to_string())?;
    sntp_offset(&answer[..length], transmitted, sent, SystemTime::now())
}

/// The offset an SNTP server's `answer` gives, to a request `transmitted`
/// at `sent` and answered at `received`: refused unless it is a server's
/// answer to that request, from a synchronised clock (RFC 4330, 5).
fn sntp_offset(
    answer: &[u8],
    transmitted: [u8; 8],
    sent: SystemTime,
    received: SystemTime,
) -> Result<f64, String> {
    if answer.len() < 48 {
        return Err("no server's answer".to_owned());
    }
    let (leap, version, mode) = (answer[0] >> 6, (answer[0] >> 3) & 0b111, answer[0] & 0b111);
    let stratum = answer[1];
    if mode != 4 || !(3..=4).contains(&version) {
        return Err("no server's answer".to_owned());
    }
    if answer[24..32] != transmitted {
        return Err("an answer to another request".to_owned());
    }
    if leap == 3 || !(1..=15).contains(&stratum) {
        return Err("its clock is not synchronised".to_owned());
    }
    if answer[40..48] == [0; 8] {
        return Err("an answer without its time".to_owned());
    }
    const UNIX_FROM_NTP: f64 = 2_208_988_800.0;
    let timestamp = |at: usize| {
        let seconds = u32::from_be_bytes(answer[at..at + 4].try_into().expect("four bytes"));
        let fraction = u32::from_be_bytes(answer[at + 4..at + 8].try_into().expect("four bytes"));
        f64::from(seconds) + f64::from(fraction) / 4_294_967_296.0 - UNIX_FROM_NTP
    };
    let unix = |at: SystemTime| {
        at.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    };
    let (took_in, sent_back) = (timestamp(32), timestamp(40));
    Ok(((took_in - unix(sent)) + (sent_back - unix(received))) / 2.0)
}

/// `at` as NTP's eight bytes: seconds since 1900, and their fraction.
fn ntp(at: SystemTime) -> [u8; 8] {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = (since.as_secs() + 2_208_988_800) as u32;
    let fraction = ((u64::from(since.subsec_nanos()) << 32) / 1_000_000_000) as u32;
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&seconds.to_be_bytes());
    bytes[4..].copy_from_slice(&fraction.to_be_bytes());
    bytes
}

/// Whether DANE is in effect: delivery's resolver on this host, validating
/// DNSSEC.
async fn dane(config: &Config, report: &mut Report) -> Result<(), String> {
    if !config.delivery.dane {
        report.warn(
            "resolver: DANE is off ([delivery] dane = false), so a route's TLSA records are not honoured and DNSSEC is not checked",
        );
        return Ok(());
    }
    let (resolver, remote) = delivery::resolver(&config.delivery)?;
    if !remote.is_empty() {
        report.warn(format!("resolver: {}", delivery::not_local(&remote)));
    } else {
        let validated = delivery::validates(&resolver).await;
        let said = format!("resolver: {}", delivery::verdict(&validated));
        if validated == Ok(true) {
            report.ok(said);
        } else {
            report.warn(said);
        }
    }
    Ok(())
}

/// Each egress: its reverse DNS, confirmed forward and named by its HELO;
/// port 25 from it; the blocklists; and the return path's SPF covering it.
/// With none, port 25 from the host's own address.
async fn egresses(
    config: &Config,
    running: &Running,
    resolver: &TokioResolver,
    authenticator: &MessageAuthenticator,
    probes: &Probes,
    report: &mut Report,
) {
    let return_path = &config.delivery.return_path_domain;
    if running.egresses.is_empty() {
        report.warn(
            "egresses: none, so mail goes out from the host's own address, whose reverse DNS and blocklisting doctor cannot see; put one with its address and HELO name",
        );
        port25(None, &probes.port25, report).await;
        return;
    }
    for egress in &running.egresses {
        let (Some(address), Some(helo)) = (
            egress["address"]
                .as_str()
                .and_then(|address| address.parse::<IpAddr>().ok()),
            egress["helo"].as_str(),
        ) else {
            continue;
        };
        let area = format!("egress {address}");
        match ptr(resolver, address).await {
            Some(names) if names.iter().any(|name| name.eq_ignore_ascii_case(helo)) => {
                let confirmed = forward(resolver, helo).await.contains(&address);
                if confirmed {
                    report.ok(format!("{area}: its PTR names {helo}, which resolves back to it, and its HELO is that name"));
                } else {
                    report.fail(format!("{area}: its PTR names {helo}, which does not resolve back to it: publish {helo} A/AAAA {address}"));
                }
            }
            Some(names) if !names.is_empty() => report.fail(format!(
                "{area}: its PTR names {}, not its HELO name {helo}: make them one, by its HELO or by asking its provider for the PTR",
                names.join(", ")
            )),
            _ => report.fail(format!(
                "{area}: it has no PTR record: ask the address's provider to point it at {helo}"
            )),
        }
        port25(Some(address), &probes.port25, report).await;
        if let IpAddr::V4(v4) = address {
            let octets = v4.octets();
            for list in BLOCKLISTS {
                let name = format!(
                    "{}.{}.{}.{}.{list}.",
                    octets[3], octets[2], octets[1], octets[0]
                );
                match resolver.lookup(name.as_str(), RecordType::A).await {
                    Ok(lookup) => {
                        let answers: Vec<std::net::Ipv4Addr> = lookup
                            .answers()
                            .iter()
                            .filter_map(|record| match &record.data {
                                RData::A(a) => Some(a.0),
                                _ => None,
                            })
                            .collect();
                        if answers
                            .iter()
                            .any(|answer| answer.octets()[..3] == [127, 255, 255])
                        {
                            report.warn(format!(
                                "{area}: {list} refuses this resolver's lookups, so it is not checked; use a resolver of your own, such as a local unbound"
                            ));
                        } else if answers.is_empty() {
                            report.ok(format!("{area}: not on {list}"));
                        } else {
                            report.fail(format!("{area}: listed on {list}: ask for its removal before sending from it"));
                        }
                    }
                    Err(error) if error.is_nx_domain() || error.is_no_records_found() => {
                        report.ok(format!("{area}: not on {list}"));
                    }
                    Err(error) => report.warn(format!("{area}: {list} did not answer ({error})")),
                }
            }
        }
        let sender = format!("postmaster@{return_path}");
        let spf = authenticator
            .verify_spf(SpfParameters::mail_from(address, helo, helo, &sender))
            .await;
        match spf.result() {
            SpfResult::Pass => report.ok(format!("{area}: {return_path}'s SPF covers it")),
            other => report.fail(format!(
                "{area}: {return_path}'s SPF does not pass it ({other:?}): publish {return_path} TXT \"v=spf1 ip{}:{address} -all\", or add it to the record there",
                if address.is_ipv4() { 4 } else { 6 }
            )),
        }
    }
}

/// Why port 25 was not reached from an address.
enum Unreached {
    /// The address cannot be bound, so the host does not hold it, and port
    /// 25 was never tried.
    NotHeld(std::io::Error),
    Failed(String),
}

impl From<std::io::Error> for Unreached {
    fn from(error: std::io::Error) -> Self {
        Self::Failed(error.to_string())
    }
}

impl From<&str> for Unreached {
    fn from(why: &str) -> Self {
        Self::Failed(why.to_owned())
    }
}

/// Port 25 to `probe`, from `from` or the host's own address: some
/// providers block it, and delivery waits until they lift it.
async fn port25(from: Option<IpAddr>, probe: &str, report: &mut Report) {
    let area = from.map_or("port 25".to_owned(), |address| format!("egress {address}"));
    let reached = tokio::time::timeout(PATIENCE, async {
        let target: SocketAddr = tokio::net::lookup_host(probe)
            .await?
            .find(|target| from.is_none_or(|from| from.is_ipv4() == target.is_ipv4()))
            .ok_or("no address of the same family")?;
        let socket = if target.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        }?;
        if let Some(from) = from {
            socket
                .bind(SocketAddr::new(from, 0))
                .map_err(Unreached::NotHeld)?;
        }
        let mut stream = socket.connect(target).await?;
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).await?;
        if &greeting == b"220" {
            Ok::<(), Unreached>(())
        } else {
            Err("it did not greet".into())
        }
    })
    .await;
    match reached {
        Ok(Ok(())) => report.ok(format!("{area}: port 25 reaches {probe}")),
        Ok(Err(Unreached::NotHeld(error))) => report.fail(format!(
            "{area}: this host cannot send from it ({error}): an egress's address must be on one of this host's interfaces"
        )),
        Ok(Err(Unreached::Failed(why))) => report.fail(format!(
            "{area}: port 25 does not reach {probe} ({why}): ask the provider to lift its block on outbound port 25"
        )),
        Err(_) => report.fail(format!(
            "{area}: port 25 to {probe} timed out: ask the provider to lift its block on outbound port 25"
        )),
    }
}

/// Each identity: its DKIM record, when it signs, and the DMARC record that
/// governs it.
async fn identities(
    config: &Config,
    running: &Running,
    resolver: &TokioResolver,
    authenticator: &MessageAuthenticator,
    report: &mut Report,
) {
    let return_path = config.delivery.return_path_domain.to_ascii_lowercase();
    for identity in &running.identities {
        let Some(name) = identity["name"].as_str() else {
            continue;
        };
        let domain = name.rsplit_once('@').map_or(name, |(_, domain)| domain);
        let area = format!("identity {name}");
        if let (Some(selector), Some(key)) = (
            identity["selector"].as_str(),
            identity["dkim_public_key"].as_str(),
        ) {
            let owner = format!("{selector}._domainkey.{domain}");
            let publish = format!("publish {owner} TXT \"v=DKIM1; k=rsa; p={key}\"");
            match verify::dkim(
                &verify::txt(resolver, &owner).await.unwrap_or_default(),
                key,
            ) {
                verify::Dkim::Ours => report.ok(format!("{area}: {owner} publishes its DKIM key")),
                verify::Dkim::Not(why) => report.fail(format!("{area}: {owner} {why}: {publish}")),
            }
        } else {
            report.warn(format!("{area}: the engine does not sign its mail, so its application must, with d={domain}"));
        }
        dmarc(authenticator, resolver, domain, &area, report).await;
        // SPF aligns with the From domain only if the return path is it
        // or under it, as its own verified MAIL FROM domain is; DKIM aligns
        // either way, with d= the From domain.
        let own = &identity["mail_from"];
        let return_path = match own["domain"].as_str() {
            Some(domain) if own["status"] == "success" => domain.to_owned(),
            _ => return_path.clone(),
        };
        let aligned = return_path == domain || return_path.ends_with(&format!(".{domain}"));
        if !aligned {
            report.warn(format!(
                "{area}: the return path's domain, {return_path}, is not {domain} or under it, so SPF does not align for DMARC, and DMARC passes on DKIM alone"
            ));
        }
    }
}

/// The DMARC record that governs `domain`, found as receivers find it
/// (RFC 9989, 4.10): the domain's own, or else its organisational domain's
/// by the DNS tree walk, and the policy it sets for mail from `domain`.
async fn dmarc(
    authenticator: &MessageAuthenticator,
    resolver: &TokioResolver,
    domain: &str,
    area: &str,
    report: &mut Report,
) {
    let publish = format!(
        "publish _dmarc.{domain} TXT \"v=DMARC1; p=none\", then tighten it once reports look right"
    );
    // Receivers discard every record at a name with more than one, and
    // then look past it, so each name the tree walk asks (at most eight,
    // the domain's own and its parents') is counted first.
    let labels: Vec<&str> = domain.split('.').collect();
    let mut own = 0;
    for start in 0..labels.len().min(8) {
        let owner = format!("_dmarc.{}", labels[start..].join("."));
        let records = verify::txt(resolver, &owner)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|record| record.starts_with("v=DMARC1"))
            .count();
        if records > 1 {
            return report.fail(format!(
                "{area}: {owner} publishes {records} DMARC records, which receivers discard: keep one"
            ));
        }
        if start == 0 {
            own = records;
        }
    }
    let raw = format!("From: <postmaster@{domain}>\r\n\r\n");
    let Some(message) = mail_auth::AuthenticatedMessage::parse(raw.as_bytes()) else {
        return report.fail(format!("{area}: {domain} is not a domain mail can be from"));
    };
    let spf = mail_auth::SpfOutput::default();
    let output = authenticator
        .verify_dmarc(mail_auth::dmarc::verify::DmarcParameters::new(
            &message,
            &[],
            domain,
            &spf,
        ))
        .await;
    if let mail_auth::DmarcResult::TempError(error) = output.dkim_result() {
        return report.warn(format!(
            "{area}: its DMARC record could not be looked up ({error})"
        ));
    }
    match output.record() {
        Some(_) => report.ok(format!(
            "{area}: DMARC governs it, with policy {}",
            output.policy()
        )),
        None if own == 1 => report.fail(format!(
            "{area}: _dmarc.{domain} publishes a DMARC record receivers do not apply, with no policy (p=) and nowhere to report: {publish}"
        )),
        None => report.fail(format!("{area}: no DMARC record governs it: {publish}")),
    }
}

/// Where bounces go: the return path domain's MX.
async fn bounces(config: &Config, resolver: &TokioResolver, report: &mut Report) {
    let domain = &config.delivery.return_path_domain;
    match resolver.mx_lookup(format!("{domain}.")).await {
        Ok(lookup) if lookup.answers().iter().any(|record| matches!(record.data, RData::MX(_))) => {
            report.ok(format!("bounces: {domain} has an MX, which bounces go to"));
        }
        _ => report.fail(format!(
            "bounces: {domain} has no MX, so bounces to its return paths go nowhere: publish one naming the host the engine's feedback listener answers on"
        )),
    }
}

/// The names `address`'s PTR records give, without their final dots.
async fn ptr(resolver: &TokioResolver, address: IpAddr) -> Option<Vec<String>> {
    let lookup = resolver.reverse_lookup(address).await.ok()?;
    Some(
        lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::PTR(name) => Some(name.0.to_string().trim_end_matches('.').to_owned()),
                _ => None,
            })
            .collect(),
    )
}

/// The addresses `name` resolves to.
async fn forward(resolver: &TokioResolver, name: &str) -> Vec<IpAddr> {
    match resolver.lookup_ip(format!("{name}.")).await {
        Ok(lookup) => lookup.iter().collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_sntp_answer_counts_only_from_a_synchronised_server_to_the_request() {
        let sent = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let transmitted = ntp(sent);
        // The server's clock two seconds ahead, answering at once.
        let server = ntp(sent + Duration::from_secs(2));
        let answer = |first: u8, stratum: u8, echoed: [u8; 8]| {
            let mut answer = [0u8; 48];
            answer[0] = first;
            answer[1] = stratum;
            answer[24..32].copy_from_slice(&echoed);
            answer[32..40].copy_from_slice(&server);
            answer[40..48].copy_from_slice(&server);
            answer
        };
        let offset = |answer: [u8; 48]| sntp_offset(&answer, transmitted, sent, sent);
        let good = offset(answer(0b0010_0100, 2, transmitted)).unwrap();
        assert!((good - 2.0).abs() < 0.001, "{good}");
        assert_eq!(
            offset(answer(0b0010_0100, 0, transmitted)),
            Err("its clock is not synchronised".to_owned())
        );
        assert_eq!(
            offset(answer(0b1110_0100, 2, transmitted)),
            Err("its clock is not synchronised".to_owned())
        );
        assert_eq!(
            offset(answer(0b0010_0100, 2, ntp(sent + Duration::from_secs(9)))),
            Err("an answer to another request".to_owned())
        );
        assert_eq!(
            offset(answer(0b0010_0011, 2, transmitted)),
            Err("no server's answer".to_owned())
        );
        assert_eq!(
            sntp_offset(&[0u8; 12], transmitted, sent, sent),
            Err("no server's answer".to_owned())
        );
    }
}
