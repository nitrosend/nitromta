//! A stub DNS on a port of its own, authoritative for the names it holds:
//! their records, an empty answer for a type a name lacks, and NXDOMAIN for
//! a name it lacks. Validating, it stands for a resolver on the test's host
//! that validates DNSSEC, `test.` its one signed zone beside the root: to a
//! query asking for DNSSEC's verdict, it sets the AD bit on a reply wholly
//! about them, and a record it holds as bogus gets SERVFAIL, as such a
//! resolver answers.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hickory_resolver::proto::dnssec::SigningKey;
use hickory_resolver::proto::dnssec::crypto::Ed25519SigningKey;
use hickory_resolver::proto::dnssec::rdata::{DNSKEY, DNSSECRData};
use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
use hickory_resolver::proto::rr::rdata::{A, CNAME, MX, NS, SOA, TLSA, TXT};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};

/// The zone a validating stub holds as signed.
pub const ZONE: &str = "test.";
/// A second, so a record a test changes is seen as soon as it changes.
const TTL: u32 = 1;

pub struct Dns {
    pub address: SocketAddr,
    zone: Arc<Mutex<Zone>>,
    /// The queries it has been sent.
    queries: Arc<AtomicUsize>,
}

#[derive(Default)]
struct Zone {
    records: BTreeMap<Name, BTreeMap<RecordType, Vec<RData>>>,
    /// Whether it validates, so `test.` and the root are secure.
    validating: bool,
    /// Records it holds as bogus, by name and type.
    bogus: BTreeSet<(Name, RecordType)>,
    /// The queries that asked for DNSSEC's verdict.
    asked: usize,
}

impl Dns {
    /// A stub that validates nothing, with an MX record for each of
    /// `routes`' domains, naming its one exchange, which is at 127.0.0.1.
    pub fn start(routes: &[(&str, &str)]) -> Self {
        let dns = Self::serve(Zone::default());
        for (domain, exchange) in routes {
            dns.route(domain, exchange);
        }
        dns
    }

    /// A validating stub holding `test.`, with `routes` as [`Dns::start`]'s.
    pub fn validating(routes: &[(&str, &str)]) -> Self {
        let mut zone = Zone {
            validating: true,
            ..Zone::default()
        };
        let (apex, ns) = (name(ZONE), name("ns.test."));
        zone.add(
            &apex,
            RData::SOA(SOA::new(
                ns.clone(),
                name("hostmaster.test."),
                1,
                3600,
                600,
                86_400,
                TTL,
            )),
        );
        zone.add(&apex, RData::NS(NS(ns.clone())));
        zone.add(&ns, RData::A(A(Ipv4Addr::LOCALHOST)));
        // The root's keys, which a validating resolver proves secure.
        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().expect("a key"))
                .expect("a key");
        let dnskey = DNSKEY::new(
            true,
            true,
            false,
            key.to_public_key().expect("its public key"),
        );
        zone.add(&Name::root(), RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)));
        let dns = Self::serve(zone);
        for (domain, exchange) in routes {
            dns.route(domain, exchange);
        }
        dns
    }

    fn serve(zone: Zone) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
        let address = socket.local_addr().expect("its address");
        let zone = Arc::new(Mutex::new(zone));
        let queries = Arc::new(AtomicUsize::new(0));
        let (serving, counting) = (Arc::clone(&zone), Arc::clone(&queries));
        std::thread::spawn(move || {
            let mut buffer = [0; 4096];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer) {
                counting.fetch_add(1, Ordering::Relaxed);
                let reply = lock(&serving).answer(&buffer[..length]);
                if let Some(reply) = reply {
                    let _ = socket.send_to(&reply, peer);
                }
            }
        });
        Self {
            address,
            zone,
            queries,
        }
    }

    /// How many queries it has been sent.
    pub fn queries(&self) -> usize {
        self.queries.load(Ordering::Relaxed)
    }

    /// How many of them asked for DNSSEC's verdict.
    pub fn asked(&self) -> usize {
        lock(&self.zone).asked
    }

    /// An MX record for `domain` naming `exchange`, at 127.0.0.1.
    pub fn route(&self, domain: &str, exchange: &str) {
        self.mx(domain, 10, exchange);
    }

    /// An MX record for `domain` naming `exchange` at `preference`, at
    /// 127.0.0.1.
    pub fn mx(&self, domain: &str, preference: u16, exchange: &str) {
        self.mx_only(domain, preference, exchange);
        self.address_of(exchange);
    }

    /// An MX record alone, its exchange's address left to the test.
    pub fn mx_only(&self, domain: &str, preference: u16, exchange: &str) {
        self.add(
            domain,
            RData::MX(MX::new(preference, name(&format!("{exchange}.")))),
        );
    }

    /// An address for `host`: 127.0.0.1.
    pub fn address_of(&self, host: &str) {
        self.add(host, RData::A(A(Ipv4Addr::LOCALHOST)));
    }

    /// A TXT record of `text`, in DNS's strings of at most 255 bytes.
    pub fn txt(&self, owner: &str, text: &str) {
        let record =
            TXT::try_new(text.as_bytes().chunks(255)).expect("a record within DNS's limits");
        self.add(owner, RData::TXT(record));
    }

    /// A TLSA record for SMTP at `host`, on `port`.
    pub fn tlsa(
        &self,
        host: &str,
        port: u16,
        usage: u8,
        selector: u8,
        matching: u8,
        data: Vec<u8>,
    ) {
        self.add(
            &format!("_{port}._tcp.{host}"),
            RData::TLSA(TLSA::new(
                CertUsage::from(usage),
                Selector::from(selector),
                Matching::from(matching),
                data,
            )),
        );
    }

    /// A CNAME record: `alias` for `target`.
    pub fn alias(&self, alias: &str, target: &str) {
        self.add(alias, RData::CNAME(CNAME(name(&format!("{target}.")))));
    }

    pub fn add(&self, owner: &str, data: RData) {
        lock(&self.zone).add(&name(&format!("{owner}.")), data);
    }

    /// Removes `owner`'s records of `kind`.
    pub fn remove(&self, owner: &str, kind: RecordType) {
        let mut zone = lock(&self.zone);
        let owner = name(&format!("{owner}."));
        if let Some(types) = zone.records.get_mut(&owner) {
            types.remove(&kind);
            if types.is_empty() {
                zone.records.remove(&owner);
            }
        }
    }

    /// Holds `owner`'s records of `kind` as bogus: their signatures do not
    /// verify.
    pub fn bogus(&self, owner: &str, kind: RecordType) {
        lock(&self.zone)
            .bogus
            .insert((name(&format!("{owner}.")), kind));
    }
}

impl Zone {
    fn add(&mut self, owner: &Name, data: RData) {
        self.records
            .entry(owner.to_lowercase())
            .or_default()
            .entry(data.record_type())
            .or_default()
            .push(data);
    }

    fn answer(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        let query = Message::from_vec(query).ok()?;
        let question = query.queries.first()?.clone();
        let mut asked = question.name().to_lowercase();
        let kind = question.query_type();
        // Either bit asks for DNSSEC's verdict (RFC 6840, 5.7).
        let verdict = query.metadata.authentic_data
            || query
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok);
        self.asked += usize::from(verdict);
        let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.authoritative = true;
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.recursion_available = true;
        reply.add_query(question);
        if let Some(asked_edns) = &query.edns {
            let mut edns = Edns::new();
            edns.set_max_payload(4096);
            edns.set_dnssec_ok(asked_edns.flags().dnssec_ok);
            reply.set_edns(edns);
        }
        // An alias's chain comes first, link by link.
        let mut owners = vec![asked.clone()];
        let mut bogus = false;
        for _ in 0..8 {
            let Some(RData::CNAME(target)) = self
                .records
                .get(&asked)
                .filter(|_| kind != RecordType::CNAME)
                .and_then(|types| types.get(&RecordType::CNAME))
                .and_then(|aliases| aliases.first())
            else {
                break;
            };
            let target = target.0.to_lowercase();
            bogus |= self.bogus.contains(&(asked.clone(), RecordType::CNAME));
            reply.add_answers(self.rrset(&asked, RecordType::CNAME));
            asked = target;
            owners.push(asked.clone());
        }
        match self.records.get(&asked) {
            Some(types) if types.contains_key(&kind) => {
                bogus |= self.bogus.contains(&(asked.clone(), kind));
                reply.add_answers(self.rrset(&asked, kind));
            }
            Some(_) => {
                reply.add_authorities(self.soa());
            }
            None => {
                reply.metadata.response_code = ResponseCode::NXDomain;
                reply.add_authorities(self.soa());
            }
        }
        if self.validating && bogus {
            reply.answers.clear();
            reply.authorities.clear();
            reply.metadata.response_code = ResponseCode::ServFail;
        } else {
            reply.metadata.authentic_data = self.validating && verdict && owners.iter().all(secure);
        }
        reply.to_vec().ok()
    }

    /// `owner`'s records of `kind`.
    fn rrset(&self, owner: &Name, kind: RecordType) -> Vec<Record> {
        self.records
            .get(owner)
            .and_then(|types| types.get(&kind))
            .into_iter()
            .flatten()
            .map(|data| Record::from_rdata(owner.clone(), TTL, data.clone()))
            .collect()
    }

    /// The zone's SOA, for an empty answer, when it holds one.
    fn soa(&self) -> Vec<Record> {
        if !self.validating {
            return Vec::new();
        }
        self.rrset(&name(ZONE), RecordType::SOA)
    }
}

/// Whether `owner` is the root or in `test.`, which a validating stub holds
/// as signed.
fn secure(owner: &Name) -> bool {
    owner.is_root() || name(ZONE).zone_of(owner)
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a name").to_lowercase()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
