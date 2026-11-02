//! A stub DNS on a port of its own, authoritative for the names it holds:
//! their records, an empty answer for a type a name lacks, and NXDOMAIN for
//! a name it lacks. Signed, it holds one zone, `test.`, under a key the
//! engine takes as its trust anchor: every answer carries its RRSIG, and
//! every empty answer or NXDOMAIN its NSEC proof, so a validating resolver
//! proves them secure. A record can also be served with a broken signature,
//! which such a resolver must find bogus.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hickory_resolver::proto::dnssec::crypto::Ed25519SigningKey;
use hickory_resolver::proto::dnssec::rdata::{DNSKEY, DNSSECRData, NSEC, RRSIG, SigInput};
use hickory_resolver::proto::dnssec::{DnssecSigner, PublicKey, SigningKey, TBS};
use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
use hickory_resolver::proto::rr::rdata::{A, CNAME, MX, NS, SOA, TLSA, TXT};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};

/// The zone a signed stub holds.
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
    signer: Option<DnssecSigner>,
    /// Records served with a broken signature, by name and type.
    forged: BTreeSet<(Name, RecordType)>,
}

impl Dns {
    /// An unsigned stub with an MX record for each of `routes`' domains,
    /// naming its one exchange, which is at 127.0.0.1.
    pub fn start(routes: &[(&str, &str)]) -> Self {
        let dns = Self::serve(Zone::default());
        for (domain, exchange) in routes {
            dns.route(domain, exchange);
        }
        dns
    }

    /// A signed stub holding `test.`, with `routes` as [`Dns::start`]'s.
    pub fn signed(routes: &[(&str, &str)]) -> Self {
        let key =
            Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().expect("a key"))
                .expect("a key");
        let dnskey = DNSKEY::new(
            true,
            true,
            false,
            key.to_public_key().expect("its public key"),
        );
        let apex = name(ZONE);
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            apex.clone(),
            Duration::from_secs(86_400),
        );
        let mut zone = Zone {
            signer: Some(signer),
            ..Zone::default()
        };
        let ns = name("ns.test.");
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
        zone.add(&apex, RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)));
        zone.add(&ns, RData::A(A(Ipv4Addr::LOCALHOST)));
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

    /// The trust anchor a signed stub's answers are proved by, as the
    /// DNSKEY record hickory reads from a file.
    pub fn trust_anchor(&self) -> String {
        let zone = lock(&self.zone);
        let signer = zone.signer.as_ref().expect("a signed stub");
        let key = signer.dnskey();
        format!(
            "{ZONE} {TTL} IN DNSKEY {} 3 {} {}\n",
            key.flags(),
            u8::from(key.public_key().algorithm()),
            base64::engine::general_purpose::STANDARD.encode(key.public_key().public_bytes())
        )
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

    /// Serves `owner`'s records of `kind` with a signature that does not
    /// verify.
    pub fn forge(&self, owner: &str, kind: RecordType) {
        lock(&self.zone)
            .forged
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

    fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let query = Message::from_vec(query).ok()?;
        let question = query.queries.first()?.clone();
        let asked = question.name().to_lowercase();
        let kind = question.query_type();
        let dnssec = query
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);
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
        let sign = dnssec && self.signer.is_some();
        // An alias's chain comes first, each link with its signature.
        let mut asked = asked;
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
            for record in self.rrset(&asked, RecordType::CNAME, sign) {
                reply.add_answer(record);
            }
            asked = target;
        }
        match self.records.get(&asked) {
            Some(types) if types.contains_key(&kind) => {
                for record in self.rrset(&asked, kind, sign) {
                    reply.add_answer(record);
                }
            }
            // An empty answer: the name's own NSEC proves it lacks the type.
            Some(_) => {
                reply.add_authorities(self.soa(sign));
                if sign {
                    reply.add_authorities(self.nsec(&asked));
                }
            }
            // NXDOMAIN: the NSEC covering the name, and the one covering
            // the wildcard that might have answered for it.
            None => {
                reply.metadata.response_code = ResponseCode::NXDomain;
                reply.add_authorities(self.soa(sign));
                if sign {
                    let covering = self.covering(&asked);
                    let wildcard = self.covering(&name("*.test."));
                    reply.add_authorities(self.nsec(&covering));
                    if wildcard != covering {
                        reply.add_authorities(self.nsec(&wildcard));
                    }
                }
            }
        }
        reply.to_vec().ok()
    }

    /// `owner`'s records of `kind`, and their signature when `sign`.
    fn rrset(&self, owner: &Name, kind: RecordType, sign: bool) -> Vec<Record> {
        let records: Vec<Record> = self
            .records
            .get(owner)
            .and_then(|types| types.get(&kind))
            .into_iter()
            .flatten()
            .map(|data| Record::from_rdata(owner.clone(), TTL, data.clone()))
            .collect();
        let mut signed = records.clone();
        if sign && let Some(signer) = &self.signer {
            let forged = self.forged.contains(&(owner.clone(), kind));
            signed.push(signature(signer, owner, kind, &records, forged));
        }
        signed
    }

    fn soa(&self, sign: bool) -> Vec<Record> {
        if self.signer.is_none() {
            return Vec::new();
        }
        self.rrset(&name(ZONE), RecordType::SOA, sign)
    }

    /// The name in the zone at or before `asked` in canonical order, whose
    /// NSEC covers `asked`.
    fn covering(&self, asked: &Name) -> Name {
        self.records
            .keys()
            .rfind(|owner| *owner <= asked)
            .cloned()
            .unwrap_or_else(|| name(ZONE))
    }

    /// `owner`'s NSEC record, naming the next name and the types `owner`
    /// has, and its signature.
    fn nsec(&self, owner: &Name) -> Vec<Record> {
        let Some(signer) = &self.signer else {
            return Vec::new();
        };
        let next = self
            .records
            .keys()
            .find(|other| *other > owner)
            .cloned()
            .unwrap_or_else(|| name(ZONE));
        let mut types: BTreeSet<RecordType> = self
            .records
            .get(owner)
            .map(|types| types.keys().copied().collect())
            .unwrap_or_default();
        types.extend([RecordType::RRSIG, RecordType::NSEC]);
        let record = Record::from_rdata(
            owner.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, types))),
        );
        let signature = signature(
            signer,
            owner,
            RecordType::NSEC,
            std::slice::from_ref(&record),
            false,
        );
        vec![record, signature]
    }
}

/// The RRSIG over `records`, `owner`'s of `kind`; `forged`, one that does
/// not verify.
fn signature(
    signer: &DnssecSigner,
    owner: &Name,
    kind: RecordType,
    records: &[Record],
    forged: bool,
) -> Record {
    let now = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs(),
    )
    .expect("before 2106");
    let input = SigInput {
        type_covered: kind,
        algorithm: signer.key().algorithm(),
        num_labels: owner.num_labels(),
        original_ttl: TTL,
        sig_expiration: SerialNumber::new(now + 86_400),
        sig_inception: SerialNumber::new(now - 3600),
        key_tag: signer.calculate_key_tag().expect("a key tag"),
        signer_name: signer.signer_name().clone(),
    };
    let tbs = TBS::from_input(owner, DNSClass::IN, &input, records.iter()).expect("signable");
    let mut signed = signer.sign(&tbs).expect("signed");
    if forged {
        signed[0] ^= 0xFF;
    }
    Record::from_rdata(
        owner.clone(),
        TTL,
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, signed))),
    )
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a name").to_lowercase()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
