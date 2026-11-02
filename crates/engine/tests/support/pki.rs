//! A test's own certificate authority, the certificates it issues, and an
//! MTA-STS policy host that serves a policy over HTTPS with one of them.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PublicKeyData as _,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::lock;

pub struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
    /// Its own certificate, and those above it to the root.
    chain: Vec<CertificateDer<'static>>,
}

/// A certificate's chain, and its key.
pub struct Certified {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivatePkcs8KeyDer<'static>,
    /// Its subjectPublicKeyInfo, which a TLSA record may bind.
    pub public_key: Vec<u8>,
}

fn authority(name: &str, path_length: Option<u8>) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
    params.is_ca = IsCa::Ca(match path_length {
        Some(length) => BasicConstraints::Constrained(length),
        None => BasicConstraints::Unconstrained,
    });
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, name);
    params
}

impl Authority {
    pub fn new() -> Self {
        Self::constrained(None)
    }

    /// A root whose paths may hold at most `path_length` intermediate
    /// authorities below it, when that is given.
    pub fn constrained(path_length: Option<u8>) -> Self {
        let issuer = CertifiedIssuer::self_signed(
            authority("Test Authority", path_length),
            KeyPair::generate().expect("a key"),
        )
        .expect("a CA");
        let chain = vec![issuer.der().clone()];
        Self { issuer, chain }
    }

    /// An authority this one issues.
    pub fn subordinate(&self) -> Self {
        self.issues("Test Subordinate")
    }

    /// An authority this one issues under its own name, as a key's
    /// rollover does: self-issued, so no path length counts it.
    pub fn rollover(&self) -> Self {
        self.issues("Test Authority")
    }

    fn issues(&self, name: &str) -> Self {
        let issuer = CertifiedIssuer::signed_by(
            authority(name, None),
            KeyPair::generate().expect("a key"),
            &self.issuer,
        )
        .expect("a subordinate CA");
        let mut chain = vec![issuer.der().clone()];
        chain.extend(self.chain.iter().cloned());
        Self { issuer, chain }
    }

    /// Its certificate, as a PEM bundle of one.
    pub fn pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn certificate(&self) -> CertificateDer<'static> {
        self.issuer.der().clone()
    }

    /// A certificate it issues for `names`, chained to its own.
    pub fn issue(&self, names: &[&str]) -> Certified {
        let key = KeyPair::generate().expect("a key");
        let params = CertificateParams::new(
            names
                .iter()
                .map(|&name| name.to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("parameters");
        let certificate = params.signed_by(&key, &self.issuer).expect("issued");
        let mut chain = vec![certificate.der().clone()];
        chain.extend(self.chain.iter().cloned());
        Certified {
            chain,
            key: PrivatePkcs8KeyDer::from(key.serialize_der()),
            public_key: key.subject_public_key_info(),
        }
    }
}

impl Certified {
    /// A certificate for `names` that no authority issued.
    pub fn self_signed(names: &[&str]) -> Self {
        let certified = rcgen::generate_simple_self_signed(
            names
                .iter()
                .map(|&name| name.to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("a certificate");
        Self {
            chain: vec![certified.cert.der().clone()],
            key: PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
            public_key: certified.signing_key.subject_public_key_info(),
        }
    }

    /// A server's configuration presenting it whatever name is asked for.
    pub fn server(&self) -> Arc<ServerConfig> {
        Arc::new(
            config()
                .with_single_cert(
                    self.chain.clone(),
                    PrivateKeyDer::Pkcs8(self.key.clone_key()),
                )
                .expect("a server configuration"),
        )
    }
}

/// A server's configuration presenting, for each name asked for, the
/// certificate given for it, whatever names that certificate holds.
pub fn by_name(certificates: &[(&str, &Certified)]) -> Arc<ServerConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let certificates = certificates
        .iter()
        .map(|(name, certified)| {
            let key = provider
                .key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(certified.key.clone_key()))
                .expect("a key");
            (
                (*name).to_owned(),
                Arc::new(CertifiedKey::new(certified.chain.clone(), key)),
            )
        })
        .collect();
    Arc::new(config().with_cert_resolver(Arc::new(ByName(certificates))))
}

#[derive(Debug)]
struct ByName(BTreeMap<String, Arc<CertifiedKey>>);

impl ResolvesServerCert for ByName {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.get(hello.server_name()?).cloned()
    }
}

fn config() -> rustls::ConfigBuilder<ServerConfig, rustls::server::WantsServerCert> {
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
}

/// An MTA-STS policy host on a port of its own: HTTPS with its certificate,
/// serving its policy at `/.well-known/mta-sts.txt` while it has one, and
/// 404 otherwise.
pub struct PolicyHost {
    pub port: u16,
    policy: Arc<Mutex<Option<String>>>,
    /// The requests it has served.
    pub fetched: Arc<Mutex<usize>>,
}

impl PolicyHost {
    pub fn start(certified: &Certified, policy: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its address").port();
        let host = Self {
            port,
            policy: Arc::new(Mutex::new(Some(policy.to_owned()))),
            fetched: Arc::default(),
        };
        let (config, policy, fetched) = (
            certified.server(),
            Arc::clone(&host.policy),
            Arc::clone(&host.fetched),
        );
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (config, policy, fetched) = (
                    Arc::clone(&config),
                    Arc::clone(&policy),
                    Arc::clone(&fetched),
                );
                std::thread::spawn(move || {
                    let Ok(session) = ServerConnection::new(config) else {
                        return;
                    };
                    let mut reader = BufReader::new(StreamOwned::new(session, stream));
                    let mut line = String::new();
                    // The request line and headers, to the blank line.
                    loop {
                        line.clear();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => return,
                            Ok(_) if line == "\r\n" => break,
                            Ok(_) => {}
                        }
                    }
                    *lock(&fetched) += 1;
                    let response = match lock(&policy).clone() {
                        Some(policy) => format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{policy}",
                            policy.len()
                        ),
                        None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                            .to_owned(),
                    };
                    let stream = reader.get_mut();
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                });
            }
        });
        host
    }

    /// Serves `policy`, or, with `None`, nothing.
    pub fn serve(&self, policy: Option<&str>) {
        *lock(&self.policy) = policy.map(str::to_owned);
    }
}
