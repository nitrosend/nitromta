//! TLS for submission, delivery and event delivery.
//!
//! Verified TLS trusts the certificate authorities `[tls] authorities`
//! names, or the system's: event subscribers over https, MTA-STS's policy
//! hosts, and the exchanges of a domain whose MTA-STS policy enforces.
//!
//! Delivery otherwise encrypts without verifying the receiver's
//! certificate, as SMTP between servers does without a policy that asks
//! for verification. An exchange with secure TLSA records is verified by
//! them instead (RFC 7672), whatever authority signed its certificate.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use engine_smtp::dane::{self, DANE_EE, DANE_TA, Tlsa};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig,
    SignatureScheme,
};

/// Where the system's trusted authorities are kept: by Debian, Ubuntu and
/// Alpine; by Fedora and RHEL; and by macOS. The first that exists is used.
const SYSTEM_AUTHORITIES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

/// A certificate webpki refused, as rustls reports one.
fn invalid(error: webpki::Error) -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::new(error))))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// How long a client's TLS handshake may take.
const HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(10);

/// A listener's certificate and key, from their PEM files, which a reload
/// reads again: a renewed certificate is served without a restart.
/// Each connection takes the acceptor current as it arrives, one read of a
/// lock no writer holds but a reload; a reload that cannot read the files
/// keeps the acceptor it had, and says why.
pub struct Certified {
    certificate: PathBuf,
    key: PathBuf,
    current: std::sync::RwLock<tokio_rustls::TlsAcceptor>,
}

impl Certified {
    pub fn load(certificate: &Path, key: &Path) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            certificate: certificate.to_owned(),
            key: key.to_owned(),
            current: std::sync::RwLock::new(tokio_rustls::TlsAcceptor::from(server(
                certificate,
                key,
            )?)),
        }))
    }

    /// The acceptor for a connection arriving now.
    /// A TLS session with the client on `stream`, once its handshake ends
    /// within [`HANDSHAKE`]; none if it fails or takes longer.
    pub async fn accept<S>(&self, stream: S) -> Option<tokio_rustls::server::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        tokio::time::timeout(HANDSHAKE, self.acceptor().accept(stream))
            .await
            .ok()?
            .ok()
    }

    pub fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Reads the certificate and key again, and serves them from the next
    /// connection on, if they are a certificate and its key.
    pub fn reload(&self) -> Result<(), String> {
        let acceptor = tokio_rustls::TlsAcceptor::from(server(&self.certificate, &self.key)?);
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = acceptor;
        Ok(())
    }

    /// The certificate file it reads, for its log lines.
    pub fn certificate(&self) -> &Path {
        &self.certificate
    }
}

/// The submission listener's configuration, from PEM files.
pub fn server(certificate: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let chain = CertificateDer::pem_file_iter(certificate)
        .and_then(|certificates| certificates.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("{}: {error}", certificate.display()))?;
    let key =
        PrivateKeyDer::from_pem_file(key).map_err(|error| format!("{}: {error}", key.display()))?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .and_then(|builder| builder.with_no_client_auth().with_single_cert(chain, key))
        .map_err(|error| format!("TLS for submission: {error}"))?;
    Ok(Arc::new(config))
}

/// Delivery's configuration without a policy: any certificate is accepted,
/// but the server must still hold the key its certificate names.
pub fn client() -> Result<Arc<ClientConfig>, String> {
    let provider = provider();
    let verifier = Encrypted(provider.signature_verification_algorithms);
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("TLS for delivery: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The authorities verified TLS trusts: those in `configured`, a PEM
/// bundle, or else in the system's bundle.
pub fn authorities(configured: Option<&Path>) -> Result<RootCertStore, String> {
    let path = match configured {
        Some(path) => path.to_owned(),
        None => SYSTEM_AUTHORITIES
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .ok_or("no system bundle of certificate authorities was found; name one as [tls] authorities")?,
    };
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&path).map_err(|error| failed(&error))? {
        let certificate = certificate.map_err(|error| failed(&error))?;
        roots.add(certificate).map_err(|error| failed(&error))?;
    }
    if roots.is_empty() {
        return Err(failed(&"no certificate authority in it"));
    }
    Ok(roots)
}

/// Verified TLS's configuration: a server's certificate must chain to one
/// of `roots` and be valid for the name it is reached by.
pub fn verified(roots: RootCertStore) -> Result<Arc<ClientConfig>, String> {
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("verified TLS: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A connection's configuration for an exchange whose secure TLSA records
/// are `records`, all usable (RFC 7672, 3.1), where a DANE-TA certificate
/// must be valid for one of `names`.
pub fn dane(records: Vec<Tlsa>, names: Vec<String>) -> Result<Arc<ClientConfig>, String> {
    let provider = provider();
    let verifier = Dane {
        records,
        names,
        algorithms: provider.signature_verification_algorithms,
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("TLS for DANE: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct Encrypted(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for Encrypted {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, signature, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, signature, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// An exchange's TLSA records, which its certificate must match (RFC 7672,
/// 3.1): a DANE-EE record by the certificate itself, whatever its names and
/// dates; a DANE-TA record by a certificate the server sent, which its
/// certificate's chain must reach within that anchor's path length, and be
/// valid for one of the reference identifiers (3.2.2).
#[derive(Debug)]
struct Dane {
    records: Vec<Tlsa>,
    names: Vec<String>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Dane {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let matched = |usage: u8, certificate: &CertificateDer<'_>| {
            self.records
                .iter()
                .any(|record| record.usage == usage && record.matches(certificate))
        };
        if matched(DANE_EE, end_entity) {
            return Ok(ServerCertVerified::assertion());
        }
        let certificate = webpki::EndEntityCert::try_from(end_entity).map_err(invalid)?;
        let mut last = None;
        for anchor in intermediates
            .iter()
            .filter(|anchor| matched(DANE_TA, anchor))
        {
            let limit = dane::path_length(anchor);
            let trusted = [webpki::anchor_from_trusted_cert(anchor).map_err(invalid)?];
            // The anchor's path length counts the intermediates below it
            // that are not self-issued (RFC 5280, 4.2.1.9).
            let within = |path: &webpki::VerifiedPath<'_>| {
                let below = path
                    .intermediate_certificates()
                    .filter(|certificate| certificate.issuer() != certificate.subject())
                    .count() as u64;
                match limit {
                    Some(limit) if below > limit => Err(webpki::Error::PathLenConstraintViolated),
                    _ => Ok(()),
                }
            };
            let verified = certificate.verify_for_usage(
                self.algorithms.all,
                &trusted,
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                None,
                Some(&within),
            );
            let named = |verified: webpki::VerifiedPath<'_>| {
                let _ = verified;
                self.names.iter().any(|name| {
                    ServerName::try_from(name.as_str()).is_ok_and(|name| {
                        certificate.verify_is_valid_for_subject_name(&name).is_ok()
                    })
                })
            };
            match verified.map(named) {
                Ok(true) => return Ok(ServerCertVerified::assertion()),
                Ok(false) => {
                    last = Some(rustls::Error::InvalidCertificate(
                        CertificateError::NotValidForName,
                    ));
                }
                Err(error) => last = Some(invalid(error)),
            }
        }
        Err(last.unwrap_or(rustls::Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
