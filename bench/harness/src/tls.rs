//! TLS for the harness's own ends: the sink's STARTTLS and the load
//! generator's. Every hop is encrypted so that every system does the same TLS
//! work, and no hop verifies its peer's certificate, which every system is
//! configured the same way to skip.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

/// A certificate and its key, both PEM.
pub struct Identity {
    pub certificate: String,
    pub key: String,
}

/// A self-signed certificate for `hostname`, with an ECDSA P-256 key.
pub fn self_signed(hostname: &str) -> Result<Identity, String> {
    let certified = rcgen::generate_simple_self_signed(vec![hostname.to_owned()])
        .map_err(|error| format!("a certificate for {hostname}: {error}"))?;
    Ok(Identity {
        certificate: certified.cert.pem(),
        key: certified.signing_key.serialize_pem(),
    })
}

/// A server configuration presenting a fresh self-signed certificate.
pub fn server_config(hostname: &str) -> Result<Arc<ServerConfig>, String> {
    let certified = rcgen::generate_simple_self_signed(vec![hostname.to_owned()])
        .map_err(|error| format!("a certificate for {hostname}: {error}"))?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .and_then(|builder| {
            builder
                .with_no_client_auth()
                .with_single_cert(vec![certified.cert.der().clone()], key)
        })
        .map_err(|error| format!("TLS server configuration: {error}"))?;
    Ok(Arc::new(config))
}

/// A client configuration that accepts any certificate, but still checks
/// that the server holds the key its certificate names.
pub fn client_config() -> Result<Arc<ClientConfig>, String> {
    let provider = provider();
    let verifier = AnyCertificate(provider.signature_verification_algorithms);
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("TLS client configuration: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[derive(Debug)]
struct AnyCertificate(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AnyCertificate {
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
