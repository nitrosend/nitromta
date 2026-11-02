//! The reference machine's component ceilings, measured on one core
//! with the engine's own code:
//! - DKIM: RSA-2048 signatures of a 16 KiB message, relaxed/relaxed over the
//!   header fields every system signs, as the engine prepares each message;
//! - SigV4: verifications of a SendEmail request carrying that message, each
//!   computing the expected signature in full, as a mismatch also does;
//! - SHA-256 over message bodies, for scale.
//!
//! The harness runs it on one of the systems' CPUs, so a system's rate reads
//! as a share of what those CPUs can sign. It prints JSON.

use std::hint::black_box;
use std::time::{Duration, Instant};

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use engine_api::sigv4::{self, Failure, Request, Scope};
use engine_core::time::Timestamp;
use engine_message::dkim::Signer;

const MESSAGE_BYTES: usize = 16 * 1024;
/// Each measurement runs at least this long.
const SPAN: Duration = Duration::from_secs(2);
/// 28 October 2026, 00:00 UTC: the request's time and the verifier's.
const NOW: Timestamp = Timestamp::from_micros(1_793_145_600_000_000);

fn main() -> Result<(), String> {
    let header = b"From: load@bench.test\r\nTo: r1@d1.sink.test\r\nSubject: ceiling\r\n\
                   Date: Wed, 28 Oct 2026 00:00:00 +0000\r\nMessage-ID: <1@bench.test>\r\n";
    let body = body();

    let pair = KeyPair::generate(KeySize::Rsa2048).map_err(|_| "an RSA key".to_owned())?;
    let der = pair.as_der().map_err(|_| "the RSA key's DER".to_owned())?;
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der.as_ref())
    );
    let signer = Signer::from_pem(
        &pem,
        "bench.test",
        "bench",
        &["From", "To", "Subject", "Date", "Message-ID"],
    )
    .map_err(|error| format!("the signer: {error:?}"))?;
    let signs = rate(|| {
        black_box(signer.sign(header, &body).ok());
    });

    let message = [&header[..], b"\r\n", &body].concat();
    let request_body = format!(
        r#"{{"Destination":{{"ToAddresses":["r1@d1.sink.test"]}},"Content":{{"Raw":{{"Data":"{}"}}}}}}"#,
        STANDARD.encode(&message)
    );
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential=AKIDBENCH/20261028/us-east-1/ses/aws4_request, \
         SignedHeaders=content-type;host;x-amz-date, Signature={}",
        "0".repeat(64)
    );
    let headers: [(&str, &[u8]); 4] = [
        ("host", b"sut.bench.test:8443"),
        ("content-type", b"application/json"),
        ("x-amz-date", b"20261028T000000Z"),
        ("authorization", authorization.as_bytes()),
    ];
    let request = Request {
        method: "POST",
        path: "/v2/email/outbound-emails",
        query: "",
        headers: &headers,
        body: request_body.as_bytes(),
    };
    let scope = Scope {
        region: "us-east-1",
        service: "ses",
    };
    let verify = || sigv4::verify(&request, &scope, NOW, |_| Some("secret"));
    // Only a request that reaches the signature's comparison costs a whole
    // verification.
    if verify() != Err(Failure::Signature) {
        return Err(format!(
            "the request stopped short of its signature: {:?}",
            verify()
        ));
    }
    let verifies = rate(|| {
        black_box(verify().ok());
    });

    let hashes = rate(|| {
        black_box(digest(&SHA256, &body));
    });

    let report = serde_json::json!({
        "message_bytes": MESSAGE_BYTES,
        "dkim_rsa2048_signs_per_second": signs,
        "sigv4_verifies_per_second": verifies,
        "sha256_mb_per_second": hashes * MESSAGE_BYTES as f64 / 1e6,
    });
    println!("{report}");
    Ok(())
}

/// A 16 KiB body of 76-character lines, as the load generator sends.
fn body() -> Vec<u8> {
    let line = [b'x'; 76];
    let mut body = Vec::with_capacity(MESSAGE_BYTES);
    while body.len() + line.len() + 2 <= MESSAGE_BYTES {
        body.extend_from_slice(&line);
        body.extend_from_slice(b"\r\n");
    }
    body.resize(MESSAGE_BYTES, b'x');
    body
}

/// How many times a second `work` runs, over at least `SPAN`.
fn rate(mut work: impl FnMut()) -> f64 {
    // Once first, outside the measurement.
    work();
    let start = Instant::now();
    let mut runs = 0u32;
    while start.elapsed() < SPAN {
        for _ in 0..16 {
            work();
        }
        runs += 16;
    }
    f64::from(runs) / start.elapsed().as_secs_f64()
}
