//! A client of the engine's SES v2 API for its tests: each request signed
//! with SigV4 as an SDK signs it, sent over TLS trusting the test's
//! certificate, and its answer read whole. Its own signer, not the
//! engine's, so a fault in one is not mirrored by the other.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::hmac;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

pub const REGION: &str = "us-east-1";

/// The API at `port`, signing as `access_key` with `secret`.
#[derive(Clone)]
pub struct Client {
    pub port: u16,
    pub certificate: CertificateDer<'static>,
    pub access_key: String,
    pub secret: String,
}

/// An answer: its status, its headers in lowercase, and its body.
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Answer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

impl Client {
    /// Sends `method` at `path`, with `query` (already in canonical form,
    /// its pairs sorted) and the JSON `body`, signed now.
    pub fn send(&self, method: &str, path: &str, query: &str, body: &str) -> Answer {
        self.signed(method, path, query, body, "ses", "application/json")
    }

    /// Posts an SNS operation, AWS Query's `form`, to `/`, signed for SNS.
    pub fn sns(&self, form: &str) -> Answer {
        self.signed(
            "POST",
            "/",
            "",
            form,
            "sns",
            "application/x-www-form-urlencoded; charset=utf-8",
        )
    }

    fn signed(
        &self,
        method: &str,
        path: &str,
        query: &str,
        body: &str,
        service: &str,
        content_type: &str,
    ) -> Answer {
        let host = format!("127.0.0.1:{}", self.port);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time = compact_utc(now);
        let date = &time[..8];
        let canonical = format!(
            "{method}\n{}\n{query}\ncontent-type:{content_type}\nhost:{host}\nx-amz-date:{time}\n\ncontent-type;host;x-amz-date\n{}",
            canonical_path(path),
            hex(digest(&SHA256, body.as_bytes()).as_ref())
        );
        let scope = format!("{date}/{REGION}/{service}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{time}\n{scope}\n{}",
            hex(digest(&SHA256, canonical.as_bytes()).as_ref())
        );
        let mut key = format!("AWS4{}", self.secret).into_bytes();
        for part in [date, REGION, service, "aws4_request"] {
            key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), part.as_bytes())
                .as_ref()
                .to_vec();
        }
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &key),
            string_to_sign.as_bytes(),
        );
        let target = if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        };
        let request = format!(
            "{method} {target} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {length}\r\n\
             X-Amz-Date: {time}\r\n\
             Authorization: AWS4-HMAC-SHA256 Credential={user}/{scope}, SignedHeaders=content-type;host;x-amz-date, Signature={signature}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            length = body.len(),
            user = self.access_key,
            signature = hex(signature.as_ref()),
        );
        self.exchange(&request)
    }

    /// Sends `method` at `path` with `query`, signed by nobody: as a
    /// subscriber visits the URLs it was posted, or a consumer fetches a
    /// certificate.
    pub fn unsigned(&self, method: &str, path: &str, query: &str) -> Answer {
        let target = if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        };
        self.exchange(&format!(
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            self.port
        ))
    }

    /// Sends `request` over TLS and reads the answer whole.
    fn exchange(&self, request: &str) -> Answer {
        let mut tls = self.open();
        tls.write_all(request.as_bytes()).expect("written");
        let mut answer = Vec::new();
        // The engine closes the connection after its answer; a TLS close
        // without its alert ends the read just as well.
        let _ = tls.read_to_end(&mut answer);
        parse(&answer)
    }

    /// A TLS connection to the API, trusting the test's certificate.
    pub fn open(&self) -> StreamOwned<ClientConnection, TcpStream> {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.clone()).expect("a root");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connection =
            ClientConnection::new(Arc::new(config), "localhost".try_into().expect("a name"))
                .expect("a TLS session");
        let tcp = TcpStream::connect(("127.0.0.1", self.port)).expect("the API connects");
        StreamOwned::new(connection, tcp)
    }
}

fn parse(answer: &[u8]) -> Answer {
    let text = String::from_utf8_lossy(answer);
    let (head, body) = text.split_once("\r\n\r\n").expect("an answer's head");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status");
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked"));
    let body = if chunked {
        dechunk(body)
    } else {
        body.to_owned()
    };
    Answer {
        status,
        headers,
        body,
    }
}

/// A chunked body, whole.
fn dechunk(mut body: &str) -> String {
    let mut whole = String::new();
    while let Some((size, rest)) = body.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if size == 0 || rest.len() < size {
            break;
        }
        whole.push_str(&rest[..size]);
        body = rest[size..].trim_start_matches("\r\n");
    }
    whole
}

/// `seconds` since the epoch as SigV4's `YYYYMMDDTHHMMSSZ`.
fn compact_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let (hour, minute, second) = (seconds % 86_400 / 3600, seconds % 3600 / 60, seconds % 60);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A path as SigV4 signs it for a service other than S3: every byte but the
/// unreserved and `/` percent-encoded again, so an escape in the path, as
/// an ARN in a label has, is encoded twice.
fn canonical_path(path: &str) -> String {
    path.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
