//! The event receiver: a subscriber's endpoint, independent of
//! the engine. It takes each batch of events posted to it over HTTP/1.1,
//! checks its signature as Standard Webhooks describes it, and counts its
//! events by kind. A batch whose signature does not check is refused, and
//! counted; a batch posted again under an ID already taken is counted once.
//!
//! A control port on the loopback interface hands the counts out and takes
//! the secret to check with: `harness hooks-ctl stats|secret <whsec_...>`
//! inside the receiver's container.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs::hmac;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::args::Args;

const DEFAULT_CONTROL: &str = "127.0.0.1:2501";
/// The most a request's head may hold, and its body.
const HEAD_LIMIT: usize = 16 * 1024;
const BODY_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Default)]
struct Hooks {
    secret: Mutex<Option<Vec<u8>>>,
    batches: AtomicU64,
    repeated: AtomicU64,
    refused: AtomicU64,
    events: Mutex<BTreeMap<String, u64>>,
    /// The ID of every batch taken.
    taken: Mutex<BTreeSet<String>>,
}

/// What `hooks-ctl stats` reports.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    /// Batches taken, each counted once.
    pub batches: u64,
    /// Batches posted again after they were taken.
    pub repeated: u64,
    /// Requests refused: unsigned, wrongly signed, or not a batch.
    pub refused: u64,
    /// The events in the batches taken, by kind.
    pub events: BTreeMap<String, u64>,
}

/// `harness hooks [--listen ADDRESS] [--control ADDRESS]`.
pub fn main(argv: &[String]) -> Result<(), String> {
    let args = Args::parse(argv, &["listen", "control"])?;
    let listen = args.get("listen").unwrap_or("0.0.0.0:8080").to_owned();
    let control = args.get("control").unwrap_or(DEFAULT_CONTROL).to_owned();
    crate::runtime()?.block_on(serve(Arc::default(), &listen, &control))
}

/// `harness hooks-ctl stats|secret <whsec_...>`: the counts, as JSON, or the
/// secret batches are checked with from now on.
pub fn control(argv: &[String]) -> Result<(), String> {
    let args = Args::parse(argv, &["control"])?;
    let command = match args.positional() {
        [command] if command == "stats" => "STATS\n".to_owned(),
        [command, secret] if command == "secret" => format!("SECRET {secret}\n"),
        _ => return Err("usage: harness hooks-ctl stats|secret <whsec_...>".to_owned()),
    };
    let address = args.get("control").unwrap_or(DEFAULT_CONTROL);
    let mut stream = std::net::TcpStream::connect(address)
        .map_err(|error| format!("the receiver's control port {address}: {error}"))?;
    let mut response = Vec::new();
    stream
        .write_all(command.as_bytes())
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .and_then(|()| stream.read_to_end(&mut response))
        .map_err(|error| format!("the receiver's control port: {error}"))?;
    io::stdout()
        .write_all(&response)
        .map_err(|error| error.to_string())
}

async fn serve(hooks: Arc<Hooks>, listen: &str, control: &str) -> Result<(), String> {
    let http = TcpListener::bind(listen)
        .await
        .map_err(|error| format!("{listen}: {error}"))?;
    let control = TcpListener::bind(control)
        .await
        .map_err(|error| format!("{control}: {error}"))?;
    tokio::spawn(controls(control, Arc::clone(&hooks)));
    loop {
        let (stream, peer) = http.accept().await.map_err(|error| error.to_string())?;
        let hooks = Arc::clone(&hooks);
        tokio::spawn(async move {
            if let Err(error) = connection(stream, &hooks).await {
                eprintln!("hooks: {peer}: {error}");
            }
        });
    }
}

async fn controls(listener: TcpListener, hooks: Arc<Hooks>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        if stream.read_line(&mut line).await.is_err() {
            continue;
        }
        let line = line.trim();
        let response = if line == "STATS" {
            serde_json::to_vec(&hooks.stats()).unwrap_or_default()
        } else if let Some(secret) = line.strip_prefix("SECRET ") {
            match secret
                .strip_prefix("whsec_")
                .and_then(|secret| STANDARD.decode(secret).ok())
            {
                Some(secret) => {
                    *lock(&hooks.secret) = Some(secret);
                    b"secret set\n".to_vec()
                }
                None => b"not a whsec_ secret\n".to_vec(),
            }
        } else {
            b"unknown command\n".to_vec()
        };
        let _ = stream.get_mut().write_all(&response).await;
    }
}

/// Serves one connection's requests, one after another, until it closes.
async fn connection(stream: TcpStream, hooks: &Hooks) -> Result<(), String> {
    let _ = stream.set_nodelay(true);
    let mut stream = BufReader::new(stream);
    loop {
        let mut head = Vec::new();
        loop {
            let before = head.len();
            let read = stream
                .read_until(b'\n', &mut head)
                .await
                .map_err(|error| error.to_string())?;
            if read == 0 {
                return Ok(());
            }
            if head.len() > HEAD_LIMIT {
                return Err("a request's head is too long".to_owned());
            }
            if head[before..] == *b"\r\n" {
                break;
            }
        }
        let request = Request::parse(&head)?;
        if request.length > BODY_LIMIT {
            return Err("a request's body is too long".to_owned());
        }
        let mut body = vec![0; request.length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|error| error.to_string())?;
        let status = if hooks.take(&request, &body) {
            "204 No Content"
        } else {
            "401 Unauthorized"
        };
        let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
        stream
            .get_mut()
            .write_all(response.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        if request.close {
            return Ok(());
        }
    }
}

/// A request's head: what the receiver needs of it.
#[derive(Debug, Default, PartialEq, Eq)]
struct Request {
    length: usize,
    close: bool,
    id: Option<String>,
    timestamp: Option<String>,
    signature: Option<String>,
}

impl Request {
    fn parse(head: &[u8]) -> Result<Self, String> {
        let head = std::str::from_utf8(head).map_err(|_| "a request's head is not text")?;
        let mut lines = head.split("\r\n");
        let line = lines.next().unwrap_or_default();
        if !line.starts_with("POST ") || !line.ends_with(" HTTP/1.1") {
            return Err(format!("not a POST over HTTP/1.1: {line}"));
        }
        let mut request = Self::default();
        for line in lines.take_while(|line| !line.is_empty()) {
            let Some((name, value)) = line.split_once(':') else {
                return Err(format!("a header without a colon: {line}"));
            };
            let value = value.trim().to_owned();
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => {
                    request.length = value.parse().map_err(|_| "a bad Content-Length")?;
                }
                "connection" => request.close = value.eq_ignore_ascii_case("close"),
                "webhook-id" => request.id = Some(value),
                "webhook-timestamp" => request.timestamp = Some(value),
                "webhook-signature" => request.signature = Some(value),
                _ => {}
            }
        }
        Ok(request)
    }
}

impl Hooks {
    /// Takes a batch if its signature checks, and says whether it did.
    fn take(&self, request: &Request, body: &[u8]) -> bool {
        let secret = lock(&self.secret).clone();
        let signed = match (secret, &request.id, &request.timestamp, &request.signature) {
            (Some(secret), Some(id), Some(timestamp), Some(signature)) => {
                verifies(&secret, id, timestamp, body, signature)
            }
            _ => false,
        };
        let events = signed.then(|| kinds(body)).flatten();
        let (Some(events), Some(id)) = (events, &request.id) else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        if !lock(&self.taken).insert(id.clone()) {
            self.repeated.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        self.batches.fetch_add(1, Ordering::Relaxed);
        let mut counts = lock(&self.events);
        for kind in events {
            *counts.entry(kind).or_default() += 1;
        }
        true
    }

    fn stats(&self) -> Stats {
        Stats {
            batches: self.batches.load(Ordering::Relaxed),
            repeated: self.repeated.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            events: lock(&self.events).clone(),
        }
    }
}

/// Whether any of a header's space-separated `v1,` signatures is the
/// HMAC-SHA256 of `id.timestamp.body` under `secret`.
fn verifies(secret: &[u8], id: &str, timestamp: &str, body: &[u8], header: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut signed = format!("{id}.{timestamp}.").into_bytes();
    signed.extend_from_slice(body);
    header.split(' ').any(|signature| {
        signature
            .strip_prefix("v1,")
            .and_then(|signature| STANDARD.decode(signature).ok())
            .is_some_and(|signature| hmac::verify(&key, &signed, &signature).is_ok())
    })
}

/// The kind of each event in a batch, if it is one.
fn kinds(body: &[u8]) -> Option<Vec<String>> {
    #[derive(Deserialize)]
    struct Batch {
        events: Vec<Event>,
    }
    #[derive(Deserialize)]
    struct Event {
        #[serde(rename = "type")]
        kind: String,
    }
    let batch: Batch = serde_json::from_slice(body).ok()?;
    Some(batch.events.into_iter().map(|event| event.kind).collect())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard Webhooks' own example, checked independently of the engine.
    const SECRET: &str = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const SIGNATURE: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

    #[test]
    fn a_signature_checks_as_the_specification_gives_it() {
        let secret = STANDARD.decode(SECRET).unwrap();
        let body = br#"{"test": 2432232314}"#;
        assert!(verifies(&secret, ID, "1614265330", body, SIGNATURE));
        assert!(verifies(
            &secret,
            ID,
            "1614265330",
            body,
            &format!("v1,AAAA {SIGNATURE}")
        ));
        assert!(!verifies(&secret, ID, "1614265331", body, SIGNATURE));
        assert!(!verifies(&secret, ID, "1614265330", b"{}", SIGNATURE));
    }

    #[test]
    fn a_batch_is_counted_once_by_its_id_and_an_unsigned_one_refused() {
        let hooks = Hooks::default();
        let secret = vec![7; 32];
        *lock(&hooks.secret) = Some(secret.clone());
        let body = br#"{"subscription":"hooks","events":[{"type":"delivered"},{"type":"delivered"},{"type":"bounced"}]}"#;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let mut signed = b"b1.1800000000.".to_vec();
        signed.extend_from_slice(body);
        let signature = format!("v1,{}", STANDARD.encode(hmac::sign(&key, &signed).as_ref()));
        let request = Request {
            length: body.len(),
            close: false,
            id: Some("b1".to_owned()),
            timestamp: Some("1800000000".to_owned()),
            signature: Some(signature),
        };
        assert!(hooks.take(&request, body));
        assert!(hooks.take(&request, body), "taken again, counted once");
        let unsigned = Request {
            signature: None,
            ..Request::default()
        };
        assert!(!hooks.take(&unsigned, body));
        assert_eq!(
            hooks.stats(),
            Stats {
                batches: 1,
                repeated: 1,
                refused: 1,
                events: BTreeMap::from([("bounced".to_owned(), 1), ("delivered".to_owned(), 2)]),
            }
        );
    }

    #[test]
    fn a_request_head_is_read_for_what_the_receiver_needs() {
        let head = b"POST /hooks HTTP/1.1\r\nHost: hooks\r\nContent-Length: 12\r\nWebhook-Id: b1\r\nwebhook-timestamp: 5\r\nwebhook-signature: v1,x\r\nConnection: close\r\n\r\n";
        assert_eq!(
            Request::parse(head),
            Ok(Request {
                length: 12,
                close: true,
                id: Some("b1".to_owned()),
                timestamp: Some("5".to_owned()),
                signature: Some("v1,x".to_owned()),
            })
        );
        assert!(Request::parse(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }
}
