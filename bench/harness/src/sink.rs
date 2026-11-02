//! The reference sink. It accepts every message for its domain and
//! the domains under it, over STARTTLS when the sender asks for it, checks
//! each one independently of whoever sent it, and keeps an arrival record for
//! the observer. It stores no message, so its capacity is CPU, never disk.
//!
//! Started with a throttle, it limits what it takes as a large provider does:
//! sessions at once, and messages a second. Beyond either it answers 421 and
//! closes the connection, until the throttle is lifted.
//!
//! A control port on the loopback interface hands the arrival records out,
//! and lifts the throttle: `harness sink-ctl take|stats|release` inside the
//! sink's container.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::args::Args;
use crate::dkim::{self, Verifier};
use crate::records::Arrival;
use crate::smtp;

const DEFAULT_CONTROL: &str = "127.0.0.1:2500";
const BUFFER: usize = 64 * 1024;
const MESSAGE_LIMIT: usize = 100 * 1024 * 1024;

struct Sink {
    hostname: String,
    domain: String,
    verifier: Verifier,
    acceptor: TlsAcceptor,
    arrivals: Mutex<Vec<Arrival>>,
    received: AtomicU64,
    connections: AtomicU64,
    /// Connections by TLS version and cipher suite.
    sessions: Mutex<BTreeMap<String, u64>>,
    throttle: Option<Throttle>,
    /// How far away the sink stands: each exchange's reply waits this long,
    /// as a receiver's does across a network.
    round_trip: Duration,
    /// Whether it offers STARTTLS. An ablation without TLS turns it off, so
    /// every system delivers in plaintext.
    starttls: bool,
    /// Sessions open now, and the most ever open at once.
    open: AtomicU64,
    most_open: AtomicU64,
    /// Sessions answered 421 by the throttle.
    refused: AtomicU64,
}

struct Throttle {
    connections: u64,
    rate: f64,
    bucket: Mutex<Bucket>,
    lifted: AtomicBool,
}

/// Messages it may take now, refilled at the throttle's rate up to one
/// second's worth.
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Throttle {
    fn active(&self) -> bool {
        !self.lifted.load(Ordering::Relaxed)
    }

    /// Takes a message's place, if one is free.
    fn take(&self) -> bool {
        let mut bucket = lock(&self.bucket);
        let now = Instant::now();
        let refill = now.duration_since(bucket.at).as_secs_f64() * self.rate;
        bucket.tokens = (bucket.tokens + refill).min(self.rate.max(1.0));
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// What `sink-ctl stats` reports.
#[derive(Serialize, Deserialize)]
pub struct Stats {
    pub received: u64,
    pub connections: u64,
    pub sessions: BTreeMap<String, u64>,
    /// Sessions the throttle answered 421.
    #[serde(default)]
    pub refused: u64,
    /// The most sessions open at once: how many connections a system kept
    /// to the sink, of those it may open.
    #[serde(default)]
    pub most_open: u64,
}

pub fn main(argv: &[String]) -> Result<(), String> {
    let args = Args::parse(
        argv,
        &[
            "listen",
            "control",
            "hostname",
            "domain",
            "dkim-key",
            "dkim-domain",
            "dkim-selector",
            "throttle-connections",
            "throttle-rate",
            "round-trip-ms",
            "starttls",
        ],
    )?;
    let hostname = args.get("hostname").unwrap_or("mx.sink.test");
    let key = STANDARD
        .decode(args.required("dkim-key")?)
        .map_err(|error| format!("`--dkim-key` is not base64: {error}"))?;
    let sink = Arc::new(Sink {
        hostname: hostname.to_owned(),
        domain: args.get("domain").unwrap_or("sink.test").to_owned(),
        verifier: Verifier::new(
            key,
            args.required("dkim-domain")?,
            args.required("dkim-selector")?,
        ),
        acceptor: TlsAcceptor::from(crate::tls::server_config(hostname)?),
        arrivals: Mutex::new(Vec::new()),
        received: AtomicU64::new(0),
        connections: AtomicU64::new(0),
        sessions: Mutex::new(BTreeMap::new()),
        throttle: match (args.get("throttle-connections"), args.get("throttle-rate")) {
            (None, None) => None,
            _ => {
                let rate: f64 = args.parse_or("throttle-rate", f64::INFINITY)?;
                Some(Throttle {
                    connections: args.parse_or("throttle-connections", u64::MAX)?,
                    rate,
                    bucket: Mutex::new(Bucket {
                        tokens: rate.max(1.0),
                        at: Instant::now(),
                    }),
                    lifted: AtomicBool::new(false),
                })
            }
        },
        round_trip: Duration::from_millis(args.parse_or("round-trip-ms", 0)?),
        starttls: args.parse_or("starttls", true)?,
        open: AtomicU64::new(0),
        most_open: AtomicU64::new(0),
        refused: AtomicU64::new(0),
    });
    let listen = args.get("listen").unwrap_or("0.0.0.0:25").to_owned();
    let control = args.get("control").unwrap_or(DEFAULT_CONTROL).to_owned();
    crate::runtime()?.block_on(serve(sink, &listen, &control))
}

/// `harness sink-ctl take|stats|release`: arrivals since the last take, as
/// records; the counters, as JSON; or the throttle lifted.
pub fn control(argv: &[String]) -> Result<(), String> {
    let args = Args::parse(argv, &["control"])?;
    let command = match args.positional() {
        [command] if command == "take" => "TAKE\n",
        [command] if command == "stats" => "STATS\n",
        [command] if command == "release" => "RELEASE\n",
        _ => return Err("usage: harness sink-ctl take|stats|release".to_owned()),
    };
    let address = args.get("control").unwrap_or(DEFAULT_CONTROL);
    let mut stream = std::net::TcpStream::connect(address)
        .map_err(|error| format!("the sink's control port {address}: {error}"))?;
    let mut response = Vec::new();
    stream
        .write_all(command.as_bytes())
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .and_then(|()| stream.read_to_end(&mut response))
        .map_err(|error| format!("the sink's control port: {error}"))?;
    io::stdout()
        .write_all(&response)
        .map_err(|error| error.to_string())
}

async fn serve(sink: Arc<Sink>, listen: &str, control: &str) -> Result<(), String> {
    let smtp = TcpListener::bind(listen)
        .await
        .map_err(|error| format!("{listen}: {error}"))?;
    let control = TcpListener::bind(control)
        .await
        .map_err(|error| format!("{control}: {error}"))?;
    tokio::spawn(controls(control, Arc::clone(&sink)));
    loop {
        let (stream, peer) = smtp.accept().await.map_err(|error| error.to_string())?;
        let sink = Arc::clone(&sink);
        tokio::spawn(async move {
            if let Err(error) = connection(stream, peer.ip(), &sink).await {
                eprintln!("sink: {peer}: {error}");
            }
        });
    }
}

async fn controls(listener: TcpListener, sink: Arc<Sink>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let mut stream = BufReader::new(stream);
        let mut line = Vec::new();
        if stream.read_until(b'\n', &mut line).await.is_err() {
            continue;
        }
        let response = match line.trim_ascii() {
            b"TAKE" => {
                let taken = std::mem::take(&mut *lock(&sink.arrivals));
                let mut bytes = Vec::with_capacity(taken.len() * crate::records::ARRIVAL_LEN);
                taken.iter().for_each(|arrival| arrival.encode(&mut bytes));
                bytes
            }
            b"STATS" => {
                let stats = Stats {
                    received: sink.received.load(Ordering::Relaxed),
                    connections: sink.connections.load(Ordering::Relaxed),
                    sessions: lock(&sink.sessions).clone(),
                    refused: sink.refused.load(Ordering::Relaxed),
                    most_open: sink.most_open.load(Ordering::Relaxed),
                };
                serde_json::to_vec(&stats).unwrap_or_default()
            }
            b"RELEASE" => {
                if let Some(throttle) = &sink.throttle {
                    throttle.lifted.store(true, Ordering::Relaxed);
                }
                b"released\n".to_vec()
            }
            _ => b"unknown command\n".to_vec(),
        };
        let _ = stream.get_mut().write_all(&response).await;
    }
}

async fn connection(stream: TcpStream, source: IpAddr, sink: &Sink) -> io::Result<()> {
    stream.set_nodelay(true)?;
    sink.connections.fetch_add(1, Ordering::Relaxed);
    let open = sink.open.fetch_add(1, Ordering::Relaxed) + 1;
    sink.most_open.fetch_max(open, Ordering::Relaxed);
    let result = greet(stream, sink, open, source).await;
    sink.open.fetch_sub(1, Ordering::Relaxed);
    result
}

async fn greet(stream: TcpStream, sink: &Sink, open: u64, source: IpAddr) -> io::Result<()> {
    let mut plain = BufReader::with_capacity(BUFFER, stream);
    if let Some(throttle) = sink.throttle.as_ref().filter(|throttle| throttle.active())
        && open > throttle.connections
    {
        sink.refused.fetch_add(1, Ordering::Relaxed);
        let refusal = format!(
            "421 4.7.0 {} Too many connections, try again later\r\n",
            sink.hostname
        );
        return sink.answer(&mut plain, refusal.as_bytes()).await;
    }
    let greeting = format!("220 {} ESMTP harness sink\r\n", sink.hostname);
    sink.answer(&mut plain, greeting.as_bytes()).await?;
    let Ended::StartTls(plain) = session(plain, false, sink, source).await? else {
        return Ok(());
    };
    // Anything the client sent ahead of the handshake would be read as
    // if it had been encrypted.
    if !plain.buffer().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "data pipelined after STARTTLS",
        ));
    }
    // The handshake takes a round trip of its own.
    tokio::time::sleep(sink.round_trip).await;
    let tls = sink.acceptor.accept(plain.into_inner()).await?;
    let (_, state) = tls.get_ref();
    let session_kind = format!(
        "{} {}",
        state
            .protocol_version()
            .map_or("unknown".to_owned(), |version| format!("{version:?}")),
        state
            .negotiated_cipher_suite()
            .map_or("unknown".to_owned(), |suite| format!("{:?}", suite.suite())),
    );
    *lock(&sink.sessions).entry(session_kind).or_default() += 1;
    session(BufReader::with_capacity(BUFFER, tls), true, sink, source).await?;
    Ok(())
}

enum Ended<S> {
    Closed,
    StartTls(BufReader<S>),
}

async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: BufReader<S>,
    tls: bool,
    sink: &Sink,
    source: IpAddr,
) -> io::Result<Ended<S>> {
    let mut line = Vec::with_capacity(512);
    let mut replies = Vec::with_capacity(512);
    let mut message = Vec::with_capacity(32 * 1024);
    let mut mail = false;
    // The recipient indices the transaction carries.
    let mut recipients: Vec<u16> = Vec::new();
    loop {
        // Replies wait while pipelined commands are still buffered, and go
        // out together before the sink waits for more (RFC 2920).
        if !replies.is_empty() && stream.buffer().is_empty() {
            sink.answer(&mut stream, &replies).await?;
            replies.clear();
        }
        if !smtp::read_line(&mut stream, &mut line).await? {
            return Ok(Ended::Closed);
        }
        let verb = line
            .split(|&byte| byte == b' ' || byte == b'\r' || byte == b'\n')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        match verb.as_slice() {
            b"EHLO" => {
                mail = false;
                recipients.clear();
                let mut keywords = vec![
                    sink.hostname.as_str(),
                    "PIPELINING",
                    "SIZE 104857600",
                    "8BITMIME",
                    "ENHANCEDSTATUSCODES",
                ];
                if !tls && sink.starttls {
                    keywords.push("STARTTLS");
                }
                for (index, keyword) in keywords.iter().enumerate() {
                    let separator = if index + 1 == keywords.len() {
                        ' '
                    } else {
                        '-'
                    };
                    replies.extend_from_slice(format!("250{separator}{keyword}\r\n").as_bytes());
                }
            }
            b"HELO" => {
                mail = false;
                recipients.clear();
                replies.extend_from_slice(format!("250 {}\r\n", sink.hostname).as_bytes());
            }
            b"STARTTLS" if !tls && sink.starttls => {
                replies.extend_from_slice(b"220 2.0.0 Ready to start TLS\r\n");
                sink.answer(&mut stream, &replies).await?;
                return Ok(Ended::StartTls(stream));
            }
            b"MAIL" => {
                if let Some(throttle) = sink.throttle.as_ref().filter(|throttle| throttle.active())
                    && !throttle.take()
                {
                    sink.refused.fetch_add(1, Ordering::Relaxed);
                    replies.extend_from_slice(b"421 4.7.0 Rate limited, try again later\r\n");
                    sink.answer(&mut stream, &replies).await?;
                    return Ok(Ended::Closed);
                }
                mail = true;
                recipients.clear();
                replies.extend_from_slice(b"250 2.1.0 Ok\r\n");
            }
            b"RCPT" if !mail => replies.extend_from_slice(b"503 5.5.1 MAIL first\r\n"),
            b"RCPT" => {
                if recipient_domain(&line).is_some_and(|domain| sink.serves(domain)) {
                    recipients.push(recipient_index(&line));
                    replies.extend_from_slice(b"250 2.1.5 Ok\r\n");
                } else {
                    replies.extend_from_slice(b"550 5.1.2 Not a sink domain\r\n");
                }
            }
            b"DATA" if recipients.is_empty() => {
                replies.extend_from_slice(b"554 5.5.1 No valid recipients\r\n");
            }
            b"DATA" => {
                replies.extend_from_slice(b"354 End data with <CR><LF>.<CR><LF>\r\n");
                sink.answer(&mut stream, &replies).await?;
                replies.clear();
                message.clear();
                read_data(&mut stream, &mut message).await?;
                // The message is checked once, and arrives once for each
                // of its recipients.
                let arrival = sink.check(&message, crate::clock::now_micros(), tls, source);
                lock(&sink.arrivals).extend(recipients.iter().map(|&recipient| Arrival {
                    recipient,
                    ..arrival
                }));
                sink.received
                    .fetch_add(recipients.len() as u64, Ordering::Relaxed);
                mail = false;
                recipients.clear();
                replies.extend_from_slice(b"250 2.0.0 Ok\r\n");
            }
            b"RSET" => {
                mail = false;
                recipients.clear();
                replies.extend_from_slice(b"250 2.0.0 Ok\r\n");
            }
            b"NOOP" => replies.extend_from_slice(b"250 2.0.0 Ok\r\n"),
            b"QUIT" => {
                replies.extend_from_slice(b"221 2.0.0 Bye\r\n");
                sink.answer(&mut stream, &replies).await?;
                return Ok(Ended::Closed);
            }
            _ => replies.extend_from_slice(b"502 5.5.2 Command not recognised\r\n"),
        }
    }
}

/// Reads message content up to the terminating dot, removing dot-stuffing.
async fn read_data<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
    message: &mut Vec<u8>,
) -> io::Result<()> {
    loop {
        let start = message.len();
        if stream.read_until(b'\n', message).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the connection closed during DATA",
            ));
        }
        let line = &message[start..];
        if line == b".\r\n" || line == b".\n" {
            message.truncate(start);
            return Ok(());
        }
        if line.first() == Some(&b'.') {
            message.remove(start);
        }
        if message.len() > MESSAGE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a message over the size limit",
            ));
        }
    }
}

/// The recipient index in `RCPT TO:<r<id>-<index>@...>`, or 0 when the
/// address has none.
fn recipient_index(line: &[u8]) -> u16 {
    let open = line.iter().position(|&byte| byte == b'<').unwrap_or(0);
    let at = line.iter().rposition(|&byte| byte == b'@').unwrap_or(0);
    let local = line.get(open + 1..at).unwrap_or_default();
    local
        .iter()
        .rposition(|&byte| byte == b'-')
        .and_then(|dash| std::str::from_utf8(&local[dash + 1..]).ok()?.parse().ok())
        .unwrap_or(0)
}

/// The domain of the address in `RCPT TO:<...>`.
fn recipient_domain(line: &[u8]) -> Option<&[u8]> {
    let open = line.iter().position(|&byte| byte == b'<')?;
    let close = open + line[open..].iter().position(|&byte| byte == b'>')?;
    let address = &line[open + 1..close];
    let at = address.iter().rposition(|&byte| byte == b'@')?;
    Some(&address[at + 1..])
}

impl Sink {
    /// Sends `replies` as a receiver at the sink's distance does, a round
    /// trip after the commands they answer.
    async fn answer<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut BufReader<S>,
        replies: &[u8],
    ) -> io::Result<()> {
        if !self.round_trip.is_zero() {
            tokio::time::sleep(self.round_trip).await;
        }
        smtp::send(stream, replies).await
    }

    /// Its domain, or one under it.
    fn serves(&self, domain: &[u8]) -> bool {
        let own = self.domain.as_bytes();
        domain.eq_ignore_ascii_case(own)
            || (domain.len() > own.len()
                && domain[domain.len() - own.len() - 1] == b'.'
                && domain[domain.len() - own.len()..].eq_ignore_ascii_case(own))
    }

    fn check(&self, message: &[u8], at: i64, tls: bool, source: IpAddr) -> Arrival {
        let (header, body) = match message.windows(4).position(|window| window == b"\r\n\r\n") {
            Some(split) => (&message[..split + 2], &message[split + 4..]),
            None => (message, &[][..]),
        };
        let fields = dkim::fields(header);
        let mut checks = if tls { Arrival::TLS } else { 0 };
        let mut id = 0;
        let mut claimed = None;
        for field in &fields {
            if dkim::named(field, "x-bench-id") {
                let value = String::from_utf8_lossy(dkim::value(field));
                if let Ok(parsed) = u64::from_str_radix(value.trim(), 16) {
                    id = parsed;
                    checks |= Arrival::IDENTIFIED;
                }
            } else if dkim::named(field, "x-bench-body") {
                claimed = Some(dkim::value(field).trim_ascii());
            }
        }
        let digest = digest::digest(&digest::SHA256, body);
        if claimed == Some(crate::hex(digest.as_ref()).as_bytes()) {
            checks |= Arrival::BODY;
        }
        if self.verifier.verify(&fields, body).is_ok() {
            checks |= Arrival::DKIM;
        }
        Arrival {
            id,
            recipient: 0,
            at,
            checks,
            source,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_indices_are_read_after_the_id() {
        assert_eq!(
            recipient_index(b"RCPT TO:<r00000000000000ab-49@d3.sink.test>\r\n"),
            49
        );
        assert_eq!(
            recipient_index(b"RCPT TO:<r00000000000000ab@sink.test>\r\n"),
            0
        );
    }

    #[test]
    fn recipient_domains_are_read_from_the_path() {
        assert_eq!(
            recipient_domain(b"RCPT TO:<r1@sink.test>\r\n"),
            Some(&b"sink.test"[..])
        );
        assert_eq!(
            recipient_domain(b"RCPT TO:<\"a@b\"@Sink.Test> NOTIFY=NEVER\r\n"),
            Some(&b"Sink.Test"[..])
        );
        assert_eq!(recipient_domain(b"RCPT TO:<postmaster>\r\n"), None);
        assert_eq!(recipient_domain(b"RCPT TO:r1@sink.test\r\n"), None);
    }

    #[test]
    fn a_sink_serves_its_domain_and_those_under_it() {
        let sink = Sink {
            hostname: "mx.sink.test".to_owned(),
            domain: "sink.test".to_owned(),
            verifier: Verifier::new(Vec::new(), "bench.test", "bench"),
            acceptor: TlsAcceptor::from(crate::tls::server_config("mx.sink.test").unwrap()),
            arrivals: Mutex::new(Vec::new()),
            received: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            sessions: Mutex::new(BTreeMap::new()),
            throttle: None,
            round_trip: Duration::ZERO,
            starttls: true,
            open: AtomicU64::new(0),
            most_open: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        };
        assert!(sink.serves(b"sink.test"));
        assert!(sink.serves(b"D12.Sink.Test"));
        assert!(!sink.serves(b"othersink.test"));
        assert!(!sink.serves(b"throttled.test"));
    }

    #[test]
    fn a_throttle_takes_its_rate_and_no_more() {
        let throttle = Throttle {
            connections: 2,
            rate: 5.0,
            bucket: Mutex::new(Bucket {
                tokens: 5.0,
                at: Instant::now(),
            }),
            lifted: AtomicBool::new(false),
        };
        let taken = (0..20).filter(|_| throttle.take()).count();
        assert_eq!(taken, 5);
        assert!(throttle.active());
        throttle.lifted.store(true, Ordering::Relaxed);
        assert!(!throttle.active());
    }

    #[tokio::test]
    async fn data_ends_at_the_dot_and_is_unstuffed() {
        let mut input =
            BufReader::new(&b"Subject: x\r\n\r\n..leading dot\r\nlast\r\n.\r\nMAIL"[..]);
        let mut message = Vec::new();
        read_data(&mut input, &mut message).await.unwrap();
        assert_eq!(message, b"Subject: x\r\n\r\n.leading dot\r\nlast\r\n");
        let mut truncated = BufReader::new(&b"no end\r\n"[..]);
        assert!(read_data(&mut truncated, &mut Vec::new()).await.is_err());
    }
}
