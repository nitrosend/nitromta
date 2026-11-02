//! The load generator. It opens every connection and finishes
//! STARTTLS and authentication, or the TLS handshake of an API connection,
//! before its clock starts. It then submits messages at the offered rate for
//! a fixed time and records when each one was due, sent and answered.
//! Records go to standard output; a summary goes to standard error as one
//! JSON line.
//!
//! Messages are 7-bit text with incompressible bodies: base64 lines of random
//! bytes, which never begin with a dot, so no line needs dot-stuffing. Each
//! carries its id and the SHA-256 of its body, so the sink can tell which
//! message arrived and whether its body arrived intact.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aws_lc_rs::digest;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::api::{self, Ingress};
use crate::args::Args;
use crate::clock;
use crate::records::{ACK_LEN, Ack};
use crate::smtp::{self, Reply};

struct Options {
    ingress: Ingress,
    target: String,
    server_name: String,
    connections: usize,
    /// Messages per second across all connections; 0 sends as fast as the
    /// connections allow.
    rate: f64,
    seconds: f64,
    /// Stop after this many messages, if sooner.
    messages: Option<u64>,
    size: usize,
    id_base: u64,
    credentials: Option<(String, String)>,
    sender: String,
    recipients: Recipients,
}

/// Where each message goes. Its recipients follow from its id alone, so the
/// observer can tell where a message was meant to go.
pub struct Recipients {
    /// Recipients per message.
    pub per_message: u16,
    /// The sink's domain.
    pub domain: String,
    /// How many of the sink's domains messages are spread across:
    /// `d0.<domain>` and on, or the domain itself when there is one.
    pub domains: u64,
    /// The share of ids that go to the throttled receiver instead.
    pub throttled_share: f64,
    pub throttled_domain: String,
}

impl Recipients {
    /// Message `id`'s recipients: `r<id>@...` for a message with one, and
    /// `r<id>-<index>@...` for each of several, spread across the domains.
    pub fn addresses(&self, id: u64) -> Vec<String> {
        let domain = |n: u64| {
            if throttled(id, self.throttled_share) {
                self.throttled_domain.clone()
            } else if self.domains > 1 {
                format!("d{}.{}", n % self.domains, self.domain)
            } else {
                self.domain.clone()
            }
        };
        if self.per_message <= 1 {
            return vec![format!("r{id:016x}@{}", domain(id))];
        }
        let per = u64::from(self.per_message);
        (0..per)
            .map(|index| format!("r{id:016x}-{index}@{}", domain(id * per + index)))
            .collect()
    }
}

/// Whether message `id` goes to the throttled receiver: an even spread of
/// `share` of all ids.
pub fn throttled(id: u64, share: f64) -> bool {
    id % 1000 < (share * 1000.0).round() as u64
}

/// What one run of the generator did, as it reports on standard error.
#[derive(Serialize, Deserialize)]
pub struct Summary {
    /// When the clock started and when the last connection finished.
    pub started: i64,
    pub ended: i64,
    pub attempted: u64,
    pub accepted: u64,
    /// Refused submissions by reply code; 0 counts connections that failed.
    pub failures: BTreeMap<u16, u64>,
    pub errors: Vec<String>,
}

pub fn main(argv: &[String]) -> Result<(), String> {
    let args = Args::parse(
        argv,
        &[
            "ingress",
            "target",
            "server-name",
            "connections",
            "rate",
            "seconds",
            "messages",
            "size",
            "id-base",
            "user",
            "password",
            "sender",
            "domain",
            "domains",
            "recipients",
            "throttled-share",
            "throttled-domain",
        ],
    )?;
    let credentials = match (args.get("user"), args.get("password")) {
        (Some(user), Some(password)) => Some((user.to_owned(), password.to_owned())),
        (None, None) => None,
        _ => return Err("`--user` and `--password` go together".to_owned()),
    };
    let options = Options {
        ingress: Ingress::parse(args.get("ingress").unwrap_or("smtp"))?,
        target: args.required("target")?.to_owned(),
        server_name: args
            .get("server-name")
            .unwrap_or("sut.bench.test")
            .to_owned(),
        connections: args.parse_or("connections", 1)?.max(1),
        rate: args.parse_or("rate", 0.0)?,
        seconds: args.parse_or("seconds", 10.0)?,
        messages: args
            .get("messages")
            .map(str::parse)
            .transpose()
            .map_err(|error| format!("`--messages`: {error}"))?,
        size: args.parse_or("size", 16 * 1024)?,
        id_base: args.parse_or("id-base", 1)?,
        credentials,
        sender: args.get("sender").unwrap_or("load@bench.test").to_owned(),
        recipients: Recipients {
            per_message: args.parse_or("recipients", 1)?,
            domain: args.get("domain").unwrap_or("sink.test").to_owned(),
            domains: args.parse_or("domains", 1)?,
            throttled_share: args.parse_or("throttled-share", 0.0)?,
            throttled_domain: args
                .get("throttled-domain")
                .unwrap_or("throttled.test")
                .to_owned(),
        },
    };
    let (acks, summary) = crate::runtime()?.block_on(generate(Arc::new(options)))?;
    let mut bytes = Vec::with_capacity(acks.len() * ACK_LEN);
    acks.iter().for_each(|ack| ack.encode(&mut bytes));
    io::stdout()
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    eprintln!(
        "{}",
        serde_json::to_string(&summary).map_err(|error| error.to_string())?
    );
    Ok(())
}

async fn generate(options: Arc<Options>) -> Result<(Vec<Ack>, Summary), String> {
    let config = crate::tls::client_config()?;
    let mut opening = JoinSet::new();
    for _ in 0..options.connections {
        let options = Arc::clone(&options);
        let config = Arc::clone(&config);
        opening.spawn(async move { Connection::open(&options, config).await });
    }
    let mut connections = Vec::with_capacity(options.connections);
    while let Some(opened) = opening.join_next().await {
        connections.push(opened.map_err(|error| error.to_string())??);
    }

    // Every connection is ready, so the clock starts now, a moment ahead so
    // that the first messages are not already late.
    let lead = Duration::from_millis(20);
    let start = Instant::now() + lead;
    let started = clock::now_micros() + i64::try_from(lead.as_micros()).unwrap_or(0);
    let date = clock::rfc5322(started);
    let next = Arc::new(AtomicU64::new(options.id_base));
    let mut running = JoinSet::new();
    for (index, connection) in connections.into_iter().enumerate() {
        let schedule = Schedule {
            options: Arc::clone(&options),
            index,
            start,
            started,
            next: Arc::clone(&next),
            date: date.clone(),
        };
        running.spawn(schedule.drive(connection));
    }
    let mut acks = Vec::new();
    let mut errors = Vec::new();
    while let Some(finished) = running.join_next().await {
        let (mut driven, error) = finished.map_err(|error| error.to_string())?;
        acks.append(&mut driven);
        errors.extend(error);
    }
    let mut failures = BTreeMap::new();
    for ack in acks.iter().filter(|ack| !ack.accepted()) {
        *failures.entry(ack.code).or_default() += 1;
    }
    let summary = Summary {
        started,
        ended: clock::now_micros(),
        attempted: acks.len() as u64,
        accepted: acks.iter().filter(|ack| ack.accepted()).count() as u64,
        failures,
        errors,
    };
    Ok((acks, summary))
}

/// One connection's share of the offered load.
struct Schedule {
    options: Arc<Options>,
    index: usize,
    start: Instant,
    started: i64,
    next: Arc<AtomicU64>,
    date: String,
}

impl Schedule {
    async fn drive(self, mut connection: Connection) -> (Vec<Ack>, Option<String>) {
        let options = &self.options;
        // Each connection offers rate / connections, staggered so that the
        // connections do not submit in lockstep.
        let interval = if options.rate > 0.0 {
            options.connections as f64 / options.rate
        } else {
            0.0
        };
        let offset = interval * self.index as f64 / options.connections as f64;
        let mut acks = Vec::new();
        let mut body = Vec::new();
        let mut message = Vec::new();
        for k in 0u64.. {
            let due = if interval > 0.0 {
                offset + k as f64 * interval
            } else {
                self.start.elapsed().as_secs_f64()
            };
            if due >= options.seconds {
                break;
            }
            tokio::time::sleep_until(self.start + Duration::from_secs_f64(due)).await;
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if options
                .messages
                .is_some_and(|messages| id >= options.id_base + messages)
            {
                break;
            }
            if let Err(error) = compose(&mut message, &mut body, id, options, &self.date) {
                return (acks, Some(error));
            }
            let due = self.started + (due * 1e6) as i64;
            let sent = clock::now_micros();
            let outcome = connection.submit(&message, id, options).await;
            let replied = clock::now_micros();
            match outcome {
                Ok(code) => acks.push(Ack {
                    id,
                    due,
                    sent,
                    replied,
                    code,
                }),
                Err(error) => {
                    acks.push(Ack {
                        id,
                        due,
                        sent,
                        replied,
                        code: 0,
                    });
                    return (acks, Some(format!("connection {}: {error}", self.index)));
                }
            }
        }
        connection.close().await;
        (acks, None)
    }
}

enum Connection {
    Smtp(Smtp),
    /// A kept-alive HTTPS connection to an API.
    Api {
        stream: BufReader<TlsStream<TcpStream>>,
        line: Vec<u8>,
    },
}

impl Connection {
    async fn open(options: &Options, config: Arc<ClientConfig>) -> Result<Self, String> {
        let tcp = TcpStream::connect(&options.target)
            .await
            .map_err(|error| format!("{}: {error}", options.target))?;
        tcp.set_nodelay(true).map_err(|error| error.to_string())?;
        if options.ingress == Ingress::Smtp {
            return Smtp::open(tcp, options, config).await.map(Self::Smtp);
        }
        let name =
            ServerName::try_from(options.server_name.clone()).map_err(|error| error.to_string())?;
        let tls = TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(|error| format!("the TLS handshake: {error}"))?;
        Ok(Self::Api {
            stream: BufReader::with_capacity(16 * 1024, tls),
            line: Vec::new(),
        })
    }

    /// One submission: its SMTP-style code (`api::code` for an API).
    async fn submit(&mut self, message: &[u8], id: u64, options: &Options) -> io::Result<u16> {
        let (stream, line) = match self {
            Self::Smtp(smtp) => return smtp.submit(message, id, options).await,
            Self::Api { stream, line } => (stream, line),
        };
        let Some((user, password)) = &options.credentials else {
            return Err(io::Error::other("an API needs `--user` and `--password`"));
        };
        let port = options
            .target
            .rsplit_once(':')
            .map_or("443", |(_, port)| port);
        let recipients = options.recipients.addresses(id);
        let request = api::request(
            options.ingress,
            &api::Submission {
                host: &format!("{}:{port}", options.server_name),
                user,
                password,
                sender: &options.sender,
                recipients: &recipients,
                message,
            },
        )
        .map_err(io::Error::other)?;
        let socket = stream.get_mut();
        socket.write_all(&request).await?;
        socket.flush().await?;
        let (status, body) = api::response(stream, line).await?;
        Ok(api::code(options.ingress, status, &body))
    }

    async fn close(self) {
        if let Self::Smtp(mut smtp) = self {
            let _ = smtp::send(&mut smtp.stream, b"QUIT\r\n").await;
        }
    }
}

struct Smtp {
    stream: BufReader<TlsStream<TcpStream>>,
    pipelining: bool,
    line: Vec<u8>,
}

impl Smtp {
    async fn open(
        tcp: TcpStream,
        options: &Options,
        config: Arc<ClientConfig>,
    ) -> Result<Self, String> {
        let mut plain = BufReader::new(tcp);
        let mut line = Vec::new();
        expect(&mut plain, &mut line, None, "the greeting").await?;
        let ehlo = expect(
            &mut plain,
            &mut line,
            Some(b"EHLO load.bench.test\r\n"),
            "EHLO",
        )
        .await?;
        if !ehlo
            .lines
            .iter()
            .any(|keyword| keyword.eq_ignore_ascii_case("STARTTLS"))
        {
            return Err(format!("{} does not offer STARTTLS", options.target));
        }
        expect(&mut plain, &mut line, Some(b"STARTTLS\r\n"), "STARTTLS").await?;
        if !plain.buffer().is_empty() {
            return Err("the server sent data ahead of the TLS handshake".to_owned());
        }
        let name =
            ServerName::try_from(options.server_name.clone()).map_err(|error| error.to_string())?;
        let tls = TlsConnector::from(config)
            .connect(name, plain.into_inner())
            .await
            .map_err(|error| format!("the TLS handshake: {error}"))?;
        let mut stream = BufReader::with_capacity(16 * 1024, tls);
        let ehlo = expect(
            &mut stream,
            &mut line,
            Some(b"EHLO load.bench.test\r\n"),
            "EHLO after STARTTLS",
        )
        .await?;
        let pipelining = ehlo
            .lines
            .iter()
            .any(|keyword| keyword.eq_ignore_ascii_case("PIPELINING"));
        if let Some((user, password)) = &options.credentials {
            let token = STANDARD.encode(format!("\0{user}\0{password}"));
            let command = format!("AUTH PLAIN {token}\r\n");
            expect(&mut stream, &mut line, Some(command.as_bytes()), "AUTH").await?;
        }
        Ok(Self {
            stream,
            pipelining,
            line,
        })
    }

    /// One transaction: the final reply's code, or the first refusal's.
    async fn submit(&mut self, message: &[u8], id: u64, options: &Options) -> io::Result<u16> {
        let mut commands = vec![format!("MAIL FROM:<{}>\r\n", options.sender)];
        commands.extend(
            options
                .recipients
                .addresses(id)
                .iter()
                .map(|recipient| format!("RCPT TO:<{recipient}>\r\n")),
        );
        commands.push("DATA\r\n".to_owned());
        let data = commands.len() - 1;
        let mut codes = vec![0u16; commands.len()];
        if self.pipelining {
            smtp::send(&mut self.stream, commands.concat().as_bytes()).await?;
            for code in &mut codes {
                *code = smtp::read_reply(&mut self.stream, &mut self.line)
                    .await?
                    .code;
            }
        } else {
            for (command, code) in commands.iter().zip(&mut codes) {
                smtp::send(&mut self.stream, command.as_bytes()).await?;
                *code = smtp::read_reply(&mut self.stream, &mut self.line)
                    .await?
                    .code;
                if *code / 100 != 2 && *code != 354 {
                    break;
                }
            }
        }
        if codes[data] != 354 {
            smtp::send(&mut self.stream, b"RSET\r\n").await?;
            smtp::read_reply(&mut self.stream, &mut self.line).await?;
            return Ok(codes
                .iter()
                .copied()
                .find(|&code| code / 100 != 2)
                .unwrap_or(codes[data]));
        }
        let stream = self.stream.get_mut();
        stream.write_all(message).await?;
        stream.write_all(b".\r\n").await?;
        stream.flush().await?;
        let reply = smtp::read_reply(&mut self.stream, &mut self.line).await?;
        // A refused recipient with a pipelined DATA still sends the content,
        // but the transaction carries the recipient's refusal.
        Ok(codes
            .into_iter()
            .take(data)
            .find(|&code| code / 100 != 2)
            .unwrap_or(reply.code))
    }
}

/// Sends `command`, if any, and reads a reply that must be positive.
async fn expect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufReader<S>,
    line: &mut Vec<u8>,
    command: Option<&[u8]>,
    what: &str,
) -> Result<Reply, String> {
    if let Some(command) = command {
        smtp::send(stream, command)
            .await
            .map_err(|error| format!("{what}: {error}"))?;
    }
    let reply = smtp::read_reply(stream, line)
        .await
        .map_err(|error| format!("{what}: {error}"))?;
    if !matches!(reply.code / 100, 2 | 3) {
        return Err(format!("{what}: {} {}", reply.code, reply.text()));
    }
    Ok(reply)
}

/// Builds message `id` into `message`, about `options.size` bytes in all.
fn compose(
    message: &mut Vec<u8>,
    body: &mut Vec<u8>,
    id: u64,
    options: &Options,
    date: &str,
) -> Result<(), String> {
    let header = format!(
        "From: Load <{sender}>\r\n\
         To: <{recipient}>\r\n\
         Subject: Load {id:016x}\r\n\
         Date: {date}\r\n\
         Message-ID: <{id:016x}@load.bench.test>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=us-ascii\r\n\
         Content-Transfer-Encoding: 7bit\r\n\
         X-Bench-Id: {id:016x}\r\n\
         X-Bench-Body: ",
        sender = options.sender,
        recipient = options.recipients.addresses(id)[0],
    );
    // The digest's 64 hex digits, its CRLF and the blank line follow.
    fill_body(body, options.size.saturating_sub(header.len() + 64 + 4))?;
    message.clear();
    message.extend_from_slice(header.as_bytes());
    message
        .extend_from_slice(crate::hex(digest::digest(&digest::SHA256, body).as_ref()).as_bytes());
    message.extend_from_slice(b"\r\n\r\n");
    message.extend_from_slice(body);
    Ok(())
}

/// About `size` bytes of base64 lines of random bytes, each 76 characters
/// and a CRLF but the last.
fn fill_body(body: &mut Vec<u8>, size: usize) -> Result<(), String> {
    const LINE: usize = 76;
    let characters = size / (LINE + 2) * LINE + (size % (LINE + 2)).saturating_sub(2);
    let mut random = vec![0; characters.div_ceil(4) * 3];
    aws_lc_rs::rand::fill(&mut random)
        .map_err(|_| "the random number generator failed".to_owned())?;
    let text = STANDARD.encode(&random);
    body.clear();
    for line in text.as_bytes()[..characters].chunks(LINE) {
        body.extend_from_slice(line);
        body.extend_from_slice(b"\r\n");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(size: usize) -> Options {
        Options {
            ingress: Ingress::Smtp,
            target: String::new(),
            server_name: String::new(),
            connections: 1,
            rate: 0.0,
            seconds: 0.0,
            messages: None,
            size,
            id_base: 1,
            credentials: None,
            sender: "load@bench.test".to_owned(),
            recipients: Recipients {
                per_message: 1,
                domain: "sink.test".to_owned(),
                domains: 1,
                throttled_share: 0.0,
                throttled_domain: "throttled.test".to_owned(),
            },
        }
    }

    #[test]
    fn recipients_spread_across_domains_and_a_share_is_throttled() {
        let mut recipients = Recipients {
            per_message: 1,
            domain: "sink.test".to_owned(),
            domains: 1000,
            throttled_share: 0.1,
            throttled_domain: "throttled.test".to_owned(),
        };
        assert_eq!(
            recipients.addresses(5),
            ["r0000000000000005@throttled.test"]
        );
        assert_eq!(
            recipients.addresses(1234),
            ["r00000000000004d2@d234.sink.test"]
        );
        recipients.per_message = 3;
        assert_eq!(
            recipients.addresses(1234),
            [
                "r00000000000004d2-0@d702.sink.test",
                "r00000000000004d2-1@d703.sink.test",
                "r00000000000004d2-2@d704.sink.test"
            ]
        );
        let held = (0..10_000).filter(|&id| throttled(id, 0.1)).count();
        assert_eq!(held, 1000);
        assert!(!(0..10_000).any(|id| throttled(id, 0.0)));
    }

    #[test]
    fn messages_have_their_size_and_a_true_digest() {
        let (mut message, mut body) = (Vec::new(), Vec::new());
        for size in [16 * 1024, 100 * 1024, 600, 0] {
            compose(
                &mut message,
                &mut body,
                0xabc,
                &options(size),
                "Tue, 27 Oct 2026 15:30:00 +0000",
            )
            .unwrap();
            if size > 600 {
                assert!(
                    message.len().abs_diff(size) <= 2,
                    "{size}: {}",
                    message.len()
                );
            }
            let text = String::from_utf8(message.clone()).unwrap();
            let (header, body) = text.split_once("\r\n\r\n").unwrap();
            let claimed = header
                .lines()
                .find_map(|line| line.strip_prefix("X-Bench-Body: "))
                .unwrap();
            assert_eq!(
                claimed,
                crate::hex(digest::digest(&digest::SHA256, body.as_bytes()).as_ref())
            );
            assert!(header.contains("X-Bench-Id: 0000000000000abc"));
            assert!(
                body.split("\r\n")
                    .all(|line| line.len() <= 76 && !line.starts_with('.'))
            );
            assert!(body.is_empty() || body.ends_with("\r\n"));
        }
    }
}
