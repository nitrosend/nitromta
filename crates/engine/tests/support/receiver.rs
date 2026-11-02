//! An SMTP receiver on a port of its own, which records every connection
//! and what it was told. It offers STARTTLS while it has certificates to
//! present, chosen by the name the client asks for.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::lock;

/// What the receiver saw on one connection.
#[derive(Clone, Debug)]
pub struct Connection {
    pub opened: Instant,
    pub closed: Option<Instant>,
    /// Its greeting refused the session.
    pub refused: bool,
    /// The name the client asked for in its TLS handshake, once one
    /// completed.
    pub tls: Option<String>,
    /// Each transaction's recipients, as each was answered at RCPT.
    pub transactions: Vec<Vec<(String, u16)>>,
    /// The recipients whose content it took.
    pub delivered: Vec<String>,
}

impl Connection {
    /// The domains of the recipients it was asked to take.
    pub fn domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self
            .transactions
            .iter()
            .flatten()
            .filter_map(|(recipient, _)| recipient.split_once('@'))
            .map(|(_, domain)| domain.to_owned())
            .collect();
        domains.dedup();
        domains
    }
}

/// How the receiver answers.
pub struct Script {
    /// The reply to MAIL for each sender.
    pub mail: fn(&str) -> &'static str,
    /// The reply to RCPT for each recipient.
    pub rcpt: fn(&str) -> &'static str,
    /// How long it takes to answer each message's content, so connections
    /// overlap.
    pub content_delay: Duration,
    /// How long it takes to answer QUIT on a connection where it deferred
    /// a recipient.
    pub slow_quit: Duration,
}

impl Default for Script {
    /// Every recipient taken, at once.
    fn default() -> Self {
        Self {
            mail: |_| "250 2.1.0 Ok",
            rcpt: |_| "250 2.1.5 Ok",
            content_delay: Duration::ZERO,
            slow_quit: Duration::ZERO,
        }
    }
}

type Seen = Arc<Mutex<Vec<Connection>>>;

pub struct Receiver {
    pub port: u16,
    connections: Seen,
    refusing: Arc<AtomicBool>,
    tls: Arc<Mutex<Option<Arc<ServerConfig>>>>,
}

impl Receiver {
    pub fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its address").port();
        let receiver = Self {
            port,
            connections: Arc::default(),
            refusing: Arc::default(),
            tls: Arc::default(),
        };
        let script = Arc::new(script);
        let (seen, refuse, tls) = (
            Arc::clone(&receiver.connections),
            Arc::clone(&receiver.refusing),
            Arc::clone(&receiver.tls),
        );
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let index = {
                    let mut seen = lock(&seen);
                    seen.push(Connection {
                        opened: Instant::now(),
                        closed: None,
                        refused: false,
                        tls: None,
                        transactions: Vec::new(),
                        delivered: Vec::new(),
                    });
                    seen.len() - 1
                };
                let (seen, script) = (Arc::clone(&seen), Arc::clone(&script));
                let refused = refuse.load(Ordering::SeqCst);
                let tls = lock(&tls).clone();
                std::thread::spawn(move || {
                    let _ = serve(stream, index, &seen, refused, tls, &script);
                    let mut seen = lock(&seen);
                    seen[index].closed = Some(Instant::now());
                    seen[index].refused = refused;
                });
            }
        });
        receiver
    }

    /// Offers STARTTLS on new connections, presenting `tls`'s
    /// certificates; or, with `None`, offers no TLS.
    pub fn present(&self, tls: Option<Arc<ServerConfig>>) {
        *lock(&self.tls) = tls;
    }

    pub fn connections(&self) -> Vec<Connection> {
        lock(&self.connections).clone()
    }

    /// Whether new sessions are refused at their greeting.
    pub fn refuse_greetings(&self, refusing: bool) {
        self.refusing.store(refusing, Ordering::SeqCst);
    }

    /// Each time a recipient was asked for, with the code it was answered.
    pub fn answered(&self) -> Vec<(String, u16)> {
        self.connections()
            .into_iter()
            .flat_map(|connection| connection.transactions.into_iter().flatten())
            .collect()
    }

    /// The recipients whose content it took.
    pub fn delivered(&self) -> Vec<String> {
        self.connections()
            .into_iter()
            .flat_map(|connection| connection.delivered)
            .collect()
    }

    /// How many times `recipient` was asked for.
    pub fn asked(&self, recipient: &str) -> usize {
        self.answered()
            .iter()
            .filter(|(asked, _)| asked == recipient)
            .count()
    }
}

fn serve(
    mut stream: TcpStream,
    index: usize,
    seen: &Mutex<Vec<Connection>>,
    refused: bool,
    tls: Option<Arc<ServerConfig>>,
    script: &Script,
) -> std::io::Result<()> {
    if refused {
        return stream.write_all(b"421 4.7.0 slow down, from the greeting\r\n");
    }
    stream.write_all(b"220 receiver.test ESMTP\r\n")?;
    let mut plain = BufReader::new(stream);
    let Some(tls) = tls else {
        return converse(&mut plain, index, seen, false, script).map(|_| ());
    };
    if !converse(&mut plain, index, seen, true, script)? {
        return Ok(());
    }
    let session = ServerConnection::new(tls).map_err(std::io::Error::other)?;
    let mut secure = StreamOwned::new(session, plain.into_inner());
    // The handshake completes before anything is read, so a client that
    // refuses the certificate never gets further.
    while secure.conn.is_handshaking() {
        secure.conn.complete_io(&mut secure.sock)?;
    }
    lock(seen)[index].tls = Some(secure.conn.server_name().unwrap_or_default().to_owned());
    converse(&mut BufReader::new(secure), index, seen, false, script).map(|_| ())
}

/// Answers commands until the session ends, or, when `offer_tls`, until
/// STARTTLS, when it returns true.
fn converse<S: Read + Write>(
    reader: &mut BufReader<S>,
    index: usize,
    seen: &Mutex<Vec<Connection>>,
    offer_tls: bool,
    script: &Script,
) -> std::io::Result<bool> {
    let (mut deferred, mut sender) = (false, false);
    let mut accepted = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(false);
        }
        let command = line.trim_end().to_owned();
        let verb = command
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        match verb.as_str() {
            "EHLO" | "HELO" if offer_tls => {
                say(
                    reader.get_mut(),
                    "250-receiver.test\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 8BITMIME",
                )?;
            }
            "EHLO" | "HELO" => say(
                reader.get_mut(),
                "250-receiver.test\r\n250-PIPELINING\r\n250 8BITMIME",
            )?,
            "STARTTLS" if offer_tls => {
                say(reader.get_mut(), "220 2.0.0 ready")?;
                return Ok(true);
            }
            "MAIL" => {
                accepted.clear();
                lock(seen)[index].transactions.push(Vec::new());
                let reply = (script.mail)(address(&command));
                sender = reply.starts_with('2');
                say(reader.get_mut(), reply)?;
            }
            "RCPT" if !sender => say(reader.get_mut(), "503 5.5.1 sender first")?,
            "RCPT" => {
                let recipient = address(&command).to_owned();
                let reply = (script.rcpt)(&recipient);
                let code: u16 = reply[..3].parse().expect("a code");
                deferred |= code / 100 == 4;
                if code / 100 == 2 {
                    accepted.push(recipient.clone());
                }
                if let Some(transaction) = lock(seen)[index].transactions.last_mut() {
                    transaction.push((recipient, code));
                }
                say(reader.get_mut(), reply)?;
            }
            "DATA" if accepted.is_empty() => {
                say(reader.get_mut(), "554 5.5.1 no valid recipients")?
            }
            "DATA" => {
                say(reader.get_mut(), "354 go ahead")?;
                loop {
                    line.clear();
                    if reader.read_line(&mut line)? == 0 || line == ".\r\n" {
                        break;
                    }
                }
                std::thread::sleep(script.content_delay);
                lock(seen)[index].delivered.append(&mut accepted);
                say(reader.get_mut(), "250 2.0.0 Ok: queued")?;
            }
            "QUIT" => {
                if deferred {
                    std::thread::sleep(script.slow_quit);
                }
                say(reader.get_mut(), "221 2.0.0 Bye")?;
                return Ok(false);
            }
            _ => say(reader.get_mut(), "250 2.0.0 Ok")?,
        }
    }
}

/// The address between a command's angle brackets.
fn address(command: &str) -> &str {
    command
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map_or("", |(address, _)| address)
}

fn say(stream: &mut impl Write, reply: &str) -> std::io::Result<()> {
    stream.write_all(format!("{reply}\r\n").as_bytes())
}
