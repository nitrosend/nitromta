//! What the engine's tests run it against: its binary, or a build of the
//! test's own, in a directory of its own; a stub DNS that answers for the test's domains, signed when a
//! test needs DNSSEC; an SMTP receiver that records each connection and
//! what it was told; a certificate authority of the test's own, with an
//! MTA-STS policy host; and a submission client. Each test file uses part
//! of it.

#![allow(dead_code)]

pub mod dns;
pub mod endpoint;
pub mod pki;
pub mod receiver;
pub mod ses;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use dns::Dns;
pub use receiver::{Receiver, Script};

use base64::Engine as _;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;

/// How long a test waits for something it expects at most.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// Waits until `done` holds, and fails the test after [`PATIENCE`].
pub fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(Instant::now() < deadline, "waited too long for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The engine's binary, running in a directory of its own, which outlives
/// its restarts.
pub struct Engine {
    pub dir: PathBuf,
    /// The build it runs.
    binary: PathBuf,
    child: Option<Child>,
    submission: u16,
    /// How much of the log earlier runs wrote.
    logged: usize,
    certificate: CertificateDer<'static>,
    password: Option<String>,
}

impl Engine {
    /// Starts the engine, delivering through `dns` to `receiver`. Its
    /// configuration's `[delivery]` section takes `delivery`'s lines as
    /// well, and `sections` follow it.
    pub fn start(
        name: &str,
        dns: &Dns,
        receiver: &Receiver,
        delivery: &str,
        sections: &str,
    ) -> Self {
        Self::start_with(name, dns, receiver, delivery, sections, &[])
    }

    /// As [`Engine::start`], with `files` written into its directory first,
    /// each a name and its contents.
    pub fn start_with(
        name: &str,
        dns: &Dns,
        receiver: &Receiver,
        delivery: &str,
        sections: &str,
        files: &[(&str, &str)],
    ) -> Self {
        let binary = Path::new(env!("CARGO_BIN_EXE_nitromta"));
        Self::start_as(binary, name, dns, receiver, delivery, sections, files)
    }

    /// As [`Engine::start_with`], running `binary`: a build with hooks of
    /// the test's own.
    pub fn start_as(
        binary: &Path,
        name: &str,
        dns: &Dns,
        receiver: &Receiver,
        delivery: &str,
        sections: &str,
        files: &[(&str, &str)],
    ) -> Self {
        let dir = std::env::temp_dir().join(format!("nitromta-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the test's directory");
        for (file, contents) in files {
            std::fs::write(dir.join(file), contents).expect("written");
        }
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a certificate");
        std::fs::write(dir.join("tls.crt"), certified.cert.pem()).expect("written");
        std::fs::write(dir.join("tls.key"), certified.signing_key.serialize_pem())
            .expect("written");
        let config = format!(
            r#"[store]
path = "store.db"
keys = "keys"

[submission]
listen = "127.0.0.1:0"
hostname = "localhost"
certificate = "tls.crt"
key = "tls.key"

[admin]
socket = "admin.sock"

[delivery]
helo = "localhost"
return_path_domain = "bounces.example.test"
return_path_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
require_tls = false
port = {port}
resolver = "{resolver}"
{delivery}

[outbound]
allow_private_destinations = true

{sections}
"#,
            port = receiver.port,
            resolver = dns.address,
        );
        std::fs::write(dir.join("config.toml"), config).expect("written");
        // The installation's keys, its owner's alone.
        let keys = dir.join("keys");
        std::fs::write(&keys, format!("1 {}\n", "5e".repeat(32))).expect("written");
        std::fs::set_permissions(&keys, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("its owner's alone");
        let mut engine = Self {
            dir,
            binary: binary.to_path_buf(),
            child: None,
            submission: 0,
            logged: 0,
            certificate: certified.cert.der().clone(),
            password: None,
        };
        engine.run();
        engine
    }

    fn run(&mut self) {
        if let Err(log) = self.try_run() {
            panic!("the engine did not start: {log}");
        }
    }

    /// Starts the engine, and waits until it serves: or, if it stops
    /// first, returns what it logged in this run.
    fn try_run(&mut self) -> Result<(), String> {
        let _ = std::fs::remove_file(self.dir.join("admin.sock"));
        // What an earlier run logged is not this one's.
        let logged = self.log().len();
        self.logged = logged;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("engine.log"))
            .expect("the log");
        let child = Command::new(&self.binary)
            .args(["run", "--config", "config.toml"])
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("the log"))
            .stderr(log)
            .spawn()
            .expect("the engine starts");
        self.child = Some(child);
        let mut stopped = None;
        wait_for("submission, or the engine to stop", || {
            if let Some(child) = self.child.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                stopped = Some(status);
                return true;
            }
            self.listening("accepting submission").is_some()
        });
        if let Some(status) = stopped {
            self.child = None;
            return Err(format!("{status}: {}", &self.log()[logged..]));
        }
        // Submission listens on the port the system gave it, which its log
        // line names.
        self.submission = self.listening("accepting submission").unwrap_or_default();
        Ok(())
    }

    /// The port a listener this run logged as `message` holds.
    pub fn listening(&self, message: &str) -> Option<u16> {
        self.log()[self.logged..]
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|line| line["message"] == message)
            .and_then(|line| line["listen"].as_str()?.rsplit_once(':')?.1.parse().ok())
    }

    /// What this run has logged.
    pub fn logged(&self) -> String {
        self.log()[self.logged..].to_owned()
    }

    /// Kills the engine, as a crash or a power cut would stop it.
    pub fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Starts the engine again after a stop: or returns what it logged if
    /// it would not start.
    pub fn start_again(&mut self) -> Result<(), String> {
        self.try_run()
    }

    /// Runs the binary with `arguments` in the engine's directory, and
    /// returns whether it succeeded and what it wrote.
    pub fn command(&self, arguments: &[&str]) -> (bool, String) {
        let output = Command::new(&self.binary)
            .args(arguments)
            .current_dir(&self.dir)
            .output()
            .expect("the binary runs");
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        (output.status.success(), text)
    }

    /// Starts the binary with `arguments` in the engine's directory, its
    /// output kept for [`std::process::Child::wait_with_output`].
    pub fn spawn(&self, arguments: &[&str]) -> std::process::Child {
        Command::new(&self.binary)
            .args(arguments)
            .current_dir(&self.dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the binary runs")
    }

    /// A GET of `path` from the operator's endpoint: its status and body.
    pub fn operator(&self, path: &str) -> (u16, String) {
        let port = self
            .listening("serving health and metrics")
            .expect("an operator endpoint");
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the operator endpoint");
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"
        )
        .expect("written");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("answered");
        let status = response
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_default();
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default();
        (status, body)
    }

    /// What submission answers a recipient, as the test's sender.
    pub fn rcpt(&mut self, recipient: &str) -> String {
        let mut session = self.session();
        session.send("MAIL FROM:<app@sender.test>", 250);
        let reply = session.ask(&format!("RCPT TO:<{recipient}>"));
        session.ask("QUIT");
        reply
    }

    /// Stops the engine as an operator does, and waits for it.
    pub fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let stopped = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(stopped.success(), "the engine takes SIGTERM");
        let status = child.wait().expect("the engine stops");
        assert!(
            status.success(),
            "the engine stopped with {status}: {}",
            self.log()
        );
    }

    pub fn restart(&mut self) {
        self.stop();
        self.run();
    }

    /// Sends the running engine `signal`, by name, as `kill` takes it.
    pub fn signal(&self, signal: &str) {
        let child = self.child.as_ref().expect("a running engine");
        let sent = Command::new("kill")
            .args([&format!("-{signal}"), &child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(sent.success(), "the engine takes SIG{signal}");
    }

    /// Whether submission's STARTTLS serves a certificate `root` vouches
    /// for, for `localhost`.
    pub fn serves(&self, root: &CertificateDer<'static>) -> bool {
        let stream =
            TcpStream::connect(("127.0.0.1", self.submission)).expect("submission connects");
        stream
            .set_read_timeout(Some(PATIENCE))
            .expect("a read timeout");
        let mut plain = BufReader::new(stream.try_clone().expect("a clone"));
        let mut writer = stream.try_clone().expect("a clone");
        reply(&mut plain, 220);
        command(&mut writer, &mut plain, "EHLO client.test", 250);
        command(&mut writer, &mut plain, "STARTTLS", 220);
        let mut roots = RootCertStore::empty();
        roots.add(root.clone()).expect("a root");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut connection =
            ClientConnection::new(Arc::new(config), "localhost".try_into().expect("a name"))
                .expect("a TLS session");
        let mut stream = stream;
        while connection.is_handshaking() {
            if connection.complete_io(&mut stream).is_err() {
                return false;
            }
        }
        true
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("engine.log")).unwrap_or_default()
    }

    /// A client of its SES v2 API, signing with an access key issued now
    /// for the test's sender's account, which sends.
    pub fn ses(&mut self) -> ses::Client {
        self.ses_permitted(&["send"])
    }

    /// As [`Engine::ses`], with a key of the `permissions` named: `send`,
    /// `manage` or both.
    pub fn ses_permitted(&mut self, permissions: &[&str]) -> ses::Client {
        self.password();
        let port = self
            .listening("serving the SES v2 API")
            .expect("an SES listener");
        let issued = self.admin(&[serde_json::json!({
            "op": "create_access_key", "account": 1, "permissions": permissions
        })]);
        let key = &issued[0]["ok"];
        ses::Client {
            port,
            certificate: self.certificate.clone(),
            access_key: key["access_key_id"]
                .as_str()
                .expect("an access key")
                .to_owned(),
            secret: key["secret_access_key"]
                .as_str()
                .expect("its secret")
                .to_owned(),
        }
    }

    /// Sends each of `requests` to the admin socket, and returns each
    /// answer.
    pub fn admin(&self, requests: &[Value]) -> Vec<Value> {
        let mut socket =
            UnixStream::connect(self.dir.join("admin.sock")).expect("the admin socket");
        for request in requests {
            writeln!(socket, "{request}").expect("written");
        }
        socket
            .shutdown(std::net::Shutdown::Write)
            .expect("shut for writing");
        let mut answers = String::new();
        socket.read_to_string(&mut answers).expect("answered");
        answers
            .lines()
            .map(|line| serde_json::from_str(line).expect("an answer is JSON"))
            .collect()
    }

    /// Creates the sender the test submits as, once.
    fn password(&mut self) -> String {
        if let Some(password) = &self.password {
            return password.clone();
        }
        let answers = self.admin(&[
            serde_json::json!({"op": "put_account", "account": 1}),
            serde_json::json!({"op": "put_identity", "account": 1, "name": "sender.test"}),
            serde_json::json!({"op": "create_login", "account": 1, "user": "app"}),
        ]);
        let password = answers[2]["ok"]["password"]
            .as_str()
            .unwrap_or_else(|| panic!("a login: {answers:?}"))
            .to_owned();
        self.password = Some(password.clone());
        password
    }

    /// A submission session over STARTTLS, logged in as the test's sender.
    pub fn session(&mut self) -> Submitting {
        let password = self.password();
        self.session_as("app", &password)
    }

    /// A submission session over STARTTLS, logged in as `user`.
    pub fn session_as(&self, user: &str, password: &str) -> Submitting {
        let stream =
            TcpStream::connect(("127.0.0.1", self.submission)).expect("submission connects");
        stream
            .set_read_timeout(Some(PATIENCE))
            .expect("a read timeout");
        let mut plain = BufReader::new(stream.try_clone().expect("a clone"));
        let mut writer = stream.try_clone().expect("a clone");
        reply(&mut plain, 220);
        command(&mut writer, &mut plain, "EHLO client.test", 250);
        command(&mut writer, &mut plain, "STARTTLS", 220);
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
        let mut session = Submitting {
            tls: BufReader::new(StreamOwned::new(connection, stream)),
        };
        session.send("EHLO client.test", 250);
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{password}"));
        session.send(&format!("AUTH PLAIN {token}"), 235);
        session
    }

    /// Submits a message to each of `recipients`, one at a time, over
    /// STARTTLS as the test's sender, waits for each acceptance, and
    /// returns each message's ID, in hex, as its acceptance named it.
    pub fn submit(&mut self, recipients: &[&str]) -> Vec<String> {
        let mut session = self.session();
        let mut messages = Vec::new();
        for recipient in recipients {
            session.send("MAIL FROM:<app@sender.test>", 250);
            session.send(&format!("RCPT TO:<{recipient}>"), 250);
            session.send("DATA", 354);
            let accepted = session.send(
                &format!(
                    "From: app@sender.test\r\nTo: {recipient}\r\nSubject: a test\r\n\r\nhello\r\n."
                ),
                250,
            );
            let id = accepted
                .trim_end()
                .rsplit_once("queued as ")
                .map(|(_, id)| id.to_owned())
                .unwrap_or_else(|| panic!("an acceptance names its message: {accepted:?}"));
            messages.push(id);
        }
        session.send("QUIT", 221);
        messages
    }

    /// What `explain` says of each delivery of `message`.
    pub fn explain(&self, message: &str) -> Vec<Value> {
        let answers = self.admin(&[serde_json::json!({"op": "explain", "message": message})]);
        answers[0]["ok"]["deliveries"]
            .as_array()
            .unwrap_or_else(|| panic!("an explanation: {answers:?}"))
            .clone()
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn command(writer: &mut TcpStream, reader: &mut impl BufRead, line: &str, code: u16) {
    writer
        .write_all(format!("{line}\r\n").as_bytes())
        .expect("written");
    reply(reader, code);
}

/// A submission session, logged in.
pub struct Submitting {
    tls: BufReader<StreamOwned<ClientConnection, TcpStream>>,
}

impl Submitting {
    /// Sends `line`, and returns its reply, which must have `code`.
    pub fn send(&mut self, line: &str, code: u16) -> String {
        let reply = self.ask(line);
        assert!(
            reply.starts_with(&code.to_string()),
            "expected {code}, got {reply:?}"
        );
        reply
    }

    /// Sends `line`, and returns its reply, whatever it is.
    pub fn ask(&mut self, line: &str) -> String {
        self.tls
            .get_mut()
            .write_all(format!("{line}\r\n").as_bytes())
            .expect("written");
        read_reply(&mut self.tls)
    }
}

/// Reads one reply, which must have `code`.
fn reply(reader: &mut impl BufRead, code: u16) -> String {
    let text = read_reply(reader);
    assert!(
        text.starts_with(&code.to_string()),
        "expected {code}, got {text:?}"
    );
    text
}

/// Reads one reply, whatever its code.
fn read_reply(reader: &mut impl BufRead) -> String {
    let mut text = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("a reply");
        assert!(line.len() >= 4, "a reply line: {line:?}");
        text.push_str(&line);
        if line.as_bytes()[3] == b' ' {
            break;
        }
    }
    text
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
