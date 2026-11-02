//! The server's protocol: SMTP (RFC 5321) for message submission (RFC 6409)
//! or for receiving mail for the server's own addresses, with STARTTLS
//! (RFC 3207), AUTH PLAIN (RFC 4954, 4616) for submission, and pipelining
//! (RFC 2920).
//!
//! A [`Session`] is one connection's state machine. Its driver feeds it the
//! bytes that arrive and the verdicts it asks for, and carries out what it
//! asks: writing bytes, starting TLS, checking credentials, and submitting a
//! transaction for acceptance. The session answers a transaction only with
//! the reply its driver gives it, which comes once acceptance has committed.

use std::borrow::Cow;
use std::mem;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use engine_core::address::Address;
use engine_core::component::Component;
use engine_core::time::{Monotonic, Now};
use smtp_proto::request::receiver::RequestReceiver;
use smtp_proto::{AUTH_PLAIN, Error as ParseError, MAIL_SMTPUTF8, Request};

use crate::data::ContentReader;
use crate::reply::Reply;

/// The longest AUTH response line accepted, CRLF included.
const MAX_AUTH_LINE: usize = 4096;

#[derive(Clone, Debug)]
pub struct Config {
    pub role: Role,
    pub hostname: String,
    pub max_message_bytes: usize,
    pub max_recipients: usize,
    /// How long the session waits for the client before closing.
    pub idle: Duration,
}

/// What a server is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Message submission: mail only over TLS, after a login.
    Submission,
    /// Mail for the server's own addresses, from anyone: no login, TLS
    /// offered but not required, and each recipient put to the driver,
    /// which refuses relay at once.
    Receiver,
}

/// The refusal of a recipient the receiver has no mailbox for.
pub fn no_such_recipient() -> Reply {
    Reply::new(550, "5.1.1 No such recipient here")
}

#[derive(Debug)]
pub enum Input {
    Received(Bytes),
    /// The TLS handshake the session asked for has completed.
    TlsStarted,
    /// The verdict on the credentials the session asked to check.
    Authenticated(bool),
    /// Whether to take mail for the recipient the session asked about:
    /// refused, with the reply that says why.
    Recipient(Result<(), Reply>),
    /// The reply to the transaction the session submitted.
    Answered(Reply),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Output {
    Send(Vec<u8>),
    /// Start TLS once everything sent so far has been written.
    StartTls,
    Authenticate {
        user: String,
        password: String,
    },
    /// Whether to take mail for the recipient [`Session::asked`] names:
    /// answered with [`Input::Recipient`].
    Recipient,
    Submit(Transaction),
    /// Close the connection once everything sent so far has been written.
    Close,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Transaction {
    /// `None` for the null reverse path.
    pub sender: Option<Address>,
    pub recipients: Vec<Address>,
    /// The message as received, with dot-stuffing removed.
    pub content: Bytes,
}

#[derive(Debug)]
enum Mode {
    Commands,
    /// After `AUTH PLAIN` without an initial response, the next line is
    /// the response.
    AuthLine,
    Data {
        reader: ContentReader,
        too_large: bool,
    },
    /// Waiting for the driver; input is kept until it answers.
    Waiting,
    Closed,
}

pub struct Session {
    config: Arc<Config>,
    mode: Mode,
    commands: RequestReceiver,
    /// Received bytes not yet processed.
    input: Vec<u8>,
    /// Replies written since the last send. Pipelined commands are answered
    /// together, in one send (RFC 2920).
    replies: Vec<u8>,
    greeted: bool,
    ehlo: bool,
    tls: bool,
    authenticated: bool,
    /// `Some(None)` after `MAIL FROM:<>`.
    sender: Option<Option<Address>>,
    recipients: Vec<Address>,
    /// The recipient the driver is asked about.
    asked: Option<Address>,
    data: Vec<u8>,
    /// Input arrived since the idle deadline was last set.
    active: bool,
    deadline: Option<Monotonic>,
}

impl Session {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            mode: Mode::Commands,
            commands: RequestReceiver::default(),
            input: Vec::new(),
            replies: Vec::new(),
            greeted: false,
            ehlo: false,
            tls: false,
            authenticated: false,
            sender: None,
            recipients: Vec::new(),
            asked: None,
            data: Vec::new(),
            active: true,
            deadline: None,
        }
    }

    /// The recipient the session asked about with [`Output::Recipient`],
    /// until it is answered.
    pub fn asked(&self) -> Option<&Address> {
        self.asked.as_ref()
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.mode, Mode::Closed)
    }

    fn reply(&mut self, code: u16, text: &str) {
        Reply::new(code, text).write(&mut self.replies);
    }

    fn flush(&mut self, out: &mut Vec<Output>) {
        if !self.replies.is_empty() {
            out.push(Output::Send(mem::take(&mut self.replies)));
        }
    }

    fn reset_transaction(&mut self) {
        self.sender = None;
        self.recipients.clear();
        self.data.clear();
    }

    fn close(&mut self, out: &mut Vec<Output>) {
        self.flush(out);
        out.push(Output::Close);
        self.mode = Mode::Closed;
        self.input.clear();
    }

    /// Processes buffered input until it runs out or the session must wait.
    fn process(&mut self, out: &mut Vec<Output>) {
        let input = mem::take(&mut self.input);
        let mut bytes = input.iter();
        let mut discard = false;
        loop {
            match &mut self.mode {
                Mode::Waiting | Mode::Closed => break,
                Mode::Data { reader, too_large } => {
                    let mut rest = bytes.as_slice();
                    let done = reader.read(&mut rest, &mut self.data);
                    bytes = rest.iter();
                    if self.data.len() > self.config.max_message_bytes {
                        *too_large = true;
                        self.data.clear();
                    }
                    if !done {
                        break;
                    }
                    let too_large = *too_large;
                    self.end_of_data(too_large, out);
                }
                Mode::AuthLine => {
                    let rest = bytes.as_slice();
                    let Some(end) = rest.iter().position(|&byte| byte == b'\n') else {
                        if rest.len() > MAX_AUTH_LINE {
                            self.mode = Mode::Commands;
                            self.reply(500, "5.5.6 Authentication response too long");
                            bytes = [].iter();
                        }
                        break;
                    };
                    let line = String::from_utf8_lossy(&rest[..end]).trim().to_owned();
                    bytes = rest[end + 1..].iter();
                    self.mode = Mode::Commands;
                    self.auth_response(&line, out);
                }
                Mode::Commands => {
                    let command = match self.commands.ingest(&mut bytes) {
                        Ok(request) => Command::from(request),
                        Err(ParseError::NeedsMoreData { .. }) => break,
                        Err(error) => {
                            self.parse_error(&error);
                            continue;
                        }
                    };
                    if self.command(command, out) == After::Discard {
                        discard = true;
                        break;
                    }
                }
            }
        }
        if !discard && !self.is_closed() {
            self.input.extend_from_slice(bytes.as_slice());
        }
    }

    fn parse_error(&mut self, error: &ParseError) {
        let (code, text) = match error {
            ParseError::UnknownCommand => (500, "5.5.1 Command not recognised"),
            ParseError::InvalidSenderAddress => (553, "5.1.7 Bad sender address syntax"),
            ParseError::InvalidRecipientAddress => (553, "5.1.3 Bad recipient address syntax"),
            ParseError::InvalidParameter { .. } | ParseError::UnsupportedParameter { .. } => {
                (555, "5.5.4 Parameter not recognised")
            }
            ParseError::ResponseTooLong => (500, "5.5.6 Line too long"),
            _ => (501, "5.5.4 Syntax error"),
        };
        self.reply(code, text);
    }

    fn command(&mut self, command: Command, out: &mut Vec<Output>) -> After {
        match command {
            Command::Ehlo => {
                self.ehlo = true;
                self.reset_transaction();
                let mut lines = vec![
                    self.config.hostname.clone(),
                    "PIPELINING".to_owned(),
                    format!("SIZE {}", self.config.max_message_bytes),
                    "8BITMIME".to_owned(),
                    "ENHANCEDSTATUSCODES".to_owned(),
                ];
                if !self.tls {
                    lines.push("STARTTLS".to_owned());
                } else if !self.authenticated && self.config.role == Role::Submission {
                    lines.push("AUTH PLAIN".to_owned());
                }
                Reply { code: 250, lines }.write(&mut self.replies);
            }
            Command::Helo => {
                self.ehlo = true;
                self.reset_transaction();
                let hostname = self.config.hostname.clone();
                self.reply(250, &hostname);
            }
            Command::StartTls if self.tls => self.reply(503, "5.5.1 TLS already active"),
            Command::StartTls => {
                self.reply(220, "2.0.0 Ready to start TLS");
                self.flush(out);
                out.push(Output::StartTls);
                self.mode = Mode::Waiting;
                // Anything sent after STARTTLS, before the handshake, was
                // not protected by it, so none of it may be acted on
                // (RFC 3207, 4.2).
                self.commands = RequestReceiver::default();
                return After::Discard;
            }
            Command::Auth { plain, initial } => {
                if self.config.role == Role::Receiver {
                    self.reply(503, "5.5.1 Authentication not offered");
                } else if !self.ehlo {
                    self.reply(503, "5.5.1 EHLO first");
                } else if !self.tls {
                    self.reply(538, "5.7.11 Encryption required for authentication");
                } else if self.authenticated {
                    self.reply(503, "5.5.1 Already authenticated");
                } else if self.sender.is_some() {
                    self.reply(503, "5.5.1 Not during a transaction");
                } else if !plain {
                    self.reply(504, "5.5.4 Only PLAIN is supported");
                } else if initial.is_empty() {
                    self.reply(334, "");
                    self.mode = Mode::AuthLine;
                } else {
                    self.auth_response(&initial, out);
                }
            }
            Command::Mail {
                address,
                size,
                smtputf8,
            } => {
                let submission = self.config.role == Role::Submission;
                if submission && !self.tls {
                    self.reply(530, "5.7.0 Must issue a STARTTLS command first");
                } else if submission && !self.authenticated {
                    self.reply(530, "5.7.0 Authentication required");
                } else if self.sender.is_some() {
                    self.reply(503, "5.5.1 Nested MAIL command");
                } else if size > self.config.max_message_bytes {
                    self.reply(552, "5.3.4 Message size exceeds fixed limit");
                } else if smtputf8 {
                    self.reply(555, "5.6.7 SMTPUTF8 is not supported");
                } else if address.is_empty() {
                    self.sender = Some(None);
                    self.reply(250, "2.1.0 Ok");
                } else if let Ok(address) = Address::parse(&address) {
                    self.sender = Some(Some(address));
                    self.reply(250, "2.1.0 Ok");
                } else {
                    self.reply(553, "5.1.7 Bad sender address syntax");
                }
            }
            Command::Rcpt { address } => {
                if self.sender.is_none() {
                    self.reply(503, "5.5.1 MAIL first");
                } else if self.recipients.len() >= self.config.max_recipients {
                    self.reply(452, "4.5.3 Too many recipients");
                } else if let Ok(address) = Address::parse(&address) {
                    // The driver says whether to take it: a receiver, for
                    // its mailboxes; submission, while the store can take
                    // more mail. It answers at once, and the replies go
                    // out together.
                    out.push(Output::Recipient);
                    self.asked = Some(address);
                    self.mode = Mode::Waiting;
                    return After::Continue;
                } else {
                    self.reply(553, "5.1.3 Bad recipient address syntax");
                }
            }
            Command::Data => {
                if self.sender.is_none() {
                    self.reply(503, "5.5.1 MAIL first");
                } else if self.recipients.is_empty() {
                    self.reply(554, "5.5.1 No valid recipients");
                } else {
                    self.reply(354, "End data with <CR><LF>.<CR><LF>");
                    self.data.clear();
                    self.mode = Mode::Data {
                        reader: ContentReader::default(),
                        too_large: false,
                    };
                }
            }
            Command::Rset => {
                self.reset_transaction();
                self.reply(250, "2.0.0 Ok");
            }
            Command::Noop => self.reply(250, "2.0.0 Ok"),
            Command::Vrfy => self.reply(252, "2.5.0 Cannot verify the user"),
            Command::Quit => {
                self.reply(221, "2.0.0 Bye");
                self.close(out);
            }
            Command::Unsupported => self.reply(502, "5.5.1 Command not implemented"),
        }
        After::Continue
    }

    /// An AUTH PLAIN response: `authzid NUL authcid NUL password`, in
    /// base64 (RFC 4616). An authorization identity other than the
    /// authentication identity is refused.
    fn auth_response(&mut self, response: &str, out: &mut Vec<Output>) {
        if response == "*" {
            self.reply(501, "5.7.0 Authentication cancelled");
            return;
        }
        let decoded = STANDARD.decode(response).ok();
        let mut parts = decoded
            .as_deref()
            .map(|decoded| decoded.split(|&byte| byte == 0));
        let fields = parts.as_mut().and_then(|parts| {
            let fields = (parts.next()?, parts.next()?, parts.next()?);
            parts.next().is_none().then_some(fields)
        });
        let credentials = fields.and_then(|(authz, authc, password)| {
            let authc = std::str::from_utf8(authc).ok()?;
            let password = std::str::from_utf8(password).ok()?;
            (authz.is_empty() || authz == authc.as_bytes())
                .then(|| (authc.to_owned(), password.to_owned()))
        });
        match credentials {
            Some((user, password)) => {
                self.flush(out);
                out.push(Output::Authenticate { user, password });
                self.mode = Mode::Waiting;
            }
            None => self.reply(501, "5.5.2 Malformed AUTH PLAIN response"),
        }
    }

    fn end_of_data(&mut self, too_large: bool, out: &mut Vec<Output>) {
        if too_large {
            self.reset_transaction();
            self.mode = Mode::Commands;
            self.reply(552, "5.3.4 Message size exceeds fixed limit");
            return;
        }
        let transaction = Transaction {
            sender: self.sender.take().flatten(),
            recipients: mem::take(&mut self.recipients),
            content: Bytes::from(mem::take(&mut self.data)),
        };
        self.flush(out);
        out.push(Output::Submit(transaction));
        self.mode = Mode::Waiting;
    }
}

impl Component for Session {
    type Input = Input;
    type Output = Output;

    fn handle(&mut self, _now: Now, input: Input) {
        match input {
            Input::Received(bytes) => {
                if !self.is_closed() {
                    self.input.extend_from_slice(&bytes);
                    self.active = true;
                }
            }
            Input::TlsStarted => {
                // The client starts again under TLS (RFC 3207, 4.2).
                self.tls = true;
                self.ehlo = false;
                self.reset_transaction();
                self.mode = Mode::Commands;
            }
            Input::Authenticated(verdict) => {
                self.authenticated = verdict;
                if verdict {
                    self.reply(235, "2.7.0 Authentication successful");
                } else {
                    self.reply(535, "5.7.8 Authentication credentials invalid");
                }
                self.mode = Mode::Commands;
            }
            Input::Recipient(verdict) => {
                if let Some(address) = self.asked.take() {
                    match verdict {
                        Ok(()) => {
                            self.recipients.push(address);
                            self.reply(250, "2.1.5 Ok");
                        }
                        Err(reply) => reply.write(&mut self.replies),
                    }
                }
                self.mode = Mode::Commands;
            }
            Input::Answered(reply) => {
                reply.write(&mut self.replies);
                self.reset_transaction();
                self.mode = Mode::Commands;
            }
        }
    }

    fn poll(&mut self, now: Now, out: &mut Vec<Output>) -> Option<Monotonic> {
        if self.is_closed() {
            return None;
        }
        if !self.greeted {
            self.greeted = true;
            let banner = format!("{} ESMTP", self.config.hostname);
            self.reply(220, &banner);
        }
        if matches!(self.mode, Mode::Waiting) {
            self.flush(out);
            return None;
        }
        if self.active {
            self.active = false;
            self.deadline = Some(now.monotonic.saturating_add(self.config.idle));
        }
        if self
            .deadline
            .is_some_and(|deadline| now.monotonic >= deadline)
        {
            self.reply(421, "4.4.2 Idle too long, closing");
            self.close(out);
            return None;
        }
        self.process(out);
        // Replies wait while a recipient's answer is asked for, which comes
        // at once, so a pipelined transaction's go out together.
        if self.asked.is_none() {
            self.flush(out);
        }
        if matches!(self.mode, Mode::Waiting | Mode::Closed) {
            None
        } else {
            self.deadline
        }
    }
}

#[derive(PartialEq, Eq)]
enum After {
    Continue,
    /// The rest of the buffered input must be dropped.
    Discard,
}

/// A command, taken out of the parser's buffer.
enum Command {
    Ehlo,
    Helo,
    StartTls,
    Auth {
        plain: bool,
        initial: String,
    },
    Mail {
        address: String,
        size: usize,
        smtputf8: bool,
    },
    Rcpt {
        address: String,
    },
    Data,
    Rset,
    Noop,
    Vrfy,
    Quit,
    Unsupported,
}

impl From<Request<Cow<'_, str>>> for Command {
    fn from(request: Request<Cow<'_, str>>) -> Self {
        match request {
            Request::Ehlo { .. } => Self::Ehlo,
            Request::Helo { .. } => Self::Helo,
            Request::StartTls => Self::StartTls,
            Request::Auth {
                mechanism,
                initial_response,
            } => Self::Auth {
                plain: mechanism == AUTH_PLAIN,
                initial: initial_response.into_owned(),
            },
            Request::Mail { from } => Self::Mail {
                address: from.address.into_owned(),
                size: from.size,
                smtputf8: from.flags & MAIL_SMTPUTF8 != 0,
            },
            Request::Rcpt { to } => Self::Rcpt {
                address: to.address.into_owned(),
            },
            Request::Data => Self::Data,
            Request::Rset => Self::Rset,
            Request::Noop { .. } => Self::Noop,
            Request::Vrfy { .. } => Self::Vrfy,
            Request::Quit => Self::Quit,
            _ => Self::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        session_as(Role::Submission)
    }

    fn session_as(role: Role) -> Session {
        Session::new(Arc::new(Config {
            role,
            hostname: "sut.test".to_owned(),
            max_message_bytes: 1000,
            max_recipients: 2,
            idle: Duration::from_secs(300),
        }))
    }

    fn at(seconds: u64) -> Now {
        Now {
            wall: engine_core::time::Timestamp::from_micros(seconds * 1_000_000),
            monotonic: Monotonic::from_micros(seconds * 1_000_000),
        }
    }

    /// Feeds `input` and returns what the session asked for.
    fn feed(session: &mut Session, input: Input) -> Vec<Output> {
        session.handle(at(1), input);
        let mut out = Vec::new();
        session.poll(at(1), &mut out);
        out
    }

    fn send(session: &mut Session, wire: &str) -> Vec<Output> {
        feed(session, Input::Received(Bytes::from(wire.to_owned())))
    }

    /// As [`send`], taking every recipient the session asks about, and
    /// every output since.
    fn send_taking(session: &mut Session, wire: &str) -> Vec<Output> {
        let mut all = send(session, wire);
        while session.asked().is_some() {
            all.extend(feed(session, Input::Recipient(Ok(()))));
        }
        all
    }

    fn text(outputs: &[Output]) -> String {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Send(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
                _ => None,
            })
            .collect()
    }

    /// A session through STARTTLS and authentication.
    fn ready() -> Session {
        let mut session = session();
        let mut out = Vec::new();
        session.poll(at(0), &mut out);
        assert_eq!(text(&out), "220 sut.test ESMTP\r\n");
        let out = send(&mut session, "EHLO client\r\nSTARTTLS\r\n");
        assert!(
            text(&out).contains("250 STARTTLS\r\n")
                && text(&out).ends_with("220 2.0.0 Ready to start TLS\r\n")
        );
        assert_eq!(out.last(), Some(&Output::StartTls));
        let out = feed(&mut session, Input::TlsStarted);
        assert!(out.is_empty());
        let auth = STANDARD.encode("\0user\0secret");
        let out = send(
            &mut session,
            &format!("EHLO client\r\nAUTH PLAIN {auth}\r\n"),
        );
        assert!(text(&out).contains("250-ENHANCEDSTATUSCODES\r\n250 AUTH PLAIN\r\n"));
        assert_eq!(
            out.last(),
            Some(&Output::Authenticate {
                user: "user".to_owned(),
                password: "secret".to_owned()
            })
        );
        assert_eq!(
            text(&feed(&mut session, Input::Authenticated(true))),
            "235 2.7.0 Authentication successful\r\n"
        );
        session
    }

    #[test]
    fn a_pipelined_transaction_is_submitted_and_answered_after_its_verdict() {
        let mut session = ready();
        let out = send_taking(
            &mut session,
            "MAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nDATA\r\nSubject: x\r\n\r\n..dot\r\nend\r\n.\r\nNOOP\r\n",
        );
        assert_eq!(
            text(&out),
            "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n354 End data with <CR><LF>.<CR><LF>\r\n"
        );
        assert_eq!(
            out.last(),
            Some(&Output::Submit(Transaction {
                sender: Some(Address::parse("a@b.test").unwrap()),
                recipients: vec![Address::parse("c@d.test").unwrap()],
                content: Bytes::from_static(b"Subject: x\r\n\r\n.dot\r\nend\r\n"),
            }))
        );
        // The NOOP waits for the verdict, then is answered after it.
        let out = feed(
            &mut session,
            Input::Answered(Reply::new(250, "2.0.0 Queued")),
        );
        assert_eq!(text(&out), "250 2.0.0 Queued\r\n250 2.0.0 Ok\r\n");
    }

    #[test]
    fn input_sent_ahead_of_the_tls_handshake_is_discarded() {
        let mut session = session();
        session.poll(at(0), &mut Vec::new());
        let out = send(
            &mut session,
            "EHLO x\r\nSTARTTLS\r\nMAIL FROM:<evil@x.test>\r\n",
        );
        assert_eq!(out.last(), Some(&Output::StartTls));
        feed(&mut session, Input::TlsStarted);
        let out = send(&mut session, "RCPT TO:<a@b.test>\r\n");
        assert_eq!(text(&out), "503 5.5.1 MAIL first\r\n");
    }

    #[test]
    fn mail_needs_tls_and_authentication() {
        let mut session = session();
        session.poll(at(0), &mut Vec::new());
        assert_eq!(
            text(&send(
                &mut session,
                "EHLO x\r\nMAIL FROM:<a@b.test>\r\nAUTH PLAIN AGEA\r\n"
            ))
            .lines()
            .skip(6)
            .collect::<Vec<_>>(),
            [
                "530 5.7.0 Must issue a STARTTLS command first",
                "538 5.7.11 Encryption required for authentication",
            ]
        );
        let mut session = self::session();
        session.poll(at(0), &mut Vec::new());
        send(&mut session, "EHLO x\r\nSTARTTLS\r\n");
        feed(&mut session, Input::TlsStarted);
        let out = send(&mut session, "EHLO x\r\nMAIL FROM:<a@b.test>\r\n");
        assert!(text(&out).ends_with("530 5.7.0 Authentication required\r\n"));
        let out = send(
            &mut session,
            &format!("AUTH PLAIN {}\r\n", STANDARD.encode("\0u\0wrong")),
        );
        assert!(matches!(out.last(), Some(Output::Authenticate { .. })));
        assert_eq!(
            text(&feed(&mut session, Input::Authenticated(false))),
            "535 5.7.8 Authentication credentials invalid\r\n"
        );
    }

    #[test]
    fn auth_takes_its_response_on_the_next_line_and_refuses_proxying() {
        let mut session = session();
        session.poll(at(0), &mut Vec::new());
        send(&mut session, "EHLO x\r\nSTARTTLS\r\n");
        feed(&mut session, Input::TlsStarted);
        assert!(text(&send(&mut session, "EHLO x\r\nAUTH PLAIN\r\n")).ends_with("334 \r\n"));
        let out = send(
            &mut session,
            &format!("{}\r\n", STANDARD.encode("other\0u\0p")),
        );
        assert_eq!(text(&out), "501 5.5.2 Malformed AUTH PLAIN response\r\n");
        assert!(text(&send(&mut session, "AUTH PLAIN\r\n")).ends_with("334 \r\n"));
        assert_eq!(
            text(&send(&mut session, "*\r\n")),
            "501 5.7.0 Authentication cancelled\r\n"
        );
    }

    #[test]
    fn limits_are_enforced() {
        let mut session = ready();
        let out = send_taking(
            &mut session,
            "MAIL FROM:<> SIZE=2000\r\nMAIL FROM:<>\r\nRCPT TO:<a@b.test>\r\nRCPT TO:<c@b.test>\r\nRCPT TO:<d@b.test>\r\nRCPT TO:<bad>\r\n",
        );
        assert_eq!(
            text(&out),
            "552 5.3.4 Message size exceeds fixed limit\r\n250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n452 4.5.3 Too many recipients\r\n553 5.1.3 Bad recipient address syntax\r\n"
        );
        let body = "x".repeat(600);
        let out = send(
            &mut session,
            &format!("DATA\r\n{body}\r\n{body}\r\n.\r\nRSET\r\n"),
        );
        assert_eq!(
            text(&out),
            "354 End data with <CR><LF>.<CR><LF>\r\n552 5.3.4 Message size exceeds fixed limit\r\n250 2.0.0 Ok\r\n"
        );
        assert!(!out.iter().any(|output| matches!(output, Output::Submit(_))));
    }

    #[test]
    fn an_idle_client_is_closed() {
        let mut session = session();
        let mut out = Vec::new();
        let deadline = session.poll(at(0), &mut out).unwrap();
        assert_eq!(deadline, Monotonic::from_micros(300_000_000));
        out.clear();
        assert_eq!(session.poll(at(299), &mut out), Some(deadline));
        session.poll(at(300), &mut out);
        assert_eq!(text(&out), "421 4.4.2 Idle too long, closing\r\n");
        assert_eq!(out.last(), Some(&Output::Close));
        assert!(session.is_closed());
    }

    #[test]
    fn unknown_and_unsupported_commands_are_answered_and_passed() {
        let mut session = ready();
        let out = send(
            &mut session,
            "FROB x\r\nBDAT 10 LAST\r\nMAIL FROM:<a b>\r\nNOOP\r\n",
        );
        assert_eq!(
            text(&out),
            "500 5.5.1 Command not recognised\r\n502 5.5.1 Command not implemented\r\n553 5.1.7 Bad sender address syntax\r\n250 2.0.0 Ok\r\n"
        );
    }

    #[test]
    fn a_receiver_takes_mail_without_a_login_only_for_recipients_it_is_given() {
        let mut session = session_as(Role::Receiver);
        session.poll(at(0), &mut Vec::new());
        let out = send(&mut session, "EHLO mx.example.net\r\nAUTH PLAIN AGEA\r\n");
        assert!(text(&out).contains("250 STARTTLS\r\n"), "TLS is offered");
        assert!(!text(&out).contains("AUTH"), "no login is offered");
        assert!(text(&out).ends_with("503 5.5.1 Authentication not offered\r\n"));
        let out = send(
            &mut session,
            "MAIL FROM:<>\r\nRCPT TO:<relay@elsewhere.test>\r\nRCPT TO:<b1@bounces.test>\r\nDATA\r\n",
        );
        // The MAIL reply waits to go out with the recipients'.
        assert_eq!(text(&out), "");
        assert!(out.contains(&Output::Recipient));
        assert_eq!(
            session.asked(),
            Some(&Address::parse("relay@elsewhere.test").unwrap())
        );
        let out = feed(&mut session, Input::Recipient(Err(no_such_recipient())));
        assert_eq!(text(&out), "");
        assert!(out.contains(&Output::Recipient));
        assert_eq!(
            session.asked(),
            Some(&Address::parse("b1@bounces.test").unwrap())
        );
        let out = feed(&mut session, Input::Recipient(Ok(())));
        assert_eq!(
            text(&out),
            "250 2.1.0 Ok\r\n550 5.1.1 No such recipient here\r\n250 2.1.5 Ok\r\n354 End data with <CR><LF>.<CR><LF>\r\n"
        );
        let out = send(&mut session, "report\r\n.\r\n");
        assert_eq!(
            out.last(),
            Some(&Output::Submit(Transaction {
                sender: None,
                recipients: vec![Address::parse("b1@bounces.test").unwrap()],
                content: Bytes::from_static(b"report\r\n"),
            }))
        );
    }

    #[test]
    fn quit_closes_after_its_reply() {
        let mut session = ready();
        let out = send(&mut session, "QUIT\r\nNOOP\r\n");
        assert_eq!(text(&out), "221 2.0.0 Bye\r\n");
        assert_eq!(out.last(), Some(&Output::Close));
    }
}
