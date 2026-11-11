//! The delivery client's protocol: one connection to one receiving server
//! (RFC 5321), with STARTTLS (RFC 3207) and pipelining when the server
//! offers it (RFC 2920). It carries one transaction at a time, for as long as
//! its driver gives it work.
//!
//! A transaction carries one message to one or more recipients.
//! Each recipient ends in its own [`Outcome`]: a refusal at RCPT is that
//! recipient's alone, and the content's reply speaks for every recipient
//! accepted. An outcome keeps SMTP's one unavoidable uncertainty apart:
//! once the content's final dot is sent, a lost reply leaves the
//! delivery uncertain, never failed.

use std::mem;
use std::time::Duration;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::component::Component;
use engine_core::time::{Monotonic, Now, Timestamp};

use crate::reply::{Reply, ReplyReader};

#[derive(Clone, Debug)]
pub struct Config {
    pub helo: String,
    /// Deliver only over TLS, with no weaker fallback.
    pub require_tls: bool,
    /// How long to wait for each reply but the one after the content.
    pub reply_timeout: Duration,
    /// How long to wait for the reply after the content.
    pub final_timeout: Duration,
}

#[derive(Debug)]
pub struct Job<T> {
    /// `None` for the null reverse path.
    pub sender: Option<Address>,
    /// Each recipient, with the tag its outcome is reported under.
    pub recipients: Vec<(T, Address)>,
    /// Header fields sent ahead of the content, none starting with a dot:
    /// the transport's own, outside any signature in the content.
    pub header: Bytes,
    /// The prepared message, sent exactly as it is.
    pub content: Bytes,
}

/// A job under way: each recipient's tag until its outcome is reported, and
/// whether the server accepted it at RCPT.
struct Transaction<T> {
    sender: Option<Address>,
    recipients: Vec<Address>,
    tags: Vec<Option<T>>,
    accepted: Vec<bool>,
    header: Bytes,
    content: Bytes,
}

impl<T> From<Job<T>> for Transaction<T> {
    fn from(job: Job<T>) -> Self {
        let (tags, recipients): (Vec<_>, Vec<_>) = job
            .recipients
            .into_iter()
            .map(|(tag, recipient)| (Some(tag), recipient))
            .unzip();
        Self {
            sender: job.sender,
            accepted: vec![false; recipients.len()],
            recipients,
            tags,
            header: job.header,
            content: job.content,
        }
    }
}

#[derive(Debug)]
pub enum Input<T> {
    Received(Bytes),
    /// The TLS handshake the session asked for has completed.
    TlsStarted,
    Deliver(Job<T>),
    /// Finish any transaction under way, then close.
    Quit,
    /// The connection failed or the server closed it.
    Lost,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Output<T> {
    Send(Vec<u8>),
    /// Content to send as it is, without a copy.
    SendContent(Bytes),
    /// Start TLS once everything sent so far has been written.
    StartTls,
    Finished {
        tag: T,
        outcome: Outcome,
        /// When the reply that decided it was read, or when it was decided,
        /// for one with no reply: the day a receiver's reply counts on,
        /// though pipelining holds it for the replies after it.
        at: Timestamp,
        /// Whether the reply was this recipient's own: its RCPT's. Only such
        /// a refusal can say its address is no good; one of the
        /// sender, or of the content, speaks of the transaction, however
        /// many recipients it has.
        own: bool,
    },
    /// The session can take a job.
    Ready,
    /// Close the connection once everything sent so far has been written.
    Close,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Delivered(Reply),
    /// The content needs 8BITMIME, which this receiver did not advertise.
    /// A permanent local failure (RFC 6152, section 3), before MAIL; the
    /// content is never rewritten, so an existing signature stays intact.
    NoEightBitMime,
    /// Refused permanently (5xx): the sender, the recipient or the message.
    Rejected(Reply),
    /// Refused for now (4xx).
    Deferred(Reply),
    /// Not tried: the content's final dot was never sent, so the server
    /// cannot have accepted it, and it is safe to try again.
    NotSent(Failure),
    /// The connection failed after the content's final dot was sent and
    /// before its reply: the server may have accepted it.
    Uncertain,
}

impl Outcome {
    /// Whether the server refused this attempt with 421: it refuses service
    /// for now, whatever the message (`Session::throttled`).
    pub fn throttled(&self) -> bool {
        match self {
            Outcome::Deferred(reply) | Outcome::NotSent(Failure::Refused(reply)) => {
                reply.code == 421
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Lost,
    TimedOut,
    /// The server does not offer STARTTLS, and TLS is required.
    NoTls,
    /// The server refused the session (its greeting, EHLO or STARTTLS).
    Refused(Reply),
    /// The server's replies broke the protocol.
    Protocol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Greeting,
    Ehlo,
    StartTls,
    Handshake,
    EhloTls,
    Idle,
    /// The envelope's replies: MAIL, RCPT, DATA.
    Envelope,
    Final,
    /// After a refused transaction, RSET's reply.
    Reset,
    Quit,
    Closed,
}

pub struct Session<T> {
    config: Config,
    phase: Phase,
    reader: ReplyReader,
    input: Vec<u8>,
    tls: bool,
    pipelining: bool,
    eight_bit_mime: bool,
    job: Option<Transaction<T>>,
    /// The envelope's commands, how many are sent, and their replies.
    envelope: Vec<Vec<u8>>,
    sent: usize,
    replies: Vec<Reply>,
    /// When each of `replies` was read.
    reply_times: Vec<Timestamp>,
    quit: bool,
    /// The driver reported the connection gone.
    gone: bool,
    deadline: Option<Monotonic>,
    /// `Ready` was reported, and no job has come since.
    ready_reported: bool,
    /// The server answered 421.
    throttled: bool,
    /// What the server said when it refused the session itself, outside
    /// any transaction.
    refusal: Option<Reply>,
    /// Why the session ended before it was ready for a job, if it did.
    unready: Option<Failure>,
}

impl<T> Session<T> {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            phase: Phase::Greeting,
            reader: ReplyReader::default(),
            input: Vec::new(),
            tls: false,
            pipelining: false,
            eight_bit_mime: false,
            job: None,
            envelope: Vec::new(),
            sent: 0,
            replies: Vec::new(),
            reply_times: Vec::new(),
            quit: false,
            gone: false,
            deadline: None,
            ready_reported: false,
            throttled: false,
            refusal: None,
            unready: None,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// Whether the server answered 421 (RFC 5321, 3.8): it refuses service
    /// for now. That speaks for the receiver rather than for any message,
    /// so no other attempt should follow it there until it cools down.
    pub fn throttled(&self) -> bool {
        self.throttled
    }

    /// What the server said when it refused the session itself, outside
    /// any transaction: at its greeting, to EHLO or STARTTLS, or with a
    /// 421 between transactions. No attempt carries that reply, so the
    /// driver judges it for the site.
    pub fn refusal(&self) -> Option<&Reply> {
        self.refusal.as_ref()
    }

    /// Why the session ended before it was ever ready for a job: no
    /// STARTTLS where TLS is required, a refusal, a lost connection or a
    /// timer, which the driver may try another exchange over.
    pub fn unready(&self) -> Option<&Failure> {
        self.unready.as_ref()
    }

    /// Whether a job given now starts without waiting for another.
    pub fn is_idle(&self) -> bool {
        self.phase == Phase::Idle && self.job.is_none()
    }

    fn expect(&mut self, now: Now, phase: Phase) {
        self.phase = phase;
        let timeout = if phase == Phase::Final {
            self.config.final_timeout
        } else {
            self.config.reply_timeout
        };
        self.deadline = Some(now.monotonic.saturating_add(timeout));
    }

    fn send(out: &mut Vec<Output<T>>, command: &str) {
        out.push(Output::Send(command.as_bytes().to_vec()));
    }

    /// Reports `outcome` for every recipient of the job under way that has
    /// none yet, which ends the job.
    fn finish_rest(
        &mut self,
        outcome: &Outcome,
        at: Timestamp,
        own: bool,
        out: &mut Vec<Output<T>>,
    ) {
        if let Some(job) = self.job.take() {
            for tag in job.tags.into_iter().flatten() {
                out.push(Output::Finished {
                    tag,
                    outcome: outcome.clone(),
                    at,
                    own,
                });
            }
        }
    }

    /// Ends the session, reporting the job under way as `outcome`.
    fn fail(&mut self, outcome: Outcome, at: Timestamp, out: &mut Vec<Output<T>>) {
        if let Outcome::NotSent(failure) = &outcome
            && matches!(
                self.phase,
                Phase::Greeting | Phase::Ehlo | Phase::StartTls | Phase::Handshake | Phase::EhloTls
            )
        {
            self.unready = Some(failure.clone());
        }
        self.finish_rest(&outcome, at, false, out);
        out.push(Output::Close);
        self.phase = Phase::Closed;
        self.deadline = None;
    }

    /// Ends the session over a failure of the connection or its timer.
    fn lost(&mut self, failure: Failure, at: Timestamp, out: &mut Vec<Output<T>>) {
        let outcome = if self.phase == Phase::Final {
            Outcome::Uncertain
        } else {
            Outcome::NotSent(failure)
        };
        self.fail(outcome, at, out);
    }

    fn quit(&mut self, now: Now, out: &mut Vec<Output<T>>) {
        Self::send(out, "QUIT\r\n");
        self.expect(now, Phase::Quit);
    }

    fn ehlo(&mut self, now: Now, out: &mut Vec<Output<T>>, phase: Phase) {
        out.push(Output::Send(
            format!("EHLO {}\r\n", self.config.helo).into_bytes(),
        ));
        self.expect(now, phase);
    }

    fn on_reply(&mut self, reply: Reply, now: Now, out: &mut Vec<Output<T>>) {
        if reply.code == 421 {
            self.throttled = true;
            if self.job.is_none() {
                self.refusal = Some(reply.clone());
            }
            // The server is closing the channel (RFC 5321, 3.8): a
            // transaction under way ends here, with no other reply to wait
            // for.
            if matches!(self.phase, Phase::Envelope | Phase::Final) {
                self.fail(Outcome::Deferred(reply), now.wall, out);
                return;
            }
        }
        match self.phase {
            Phase::Greeting if reply.code == 220 => self.ehlo(now, out, Phase::Ehlo),
            Phase::Ehlo | Phase::EhloTls if reply.code == 250 => {
                let has = |keyword: &str| {
                    reply.lines.iter().skip(1).any(|line| {
                        line.split_ascii_whitespace()
                            .next()
                            .is_some_and(|word| word.eq_ignore_ascii_case(keyword))
                    })
                };
                self.pipelining = has("PIPELINING");
                self.eight_bit_mime = has("8BITMIME");
                if self.phase == Phase::Ehlo && has("STARTTLS") {
                    Self::send(out, "STARTTLS\r\n");
                    self.expect(now, Phase::StartTls);
                } else if !self.tls && self.config.require_tls {
                    self.fail(Outcome::NotSent(Failure::NoTls), now.wall, out);
                } else {
                    self.phase = Phase::Idle;
                    self.deadline = None;
                }
            }
            Phase::StartTls if reply.code == 220 => {
                out.push(Output::StartTls);
                self.phase = Phase::Handshake;
            }
            Phase::Greeting | Phase::Ehlo | Phase::StartTls | Phase::EhloTls => {
                self.refusal = Some(reply.clone());
                self.fail(Outcome::NotSent(Failure::Refused(reply)), now.wall, out);
            }
            Phase::Envelope => self.envelope_reply(reply, now, out),
            Phase::Final => {
                let outcome = match reply.code / 100 {
                    2 => Outcome::Delivered(reply),
                    5 => Outcome::Rejected(reply),
                    _ => Outcome::Deferred(reply),
                };
                // The content's reply speaks for every recipient accepted,
                // as none's own.
                self.finish_rest(&outcome, now.wall, false, out);
                self.phase = Phase::Idle;
                self.deadline = None;
            }
            Phase::Reset if reply.code == 250 => {
                self.phase = Phase::Idle;
                self.deadline = None;
            }
            Phase::Reset => self.fail(Outcome::NotSent(Failure::Protocol), now.wall, out),
            Phase::Quit => {
                out.push(Output::Close);
                self.phase = Phase::Closed;
                self.deadline = None;
            }
            // A reply nobody asked for: usually 421, the server closing.
            Phase::Idle | Phase::Handshake | Phase::Closed => {
                self.fail(Outcome::NotSent(Failure::Protocol), now.wall, out);
            }
        }
    }

    fn start(&mut self, now: Now, out: &mut Vec<Output<T>>) {
        let Some(job) = &self.job else {
            return;
        };
        // 8BITMIME also carries 7-bit content. On a capable receiver no
        // extra content scan is needed; the bytes remain shared. Only a
        // receiver without it needs the vectorized ASCII check.
        if !self.eight_bit_mime && (!job.header.is_ascii() || !job.content.is_ascii()) {
            self.finish_rest(&Outcome::NoEightBitMime, now.wall, false, out);
            self.job = None;
            return;
        }
        self.envelope = Vec::with_capacity(job.recipients.len() + 2);
        self.envelope.push(
            format!(
                "MAIL FROM:<{}>{}\r\n",
                job.sender.as_ref().map_or("", Address::as_str),
                if self.eight_bit_mime {
                    " BODY=8BITMIME"
                } else {
                    ""
                },
            )
            .into_bytes(),
        );
        for recipient in &job.recipients {
            self.envelope
                .push(format!("RCPT TO:<{}>\r\n", recipient.as_str()).into_bytes());
        }
        self.envelope.push(b"DATA\r\n".to_vec());
        self.replies.clear();
        self.reply_times.clear();
        self.sent = if self.pipelining {
            self.envelope.len()
        } else {
            1
        };
        out.push(Output::Send(self.envelope[..self.sent].concat()));
        self.expect(now, Phase::Envelope);
    }

    /// The envelope's replies, in the order of its commands: MAIL, each
    /// RCPT, then DATA. Pipelined, every command is sent at once and the
    /// replies are judged together; otherwise each command waits for the
    /// last one's reply.
    fn envelope_reply(&mut self, reply: Reply, now: Now, out: &mut Vec<Output<T>>) {
        self.replies.push(reply);
        self.reply_times.push(now.wall);
        if self.replies.len() < self.sent {
            return;
        }
        let Some(job) = self.job.as_mut() else {
            return;
        };
        let recipients = job.recipients.len();
        // MAIL refused: every recipient is refused alike.
        if self.replies[0].code / 100 != 2 {
            let refusal = refusal(&self.replies[0]);
            self.finish_rest(&refusal, self.reply_times[0], false, out);
            return self.reset(now, out);
        }
        // Each RCPT answered: a refusal is that recipient's alone.
        let answered = (self.replies.len() - 1).min(recipients);
        for index in 0..answered {
            let reply = &self.replies[1 + index];
            if reply.code / 100 == 2 {
                job.accepted[index] = true;
            } else if let Some(tag) = job.tags[index].take() {
                out.push(Output::Finished {
                    tag,
                    outcome: refusal(reply),
                    at: self.reply_times[1 + index],
                    own: true,
                });
            }
        }
        let any_accepted = job.accepted.iter().any(|&accepted| accepted);
        if self.sent < self.envelope.len() {
            // Without pipelining, the next command: the next RCPT, or DATA
            // once a recipient is accepted.
            if self.sent <= recipients || any_accepted {
                out.push(Output::Send(self.envelope[self.sent].clone()));
                self.sent += 1;
                self.expect(now, Phase::Envelope);
            } else {
                self.job = None;
                self.reset(now, out);
            }
            return;
        }
        let data = &self.replies[recipients + 1];
        if data.code == 354 {
            if any_accepted {
                return self.content(now, out);
            }
            // A server that takes DATA though it took no recipient waits for
            // content, and would read RSET as a line of it: an empty message
            // ends the transaction, as Postfix ends it (RFC 2920, 3.1).
            Self::send(out, ".\r\n");
            return self.expect(now, Phase::Final);
        }
        // DATA refused: every accepted recipient is refused alike.
        let refusal = refusal(data);
        let at = self.reply_times[recipients + 1];
        self.finish_rest(&refusal, at, false, out);
        self.reset(now, out);
    }

    /// Ends a refused transaction with RSET.
    fn reset(&mut self, now: Now, out: &mut Vec<Output<T>>) {
        self.job = None;
        Self::send(out, "RSET\r\n");
        self.expect(now, Phase::Reset);
    }

    /// Sends the content, dot-stuffed (RFC 5321, 4.5.2), and its final dot.
    /// Content with no line that starts with a dot is sent without a copy.
    fn content(&mut self, now: Now, out: &mut Vec<Output<T>>) {
        let Some(job) = &self.job else {
            return;
        };
        if !job.header.is_empty() {
            out.push(Output::SendContent(job.header.clone()));
        }
        let content = &job.content;
        let stuffed =
            content.first() == Some(&b'.') || content.windows(3).any(|window| window == b"\r\n.");
        if stuffed {
            let mut copy = Vec::with_capacity(content.len() + content.len() / 64);
            let mut line_start = true;
            for (index, &byte) in content.iter().enumerate() {
                if line_start && byte == b'.' {
                    copy.push(b'.');
                }
                copy.push(byte);
                line_start = byte == b'\n' && index > 0 && content[index - 1] == b'\r';
            }
            out.push(Output::Send(copy));
        } else {
            out.push(Output::SendContent(content.clone()));
        }
        let ending: &[u8] = if content.is_empty() || content.ends_with(b"\r\n") {
            b".\r\n"
        } else {
            b"\r\n.\r\n"
        };
        out.push(Output::Send(ending.to_vec()));
        self.expect(now, Phase::Final);
    }
}

impl<T> Component for Session<T> {
    type Input = Input<T>;
    type Output = Output<T>;

    fn handle(&mut self, _now: Now, input: Input<T>) {
        match input {
            Input::Received(bytes) => {
                if !self.is_closed() {
                    self.input.extend_from_slice(&bytes);
                }
            }
            Input::TlsStarted => {
                if self.phase == Phase::Handshake {
                    self.tls = true;
                    self.phase = Phase::EhloTls;
                    // EHLO again, from poll, with a fresh timer.
                    self.deadline = None;
                }
            }
            Input::Deliver(job) => {
                assert!(
                    self.job.is_none(),
                    "a client session carries one job at a time"
                );
                assert!(
                    !job.recipients.is_empty(),
                    "a job has a recipient to send to"
                );
                self.job = Some(Transaction::from(job));
                self.ready_reported = false;
            }
            Input::Quit => self.quit = true,
            Input::Lost => self.gone = true,
        }
    }

    fn poll(&mut self, now: Now, out: &mut Vec<Output<T>>) -> Option<Monotonic> {
        if self.is_closed() {
            return None;
        }
        if self.gone {
            self.lost(Failure::Lost, now.wall, out);
            return None;
        }
        if self.phase == Phase::EhloTls && self.deadline.is_none() {
            self.ehlo(now, out, Phase::EhloTls);
        }
        let input = mem::take(&mut self.input);
        let mut rest = &input[..];
        while !self.is_closed() {
            match self.reader.read(&mut rest) {
                Ok(Some(reply)) => self.on_reply(reply, now, out),
                Ok(None) => break,
                Err(_) => {
                    self.lost(Failure::Protocol, now.wall, out);
                    break;
                }
            }
            // Nothing may arrive between STARTTLS's reply and the
            // handshake: it would be read as if TLS protected it (RFC 3207,
            // 4.2).
            if self.phase == Phase::Handshake {
                if !rest.is_empty() {
                    self.fail(Outcome::NotSent(Failure::Protocol), now.wall, out);
                }
                break;
            }
        }
        if !self.is_closed() {
            self.input.extend_from_slice(rest);
        }
        if self.is_closed() {
            return None;
        }
        if self
            .deadline
            .is_some_and(|deadline| now.monotonic >= deadline)
        {
            self.lost(Failure::TimedOut, now.wall, out);
            return None;
        }
        if self.phase == Phase::Idle && self.job.is_some() {
            self.start(now, out);
        }
        if self.phase == Phase::Idle && self.job.is_none() {
            if self.quit {
                self.quit(now, out);
            } else if !self.ready_reported {
                self.ready_reported = true;
                out.push(Output::Ready);
            }
        }
        self.deadline
    }
}

/// What a refusal says for the recipients it covers.
fn refusal(reply: &Reply) -> Outcome {
    match reply.code / 100 {
        5 => Outcome::Rejected(reply.clone()),
        4 => Outcome::Deferred(reply.clone()),
        _ => Outcome::NotSent(Failure::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(require_tls: bool) -> Config {
        Config {
            helo: "out.test".to_owned(),
            require_tls,
            reply_timeout: Duration::from_secs(300),
            final_timeout: Duration::from_secs(600),
        }
    }

    fn at(seconds: u64) -> Now {
        Now {
            wall: engine_core::time::Timestamp::from_micros(seconds * 1_000_000),
            monotonic: Monotonic::from_micros(seconds * 1_000_000),
        }
    }

    fn job(content: &'static [u8]) -> Job<u32> {
        Job {
            sender: Some(Address::parse("s@a.test").unwrap()),
            recipients: vec![(7, Address::parse("r@b.test").unwrap())],
            header: Bytes::new(),
            content: Bytes::from_static(content),
        }
    }

    fn step(session: &mut Session<u32>, seconds: u64, input: Input<u32>) -> Vec<Output<u32>> {
        session.handle(at(seconds), input);
        let mut out = Vec::new();
        session.poll(at(seconds), &mut out);
        out
    }

    fn reply(session: &mut Session<u32>, wire: &str) -> Vec<Output<u32>> {
        step(session, 1, Input::Received(Bytes::from(wire.to_owned())))
    }

    fn sent(outputs: &[Output<u32>]) -> String {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Send(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
                Output::SendContent(bytes) => Some(format!("[{}]", String::from_utf8_lossy(bytes))),
                _ => None,
            })
            .collect()
    }

    /// A session through STARTTLS, ready for a job.
    fn ready(pipelining: bool) -> Session<u32> {
        let mut session = Session::new(config(true));
        assert_eq!(
            sent(&reply(&mut session, "220 mx.test ESMTP\r\n")),
            "EHLO out.test\r\n"
        );
        let extension = if pipelining { "250-PIPELINING\r\n" } else { "" };
        let out = reply(
            &mut session,
            &format!("250-mx.test\r\n{extension}250 STARTTLS\r\n"),
        );
        assert_eq!(sent(&out), "STARTTLS\r\n");
        assert_eq!(reply(&mut session, "220 2.0.0 go\r\n"), [Output::StartTls]);
        assert_eq!(
            sent(&step(&mut session, 1, Input::TlsStarted)),
            "EHLO out.test\r\n"
        );
        let out = reply(
            &mut session,
            &format!("250-mx.test\r\n{extension}250 SIZE 1000\r\n"),
        );
        assert_eq!(out, [Output::Ready]);
        session
    }

    #[test]
    fn a_pipelined_transaction_is_delivered() {
        let mut session = ready(true);
        let out = step(
            &mut session,
            2,
            Input::Deliver(job(b"Subject: x\r\n\r\nbody\r\n")),
        );
        assert_eq!(
            sent(&out),
            "MAIL FROM:<s@a.test>\r\nRCPT TO:<r@b.test>\r\nDATA\r\n"
        );
        let out = reply(&mut session, "250 ok\r\n250 ok\r\n354 go\r\n");
        assert_eq!(sent(&out), "[Subject: x\r\n\r\nbody\r\n].\r\n");
        let out = reply(&mut session, "250 2.0.0 queued\r\n");
        assert_eq!(
            out,
            [
                Output::Finished {
                    tag: 7,
                    outcome: Outcome::Delivered(Reply::new(250, "2.0.0 queued")),
                    at: at(1).wall,
                    own: false,
                },
                Output::Ready,
            ]
        );
        let out = step(&mut session, 3, Input::Quit);
        assert_eq!(sent(&out), "QUIT\r\n");
        assert_eq!(reply(&mut session, "221 bye\r\n"), [Output::Close]);
    }

    fn shared(recipients: &[(u32, &str)]) -> Job<u32> {
        Job {
            sender: Some(Address::parse("s@a.test").unwrap()),
            recipients: recipients
                .iter()
                .map(|&(tag, address)| (tag, Address::parse(address).unwrap()))
                .collect(),
            header: Bytes::new(),
            content: Bytes::from_static(b"Subject: x\r\n\r\nbody\r\n"),
        }
    }

    fn finished(outputs: &[Output<u32>]) -> Vec<(u32, Outcome)> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Finished { tag, outcome, .. } => Some((*tag, outcome.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn recipients_share_a_transaction_and_a_refusal_at_rcpt_is_theirs_alone() {
        let mut session = ready(true);
        let out = step(
            &mut session,
            2,
            Input::Deliver(shared(&[(1, "a@b.test"), (2, "c@b.test"), (3, "d@b.test")])),
        );
        assert_eq!(
            sent(&out),
            "MAIL FROM:<s@a.test>\r\nRCPT TO:<a@b.test>\r\nRCPT TO:<c@b.test>\r\nRCPT TO:<d@b.test>\r\nDATA\r\n"
        );
        let out = reply(
            &mut session,
            "250 ok\r\n250 ok\r\n550 5.1.1 no such user\r\n451 4.2.1 busy\r\n354 go\r\n",
        );
        assert_eq!(
            finished(&out),
            [
                (2, Outcome::Rejected(Reply::new(550, "5.1.1 no such user"))),
                (3, Outcome::Deferred(Reply::new(451, "4.2.1 busy"))),
            ]
        );
        assert_eq!(sent(&out), "[Subject: x\r\n\r\nbody\r\n].\r\n");
        // The content's reply speaks for the one recipient accepted.
        let out = reply(&mut session, "250 2.0.0 queued\r\n");
        assert_eq!(
            finished(&out),
            [(1, Outcome::Delivered(Reply::new(250, "2.0.0 queued")))]
        );
    }

    #[test]
    fn a_refusal_of_the_sender_is_no_recipients_own() {
        let mut session = ready(true);
        step(
            &mut session,
            2,
            Input::Deliver(shared(&[(1, "a@b.test"), (2, "c@b.test")])),
        );
        // The sender refused, in words that name an unknown user: it speaks
        // of neither recipient's address.
        let out = reply(
            &mut session,
            "550 5.1.1 sender verify failed\r\n250 ok\r\n250 ok\r\n554 no valid recipients\r\n",
        );
        let owns: Vec<(u32, bool)> = out
            .iter()
            .filter_map(|output| match output {
                Output::Finished { tag, own, .. } => Some((*tag, *own)),
                _ => None,
            })
            .collect();
        assert_eq!(owns, [(1, false), (2, false)]);

        // Refused after its content, in the same words, the one recipient
        // accepted: the reply is the transaction's, not its address's.
        assert_eq!(reply(&mut session, "250 ok\r\n"), [Output::Ready]);
        step(&mut session, 3, Input::Deliver(job(b"x\r\n")));
        reply(&mut session, "250 ok\r\n250 ok\r\n354 go\r\n");
        let out = reply(&mut session, "550 5.1.1 sender address rejected\r\n");
        assert!(
            matches!(out[0], Output::Finished { own: false, .. }),
            "{out:?}"
        );
    }

    #[test]
    fn a_pipelined_refusal_keeps_the_time_its_own_reply_came() {
        let mut session = ready(true);
        step(
            &mut session,
            2,
            Input::Deliver(shared(&[(1, "a@b.test"), (2, "c@b.test")])),
        );
        // MAIL's and the first RCPT's replies, then, later, the rest.
        assert!(finished(&reply(&mut session, "250 ok\r\n550 5.1.1 no such user\r\n")).is_empty());
        let out = step(
            &mut session,
            9,
            Input::Received(Bytes::from_static(b"250 ok\r\n354 go\r\n")),
        );
        let refused = out.iter().find_map(|output| match output {
            Output::Finished { tag: 1, at, .. } => Some(*at),
            _ => None,
        });
        assert_eq!(refused, Some(at(1).wall), "read at 1, reported at 9");
        let out = step(
            &mut session,
            12,
            Input::Received(Bytes::from_static(b"250 2.0.0 queued\r\n")),
        );
        assert!(matches!(
            out[0],
            Output::Finished { tag: 2, at, .. } if at == at_wall(12)
        ));
    }

    fn at_wall(seconds: u64) -> engine_core::time::Timestamp {
        at(seconds).wall
    }

    #[test]
    fn without_pipelining_a_transaction_with_no_recipient_accepted_sends_no_data() {
        let mut session = ready(false);
        let out = step(
            &mut session,
            2,
            Input::Deliver(shared(&[(1, "a@b.test"), (2, "c@b.test")])),
        );
        assert_eq!(sent(&out), "MAIL FROM:<s@a.test>\r\n");
        assert_eq!(
            sent(&reply(&mut session, "250 ok\r\n")),
            "RCPT TO:<a@b.test>\r\n"
        );
        // Each refusal is reported as its reply comes.
        let out = reply(&mut session, "550 5.1.1 no\r\n");
        assert_eq!(sent(&out), "RCPT TO:<c@b.test>\r\n");
        assert_eq!(finished(&out).len(), 1);
        let out = reply(&mut session, "550 5.1.1 no\r\n");
        assert_eq!(finished(&out).len(), 1);
        assert_eq!(sent(&out), "RSET\r\n");
    }

    #[test]
    fn a_lost_connection_ends_every_recipient_of_the_transaction() {
        let mut session = ready(true);
        step(
            &mut session,
            2,
            Input::Deliver(shared(&[(1, "a@b.test"), (2, "c@b.test")])),
        );
        reply(&mut session, "250 ok\r\n250 ok\r\n250 ok\r\n354 go\r\n");
        // After the final dot, a lost reply leaves both uncertain.
        let out = step(&mut session, 3, Input::Lost);
        assert_eq!(
            finished(&out),
            [(1, Outcome::Uncertain), (2, Outcome::Uncertain)]
        );
    }

    #[test]
    fn without_pipelining_each_command_waits_for_its_reply() {
        let mut session = ready(false);
        assert_eq!(
            sent(&step(&mut session, 2, Input::Deliver(job(b"x\r\n")))),
            "MAIL FROM:<s@a.test>\r\n"
        );
        assert_eq!(
            sent(&reply(&mut session, "250 ok\r\n")),
            "RCPT TO:<r@b.test>\r\n"
        );
        assert_eq!(sent(&reply(&mut session, "250 ok\r\n")), "DATA\r\n");
        assert_eq!(sent(&reply(&mut session, "354 go\r\n")), "[x\r\n].\r\n");
    }

    #[test]
    fn refusals_are_rejections_or_deferrals_and_reset_the_transaction() {
        let mut session = ready(true);
        step(&mut session, 2, Input::Deliver(job(b"x\r\n")));
        let out = reply(
            &mut session,
            "250 ok\r\n550 5.1.1 no such user\r\n554 5.5.1 no recipients\r\n",
        );
        assert_eq!(
            out[0],
            Output::Finished {
                tag: 7,
                outcome: Outcome::Rejected(Reply::new(550, "5.1.1 no such user")),
                at: at(1).wall,
                own: true,
            }
        );
        assert_eq!(sent(&out), "RSET\r\n");
        assert_eq!(reply(&mut session, "250 ok\r\n"), [Output::Ready]);

        // A server that takes DATA though it took no recipient gets an empty
        // message, and its answer to that speaks for no one.
        step(&mut session, 2, Input::Deliver(job(b"x\r\n")));
        let out = reply(
            &mut session,
            "250 ok\r\n550 5.1.1 no such user\r\n354 go\r\n",
        );
        assert!(matches!(
            out[0],
            Output::Finished {
                outcome: Outcome::Rejected(_),
                ..
            }
        ));
        assert_eq!(sent(&out), ".\r\n");
        assert_eq!(
            reply(&mut session, "554 5.5.1 no valid recipients\r\n"),
            [Output::Ready]
        );

        step(&mut session, 2, Input::Deliver(job(b"x\r\n")));
        reply(&mut session, "250 ok\r\n250 ok\r\n354 go\r\n");
        let out = reply(&mut session, "451 4.3.0 try later\r\n");
        assert_eq!(
            out[0],
            Output::Finished {
                tag: 7,
                outcome: Outcome::Deferred(Reply::new(451, "4.3.0 try later")),
                at: at(1).wall,
                own: false,
            }
        );
    }

    #[test]
    fn a_lost_final_reply_is_uncertain_and_a_lost_envelope_is_not_sent() {
        let mut session = ready(true);
        step(&mut session, 2, Input::Deliver(job(b"x\r\n")));
        reply(&mut session, "250 ok\r\n250 ok\r\n354 go\r\n");
        assert_eq!(
            step(&mut session, 3, Input::Lost),
            [
                Output::Finished {
                    tag: 7,
                    outcome: Outcome::Uncertain,
                    at: at(3).wall,
                    own: false,
                },
                Output::Close
            ]
        );

        let mut session = ready(true);
        step(&mut session, 2, Input::Deliver(job(b"x\r\n")));
        reply(&mut session, "250 ok\r\n");
        assert_eq!(
            step(&mut session, 3, Input::Lost),
            [
                Output::Finished {
                    tag: 7,
                    outcome: Outcome::NotSent(Failure::Lost),
                    at: at(3).wall,
                    own: false,
                },
                Output::Close
            ]
        );
    }

    #[test]
    fn a_silent_server_times_out() {
        let mut session = ready(true);
        step(&mut session, 2, Input::Deliver(job(b"x\r\n")));
        reply(&mut session, "250 ok\r\n250 ok\r\n354 go\r\n");
        let mut out = Vec::new();
        assert_eq!(
            session.poll(at(600), &mut out),
            Some(Monotonic::from_micros(601_000_000))
        );
        session.poll(at(601), &mut out);
        assert_eq!(
            out,
            [
                Output::Finished {
                    tag: 7,
                    outcome: Outcome::Uncertain,
                    at: at(601).wall,
                    own: false,
                },
                Output::Close
            ]
        );
    }

    #[test]
    fn tls_is_required_and_cannot_be_preempted() {
        let mut session = Session::new(config(true));
        session.handle(at(0), Input::Deliver(job(b"x\r\n")));
        reply(&mut session, "220 mx.test\r\n");
        let out = reply(&mut session, "250-mx.test\r\n250 PIPELINING\r\n");
        assert_eq!(
            out,
            [
                Output::Finished {
                    tag: 7,
                    outcome: Outcome::NotSent(Failure::NoTls),
                    at: at(1).wall,
                    own: false,
                },
                Output::Close
            ]
        );
        assert_eq!(
            session.unready(),
            Some(&Failure::NoTls),
            "it ended before it was ready, which another exchange may help"
        );

        let mut session = Session::new(config(true));
        reply(&mut session, "220 mx.test\r\n");
        reply(&mut session, "250-mx.test\r\n250 STARTTLS\r\n");
        let out = reply(&mut session, "220 go\r\n250 injected\r\n");
        assert_eq!(out, [Output::StartTls, Output::Close]);

        let mut session = Session::new(config(true));
        session.handle(at(0), Input::Deliver(job(b"x\r\n")));
        let out = reply(&mut session, "554 5.7.1 go away\r\n");
        assert_eq!(
            out,
            [
                Output::Finished {
                    tag: 7,
                    outcome: Outcome::NotSent(Failure::Refused(Reply::new(554, "5.7.1 go away"))),
                    at: at(1).wall,
                    own: false,
                },
                Output::Close,
            ]
        );
    }

    #[test]
    fn a_421_marks_the_receiver_throttled_wherever_it_comes() {
        let mut session = Session::<u32>::new(config(true));
        reply(&mut session, "421 4.7.0 too many connections\r\n");
        assert!(session.throttled() && session.is_closed());
        // No attempt carries a refusal of the session itself: it is kept
        // for the driver to judge.
        assert_eq!(
            session.refusal(),
            Some(&Reply::new(421, "4.7.0 too many connections"))
        );
        let mut session = Session::<u32>::new(config(true));
        reply(&mut session, "554 5.7.1 your address is blocked\r\n");
        assert_eq!(session.refusal().map(|reply| reply.code), Some(554));

        let mut session = ready(true);
        step(&mut session, 2, Input::Deliver(job(b"x\r\n")));
        let out = reply(&mut session, "421 4.7.0 rate limited\r\n");
        let Output::Finished { outcome, .. } = &out[0] else {
            panic!("{out:?}");
        };
        assert!(outcome.throttled() && session.throttled());
        assert_eq!(session.refusal(), None, "the attempt carries it");

        let mut session = ready(true);
        step(&mut session, 2, Input::Deliver(job(b"x\r\n")));
        let out = reply(
            &mut session,
            "250 ok\r\n451 4.2.1 mailbox busy\r\n554 5.5.1 no recipients\r\n",
        );
        let Output::Finished { outcome, .. } = &out[0] else {
            panic!("{out:?}");
        };
        assert!(!outcome.throttled() && !session.throttled());
    }

    #[test]
    fn content_is_dot_stuffed_only_when_it_must_be() {
        let mut session = ready(true);
        step(
            &mut session,
            2,
            Input::Deliver(job(b".a\r\nb\r\n..c\r\nend")),
        );
        let out = reply(&mut session, "250 ok\r\n250 ok\r\n354 go\r\n");
        assert_eq!(sent(&out), "..a\r\nb\r\n...c\r\nend\r\n.\r\n");
    }

    #[test]
    fn its_header_goes_ahead_of_the_content_without_a_copy_of_either() {
        let mut session = ready(true);
        let mut with_header = job(b"Subject: x\r\n\r\nbody\r\n");
        with_header.header = Bytes::from_static(b"X-Token: t\r\n");
        step(&mut session, 2, Input::Deliver(with_header));
        let out = reply(&mut session, "250 ok\r\n250 ok\r\n354 go\r\n");
        assert!(matches!(
            out.as_slice(),
            [
                Output::SendContent(_),
                Output::SendContent(_),
                Output::Send(_)
            ]
        ));
        assert_eq!(
            sent(&out),
            "[X-Token: t\r\n][Subject: x\r\n\r\nbody\r\n].\r\n"
        );
    }
    #[test]
    fn eight_bit_content_needs_the_receivers_capability_and_never_loses_its_bytes() {
        let content = b"Subject: x\r\n\r\ncaf\xc3\xa9\r\n";
        let mut without = ready(true);
        let out = step(&mut without, 2, Input::Deliver(job(content)));
        assert!(matches!(
            out.as_slice(),
            [
                Output::Finished {
                    outcome: Outcome::NoEightBitMime,
                    own: false,
                    ..
                },
                Output::Ready
            ]
        ));
        assert!(without.is_idle());
        assert_eq!(sent(&out), "", "no MAIL or DATA is sent");
        // The same connection can immediately carry ordinary 7-bit mail.
        let out = step(&mut without, 3, Input::Deliver(job(b"ascii\r\n")));
        assert!(sent(&out).starts_with("MAIL FROM:<s@a.test>\r\n"));

        let mut session = Session::new(config(false));
        reply(&mut session, "220 mx.test ESMTP\r\n");
        reply(
            &mut session,
            "250-mx.test\r\n250-PIPELINING\r\n250 8bitmime\r\n",
        );
        let input = job(content);
        let shared = input.content.clone();
        let out = step(&mut session, 2, Input::Deliver(input));
        assert!(sent(&out).starts_with("MAIL FROM:<s@a.test> BODY=8BITMIME\r\n"));
        let out = reply(&mut session, "250 ok\r\n250 ok\r\n354 go\r\n");
        assert!(
            matches!(&out[0], Output::SendContent(bytes) if bytes.as_ptr() == shared.as_ptr() && bytes == &shared)
        );
    }

    #[test]
    fn eight_bit_mime_is_negotiated_again_after_starttls() {
        let mut session = Session::new(config(true));
        reply(&mut session, "220 mx.test ESMTP\r\n");
        reply(
            &mut session,
            "250-mx.test\r\n250-8BITMIME\r\n250 STARTTLS\r\n",
        );
        reply(&mut session, "220 go\r\n");
        step(&mut session, 1, Input::TlsStarted);
        reply(&mut session, "250-mx.test\r\n250 PIPELINING\r\n");
        let out = step(&mut session, 2, Input::Deliver(job(b"\xff\r\n")));
        assert!(matches!(
            &out[0],
            Output::Finished {
                outcome: Outcome::NoEightBitMime,
                ..
            }
        ));
        assert_eq!(sent(&out), "");
    }
}
