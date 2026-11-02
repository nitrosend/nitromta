//! A fuzz target for every parser: provider decoding, MIME and
//! substitution, SMTP both ways, DSN and ARF, MTA-STS, receiver replies and
//! the store's records. Each takes any bytes and must neither panic nor
//! hang, whatever they are. `fuzz_targets` runs each under libFuzzer, from
//! its corpus, through `cargo xtask fuzz`; `tests/corpus.rs` runs every
//! input each corpus keeps through its target in every check.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::component::Component;
use engine_core::id::{AccountId, DeliveryId, EgressId, Id, MessageId};
use engine_core::time::{Monotonic, Now, Timestamp};
use engine_store::keys::{Keyring, Keys};
use engine_store::records;

/// When every target runs.
const NOW: Now = Now {
    wall: Timestamp::from_micros(1_800_000_000_000_000),
    monotonic: Monotonic::from_micros(0),
};

/// A target: any bytes, given to a parser.
pub type Target = fn(&[u8]);

/// The targets, by name, as `fuzz_targets` and the corpus name them.
pub const TARGETS: &[(&str, Target)] = &[
    ("provider", provider),
    ("mime", mime),
    ("template", template),
    ("smtp_server", smtp_server),
    ("smtp_client", smtp_client),
    ("feedback", feedback),
    ("sts", sts),
    ("replies", replies),
    ("records", records),
];

/// `data` cut at its first `N - 1` NUL bytes into `N` fields, the last
/// holding the rest; those it runs out before are empty.
fn fields<const N: usize>(data: &[u8]) -> [&[u8]; N] {
    let mut fields = [&[][..]; N];
    let mut rest = data;
    for field in fields.iter_mut().take(N - 1) {
        let (head, tail) = match rest.iter().position(|byte| *byte == 0) {
            Some(at) => (&rest[..at], &rest[at + 1..]),
            None => (rest, &[][..]),
        };
        *field = head;
        rest = tail;
    }
    fields[N - 1] = rest;
    fields
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or_default()
}

/// A request's signature, its listing's query, and an SNS form: what the
/// SES and SNS listeners decode before anything else.
pub fn provider(data: &[u8]) {
    let [method, path, query, headers, body] = fields::<5>(data);
    let headers: Vec<(&str, &[u8])> = headers
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let at = line.iter().position(|byte| *byte == b':')?;
            Some((
                std::str::from_utf8(&line[..at]).ok()?,
                line[at + 1..].trim_ascii(),
            ))
        })
        .collect();
    let request = engine_api::sigv4::Request {
        method: text(method),
        path: text(path),
        query: text(query),
        headers: &headers,
        body,
    };
    let scope = engine_api::sigv4::Scope {
        region: "us-east-1",
        service: "ses",
    };
    let _ = engine_api::sigv4::verify(&request, &scope, NOW.wall, |_| Some("secret"));
    let _ = engine_api::ses::older_listing(text(method), text(path), text(query));
    let form = engine_api::sns::Request::parse(body);
    let _ = (form.action(), form.account());
}

/// A submitted message checked as preparation checks it, and its address
/// fields read.
pub fn mime(data: &[u8]) {
    let limits = engine_message::prepare::Limits { max_bytes: 1 << 20 };
    if let Ok(checked) = engine_message::prepare::check(data, limits) {
        let _ = checked.from();
    }
    let _ = engine_message::prepare::mailbox(data);
    let _ = engine_message::prepare::mailboxes(data);
}

/// A bulk template rendered with its default data and an entry's own.
pub fn template(data: &[u8]) {
    let [template, default, entry] = fields::<3>(data);
    let (default, entry) = (text(default), text(entry));
    if let Ok(data) = engine_api::template::data(
        (!default.is_empty()).then_some(default),
        (!entry.is_empty()).then_some(entry),
    ) {
        let _ = engine_api::template::render(text(template), &data, 1 << 16);
    }
}

/// A client's commands, in pieces the first byte sizes, to a submission
/// server and to a feedback receiver, each answered as a driver would.
pub fn smtp_server(data: &[u8]) {
    use engine_smtp::reply::Reply;
    use engine_smtp::server::{Config, Input, Output, Role, Session};

    let Some((size, data)) = data.split_first() else {
        return;
    };
    for role in [Role::Submission, Role::Receiver] {
        let mut session = Session::new(Arc::new(Config {
            role,
            hostname: "fuzz.test".to_owned(),
            max_message_bytes: 1 << 16,
            max_recipients: 8,
            idle: Duration::from_secs(300),
        }));
        let mut out = Vec::new();
        let mut drive = |session: &mut Session| loop {
            out.clear();
            session.poll(NOW, &mut out);
            let mut answered = false;
            for output in out.drain(..) {
                let input = match output {
                    Output::StartTls => Input::TlsStarted,
                    Output::Authenticate { .. } => Input::Authenticated(true),
                    Output::Recipient => Input::Recipient(Ok(())),
                    Output::Submit(_) => Input::Answered(Reply::new(250, "2.0.0 Ok")),
                    Output::Send(_) | Output::Close => continue,
                };
                session.handle(NOW, input);
                answered = true;
            }
            if !answered {
                break;
            }
        };
        drive(&mut session);
        for piece in data.chunks(usize::from(*size).max(1)) {
            session.handle(NOW, Input::Received(Bytes::copy_from_slice(piece)));
            drive(&mut session);
        }
    }
}

/// A receiver's replies, in pieces the first byte sizes, to a client
/// delivering one message to two recipients.
pub fn smtp_client(data: &[u8]) {
    use engine_smtp::client::{Config, Input, Job, Output, Session};

    let Some((size, data)) = data.split_first() else {
        return;
    };
    let address = |text: &str| Address::parse(text).expect("an address");
    for require_tls in [false, true] {
        let mut session = Session::new(Config {
            helo: "fuzz.test".to_owned(),
            require_tls,
            reply_timeout: Duration::from_secs(300),
            final_timeout: Duration::from_secs(600),
        });
        session.handle(
            NOW,
            Input::Deliver(Job {
                sender: Some(address("app@sender.test")),
                recipients: vec![
                    (0_u8, address("one@fuzz.test")),
                    (1, address("two@fuzz.test")),
                ],
                content: Bytes::from_static(b"Subject: a test\r\n\r\nhello\r\n"),
            }),
        );
        let mut out = Vec::new();
        let mut drive = |session: &mut Session<u8>| loop {
            out.clear();
            session.poll(NOW, &mut out);
            let started = out.iter().any(|output| matches!(output, Output::StartTls));
            if !started {
                break;
            }
            session.handle(NOW, Input::TlsStarted);
        };
        drive(&mut session);
        for piece in data.chunks(usize::from(*size).max(1)) {
            session.handle(NOW, Input::Received(Bytes::copy_from_slice(piece)));
            drive(&mut session);
        }
        session.handle(NOW, Input::Lost);
        drive(&mut session);
    }
}

/// A report as the feedback receiver reads it, its MIME parts, and the
/// return path's correlation token.
pub fn feedback(data: &[u8]) {
    let _ = engine_feedback::report::read(data);
    let _ = engine_feedback::mime::parts(data, "boundary");
    let key = engine_feedback::token::Key::new(b"a correlation key for fuzzing it");
    let _ = engine_feedback::token::message(&key, text(data));
}

/// A domain's `_mta-sts` records, a line each, and its policy file.
pub fn sts(data: &[u8]) {
    let [records, policy] = fields::<2>(data);
    let records: Vec<String> = text(records).lines().map(str::to_owned).collect();
    let _ = engine_smtp::sts::record(&records);
    let _ = engine_smtp::sts::parse("fuzz.test", "1", text(policy), NOW.wall);
}

/// A receiver's reply, its code from the first two bytes, judged by the
/// shipped rules at a site their exchanges name.
pub fn replies(data: &[u8]) {
    static RULES: OnceLock<engine_rules::Rules> = OnceLock::new();
    let rules = RULES.get_or_init(|| engine_rules::Rules::new(&BTreeMap::new()).expect("shipped"));
    let [exchanges, reply] = fields::<2>(data);
    let exchanges: Vec<String> = text(exchanges).lines().map(str::to_owned).collect();
    let site = rules.site(&exchanges);
    let (code, reply) = match reply {
        [high, low, rest @ ..] => (u16::from_be_bytes([*high, *low]), rest),
        _ => (550, reply),
    };
    let _ = site.judged(code, text(reply));
}

/// A record as the store reads it back, by the first byte's kind, with
/// the installation's keys or without.
pub fn records(data: &[u8]) {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    let keys =
        KEYS.get_or_init(|| Keys::new(Arc::new(Keyring::new(&[(1, [7; 32])]).expect("a key"))));
    let Some((kind, record)) = data.split_first() else {
        return;
    };
    let id = Id::from_u64(1 << 40).expect("an ID");
    let keys = (kind & 0x80 != 0).then_some(keys);
    match kind & 0x0f {
        0 => drop(records::decode_mail(record, MessageId(id), keys)),
        1 => drop(records::decode_message(MessageId(id), record)),
        2 => drop(records::decode_delivery(DeliveryId(id), record, keys)),
        3 => drop(records::decode_cooldown(
            Some(EgressId(id)),
            Arc::from("fuzz.test"),
            NOW.wall,
            record,
            keys,
        )),
        4 => drop(records::decode_sts("fuzz.test", NOW.wall, record)),
        5 => drop(records::decode_dispatched(record)),
        6 => drop(records::decode_suppression(
            record,
            AccountId(id),
            b"one@fuzz.test",
            keys,
        )),
        7 => drop(records::decode_topics(Some(record))),
        8 => drop(records::decode_entry(record, keys)),
        _ => {
            let keyring = Keyring::new(&[(1, [7; 32])]).expect("a key");
            drop(records::decode_policy(id, record, &keyring));
        }
    }
}
