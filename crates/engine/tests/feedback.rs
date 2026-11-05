//! Feedback trust through the release binary: a complaint
//! counts only from the class of evidence the operator trusts. Trusting
//! only authenticated reports, an unsigned complaint is recorded and
//! suppresses nothing, as is one signed by a domain the operator never
//! enrolled; the same complaint signed by an enrolled reporter, after its
//! unsigned copy, suppresses its recipient.

mod support;

use std::io::{BufRead as _, BufReader, Write as _};

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use engine_message::dkim::Signer;
use serde_json::{Value, json};
use support::{Dns, Engine, Receiver, Script, wait_for};

const SES: &str = "[ses]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nregion = \"us-east-1\"";

/// A signer for `domain` at selector `s1`, and its DKIM record.
fn signer(domain: &str) -> (Signer, String) {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let der = STANDARD.encode(AsDer::<Pkcs8V1Der>::as_der(&pair).unwrap().as_ref());
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{der}\n-----END PRIVATE KEY-----\n");
    let signer =
        Signer::from_pem(&pem, domain, "s1", &["From", "Message-ID", "Content-Type"]).unwrap();
    let record = format!("v=DKIM1; k=rsa; p={}", signer.public_key());
    (signer, record)
}

/// A complaint of abuse about the message sent with `return_path`, by
/// `reporter`, under its own `id`.
fn complaint(reporter: &str, id: &str, return_path: &str) -> (String, String) {
    let header = format!(
        "From: <fbl@{reporter}>\r\n\
Message-ID: <{id}@{reporter}>\r\n\
Content-Type: multipart/report; report-type=feedback-report; boundary=b\r\n"
    );
    let body = format!(
        "--b\r\n\
Content-Type: message/feedback-report\r\n\
\r\n\
Feedback-Type: abuse\r\n\
Original-Mail-From: <{return_path}>\r\n\
Original-Rcpt-To: <one@plain.test>\r\n\
\r\n\
--b--\r\n"
    );
    (header, body)
}

/// Sends `content` to the feedback listener at `port` for `to`, and
/// returns the reply to its end.
fn report(port: u16, to: &str, content: &str) -> String {
    let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("it connects");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("a read timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("a clone"));
    let mut writer = stream;
    let mut reply = || {
        let mut whole = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("a reply");
            whole.push_str(&line);
            if line.as_bytes().get(3) != Some(&b'-') {
                return whole;
            }
        }
    };
    reply();
    for line in [
        "EHLO reporter.test".to_owned(),
        "MAIL FROM:<>".to_owned(),
        format!("RCPT TO:<{to}>"),
        "DATA".to_owned(),
    ] {
        write!(writer, "{line}\r\n").expect("written");
        let answer = reply();
        assert!(
            answer.starts_with('2') || answer.starts_with('3'),
            "{line}: {answer}"
        );
    }
    write!(writer, "{content}.\r\n").expect("written");
    let answer = reply();
    write!(writer, "QUIT\r\n").expect("written");
    answer
}

#[test]
fn only_an_enrolled_reporters_signed_complaint_suppresses_when_only_those_are_trusted() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!(
        "{SES}\n\n[capture]\ndirectory = \"capture\"\n\n[feedback]\nlisten = \"127.0.0.1:0\"\nhostname = \"mx.bounces.test\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nloops = [\"fbl@mx.bounces.test\"]\nreporters = [\"reporter.test\"]\ntrusted = \"authenticated\""
    );
    let mut engine = Engine::start("trust", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses_permitted(&["send", "manage"]);
    let feedback = engine
        .listening("taking bounce and complaint reports")
        .expect("a feedback listener");
    let answers =
        engine.admin(&[json!({"op": "put_identity", "account": 1, "name": "brand.test"})]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let body = json!({
        "FromEmailAddress": "news@brand.test",
        "Destination": {"ToAddresses": ["one@plain.test"]},
        "Content": {"Simple": {"Subject": {"Data": "a test"}, "Body": {"Text": {"Data": "hello"}}}},
    });
    let sent = ses.send("POST", "/v2/email/outbound-emails", "", &body.to_string());
    assert_eq!(sent.status, 200, "{}", sent.body);
    let directory = engine.dir.join("capture");
    let return_path = || -> Option<String> {
        std::fs::read_dir(&directory)
            .ok()?
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
            .find_map(|entry| {
                let envelope: Value =
                    serde_json::from_slice(&std::fs::read(entry.path()).ok()?).ok()?;
                envelope["from"].as_str().map(str::to_owned)
            })
    };
    wait_for("its capture", || return_path().is_some());
    let return_path = return_path().unwrap();
    let suppressed = || {
        ses.send(
            "GET",
            "/v2/email/suppression/addresses/one%40plain.test",
            "",
            "",
        )
        .status
            == 200
    };

    // Unsigned: recorded, and nothing more.
    let (header, body) = complaint("reporter.test", "unsigned", &return_path);
    let taken = report(
        feedback,
        "fbl@mx.bounces.test",
        &format!("{header}\r\n{body}"),
    );
    assert!(taken.starts_with("250"), "{taken}");
    assert!(!suppressed());

    // Signed by a domain never enrolled: the same.
    let (stranger, stranger_record) = signer("stranger.test");
    dns.txt("s1._domainkey.stranger.test", &stranger_record);
    let (header, body) = complaint("stranger.test", "stranger", &return_path);
    let signature =
        String::from_utf8(stranger.sign(header.as_bytes(), body.as_bytes()).unwrap()).unwrap();
    let taken = report(
        feedback,
        "fbl@mx.bounces.test",
        &format!("{signature}{header}\r\n{body}"),
    );
    assert!(taken.starts_with("250"), "{taken}");
    assert!(!suppressed());

    // The same complaint, signed by the enrolled reporter: its recipient is
    // suppressed, though its unsigned copy came first.
    let (enrolled, record) = signer("reporter.test");
    dns.txt("s1._domainkey.reporter.test", &record);
    let (header, body) = complaint("reporter.test", "unsigned", &return_path);
    let signature =
        String::from_utf8(enrolled.sign(header.as_bytes(), body.as_bytes()).unwrap()).unwrap();
    let taken = report(
        feedback,
        "fbl@mx.bounces.test",
        &format!("{signature}{header}\r\n{body}"),
    );
    assert!(taken.starts_with("250"), "{taken}");
    assert!(suppressed(), "an enrolled reporter's complaint suppresses");
    let got = ses
        .send(
            "GET",
            "/v2/email/suppression/addresses/one%40plain.test",
            "",
            "",
        )
        .json();
    assert_eq!(got["SuppressedDestination"]["Reason"], "COMPLAINT", "{got}");
}

/// A complaint as Microsoft's loop has sent one since June 2026: no return
/// path, no recipient, and whatever looks like an address replaced, with
/// `kept` among the fields of the copy it carries.
fn redacted(id: &str, kept: &str) -> String {
    format!(
        "From: <X>\r\n\
Message-ID: <{id}@jmrp.protection.outlook.com>\r\n\
Auto-Submitted: auto-generated\r\n\
Content-Type: multipart/report; report-type=feedback-report; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: message/feedback-report\r\n\
\r\n\
Feedback-Type: abuse\r\n\
User-Agent: JMRP/1.0\r\n\
Version: 1\r\n\
\r\n\
--b\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
{kept}From: news@brand.test\r\n\
To: Undisclosed Recipients <X>\r\n\
Subject: a test\r\n\
\r\n\
--b--\r\n"
    )
}

#[test]
fn a_redacted_complaint_finds_its_mail_by_the_header_it_kept() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!(
        "{SES}\n\n[capture]\ndirectory = \"capture\"\n\n[feedback]\nlisten = \"127.0.0.1:0\"\nhostname = \"mx.bounces.test\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nloops = [\"fbl@mx.bounces.test\"]\n\n[operator]\nlisten = \"127.0.0.1:0\""
    );
    let mut engine = Engine::start("redacted", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses_permitted(&["send", "manage"]);
    let feedback = engine
        .listening("taking bounce and complaint reports")
        .expect("a feedback listener");
    let answers =
        engine.admin(&[json!({"op": "put_identity", "account": 1, "name": "brand.test"})]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let body = json!({
        "FromEmailAddress": "news@brand.test",
        "Destination": {"ToAddresses": ["one@plain.test"]},
        "Content": {"Simple": {"Subject": {"Data": "a test"}, "Body": {"Text": {"Data": "hello"}}}},
    });
    let sent = ses.send("POST", "/v2/email/outbound-emails", "", &body.to_string());
    assert_eq!(sent.status, 200, "{}", sent.body);
    // The field as it went out: the return path's token, ahead of the rest.
    let directory = engine.dir.join("capture");
    let captured = |extension: &str| -> Option<String> {
        std::fs::read_dir(&directory)
            .ok()?
            .flatten()
            .find(|entry| entry.file_name().to_string_lossy().ends_with(extension))
            .and_then(|entry| std::fs::read_to_string(entry.path()).ok())
    };
    wait_for("its capture", || captured(".json").is_some());
    let envelope: Value = serde_json::from_str(&captured(".json").unwrap()).unwrap();
    let (token, _) = envelope["from"].as_str().unwrap().split_once('@').unwrap();
    let kept = format!("X-NitroMTA-Report: {token}\r\n");
    assert!(captured(".eml").unwrap().starts_with(&kept));

    let suppressed = || {
        ses.send(
            "GET",
            "/v2/email/suppression/addresses/one%40plain.test",
            "",
            "",
        )
        .status
            == 200
    };
    let unmatched = || {
        engine
            .operator("/metrics")
            .1
            .contains("nitromta_reports_unmatched_total 1")
    };
    // Without the field nothing names its message: recorded, and counted as
    // finding no mail, whatever the listener answers.
    let taken = report(feedback, "fbl@mx.bounces.test", &redacted("stripped", ""));
    assert!(taken.starts_with("250"), "{taken}");
    assert!(!suppressed());
    assert!(unmatched());
    // With it, its recipient is suppressed, and it is not counted so.
    let taken = report(feedback, "fbl@mx.bounces.test", &redacted("kept", &kept));
    assert!(taken.starts_with("250"), "{taken}");
    assert!(suppressed(), "the field names its message");
    assert!(unmatched(), "still only the first");
}
