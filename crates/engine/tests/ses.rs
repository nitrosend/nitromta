//! The SES v2 API through the release binary: each
//! operation as an SDK calls it, signed as an SDK signs it.

mod support;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use support::{Dns, Engine, Receiver, Script, wait_for};

/// The API's listener, beside submission.
const SES: &str = "[ses]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nregion = \"us-east-1\"";

#[test]
fn what_a_client_holds_before_it_is_verified_is_bounded() {
    use std::io::{Read as _, Write as _};
    use std::time::{Duration, Instant};

    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let mut engine = Engine::start("ses-bounded", &dns, &receiver, "dane = false", SES);
    let ses = engine.ses();
    // Requests that say they come to as much as a request may, their
    // bodies yet to come: four fit what the engine holds of bodies not
    // yet verified, and the fifth is refused at once, to be tried again.
    let most = 40_000_000usize.div_ceil(3) * 4 + (1 << 20);
    let mut open: Vec<_> = (0..5)
        .map(|_| {
            let mut tls = ses.open();
            write!(
                tls,
                "POST /v2/email/outbound-emails HTTP/1.1\r\nHost: localhost\r\nContent-Length: {most}\r\n\r\n"
            )
            .expect("written");
            tls.flush().expect("flushed");
            tls
        })
        .collect();
    let mut answered = Vec::new();
    for tls in &mut open {
        tls.sock
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("a timeout");
        let mut answer = [0; 512];
        if let Ok(read) = tls.read(&mut answer) {
            answered.push(String::from_utf8_lossy(&answer[..read]).into_owned());
        }
    }
    assert_eq!(answered.len(), 1, "{answered:?}");
    assert!(answered[0].starts_with("HTTP/1.1 429"), "{}", answered[0]);
    assert!(
        answered[0].contains("TooManyRequestsException"),
        "{}",
        answered[0]
    );
    // A request with no body, its length never given, holds nothing, so it
    // is answered meanwhile: here refused its signature, which it lacks.
    let mut bodiless = ses.open();
    bodiless
        .write_all(
            b"GET /v2/email/account HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .expect("written");
    let mut answer = Vec::new();
    let _ = bodiless.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    drop(open);
    // A connection that never starts its handshake is closed once its
    // deadline passes.
    let mut silent =
        std::net::TcpStream::connect(("127.0.0.1", ses.port)).expect("the API connects");
    silent
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a timeout");
    let started = Instant::now();
    assert_eq!(silent.read(&mut [0; 1]).expect("closed, not timed out"), 0);
    let waited = started.elapsed();
    assert!(
        (Duration::from_secs(9)..Duration::from_secs(20)).contains(&waited),
        "{waited:?}"
    );
}

#[test]
fn an_operation_the_engine_does_not_implement_is_refused_for_good() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let mut engine = Engine::start("ses", &dns, &receiver, "dane = false", SES);
    let ses = engine.ses_permitted(&["send", "manage"]);
    // ListContactLists, which it does not implement: a modeled error SDKs neither
    // retry nor take for success, naming what was asked.
    let refused = ses.send("GET", "/v2/email/contact-lists", "", "");
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(
        refused.header("x-amzn-errortype"),
        Some("BadRequestException")
    );
    assert!(
        refused
            .body
            .contains("does not implement this SES v2 operation (GET /v2/email/contact-lists)"),
        "{}",
        refused.body
    );
    // SendEmail, which it does.
    let body = serde_json::json!({
        "FromEmailAddress": "app@sender.test",
        "Destination": {"ToAddresses": ["one@plain.test"]},
        "Content": {"Simple": {"Subject": {"Data": "a test"}, "Body": {"Text": {"Data": "hello"}}}},
    });
    let sent = ses.send("POST", "/v2/email/outbound-emails", "", &body.to_string());
    assert_eq!(sent.status, 200, "{}", sent.body);
    assert!(sent.json()["MessageId"].is_string(), "{}", sent.body);
    // Each answer names its request, as SES's do, a UUID of its own.
    let ids: Vec<&str> = [&refused, &sent]
        .iter()
        .filter_map(|answer| answer.header("x-amzn-requestid"))
        .collect();
    assert!(
        ids.len() == 2
            && ids[0] != ids[1]
            && ids
                .iter()
                .all(|id| id.len() == 36 && id.as_bytes()[14] == b'4'),
        "{ids:?}"
    );
}

#[test]
fn a_raw_message_without_a_destination_goes_to_its_own_recipients_and_ses_fields_are_honoured_and_taken_out()
 {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let sections = format!("{SES}\n\n[capture]\ndirectory = \"capture\"");
    let mut engine = Engine::start("ses-raw", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses();
    let answers = engine.admin(&[serde_json::json!({
        "op": "put_configuration", "account": 1, "name": "receipts"
    })]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let message = |configuration: &str| {
        format!(
            "X-SES-CONFIGURATION-SET: {configuration}\r\nX-SES-MESSAGE-TAGS: campaign=autumn\r\nFrom: app@sender.test\r\nTo: \"One\" <one@plain.test>\r\nCc: Team: two@plain.test;\r\nBcc: three@plain.test\r\nSubject: a test\r\n\r\nhello\r\n"
        )
    };
    let send = |raw: String| {
        let body = serde_json::json!({"Content": {"Raw": {"Data": STANDARD.encode(raw)}}});
        ses.send("POST", "/v2/email/outbound-emails", "", &body.to_string())
    };
    // The configuration set the field names is the one sent under: one
    // that does not exist is refused, as the request's own would be.
    let refused = send(message("nowhere"));
    assert_eq!(refused.status, 404, "{}", refused.body);
    let sent = send(message("receipts"));
    assert_eq!(sent.status, 200, "{}", sent.body);
    // Captured: sent to every address its fields name, without its Bcc
    // field or SES's own.
    let directory = engine.dir.join("capture");
    let envelopes = || -> Vec<serde_json::Value> {
        std::fs::read_dir(&directory)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
                    .filter_map(|entry| {
                        serde_json::from_slice(&std::fs::read(entry.path()).ok()?).ok()
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    wait_for("its capture", || {
        envelopes()
            .iter()
            .map(|envelope| envelope["to"].as_array().map_or(0, Vec::len))
            .sum::<usize>()
            == 3
    });
    let mut to: Vec<String> = envelopes()
        .iter()
        .flat_map(|envelope| envelope["to"].as_array().cloned().unwrap_or_default())
        .filter_map(|address| address.as_str().map(str::to_owned))
        .collect();
    to.sort();
    assert_eq!(to, ["one@plain.test", "three@plain.test", "two@plain.test"]);
    let captured: Vec<String> = std::fs::read_dir(&directory)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".eml"))
        .map(|entry| std::fs::read_to_string(entry.path()).unwrap())
        .collect();
    assert!(!captured.is_empty());
    for content in &captured {
        assert!(
            !content.to_ascii_lowercase().contains("x-ses-"),
            "{content}"
        );
        assert!(!content.contains("Bcc:"), "{content}");
        assert!(content.contains("Cc: Team: two@plain.test;"), "{content}");
    }
    // Over SMTP too, as SES's SMTP interface honours it.
    let mut session = engine.session();
    session.send("MAIL FROM:<app@sender.test>", 250);
    session.send("RCPT TO:<four@plain.test>", 250);
    session.send("DATA", 354);
    let refused = session.ask(
        "X-SES-CONFIGURATION-SET: nowhere\r\nFrom: app@sender.test\r\nTo: four@plain.test\r\nSubject: a test\r\n\r\nhello\r\n.",
    );
    assert!(refused.starts_with('5'), "{refused}");
}

#[test]
fn a_bulk_request_renders_each_entry_and_answers_each_in_order() {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let sections = format!("{SES}\n\n[capture]\ndirectory = \"capture\"");
    let mut engine = Engine::start("ses-bulk", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses();
    let entry = |to: &str, data: serde_json::Value, headers: serde_json::Value| {
        serde_json::json!({
            "Destination": {"ToAddresses": [to]},
            "ReplacementEmailContent": {"ReplacementTemplate": {"ReplacementTemplateData": data.to_string()}},
            "ReplacementHeaders": headers,
        })
    };
    let body = serde_json::json!({
        "FromEmailAddress": "app@sender.test",
        "DefaultContent": {"Template": {
            "TemplateContent": {"Subject": "{{subject}}", "Html": "{{html_body}}", "Text": "{{text_body}}"},
            "TemplateData": serde_json::json!({"subject": "The default subject"}).to_string(),
            "Headers": [{"Name": "X-Nitro-Campaign", "Value": "autumn"}],
        }},
        "BulkEmailEntries": [
            entry("one@plain.test", serde_json::json!({"subject": "Hi Ann", "html_body": "<p>Hello Ann</p>", "text_body": "Hello Ann"}), serde_json::json!([{"Name": "X-Nitro-Id", "Value": "one"}])),
            entry("two@plain.test", serde_json::json!({"html_body": "<p>Hello Bo</p>", "text_body": "Hello Bo"}), serde_json::json!([])),
            entry("three@plain.test", serde_json::json!({"html_body": "<p>no text</p>"}), serde_json::json!([])),
            entry("not an address", serde_json::json!({"html_body": "x", "text_body": "x"}), serde_json::json!([])),
        ],
    });
    let answer = ses.send(
        "POST",
        "/v2/email/outbound-bulk-emails",
        "",
        &body.to_string(),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    let results = answer.json()["BulkEmailEntryResults"].clone();
    let statuses: Vec<&str> = results
        .as_array()
        .unwrap()
        .iter()
        .map(|result| result["Status"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        statuses,
        [
            "SUCCESS",
            "SUCCESS",
            "MESSAGE_REJECTED",
            "INVALID_PARAMETER"
        ],
        "{}",
        answer.body
    );
    assert!(results[2]["MessageId"].is_null());
    assert!(
        results[2]["Error"]
            .as_str()
            .is_some_and(|error| error.contains("'text_body'")),
        "{}",
        answer.body
    );
    // Each sent entry rendered with its own data over the default, with
    // the template's headers and its own, under the ID its result gives.
    let directory = engine.dir.join("capture");
    let captured = |result: &serde_json::Value| -> Option<(String, serde_json::Value)> {
        let id = result["MessageId"].as_str()?;
        let name = std::fs::read_dir(&directory)
            .ok()?
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .find(|name| name.starts_with(&format!("{id}-")) && name.ends_with(".json"))?;
        let name = name.strip_suffix(".json")?;
        let envelope = std::fs::read(directory.join(format!("{name}.json"))).ok()?;
        Some((
            std::fs::read_to_string(directory.join(format!("{name}.eml"))).ok()?,
            serde_json::from_slice(&envelope).ok()?,
        ))
    };
    wait_for("both captured", || {
        captured(&results[0]).is_some() && captured(&results[1]).is_some()
    });
    let (ann, envelope) = captured(&results[0]).unwrap();
    assert_eq!(envelope["to"], serde_json::json!(["one@plain.test"]));
    assert!(ann.contains("Subject: Hi Ann"), "{ann}");
    assert!(
        ann.contains("X-Nitro-Id: one") && ann.contains("X-Nitro-Campaign: autumn"),
        "{ann}"
    );
    assert!(ann.contains("Hello Ann"), "{ann}");
    let (bo, envelope) = captured(&results[1]).unwrap();
    assert_eq!(envelope["to"], serde_json::json!(["two@plain.test"]));
    assert!(bo.contains("Hello Bo"), "{bo}");
    assert!(bo.contains("Subject: The default subject"), "{bo}");
    // A template the account does not keep is not found, whole.
    let stored = serde_json::json!({
        "FromEmailAddress": "app@sender.test",
        "DefaultContent": {"Template": {"TemplateName": "welcome"}},
        "BulkEmailEntries": [{"Destination": {"ToAddresses": ["one@plain.test"]}}],
    });
    let refused = ses.send(
        "POST",
        "/v2/email/outbound-bulk-emails",
        "",
        &stored.to_string(),
    );
    assert_eq!(refused.status, 404, "{}", refused.body);
    assert!(
        refused.body.contains("Template welcome does not exist"),
        "{}",
        refused.body
    );
    // Its rates are charged what its template renders, not the template:
    // ten bytes of template, rendered to 5,000. A request larger than a
    // second's worth is let through, and the next waits until it is paid.
    let answers = engine.admin(&[serde_json::json!(
        {"op": "put_account", "account": 1, "bytes_per_second": 2_000}
    )]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let rendered = serde_json::json!({
        "FromEmailAddress": "app@sender.test",
        "DefaultContent": {"Template": {
            "TemplateContent": {"Subject": "s", "Text": "{{x}}{{x}}"},
            "TemplateData": serde_json::json!({"x": "a".repeat(2_500)}).to_string(),
        }},
        "BulkEmailEntries": [{"Destination": {"ToAddresses": ["one@plain.test"]}}],
    });
    let send = || {
        ses.send(
            "POST",
            "/v2/email/outbound-bulk-emails",
            "",
            &rendered.to_string(),
        )
    };
    let admitted = send();
    assert_eq!(admitted.status, 200, "{}", admitted.body);
    let refused = send();
    assert_eq!(refused.status, 429, "{}", refused.body);
    assert!(
        refused.body.contains("Maximum sending rate exceeded."),
        "{}",
        refused.body
    );
}
