//! Capture mode through the release binary: mail accepted as ever
//! is captured into a directory in place of being sent, finishes captured,
//! never delivered, without a lookup or a connection, and the operator
//! endpoint's inspector shows it; a delivery captured before the engine
//! stopped, its outcome not yet kept, is found again, never written twice.

mod support;

use std::os::unix::fs::PermissionsExt as _;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use support::{Dns, Engine, Receiver, Script, wait_for};

#[test]
fn captured_mail_is_never_sent_and_the_inspector_shows_it() {
    // Routes that work, DANE and MTA-STS on: capture mode looks none of it
    // up.
    let (dns, receiver, mut engine) = start("capture");
    let messages = engine.submit(&["one@plain.test", "two@elsewhere.test"]);
    let directory = engine.dir.join("capture");
    wait_for("both captured", || captured(&directory).len() == 2);
    // Each finishes captured, and nothing reached the receiver.
    for message in &messages {
        wait_for("its delivery finished", || {
            engine
                .explain(message)
                .iter()
                .all(|delivery| delivery["state"] == "finished")
        });
        let explained = engine.explain(message);
        assert_eq!(explained[0]["completion"], "captured", "{explained:?}");
    }
    assert_eq!(dns.queries(), 0, "nothing looked up");
    assert!(receiver.connections().is_empty(), "nothing connected to");
    let (_, metrics) = engine.operator("/metrics");
    assert!(
        metrics.contains("nitromta_attempts_total{result=\"captured\"} 2\n"),
        "{metrics}"
    );
    assert!(
        metrics.contains("nitromta_attempts_total{result=\"delivered\"} 0\n"),
        "{metrics}"
    );
    // Its files are its owner's alone, the content as signed and sent.
    let name = &captured(&directory)[0];
    let content = std::fs::read(directory.join(format!("{name}.eml"))).unwrap();
    for file in [format!("{name}.eml"), format!("{name}.json")] {
        let mode = std::fs::metadata(directory.join(&file))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{file}");
    }
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join(format!("{name}.json"))).unwrap())
            .unwrap();
    assert!(
        envelope["from"]
            .as_str()
            .is_some_and(|from| from.ends_with("@bounces.example.test")),
        "{envelope}"
    );
    // The inspector: the list, a message with its lifecycle, its raw bytes.
    let (status, index) = engine.operator("/capture");
    assert_eq!(status, 200);
    assert!(index.contains("2 captured, newest first"), "{index}");
    assert!(index.contains("a test"), "{index}");
    let (status, page) = engine.operator(&format!("/capture/{name}"));
    assert_eq!(status, 200);
    assert!(
        page.contains("<h2>Lifecycle</h2>") && page.contains("finished, captured"),
        "{page}"
    );
    assert!(page.contains("Subject: a test"), "{page}");
    let (status, raw) = engine.operator(&format!("/capture/{name}.eml"));
    assert_eq!(status, 200);
    assert_eq!(raw.as_bytes(), content.as_slice());
    // Nothing but its own names is read, not a file beside the directory.
    std::fs::write(engine.dir.join("outside.eml"), "not captured").unwrap();
    let (status, body) = engine.operator("/capture/../outside.eml");
    assert_eq!(status, 404, "{body}");
    // Nor through a link of its name, nor anything but a file.
    std::os::unix::fs::symlink(engine.dir.join("config.toml"), directory.join("a.eml")).unwrap();
    let (status, body) = engine.operator("/capture/a.eml");
    assert_eq!(status, 404, "{body}");
    std::fs::create_dir(directory.join("b.eml")).unwrap();
    let (status, body) = engine.operator("/capture/b.eml");
    assert_eq!(status, 404, "{body}");
}

#[test]
fn a_delivery_captured_before_a_restart_is_never_captured_twice() {
    let (_dns, _receiver, mut engine) = start("recaptured");
    // The test's sender exists once a session has logged in.
    drop(engine.session());
    hold(&engine, "hold");
    let messages = engine.submit(&["one@plain.test", "two@plain.test", "three@plain.test"]);
    let deliveries: Vec<String> = messages
        .iter()
        .map(|message| {
            wait_for("its delivery paused", || {
                engine.explain(message)[0]["state"] == "paused"
            });
            engine.explain(message)[0]["delivery"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    // As if the engine stopped once the first was captured, before its
    // outcome was kept.
    engine.stop();
    let directory = engine.dir.join("capture");
    let name = format!("{}-{}", messages[0], deliveries[0]);
    let envelope = serde_json::json!({
        "message": messages[0],
        "from": "a@bounces.example.test",
        "to": ["one@plain.test"],
        "deliveries": [deliveries[0]],
        "captured": "2026-10-29T00:00:00Z",
    })
    .to_string();
    std::fs::write(
        directory.join(format!("{name}.eml")),
        "Subject: found\r\n\r\n",
    )
    .unwrap();
    std::fs::write(directory.join(format!("{name}.json")), &envelope).unwrap();
    // The second's envelope alone, its content never kept: not captured.
    let partial = format!("{}-{}", messages[1], deliveries[1]);
    let alone = serde_json::json!({
        "message": messages[1],
        "from": "a@bounces.example.test",
        "to": ["two@plain.test"],
        "deliveries": [deliveries[1]],
        "captured": "2026-10-29T00:00:00Z",
    })
    .to_string();
    std::fs::write(directory.join(format!("{partial}.json")), &alone).unwrap();
    // The third's envelope beside content that does not open as its own, as
    // sealed content damaged or moved from another capture: not captured.
    let damaged = format!("{}-{}", messages[2], deliveries[2]);
    let beside = serde_json::json!({
        "message": messages[2],
        "from": "a@bounces.example.test",
        "to": ["three@plain.test"],
        "deliveries": [deliveries[2]],
        "captured": "2026-10-29T00:00:00Z",
    })
    .to_string();
    std::fs::write(
        directory.join(format!("{damaged}.eml")),
        b"\0\x01not sealed here",
    )
    .unwrap();
    std::fs::write(directory.join(format!("{damaged}.json")), &beside).unwrap();
    engine.restart();
    hold(&engine, "release");
    for message in &messages {
        wait_for("its delivery captured", || {
            engine.explain(message)[0]["completion"] == "captured"
        });
    }
    // The first is the capture found, as it was; only the second and third
    // are written.
    let names = captured(&directory);
    let mut expected = [name.clone(), partial.clone(), damaged.clone()];
    expected.sort();
    assert_eq!(names, expected);
    assert_ne!(
        std::fs::read(directory.join(format!("{damaged}.eml"))).unwrap(),
        b"\0\x01not sealed here"
    );
    assert_ne!(
        std::fs::read_to_string(directory.join(format!("{partial}.json"))).unwrap(),
        alone
    );
    assert!(directory.join(format!("{partial}.eml")).is_file());
    assert_eq!(
        std::fs::read_to_string(directory.join(format!("{name}.json"))).unwrap(),
        envelope
    );
    assert_eq!(
        std::fs::read_to_string(directory.join(format!("{name}.eml"))).unwrap(),
        "Subject: found\r\n\r\n"
    );
}

/// A signed zone routing plain.test and elsewhere.test to the receiver,
/// each with an MTA-STS policy, and an engine capturing, which validates
/// the zone and honours DANE and MTA-STS.
#[test]
fn with_encryption_on_neither_the_store_nor_capture_keeps_a_body_or_address_in_the_clear_and_mail_goes_out_whole()
 {
    let (_dns, _receiver, mut engine) = start("capture-sealed");
    let config = engine.dir.join("config.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "keys = \"keys\"",
            "keys = \"keys\"\nencryption = \"installation\"",
        ),
    )
    .unwrap();
    engine.restart();
    // Held, its mail waits in the store, body and all. The test's sender
    // exists once a session has logged in.
    drop(engine.session());
    hold(&engine, "hold");
    let messages = engine.submit(&["confidential.reader@plain.test"]);
    wait_for("its delivery paused", || {
        engine
            .explain(&messages[0])
            .iter()
            .all(|delivery| delivery["state"] == "paused")
    });
    let in_the_clear = |needle: &[u8]| {
        ["store.db", "store.db-wal"].iter().any(|file| {
            std::fs::read(engine.dir.join(file))
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
        })
    };
    assert!(
        !in_the_clear(b"confidential.reader"),
        "an address in the clear"
    );
    assert!(!in_the_clear(b"Subject: a test"), "a body in the clear");
    // Released, it goes out as it was prepared, and its capture is sealed
    // as its body was: the inspector opens it.
    hold(&engine, "release");
    let directory = engine.dir.join("capture");
    wait_for("its capture", || captured(&directory).len() == 1);
    let name = &captured(&directory)[0];
    for file in [format!("{name}.eml"), format!("{name}.json")] {
        let kept = std::fs::read(directory.join(&file)).unwrap();
        for needle in [&b"confidential.reader"[..], b"Subject: a test"] {
            assert!(
                !kept.windows(needle.len()).any(|window| window == needle),
                "{file} keeps {} in the clear",
                String::from_utf8_lossy(needle)
            );
        }
    }
    let (status, content) = engine.operator(&format!("/capture/{name}.eml"));
    assert_eq!(status, 200);
    assert!(
        content.contains("To: confidential.reader@plain.test\r\nSubject: a test\r\n\r\nhello"),
        "{content}"
    );
    let (status, index) = engine.operator("/capture");
    assert_eq!(status, 200);
    assert!(index.contains("confidential.reader@plain.test"), "{index}");
}

fn start(name: &str) -> (Dns, Receiver, Engine) {
    let dns = Dns::signed(&[
        ("plain.test", "mx.plain.test"),
        ("elsewhere.test", "mx.elsewhere.test"),
    ]);
    for domain in ["plain.test", "elsewhere.test"] {
        dns.txt(&format!("_mta-sts.{domain}"), "v=STSv1; id=1;");
        dns.address_of(&format!("mta-sts.{domain}"));
    }
    let receiver = Receiver::start(Script::default());
    let anchor = dns.trust_anchor();
    let sections = "[operator]\nlisten = \"127.0.0.1:0\"\n\n[capture]\ndirectory = \"capture\"";
    let engine = Engine::start_with(
        name,
        &dns,
        &receiver,
        "trust_anchor = \"anchor.key\"",
        sections,
        &[("anchor.key", &anchor)],
    );
    (dns, receiver, engine)
}

/// Holds or releases the test's sender's mail.
fn hold(engine: &Engine, op: &str) {
    let request = match op {
        "hold" => {
            serde_json::json!({"op": "hold", "account": 1, "identity": "sender.test", "reason": "a test"})
        }
        _ => serde_json::json!({"op": "release", "account": 1, "identity": "sender.test"}),
    };
    let answers = engine.admin(&[request]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
}

/// The captures in `directory`, by name, in order.
fn captured(directory: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    name.strip_suffix(".json").map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn an_identity_created_through_ses_is_taken_as_verified_without_a_lookup() {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let sections = "[ses]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nregion = \"us-east-1\"\n\n[capture]\ndirectory = \"capture\"";
    let mut engine = Engine::start(
        "capture-identity",
        &dns,
        &receiver,
        "dane = false",
        sections,
    );
    let manager = engine.ses_permitted(&["send", "manage"]);
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let private = STANDARD.encode(AsDer::<Pkcs8V1Der>::as_der(&pair).unwrap().as_ref());
    let body = serde_json::json!({
        "EmailIdentity": "brand.test",
        "DkimSigningAttributes": {
            "DomainSigningSelector": "s1",
            "DomainSigningPrivateKey": private,
        },
    });
    let created = manager.send("POST", "/v2/email/identities", "", &body.to_string());
    assert_eq!(created.status, 200, "{}", created.body);
    // Capture mode looks nothing up: its record is taken as found.
    wait_for("the identity verified", || {
        manager
            .send("GET", "/v2/email/identities/brand.test", "", "")
            .json()["VerifiedForSendingStatus"]
            == true
    });
    let send = serde_json::json!({
        "FromEmailAddress": "news@brand.test",
        "Destination": {"ToAddresses": ["one@plain.test"]},
        "Content": {"Simple": {"Subject": {"Data": "a test"}, "Body": {"Text": {"Data": "hello"}}}},
    });
    let sent = manager.send("POST", "/v2/email/outbound-emails", "", &send.to_string());
    assert_eq!(sent.status, 200, "{}", sent.body);
    wait_for("its capture", || {
        captured(&engine.dir.join("capture")).len() == 1
    });
    assert_eq!(dns.queries(), 0, "nothing looked up");
}
