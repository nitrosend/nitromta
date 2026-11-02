//! `nitromta doctor` through the release binary, against a
//! stub DNS holding what a correct installation publishes, the test's
//! receiver as the SMTP server port 25 reaches, and a time server of the
//! test's own: each record and probe as doctor finds it, and what it says
//! to change when one is missing.

mod support;

use std::net::{Ipv4Addr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hickory_resolver::proto::rr::rdata::{A, PTR};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use serde_json::json;
use support::{Dns, Engine, Receiver, Script};

/// A time server answering SNTP with this host's clock, and its address.
fn time_server() -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a port");
    let address = socket.local_addr().expect("its address").to_string();
    std::thread::spawn(move || {
        let mut request = [0u8; 48];
        while let Ok((_, from)) = socket.recv_from(&mut request) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let seconds = (now.as_secs() + 2_208_988_800) as u32;
            let fraction = ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000) as u32;
            let mut answer = [0u8; 48];
            // No leap warning, version 4, a server, of stratum 1, answering
            // the request it was sent.
            answer[0] = 0b0010_0100;
            answer[1] = 1;
            answer[24..32].copy_from_slice(&request[40..48]);
            for at in [32, 40] {
                answer[at..at + 4].copy_from_slice(&seconds.to_be_bytes());
                answer[at + 4..at + 8].copy_from_slice(&fraction.to_be_bytes());
            }
            let _ = socket.send_to(&answer, from);
        }
    });
    address
}

/// An RSA key as a PEM PKCS #8 private key.
fn pem(key: &KeyPair) -> String {
    let pkcs8 = aws_lc_rs::encoding::AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(key).unwrap();
    let body = STANDARD.encode(pkcs8.as_ref());
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    )
}

#[test]
fn doctor_finds_each_record_and_says_what_to_publish_for_one_missing() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    // The test's certificate is its own authority, as a real one's chain
    // goes to one the system trusts.
    let mut engine = Engine::start(
        "doctor",
        &dns,
        &receiver,
        "dane = false",
        "[tls]\nauthorities = \"tls.crt\"",
    );
    // An identity that signs.
    let key = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let private_key = pem(&key);
    let changed = |requests: &[serde_json::Value]| {
        let answers = engine.admin(requests);
        assert!(
            answers.iter().all(|answer| answer["ok"].is_object()),
            "{answers:?}"
        );
    };
    // It, a subdomain of it that does not sign, and a domain with two DMARC
    // records.
    changed(&[
        json!({"op": "put_account", "account": 1}),
        json!({"op": "put_identity", "account": 1, "name": "signed.test", "selector": "s1", "private_key": private_key}),
        json!({"op": "put_identity", "account": 1, "name": "a.mail.signed.test"}),
        json!({"op": "put_identity", "account": 1, "name": "twice.test"}),
        json!({"op": "put_identity", "account": 1, "name": "news.twice.test"}),
    ]);
    // What a correct installation publishes: its DKIM key, too long for
    // one of DNS's strings, in several, as published, and as an
    // RSAPublicKey, as some publish it, rather than the
    // SubjectPublicKeyInfo the engine lists (the same 2048-bit key after
    // that's fixed header); DMARC; and the return path's SPF and MX.
    let spki = key.public_key().as_der().unwrap();
    let public = STANDARD.encode(spki.as_ref());
    let record = format!(
        "v=DKIM1; k=rsa; p={}",
        STANDARD.encode(&spki.as_ref()[24..])
    );
    dns.txt("s1._domainkey.signed.test", &record);
    // The organisational domain's record governs the subdomain, not the
    // nearer one between them, as receivers walk the tree (RFC 9989).
    dns.txt(
        "_dmarc.signed.test",
        "v=DMARC1; p=none; sp=quarantine; np=quarantine",
    );
    dns.txt("_dmarc.mail.signed.test", "v=DMARC1; p=reject");
    dns.txt("_dmarc.twice.test", "v=DMARC1; p=none");
    dns.txt("_dmarc.twice.test", "v=DMARC1; p=reject");
    dns.txt("bounces.example.test", "v=spf1 ip4:192.0.2.10 -all");
    dns.mx("bounces.example.test", 10, "feedback.example.test");
    let (time, port25) = (time_server(), format!("127.0.0.1:{}", receiver.port));
    let doctor = |engine: &Engine| {
        engine.command(&[
            "doctor",
            "--config",
            "config.toml",
            "--time-server",
            &time,
            "--port25",
            &port25,
        ])
    };
    let has = |said: &str, lines: &[&str]| {
        for line in lines {
            assert!(said.contains(line), "{line:?} in:\n{said}");
        }
    };
    // Mail from the host's own address: everything there is passes, but
    // for the domain with two DMARC records.
    let (passed, said) = doctor(&engine);
    assert!(!passed, "{said}");
    has(
        &said,
        &[
            "ok    store: the running engine holds it",
            "ok    keys: keys holds key 1",
            "ok    submission: its certificate is valid for localhost, past two weeks",
            "ok    clock: ",
            "warn  resolver: DANE is off",
            "warn  egresses: none, so mail goes out from the host's own address",
            &format!("ok    port 25: port 25 reaches {port25}"),
            "ok    identity signed.test: s1._domainkey.signed.test publishes its DKIM key",
            "ok    identity signed.test: DMARC governs it, with policy none",
            "ok    identity a.mail.signed.test: DMARC governs it, with policy quarantine",
            "fail  identity twice.test: _dmarc.twice.test publishes 2 DMARC records, which receivers discard: keep one",
            // Its subdomain, governed by those, which receivers discard.
            "fail  identity news.twice.test: _dmarc.twice.test publishes 2 DMARC records, which receivers discard: keep one",
            "warn  identity signed.test: the return path's domain, bounces.example.test, is not signed.test or under it",
            "ok    bounces: bounces.example.test has an MX",
        ],
    );
    // An egress, its reverse DNS published and confirmed: each found, and
    // port 25 from it failing here, where nothing has its address.
    changed(&[
        json!({"op": "put_egress", "account": 1, "address": "192.0.2.10", "helo": "mx.out.test"}),
    ]);
    dns.add(
        "10.2.0.192.in-addr.arpa",
        RData::PTR(PTR(Name::from_ascii("mx.out.test.").unwrap())),
    );
    dns.add("mx.out.test", RData::A(A(Ipv4Addr::new(192, 0, 2, 10))));
    let (passed, said) = doctor(&engine);
    assert!(!passed, "{said}");
    has(
        &said,
        &[
            "ok    egress 192.0.2.10: its PTR names mx.out.test, which resolves back to it, and its HELO is that name",
            "ok    egress 192.0.2.10: not on zen.spamhaus.org",
            "ok    egress 192.0.2.10: bounces.example.test's SPF covers it",
            &format!("fail  egress 192.0.2.10: port 25 does not reach {port25} (binding to it:"),
        ],
    );
    // Its PTR gone, and the DKIM record: what to do about each.
    dns.remove("10.2.0.192.in-addr.arpa", RecordType::PTR);
    dns.remove("s1._domainkey.signed.test", RecordType::TXT);
    let (passed, said) = doctor(&engine);
    assert!(!passed, "{said}");
    has(
        &said,
        &[
            "fail  egress 192.0.2.10: it has no PTR record: ask the address's provider to point it at mx.out.test",
            &format!(
                "fail  identity signed.test: s1._domainkey.signed.test publishes no DKIM key: publish s1._domainkey.signed.test TXT \"v=DKIM1; k=rsa; p={public}\""
            ),
            "doctor found what to change, above",
        ],
    );
    // A key rotated, and the engine sealing under the new one: the old one,
    // which seals nothing kept here, where nothing is sealed, may go.
    let (rotated, text) = engine.command(&["key", "--to", "keys"]);
    assert!(rotated, "{text}");
    engine.restart();
    let (_, said) = doctor(&engine);
    has(
        &said,
        &[
            "ok    keys: key 1 seals nothing kept any longer: `nitromta key retire --id 1` removes it",
        ],
    );
    // A key that is not the certificate's, which the engine would refuse
    // at its next start.
    let other = KeyPair::generate(KeySize::Rsa2048).unwrap();
    std::fs::write(engine.dir.join("tls.key"), pem(&other)).unwrap();
    let (passed, said) = doctor(&engine);
    assert!(!passed, "{said}");
    has(
        &said,
        &["fail  submission: the engine cannot serve its certificate and key ("],
    );
}

#[test]
fn records_are_found_as_receivers_see_them_while_dane_is_honoured() {
    // DANE honoured, as by default, through a resolver that validates
    // nothing: doctor says so, and still finds each record, which no
    // receiver needs DNSSEC to read.
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let engine = Engine::start(
        "doctor-dane",
        &dns,
        &receiver,
        "",
        "[tls]\nauthorities = \"tls.crt\"",
    );
    let key = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let answers = engine.admin(&[
        json!({"op": "put_account", "account": 1}),
        json!({"op": "put_identity", "account": 1, "name": "signed.test", "selector": "s1", "private_key": pem(&key)}),
    ]);
    assert!(
        answers.iter().all(|answer| answer["ok"].is_object()),
        "{answers:?}"
    );
    let spki = key.public_key().as_der().unwrap();
    let record = format!(
        "v=DKIM1; k=rsa; p={}",
        STANDARD.encode(&spki.as_ref()[24..])
    );
    dns.txt("s1._domainkey.signed.test", &record);
    dns.txt("_dmarc.signed.test", "v=DMARC1; p=reject");
    let (time, port25) = (time_server(), format!("127.0.0.1:{}", receiver.port));
    let (passed, said) = engine.command(&[
        "doctor",
        "--config",
        "config.toml",
        "--time-server",
        &time,
        "--port25",
        &port25,
    ]);
    assert!(!passed, "{said}");
    for line in [
        "fail  resolver: it does not validate DNSSEC",
        "ok    identity signed.test: s1._domainkey.signed.test publishes its DKIM key",
        "ok    identity signed.test: DMARC governs it, with policy reject",
    ] {
        assert!(said.contains(line), "{line:?} in:\n{said}");
    }
}
