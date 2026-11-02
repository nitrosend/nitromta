//! SES's identity operations through the release binary,
//! as Nitrosend calls them: a domain identity created with
//! its own DKIM key, its record a CNAME to the sender's own, verified once
//! the engine finds it there, and sending only then; a new key checked
//! again; and the rest of its life, for a key that manages its account.

mod support;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use support::{Dns, Engine, Receiver, Script, wait_for};

const SES: &str = "[ses]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nregion = \"us-east-1\"";

/// A new key: its private half as SES takes it, PKCS #8 DER in base64, and
/// its DKIM record.
fn key() -> (String, String) {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let private = AsDer::<Pkcs8V1Der>::as_der(&pair).unwrap();
    let public = pair.public_key().as_der().unwrap();
    (
        STANDARD.encode(private.as_ref()),
        format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(public.as_ref())),
    )
}

fn status(identity: &Value) -> (&str, &str, bool) {
    (
        identity["VerificationStatus"].as_str().unwrap_or_default(),
        identity["DkimAttributes"]["Status"]
            .as_str()
            .unwrap_or_default(),
        identity["VerifiedForSendingStatus"] == json!(true),
    )
}

#[test]
fn a_domain_with_its_own_key_sends_once_its_record_is_found_and_is_managed_through_ses() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!("{SES}\n\n[capture]\ndirectory = \"capture\"");
    let mut engine = Engine::start("identity", &dns, &receiver, "dane = false", &sections);
    let sender = engine.ses();
    let manager = engine.ses_permitted(&["send", "manage"]);
    let (private, record) = key();
    let create = |name: &str, selector: &str, private: &str| {
        let body = json!({
            "EmailIdentity": name,
            "DkimSigningAttributes": {
                "DomainSigningSelector": selector,
                "DomainSigningPrivateKey": private,
            },
        });
        manager.send("POST", "/v2/email/identities", "", &body.to_string())
    };
    let get = |name: &str| manager.send("GET", &format!("/v2/email/identities/{name}"), "", "");
    let send_as = |name: &str| {
        let body = json!({
            "FromEmailAddress": format!("news@{name}"),
            "Destination": {"ToAddresses": ["one@plain.test"]},
            "Content": {"Simple": {"Subject": {"Data": "a test"}, "Body": {"Text": {"Data": "hello"}}}},
        });
        sender.send("POST", "/v2/email/outbound-emails", "", &body.to_string())
    };

    // A key that only sends may not manage, refused before it is decoded.
    let denied = sender.send("POST", "/v2/email/identities", "", "{}");
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(
        denied.header("x-amzn-errortype"),
        Some("AccessDeniedException")
    );

    // Its record a CNAME to the sender's own, as Nitrosend delegates them.
    dns.alias("s1._domainkey.checked.test", "s1.keys.sender.test");
    dns.txt("s1.keys.sender.test", &record);
    let created = create("checked.test", "s1", &private);
    assert_eq!(created.status, 200, "{}", created.body);
    let made = created.json();
    assert_eq!(made["IdentityType"], "DOMAIN", "{made}");
    assert_eq!(made["VerifiedForSendingStatus"], false, "{made}");
    assert_eq!(made["DkimAttributes"]["Status"], "PENDING", "{made}");
    assert_eq!(made["DkimAttributes"]["Tokens"], json!(["s1"]), "{made}");
    assert_eq!(
        made["DkimAttributes"]["SigningAttributesOrigin"], "EXTERNAL",
        "{made}"
    );
    let again = create("checked.test", "s1", &private);
    assert_eq!(
        again.header("x-amzn-errortype"),
        Some("AlreadyExistsException"),
        "{}",
        again.body
    );
    wait_for("its record to be found", || {
        status(&get("checked.test").json()) == ("SUCCESS", "SUCCESS", true)
    });
    let sent = send_as("checked.test");
    assert_eq!(sent.status, 200, "{}", sent.body);

    // One whose record is not published does not send; a new key, whose
    // record is, is checked again at once.
    let created = create("pending.test", "s1", &private);
    assert_eq!(created.status, 200, "{}", created.body);
    let refused = send_as("pending.test");
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(
        refused.body.contains("Email address is not verified"),
        "{}",
        refused.body
    );
    assert_eq!(
        status(&get("pending.test").json()),
        ("PENDING", "PENDING", false)
    );
    let (private, record) = key();
    dns.txt("s2._domainkey.pending.test", &record);
    let body = json!({
        "SigningAttributesOrigin": "EXTERNAL",
        "SigningAttributes": {
            "DomainSigningSelector": "s2",
            "DomainSigningPrivateKey": private,
        },
    });
    // An origin given again inside the attributes is refused.
    let mut nested = body.clone();
    nested["SigningAttributes"]["DomainSigningAttributesOrigin"] = json!("AWS_SES");
    let refused = manager.send(
        "PUT",
        "/v2/email/identities/pending.test/dkim/signing",
        "",
        &nested.to_string(),
    );
    assert_eq!(refused.status, 400, "{}", refused.body);
    let keyed = manager.send(
        "PUT",
        "/v2/email/identities/pending.test/dkim/signing",
        "",
        &body.to_string(),
    );
    assert_eq!(keyed.status, 200, "{}", keyed.body);
    assert_eq!(keyed.json()["DkimStatus"], "PENDING", "{}", keyed.body);
    assert_eq!(keyed.json()["DkimTokens"], json!(["s2"]), "{}", keyed.body);
    wait_for("the new key's record to be found", || {
        status(&get("pending.test").json()) == ("SUCCESS", "SUCCESS", true)
    });
    assert_eq!(send_as("pending.test").status, 200);

    // Signing turned off, and feedback forwarding, which is never on.
    let put = |path: &str, body: Value| {
        manager.send(
            "PUT",
            &format!("/v2/email/identities/checked.test/{path}"),
            "",
            &body.to_string(),
        )
    };
    assert_eq!(put("dkim", json!({"SigningEnabled": false})).status, 200);
    let got = get("checked.test").json();
    assert_eq!(got["DkimAttributes"]["SigningEnabled"], false, "{got}");
    assert_eq!(got["FeedbackForwardingStatus"], false, "{got}");
    assert_eq!(
        put("feedback", json!({"EmailForwardingEnabled": false})).status,
        200
    );
    let forwarding = put("feedback", json!({"EmailForwardingEnabled": true}));
    assert_eq!(
        forwarding.header("x-amzn-errortype"),
        Some("BadRequestException"),
        "{}",
        forwarding.body
    );

    // What SES offers beyond Bring Your Own DKIM on a domain is refused.
    let address = create("news@checked.test", "s1", &private);
    assert_eq!(address.status, 400, "{}", address.body);
    let easy = manager.send(
        "POST",
        "/v2/email/identities",
        "",
        &json!({"EmailIdentity": "easy.test"}).to_string(),
    );
    assert_eq!(easy.status, 400, "{}", easy.body);

    // A hold that accepts new mail leaves an identity sending.
    let held = engine.admin(&[json!({
        "op": "hold", "account": 1, "identity": "sender.test", "accepting": true, "reason": "a look"
    })]);
    assert!(held[0]["ok"].is_object(), "{held:?}");
    // Listed a page at a time in the order of their names, with the
    // operator's own; a token not of the engine's is refused.
    let list = |query: &str| manager.send("GET", "/v2/email/identities", query, "");
    let mut names = Vec::new();
    let mut query = "PageSize=1".to_owned();
    loop {
        let page = list(&query);
        assert_eq!(page.status, 200, "{}", page.body);
        let page = page.json();
        let identities = page["EmailIdentities"].as_array().unwrap().clone();
        assert!(identities.len() <= 1, "{page}");
        names.extend(identities.iter().map(|identity| {
            assert_eq!(identity["SendingEnabled"], true, "{identity}");
            identity["IdentityName"].as_str().unwrap().to_owned()
        }));
        match page["NextToken"].as_str() {
            Some(token) => query = format!("NextToken={token}&PageSize=1"),
            None => break,
        }
    }
    assert_eq!(names, ["checked.test", "pending.test", "sender.test"]);
    // The engine's model lists with a POST, as later SDKs do; the GET
    // above is how Nitrosend's SDK lists, and both are taken.
    let posted = manager.send(
        "POST",
        "/v2/email/list-identities",
        "",
        &json!({"PageSize": 1000}).to_string(),
    );
    let posted: Vec<Value> = posted.json()["EmailIdentities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|identity| identity["IdentityName"].clone())
        .collect();
    assert_eq!(
        posted,
        names.iter().map(|name| json!(name)).collect::<Vec<_>>()
    );
    let invalid = list("NextToken=nonsense");
    assert_eq!(
        invalid.header("x-amzn-errortype"),
        Some("BadRequestException"),
        "{}",
        invalid.body
    );

    // Deleted, it is gone, and deleting it again finds nothing.
    let delete = || manager.send("DELETE", "/v2/email/identities/pending.test", "", "");
    assert_eq!(delete().status, 200);
    for gone in [get("pending.test"), delete()] {
        assert_eq!(
            gone.header("x-amzn-errortype"),
            Some("NotFoundException"),
            "{}",
            gone.body
        );
    }
    assert_eq!(send_as("pending.test").status, 400);
}

/// The SMTP reply to each of `lines`, at the plain listener on `port`,
/// after its greeting.
fn smtp(port: u16, lines: &[&str]) -> Vec<String> {
    use std::io::{BufRead as _, BufReader, Write as _};
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
    lines
        .iter()
        .map(|line| {
            write!(writer, "{line}\r\n").expect("written");
            reply()
        })
        .collect()
}

#[test]
fn mail_goes_with_a_return_path_at_its_own_mail_from_domain_once_that_points_at_the_bounce_host() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!(
        "{SES}\n\n[capture]\ndirectory = \"capture\"\n\n[feedback]\nlisten = \"127.0.0.1:0\"\nhostname = \"mx.bounces.test\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\""
    );
    let mut engine = Engine::start("mail-from", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses_permitted(&["send", "manage"]);
    let feedback = engine
        .listening("taking bounce and complaint reports")
        .expect("a feedback listener");
    let (private, record) = key();
    dns.txt("s1._domainkey.brand.test", &record);
    let body = json!({
        "EmailIdentity": "brand.test",
        "DkimSigningAttributes": {"DomainSigningSelector": "s1", "DomainSigningPrivateKey": private},
    });
    let created = ses.send("POST", "/v2/email/identities", "", &body.to_string());
    assert_eq!(created.status, 200, "{}", created.body);
    let get = || {
        ses.send("GET", "/v2/email/identities/brand.test", "", "")
            .json()
    };
    wait_for("its DKIM record to be found", || {
        get()["VerifiedForSendingStatus"] == json!(true)
    });
    let mail_from = |domain: &str, behavior: &str| {
        let body = json!({"MailFromDomain": domain, "BehaviorOnMxFailure": behavior});
        ses.send(
            "PUT",
            "/v2/email/identities/brand.test/mail-from",
            "",
            &body.to_string(),
        )
    };
    let send = || {
        let body = json!({
            "FromEmailAddress": "news@brand.test",
            "Destination": {"ToAddresses": ["one@plain.test"]},
            "Content": {"Simple": {"Subject": {"Data": "a test"}, "Body": {"Text": {"Data": "hello"}}}},
        });
        ses.send("POST", "/v2/email/outbound-emails", "", &body.to_string())
    };

    // Not under the identity's domain, it is refused.
    assert_eq!(
        mail_from("bounces.other.test", "USE_DEFAULT_VALUE").status,
        400
    );
    // Not yet pointing at the bounce host, mail it says to reject is
    // refused, as SES refuses it.
    let put = mail_from("bounces.brand.test", "REJECT_MESSAGE");
    assert_eq!(put.status, 200, "{}", put.body);
    let attributes = get()["MailFromAttributes"].clone();
    assert_eq!(
        attributes,
        json!({
            "MailFromDomain": "bounces.brand.test",
            "MailFromDomainStatus": "PENDING",
            "BehaviorOnMxFailure": "REJECT_MESSAGE",
        })
    );
    let refused = send();
    assert_eq!(
        refused.header("x-amzn-errortype"),
        Some("MailFromDomainNotVerifiedException"),
        "{}",
        refused.body
    );
    // Its MX, through a CNAME as Nitrosend delegates it, at the bounce
    // host; put again, it is checked at once.
    dns.alias("bounces.brand.test", "bounces.brand.test.rp.sender.test");
    dns.mx("bounces.brand.test.rp.sender.test", 10, "mx.bounces.test");
    assert_eq!(
        mail_from("bounces.brand.test", "REJECT_MESSAGE").status,
        200
    );
    wait_for("its MX to be found", || {
        get()["MailFromAttributes"]["MailFromDomainStatus"] == "SUCCESS"
    });
    let sent = send();
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
    let (token, domain) = return_path.rsplit_once('@').unwrap();
    assert_eq!(domain, "bounces.brand.test");
    // A bounce to it comes back to the engine and is taken; the same token
    // at a domain no identity has is relay.
    let replies = smtp(
        feedback,
        &[
            "EHLO reporter.test",
            "MAIL FROM:<>",
            &format!("RCPT TO:<{token}@bounces.brand.test>"),
            &format!("RCPT TO:<{token}@elsewhere.test>"),
            "QUIT",
        ],
    );
    assert!(replies[2].starts_with("250"), "{replies:?}");
    assert!(replies[3].starts_with("550"), "{replies:?}");
    // Taken away, mail goes with the installation's return path again.
    let removed = ses.send(
        "PUT",
        "/v2/email/identities/brand.test/mail-from",
        "",
        &json!({}).to_string(),
    );
    assert_eq!(removed.status, 200, "{}", removed.body);
    assert!(get()["MailFromAttributes"].is_null());
}
