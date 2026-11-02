//! The SNS subset through the release binary: a
//! topic created as Nitrosend's provisioning creates one, an endpoint
//! subscribed and posted its confirmation, signed as SNS signs one, and
//! confirmed by the `SubscribeURL` it was posted, with no signature; then
//! listed, refused what it may not do, and unsubscribed.

mod support;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use support::endpoint::Endpoint;
use support::{Dns, Engine, Receiver, Script, wait_for};

const SES: &str = "[ses]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nregion = \"us-east-1\"\n\n[sns]\nurl = \"https://ses.test\"\nkey = \"sns.key\"\ncertificate = \"sns.crt\"";

const TOPIC: &str = "arn:aws:sns:us-east-1:000000000001:feedback";

/// An RSA key in PEM, its certificate, and its public key.
fn signing() -> (String, String, Vec<u8>) {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&pair).unwrap();
    let lines: Vec<String> = STANDARD
        .encode(pkcs8.as_ref())
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
        .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    );
    let key = rcgen::KeyPair::from_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256).unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["ses.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (pem, certificate.pem(), pair.public_key().as_ref().to_vec())
}

/// Text as a form's value holds it.
fn form(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// The text of the first element named `name` in `xml`.
fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(&xml[start..end])
}

#[test]
fn an_endpoint_is_subscribed_posted_its_signed_confirmation_and_confirms_by_its_url() {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let (key, certificate, public) = signing();
    let mut engine = Engine::start_with(
        "sns",
        &dns,
        &receiver,
        "dane = false",
        SES,
        &[("sns.key", &key), ("sns.crt", &certificate)],
    );
    let sender = engine.ses();
    let manager = engine.ses_permitted(&["send", "manage"]);

    // As Nitrosend's provisioning creates its feedback topic, and again:
    // the same topic.
    for _ in 0..2 {
        let created = manager.sns("Action=CreateTopic&Name=feedback&Version=2010-03-31");
        assert_eq!(created.status, 200, "{}", created.body);
        assert_eq!(element(&created.body, "TopicArn"), Some(TOPIC));
    }
    // A key that only sends may not manage.
    let refused = sender.sns("Action=CreateTopic&Name=other&Version=2010-03-31");
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(element(&refused.body, "Code"), Some("AuthorizationError"));
    // A signature that does not sign it, and a key the engine never issued,
    // answered in SNS's XML, as an SNS SDK reads them.
    for (client, code) in [
        (
            support::ses::Client {
                secret: "not the secret".to_owned(),
                ..manager.clone()
            },
            "SignatureDoesNotMatch",
        ),
        (
            support::ses::Client {
                access_key: "NMTAUNKNOWN".to_owned(),
                ..manager.clone()
            },
            "InvalidClientTokenId",
        ),
    ] {
        let denied = client.sns("Action=CreateTopic&Name=other&Version=2010-03-31");
        assert_eq!(denied.status, 403, "{}", denied.body);
        assert_eq!(denied.header("content-type"), Some("text/xml"));
        assert_eq!(element(&denied.body, "Code"), Some(code), "{}", denied.body);
    }

    let subscriber = Endpoint::start("/hooks/ses", true);
    let subscribe = format!(
        "Action=Subscribe&TopicArn={}&Protocol=http&Endpoint={}&Version=2010-03-31",
        form(TOPIC),
        form(&subscriber.url)
    );
    let subscribed = manager.sns(&subscribe);
    assert_eq!(subscribed.status, 200, "{}", subscribed.body);
    assert_eq!(
        element(&subscribed.body, "SubscriptionArn"),
        Some("pending confirmation")
    );
    wait_for("its confirmation", || !subscriber.posts().is_empty());
    let posted = subscriber.posts()[0].clone();
    assert_eq!(
        posted.header("x-amz-sns-message-type"),
        Some("SubscriptionConfirmation")
    );
    assert_eq!(posted.header("x-amz-sns-topic-arn"), Some(TOPIC));
    let message = posted.json();
    assert_eq!(message["Type"], "SubscriptionConfirmation");
    assert_eq!(message["TopicArn"], TOPIC);
    assert_eq!(message["SignatureVersion"], "2");
    // Signed as SNS signs one, with the key whose certificate it names.
    let member = |name: &str| message[name].as_str().unwrap_or_default().to_owned();
    let string: String = [
        "Message",
        "MessageId",
        "SubscribeURL",
        "Timestamp",
        "Token",
        "TopicArn",
        "Type",
    ]
    .iter()
    .map(|name| format!("{name}\n{}\n", member(name)))
    .collect();
    let signature = STANDARD.decode(member("Signature")).unwrap();
    assert!(
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
            .verify(string.as_bytes(), &signature)
            .is_ok(),
        "its signature verifies"
    );
    let certificate_path = member("SigningCertURL")
        .strip_prefix("https://ses.test")
        .expect("under the url consumers reach")
        .to_owned();
    let served = manager.unsigned("GET", &certificate_path, "");
    assert_eq!(served.status, 200, "{}", served.body);
    assert_eq!(served.body, certificate);

    let attributes = manager.sns(&format!(
        "Action=GetTopicAttributes&TopicArn={}&Version=2010-03-31",
        form(TOPIC)
    ));
    assert!(
        attributes
            .body
            .contains("<entry><key>SubscriptionsPending</key><value>1</value></entry>"),
        "{}",
        attributes.body
    );
    // A token that is not its own confirms nothing, and counts as a failed
    // sign-in.
    let wrong = format!(
        "Action=ConfirmSubscription&TopicArn={}&Token={}",
        form(TOPIC),
        "0".repeat(64)
    );
    let refused = manager.unsigned("GET", "/", &wrong);
    assert_eq!(refused.status, 403, "{}", refused.body);
    // Its SubscribeURL, visited as Nitrosend's controller visits it.
    let subscribe_url = member("SubscribeURL");
    let query = subscribe_url
        .strip_prefix("https://ses.test/?")
        .expect("the listener's own");
    let confirmed = manager.unsigned("GET", "/", query);
    assert_eq!(confirmed.status, 200, "{}", confirmed.body);
    let arn = element(&confirmed.body, "SubscriptionArn")
        .expect("its ARN")
        .to_owned();
    assert!(arn.starts_with(&format!("{TOPIC}:")), "{arn}");
    let listed = manager.sns(&format!(
        "Action=ListSubscriptionsByTopic&TopicArn={}&Version=2010-03-31",
        form(TOPIC)
    ));
    assert_eq!(element(&listed.body, "SubscriptionArn"), Some(arn.as_str()));
    assert_eq!(
        element(&listed.body, "Endpoint"),
        Some(subscriber.url.as_str())
    );
    // Subscribed again once confirmed: its ARN, and nothing posted.
    let again = manager.sns(&subscribe);
    assert_eq!(element(&again.body, "SubscriptionArn"), Some(arn.as_str()));

    let unknown = manager.sns("Action=Publish&TopicArn=x&Message=y&Version=2010-03-31");
    assert_eq!(element(&unknown.body, "Code"), Some("InvalidAction"));
    let unsubscribed = manager.sns(&format!(
        "Action=Unsubscribe&SubscriptionArn={}&Version=2010-03-31",
        form(&arn)
    ));
    assert_eq!(unsubscribed.status, 200, "{}", unsubscribed.body);
    let listed = manager.sns(&format!(
        "Action=ListSubscriptionsByTopic&TopicArn={}&Version=2010-03-31",
        form(TOPIC)
    ));
    assert_eq!(element(&listed.body, "SubscriptionArn"), None);
    let posts: Vec<Value> = subscriber.bodies();
    assert_eq!(posts.len(), 1, "only its confirmation was posted");
    // An address past its failures is refused before its signature is
    // checked, in SNS's XML on SNS's route, as throttling an SDK retries.
    let forged = support::ses::Client {
        secret: "not the secret".to_owned(),
        ..manager.clone()
    };
    let throttled = (0..12)
        .map(|_| forged.sns("Action=CreateTopic&Name=other&Version=2010-03-31"))
        .find(|answer| answer.status == 429)
        .expect("refused once past its failures");
    assert_eq!(throttled.header("content-type"), Some("text/xml"));
    assert_eq!(element(&throttled.body, "Code"), Some("Throttling"));
}

#[test]
fn a_configuration_set_publishes_to_a_topic_by_its_event_destination_as_nitrosend_makes_one() {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let (key, certificate, _) = signing();
    let mut engine = Engine::start_with(
        "sns-destinations",
        &dns,
        &receiver,
        "dane = false",
        SES,
        &[("sns.key", &key), ("sns.crt", &certificate)],
    );
    let manager = engine.ses_permitted(&["send", "manage"]);
    assert_eq!(
        manager
            .sns("Action=CreateTopic&Name=feedback&Version=2010-03-31")
            .status,
        200
    );
    let created = manager.send(
        "POST",
        "/v2/email/configuration-sets",
        "",
        &serde_json::json!({"ConfigurationSetName": "cohort-a"}).to_string(),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let path = "/v2/email/configuration-sets/cohort-a/event-destinations";
    let destination = |types: Value, topic: &str| {
        serde_json::json!({
            "EventDestinationName": "cohort-a-feedback",
            "EventDestination": {
                "Enabled": true,
                "MatchingEventTypes": types,
                "SnsDestination": {"TopicArn": topic},
            },
        })
        .to_string()
    };
    let errortype = |answer: &support::ses::Answer| {
        answer
            .header("x-amzn-errortype")
            .unwrap_or_default()
            .to_owned()
    };
    // As `ses_tenant_provisioner.rb` makes it, and again.
    let types = serde_json::json!(["BOUNCE", "COMPLAINT", "DELIVERY"]);
    let made = manager.send("POST", path, "", &destination(types.clone(), TOPIC));
    assert_eq!(made.status, 200, "{}", made.body);
    let again = manager.send("POST", path, "", &destination(types.clone(), TOPIC));
    assert_eq!(errortype(&again), "AlreadyExistsException");
    // Events the engine never makes, another kind of destination, and a
    // topic it does not have are refused.
    let opens = manager.send(
        "POST",
        path,
        "",
        &destination(serde_json::json!(["OPEN"]), TOPIC),
    );
    assert_eq!(errortype(&opens), "BadRequestException", "{}", opens.body);
    let elsewhere = "arn:aws:sns:us-east-1:000000000001:nowhere";
    let missing = destination(types.clone(), elsewhere).replace("cohort-a-feedback", "other");
    let missing = manager.send("POST", path, "", &missing);
    assert_eq!(errortype(&missing), "NotFoundException", "{}", missing.body);
    let watched = serde_json::json!({
        "EventDestinationName": "watched",
        "EventDestination": {
            "MatchingEventTypes": ["BOUNCE"],
            "CloudWatchDestination": {"DimensionConfigurations": []},
        },
    });
    let watched = manager.send("POST", path, "", &watched.to_string());
    assert_eq!(
        errortype(&watched),
        "BadRequestException",
        "{}",
        watched.body
    );
    let shown = |manager: &support::ses::Client| {
        manager.send("GET", path, "", "").json()["EventDestinations"].clone()
    };
    assert_eq!(
        shown(&manager),
        serde_json::json!([{
            "Name": "cohort-a-feedback",
            "Enabled": true,
            "MatchingEventTypes": ["DELIVERY", "BOUNCE", "COMPLAINT"],
            "SnsDestination": {"TopicArn": TOPIC},
        }])
    );
    let disabled = serde_json::json!({
        "EventDestination": {
            "Enabled": false,
            "MatchingEventTypes": ["BOUNCE"],
            "SnsDestination": {"TopicArn": TOPIC},
        },
    });
    let named = format!("{path}/cohort-a-feedback");
    let updated = manager.send("PUT", &named, "", &disabled.to_string());
    assert_eq!(updated.status, 200, "{}", updated.body);
    assert_eq!(shown(&manager)[0]["Enabled"], false);
    assert_eq!(
        shown(&manager)[0]["MatchingEventTypes"],
        serde_json::json!(["BOUNCE"])
    );
    let deleted = manager.send("DELETE", &named, "", "");
    assert_eq!(deleted.status, 200, "{}", deleted.body);
    assert_eq!(shown(&manager), serde_json::json!([]));
    assert_eq!(
        errortype(&manager.send("DELETE", &named, "", "")),
        "NotFoundException"
    );
}

#[test]
fn a_bounce_delivery_and_complaint_reach_a_confirmed_subscriber_in_sess_shape_as_nitrosend_reads_it()
 {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let (key, certificate, public) = signing();
    let mut engine = Engine::start_with(
        "sns-events",
        &dns,
        &receiver,
        "dane = false",
        SES,
        &[("sns.key", &key), ("sns.crt", &certificate)],
    );
    let manager = engine.ses_permitted(&["send", "manage"]);
    let json = |value: Value| value.to_string();
    assert_eq!(
        manager
            .sns("Action=CreateTopic&Name=feedback&Version=2010-03-31")
            .status,
        200
    );
    let created = manager.send(
        "POST",
        "/v2/email/configuration-sets",
        "",
        &json(serde_json::json!({"ConfigurationSetName": "cohort-a"})),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let destination = serde_json::json!({
        "EventDestinationName": "cohort-a-feedback",
        "EventDestination": {
            "Enabled": true,
            "MatchingEventTypes": ["BOUNCE", "COMPLAINT", "DELIVERY"],
            "SnsDestination": {"TopicArn": TOPIC},
        },
    });
    let made = manager.send(
        "POST",
        "/v2/email/configuration-sets/cohort-a/event-destinations",
        "",
        &json(destination),
    );
    assert_eq!(made.status, 200, "{}", made.body);
    // Subscribed and confirmed, as Nitrosend's controller confirms.
    let subscriber = Endpoint::start("/hooks/ses", true);
    let subscribed = manager.sns(&format!(
        "Action=Subscribe&TopicArn={}&Protocol=http&Endpoint={}&Version=2010-03-31",
        form(TOPIC),
        form(&subscriber.url)
    ));
    assert_eq!(subscribed.status, 200, "{}", subscribed.body);
    wait_for("its confirmation", || !subscriber.posts().is_empty());
    let confirmation = subscriber.posts()[0].json();
    let query = confirmation["SubscribeURL"]
        .as_str()
        .unwrap()
        .strip_prefix("https://ses.test/?")
        .unwrap()
        .to_owned();
    assert_eq!(manager.unsigned("GET", "/", &query).status, 200);

    // Sent under the configuration set to the mailbox simulator, with the
    // headers and tags Nitrosend reads back.
    // The complaint address twice, so it is complained of once for each
    // of its deliveries, never once for each with each.
    let raw = "From: app@sender.test\r\nTo: bounce@simulator.amazonses.com, complaint@simulator.amazonses.com, COMPLAINT@simulator.amazonses.com, suppressionlist@simulator.amazonses.com\r\nSubject: Autumn\r\nX-Nitro-Message: m-7\r\nX-SES-MESSAGE-TAGS: campaign=autumn\r\n\r\nhello\r\n";
    // For a tenant, its identity and configuration set associated.
    let answers = engine.admin(&[serde_json::json!({
        "op": "put_tenant", "account": 1, "name": "acme",
        "identities": ["sender.test"], "configurations": ["cohort-a"]
    })]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let body = serde_json::json!({
        "Content": {"Raw": {"Data": STANDARD.encode(raw)}},
        "ConfigurationSetName": "cohort-a",
        "TenantName": "acme",
        "EmailTags": [{"Name": "message_id", "Value": "m-7"}],
    });
    let sent = manager.send("POST", "/v2/email/outbound-emails", "", &json(body));
    assert_eq!(sent.status, 200, "{}", sent.body);
    let message_id = sent.json()["MessageId"].as_str().unwrap().to_owned();
    let notifications = || -> Vec<(Value, Value)> {
        subscriber
            .posts()
            .iter()
            .filter(|posted| posted.header("x-amz-sns-message-type") == Some("Notification"))
            .map(|posted| {
                let wrapper = posted.json();
                let event = serde_json::from_str(wrapper["Message"].as_str().unwrap()).unwrap();
                (wrapper, event)
            })
            .collect()
    };
    wait_for("its deliveries, bounces and complaints", || {
        notifications().len() >= 6
    });
    // Nothing more comes.
    std::thread::sleep(std::time::Duration::from_secs(1));
    let found = notifications();
    let kinds = |kind: &str| -> Vec<Value> {
        found
            .iter()
            .filter(|(_, event)| event["eventType"] == kind)
            .map(|(_, event)| event.clone())
            .collect()
    };
    assert_eq!(found.len(), 6, "{found:?}");
    assert_eq!(kinds("Complaint").len(), 2, "{found:?}");
    // An event of its kind for one of its recipients.
    let of = |kind: &str, address: &str| {
        found
            .iter()
            .find(|(_, event)| {
                let recipient = match kind {
                    "Bounce" => &event["bounce"]["bouncedRecipients"][0]["emailAddress"],
                    "Delivery" => &event["delivery"]["recipients"][0],
                    _ => &event["complaint"]["complainedRecipients"][0]["emailAddress"],
                };
                event["eventType"] == kind && recipient == address
            })
            .unwrap_or_else(|| panic!("no {kind} for {address} among {found:?}"))
            .clone()
    };
    // The suppressed address bounced as SES's simulator bounces it, in its
    // words (the fidelity fixtures).
    let (_, suppressed) = of("Bounce", "suppressionlist@simulator.amazonses.com");
    assert_eq!(suppressed["bounce"]["bounceType"], "Permanent");
    assert_eq!(
        suppressed["bounce"]["bounceSubType"], "General",
        "{suppressed}"
    );
    assert_eq!(
        suppressed["bounce"]["bouncedRecipients"][0]["diagnosticCode"],
        "smtp; 550 5.1.1 As requested: user unknown (suppressed address: suppressionlist@simulator.amazonses.com)"
    );
    let (wrapper, bounce) = of("Bounce", "bounce@simulator.amazonses.com");
    assert_eq!(bounce["bounce"]["bounceSubType"], "General");
    assert_eq!(bounce["bounce"]["bounceType"], "Permanent");
    assert_eq!(
        bounce["bounce"]["bouncedRecipients"][0]["emailAddress"],
        "bounce@simulator.amazonses.com"
    );
    assert_eq!(bounce["mail"]["messageId"], message_id.as_str());
    assert_eq!(
        bounce["mail"]["tags"]["message_id"],
        serde_json::json!(["m-7"])
    );
    assert_eq!(
        bounce["mail"]["tags"]["campaign"],
        serde_json::json!(["autumn"])
    );
    assert_eq!(
        bounce["mail"]["tags"]["ses:configuration-set"],
        serde_json::json!(["cohort-a"])
    );
    // Its tenant, as SES tags a tenant's events (fixtures/ses).
    assert_eq!(
        bounce["mail"]["tags"]["ses:tenant"],
        serde_json::json!(["acme"])
    );
    let headers = bounce["mail"]["headers"].as_array().unwrap();
    assert!(
        headers.contains(&serde_json::json!({"name": "X-Nitro-Message", "value": "m-7"})),
        "{headers:?}"
    );
    // Signed as SNS signs a notification, with the key its certificate is.
    let member = |name: &str| wrapper[name].as_str().unwrap_or_default().to_owned();
    let string: String = ["Message", "MessageId", "Timestamp", "TopicArn", "Type"]
        .iter()
        .map(|name| format!("{name}\n{}\n", member(name)))
        .collect();
    let signature = STANDARD.decode(member("Signature")).unwrap();
    assert!(
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
            .verify(string.as_bytes(), &signature)
            .is_ok()
    );
    assert!(member("UnsubscribeURL").starts_with("https://ses.test/?Action=Unsubscribe"));
    let (_, delivery) = of("Delivery", "complaint@simulator.amazonses.com");
    assert_eq!(
        delivery["delivery"]["recipients"],
        serde_json::json!(["complaint@simulator.amazonses.com"])
    );
    let (_, complaint) = of("Complaint", "complaint@simulator.amazonses.com");
    assert_eq!(complaint["complaint"]["complaintFeedbackType"], "abuse");
    let mut complained: Vec<String> = kinds("Complaint")
        .iter()
        .map(|event| {
            event["complaint"]["complainedRecipients"][0]["emailAddress"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    complained.sort();
    assert_eq!(
        complained,
        [
            "COMPLAINT@simulator.amazonses.com",
            "complaint@simulator.amazonses.com"
        ]
    );
}
