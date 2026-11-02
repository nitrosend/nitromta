//! SNS's messages: what SNS posts to a topic's
//! subscribers, a `SubscriptionConfirmation` and a `Notification`, each
//! signed with SignatureVersion 2, SHA-256 with RSA over SNS's string to
//! sign, so a consumer verifies one as it verifies SNS's own, trusting the
//! engine's certificate.

use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::signature::RSA_PKCS1_SHA256;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;

/// The header that tells a subscriber which kind of message a post is.
pub const MESSAGE_TYPE: &str = "x-amz-sns-message-type";
/// The headers naming a post's message and topic.
pub const MESSAGE_ID: &str = "x-amz-sns-message-id";
pub const TOPIC_ARN: &str = "x-amz-sns-topic-arn";
/// SNS posts its messages as plain text, holding JSON.
pub const CONTENT_TYPE: &str = "text/plain; charset=UTF-8";
/// The engine's own header marking a notification posted again by the
/// operator's replay, outside what is signed.
pub const REPLAY: &str = "x-nitromta-replay";

/// What topic subscribers are posted under: the signer, the HTTPS origin
/// their `UnsubscribeURL`s are under, and the region topics' ARNs name.
pub struct Publishing {
    pub signer: std::sync::Arc<Signer>,
    pub url: String,
    pub region: String,
}

/// Its key is never shown.
impl std::fmt::Debug for Publishing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Publishing")
            .field("url", &self.url)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl Publishing {
    /// A topic's ARN, as the SNS subset names it.
    pub fn topic_arn(&self, account: engine_core::id::AccountId, topic: &str) -> String {
        format!(
            "arn:aws:sns:{}:{:012}:{topic}",
            self.region,
            account.0.as_u64()
        )
    }
}

/// The engine's key, and the URL its certificate is served at.
pub struct Signer {
    key: KeyPair,
    certificate_url: String,
}

impl Signer {
    /// The signer of an RSA private key in PEM, PKCS #8 or PKCS #1, whose
    /// certificate is at `certificate_url`.
    pub fn from_pem(pem: &str, certificate_url: String) -> Result<Self, String> {
        let (label, der) = pem_body(pem).ok_or("the SNS key is not PEM")?;
        let key = match label {
            "PRIVATE KEY" => KeyPair::from_pkcs8(&der),
            "RSA PRIVATE KEY" => KeyPair::from_der(&der),
            _ => return Err("the SNS key is not an RSA private key".to_owned()),
        }
        .map_err(|_| "the SNS key is not an RSA private key of 2048 bits or more".to_owned())?;
        Ok(Self {
            key,
            certificate_url,
        })
    }

    /// `string`'s signature, in base64.
    pub fn sign(&self, string: &str) -> String {
        let mut signature = vec![0; self.key.public_modulus_len()];
        signed(&self.key, string.as_bytes(), &mut signature);
        STANDARD.encode(signature)
    }
}

/// aws-lc-rs takes a generator for RSA signing and ignores it: PKCS#1 v1.5
/// signatures are deterministic, so nothing random reaches the output.
#[allow(clippy::disallowed_types)]
fn signed(key: &KeyPair, input: &[u8], signature: &mut [u8]) {
    key.sign(
        &RSA_PKCS1_SHA256,
        &aws_lc_rs::rand::SystemRandom::new(),
        input,
        signature,
    )
    .expect("a signature the key's own length always signs");
}

/// A `SubscriptionConfirmation`: what a new subscriber is posted, so it can
/// confirm by visiting `subscribe_url`.
pub struct Confirmation<'a> {
    pub message_id: &'a str,
    pub topic_arn: &'a str,
    pub token: &'a str,
    pub subscribe_url: &'a str,
    /// In SNS's form, `2026-10-29T12:00:00.000Z`.
    pub timestamp: &'a str,
}

/// A `Notification`: one event published to the topic.
pub struct Notification<'a> {
    pub message_id: &'a str,
    pub topic_arn: &'a str,
    /// The event, as SES publishes it: JSON, held as a string.
    pub message: &'a str,
    pub timestamp: &'a str,
    pub unsubscribe_url: &'a str,
}

/// A message's JSON, its members in SNS's order.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Message<'a> {
    #[serde(rename = "Type")]
    kind: &'static str,
    message_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    topic_arn: &'a str,
    message: &'a str,
    #[serde(rename = "SubscribeURL", skip_serializing_if = "Option::is_none")]
    subscribe_url: Option<&'a str>,
    timestamp: &'a str,
    signature_version: &'static str,
    signature: String,
    #[serde(rename = "SigningCertURL")]
    signing_cert_url: &'a str,
    #[serde(rename = "UnsubscribeURL", skip_serializing_if = "Option::is_none")]
    unsubscribe_url: Option<&'a str>,
}

/// The `SubscriptionConfirmation` a new subscriber is posted, signed.
pub fn confirmation(signer: &Signer, confirmation: &Confirmation<'_>) -> Vec<u8> {
    let message = format!(
        "You have chosen to subscribe to the topic {}.\nTo confirm the subscription, visit the SubscribeURL included in this message.",
        confirmation.topic_arn
    );
    // SNS's string to sign for a confirmation (SignatureVersion 2).
    let string = [
        ("Message", message.as_str()),
        ("MessageId", confirmation.message_id),
        ("SubscribeURL", confirmation.subscribe_url),
        ("Timestamp", confirmation.timestamp),
        ("Token", confirmation.token),
        ("TopicArn", confirmation.topic_arn),
        ("Type", "SubscriptionConfirmation"),
    ];
    serde_json::to_vec(&Message {
        kind: "SubscriptionConfirmation",
        message_id: confirmation.message_id,
        token: Some(confirmation.token),
        topic_arn: confirmation.topic_arn,
        message: &message,
        subscribe_url: Some(confirmation.subscribe_url),
        timestamp: confirmation.timestamp,
        signature_version: "2",
        signature: signer.sign(&to_sign(&string)),
        signing_cert_url: &signer.certificate_url,
        unsubscribe_url: None,
    })
    .expect("a message always serialises")
}

/// A `Notification` of one event, signed.
pub fn notification(signer: &Signer, notification: &Notification<'_>) -> Vec<u8> {
    // SNS's string to sign for a notification with no subject.
    let string = [
        ("Message", notification.message),
        ("MessageId", notification.message_id),
        ("Timestamp", notification.timestamp),
        ("TopicArn", notification.topic_arn),
        ("Type", "Notification"),
    ];
    serde_json::to_vec(&Message {
        kind: "Notification",
        message_id: notification.message_id,
        token: None,
        topic_arn: notification.topic_arn,
        message: notification.message,
        subscribe_url: None,
        timestamp: notification.timestamp,
        signature_version: "2",
        signature: signer.sign(&to_sign(&string)),
        signing_cert_url: &signer.certificate_url,
        unsubscribe_url: Some(notification.unsubscribe_url),
    })
    .expect("a message always serialises")
}

/// SNS's string to sign: each member's name and value on lines of their
/// own, in the order SNS gives.
fn to_sign(members: &[(&str, &str)]) -> String {
    members
        .iter()
        .map(|(name, value)| format!("{name}\n{value}\n"))
        .collect()
}

/// A PEM block's label and its body, decoded.
fn pem_body(pem: &str) -> Option<(&str, Vec<u8>)> {
    let begin = pem.find("-----BEGIN ")? + "-----BEGIN ".len();
    let rest = &pem[begin..];
    let label_end = rest.find("-----")?;
    let label = &rest[..label_end];
    let body_start = label_end + 5;
    let end = rest.find(&format!("-----END {label}-----"))?;
    let body: String = rest[body_start..end]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    STANDARD.decode(body).ok().map(|der| (label, der))
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    use super::*;

    fn signer() -> (Signer, Vec<u8>) {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&pair).unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(pkcs8.as_ref())
        );
        let public = pair.public_key().as_ref().to_vec();
        let signer =
            Signer::from_pem(&pem, "https://ses.example.test/sns/abc.pem".to_owned()).unwrap();
        (signer, public)
    }

    /// Checks a message as SNS's own verifiers check one: the string to
    /// sign rebuilt from its members, by type, against its signature.
    fn verifies(public: &[u8], message: &serde_json::Value) -> bool {
        let member = |name: &str| message[name].as_str().unwrap_or_default().to_owned();
        let names: &[&str] = match message["Type"].as_str() {
            Some("Notification") => &["Message", "MessageId", "Timestamp", "TopicArn", "Type"],
            _ => &[
                "Message",
                "MessageId",
                "SubscribeURL",
                "Timestamp",
                "Token",
                "TopicArn",
                "Type",
            ],
        };
        let string: String = names
            .iter()
            .map(|name| format!("{name}\n{}\n", member(name)))
            .collect();
        let signature = STANDARD.decode(member("Signature")).unwrap();
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public)
            .verify(string.as_bytes(), &signature)
            .is_ok()
    }

    #[test]
    fn a_confirmation_and_a_notification_verify_as_snss_own_do() {
        let (signer, public) = signer();
        let topic = "arn:aws:sns:us-east-1:000000000001:feedback";
        let confirmation = confirmation(
            &signer,
            &Confirmation {
                message_id: "m-1",
                topic_arn: topic,
                token: "0a1b",
                subscribe_url: "https://ses.example.test/?Action=ConfirmSubscription&Token=0a1b",
                timestamp: "2026-10-29T12:00:00.000Z",
            },
        );
        let confirmation: serde_json::Value = serde_json::from_slice(&confirmation).unwrap();
        assert_eq!(confirmation["Type"], "SubscriptionConfirmation");
        assert_eq!(confirmation["SignatureVersion"], "2");
        assert_eq!(
            confirmation["SigningCertURL"],
            "https://ses.example.test/sns/abc.pem"
        );
        assert!(verifies(&public, &confirmation));
        let event = r#"{"eventType":"Bounce","mail":{"messageId":"0001"}}"#;
        let notification = notification(
            &signer,
            &Notification {
                message_id: "m-2",
                topic_arn: topic,
                message: event,
                timestamp: "2026-10-29T12:00:01.000Z",
                unsubscribe_url: "https://ses.example.test/?Action=Unsubscribe",
            },
        );
        let notification: serde_json::Value = serde_json::from_slice(&notification).unwrap();
        assert_eq!(notification["Message"], event, "the event, as a string");
        assert!(verifies(&public, &notification));
        // A changed member no longer verifies.
        let mut forged = notification.clone();
        forged["Message"] = serde_json::Value::from("{}");
        assert!(!verifies(&public, &forged));
    }
}
