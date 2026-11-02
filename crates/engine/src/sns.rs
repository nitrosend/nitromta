//! The SNS subset's key and certificates: what its messages are
//! signed with, read from `[sns] key` at the start and again on SIGHUP, and
//! the certificates consumers verify them with, served by the SES API's
//! listener at `/sns/<the certificate's SHA-256>.pem`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use aws_lc_rs::digest::{SHA256, digest};
use aws_smithy_http_server::body::{BoxBody, to_boxed};
use bytes::Bytes;
use engine_api::ses::ErrorResponse;
use engine_api::sigv4;
use engine_api::snapshot::Snapshot;
use engine_api::sns::{self, Arns, Operation, Refused, Request, SERVICE};
use engine_core::command::{Answer, Command, Commit};
use engine_core::id::{SubscriptionId, TopicId};
use engine_core::policy::{Change, Policy};
use engine_events::sns::Signer;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;

use crate::config;
use crate::ses::Ses;

/// Where certificates are served, under `[sns] url`.
pub const CERTIFICATES: &str = "/sns/";

pub struct Sns {
    /// The HTTPS origin consumers reach the listener at.
    pub url: String,
    settings: Settings,
    current: RwLock<Arc<Signing>>,
}

/// Where its key and certificates are read from.
struct Settings {
    key: std::path::PathBuf,
    certificate: std::path::PathBuf,
    previous: Vec<std::path::PathBuf>,
}

/// The signer, and every certificate served, by its path.
pub struct Signing {
    pub signer: Arc<Signer>,
    certificates: BTreeMap<String, String>,
}

impl Sns {
    pub fn load(config: &config::Sns) -> Result<Self, String> {
        let url = config.url.trim_end_matches('/').to_owned();
        let origin = url
            .strip_prefix("https://")
            .is_some_and(|host| !host.is_empty() && !host.contains('/'));
        if !origin {
            return Err(
                "sns's url must be an https origin, such as https://ses.example.com".to_owned(),
            );
        }
        let settings = Settings {
            key: config.key.clone(),
            certificate: config.certificate.clone(),
            previous: config.previous_certificates.clone(),
        };
        let signing = signing(&settings, &url)?;
        Ok(Self {
            url,
            settings,
            current: RwLock::new(Arc::new(signing)),
        })
    }

    /// Reads the key and certificates again: one that cannot be read, or a
    /// key that is not its certificate's, leaves the ones there were.
    pub fn reload(&self) -> Result<(), String> {
        let signing = signing(&self.settings, &self.url)?;
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(signing);
        Ok(())
    }

    pub fn signing(&self) -> Arc<Signing> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// The certificate served at `path`, if it is one.
    pub fn certificate(&self, path: &str) -> Option<String> {
        self.signing().certificates.get(path).cloned()
    }

    pub fn key(&self) -> &Path {
        &self.settings.key
    }
}

/// The signer of the key in `settings`, whose certificate must be its own,
/// and the certificates served.
fn signing(settings: &Settings, url: &str) -> Result<Signing, String> {
    let read = |path: &Path| {
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
    };
    // Read once: what is served is what the key is checked against, however
    // the file changes meanwhile.
    let pem = read(&settings.certificate)?;
    let (current, current_pem) = served(&pem)?;
    let signer = Signer::from_pem(&read(&settings.key)?, format!("{url}{current}"))?;
    // The key signs what its certificate verifies, or consumers verify
    // nothing it signs.
    let der = CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|error| format!("{}: {error}", settings.certificate.display()))?;
    let certificate = webpki::EndEntityCert::try_from(&der)
        .map_err(|error| format!("{}: {error}", settings.certificate.display()))?;
    let probe = "a probe of the SNS key";
    let signature = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        signer.sign(probe),
    )
    .map_err(|_| "the SNS key's signature is not base64".to_owned())?;
    certificate
        .verify_signature(
            webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
            probe.as_bytes(),
            &signature,
        )
        .map_err(|_| {
            format!(
                "{} is not the certificate of the key in {}",
                settings.certificate.display(),
                settings.key.display()
            )
        })?;
    let mut certificates = BTreeMap::from([(current, current_pem)]);
    for path in &settings.previous {
        let (at, pem) = served(&read(path)?)?;
        certificates.insert(at, pem);
    }
    Ok(Signing {
        signer: Arc::new(signer),
        certificates,
    })
}

/// Where a certificate in PEM is served, by the SHA-256 of its DER, and the
/// PEM served there.
fn served(pem: &str) -> Result<(String, String), String> {
    let der = CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|error| format!("an SNS certificate: {error}"))?;
    let hash: String = digest(&SHA256, der.as_ref())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((format!("{CERTIFICATES}{hash}.pem"), pem.to_owned()))
}

/// A refusal the listener makes before it reads a request on SNS's route,
/// in SNS's XML.
pub fn early(ses: &Ses, refused: &ErrorResponse) -> http::Response<BoxBody> {
    let request_id = format!("{:016x}", ses.new_id().as_u64());
    let answer = engine_api::sns::refusal(&Refused::early(refused), &request_id);
    respond(answer.status, "text/xml", answer.body)
}

/// Answers an SNS request on the SES API's listener: a certificate, or one
/// of the subset's operations, signed for SNS by a key that manages its
/// account, or authorised by the subscriber's token its URL carries.
pub async fn answer(
    ses: &Arc<Ses>,
    sns: &Arc<Sns>,
    parts: &http::request::Parts,
    body: &Bytes,
    peer: IpAddr,
) -> http::Response<BoxBody> {
    let path = parts.uri.path();
    if parts.method == http::Method::GET && path.starts_with(CERTIFICATES) {
        return match sns.certificate(path) {
            Some(pem) => respond(200, "application/x-pem-file", pem),
            None => respond(404, "text/plain", "No such certificate".to_owned()),
        };
    }
    let request_id = format!("{:016x}", ses.new_id().as_u64());
    let refused = |refused: &Refused| {
        let answer = engine_api::sns::refusal(refused, &request_id);
        respond(answer.status, "text/xml", answer.body)
    };
    let form = if parts.method == http::Method::GET {
        parts.uri.query().unwrap_or_default().as_bytes()
    } else {
        body
    };
    let request = Request::parse(form);
    let snapshot = ses.policy.load();
    let account = if parts.headers.contains_key(http::header::AUTHORIZATION) {
        let headers: Vec<(&str, &[u8])> = parts
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect();
        let signed = sigv4::Request {
            method: parts.method.as_str(),
            path,
            query: parts.uri.query().unwrap_or_default(),
            headers: &headers,
            body,
        };
        let now = ses.clock.now().wall;
        let region = &ses.region;
        match engine_api::ses::verify(&signed, snapshot.policy(), region, SERVICE, now) {
            Ok(credential) if credential.permissions.manages => credential.account,
            Ok(_) => {
                return refused(&Refused::not_authorised(
                    "This access key may not manage its account: it only sends",
                ));
            }
            Err(failure) => {
                ses.acceptance.authentication_failed(peer);
                return refused(&Refused::denied(&failure));
            }
        }
    } else {
        match request.account() {
            Some(account) => account,
            None => return refused(&Refused::not_authorised("The request is not signed")),
        }
    };
    let signed = parts.headers.contains_key(http::header::AUTHORIZATION);
    let arns = Arns {
        region: &ses.region,
        account,
    };
    let operation = match engine_api::sns::operation(&request, arns) {
        Ok(operation) if signed || operation.authorised_by_token() => operation,
        Ok(_) => return refused(&Refused::not_authorised("The request is not signed")),
        Err(refusal) => return refused(&refusal),
    };
    let answered = operate(ses, sns, snapshot.policy(), arns, operation, &request_id).await;
    match answered {
        Ok(answer) => respond(answer.status, "text/xml", answer.body),
        Err(refusal) => {
            // A token that confirms nothing counts as a failed sign-in, so
            // tokens cannot be guessed at speed.
            if !signed && refusal.status == 403 {
                ses.acceptance.authentication_failed(peer);
            }
            refused(&refusal)
        }
    }
}

/// Carries out `operation`, as `arns`' account asked.
async fn operate(
    ses: &Arc<Ses>,
    sns: &Arc<Sns>,
    policy: &Policy,
    arns: Arns<'_>,
    operation: Operation,
    request_id: &str,
) -> Result<engine_api::sns::Answer, Refused> {
    let account = arns.account;
    Ok(match operation {
        Operation::CreateTopic { name } => {
            let id = TopicId(ses.new_id());
            let snapshot = changed(ses, sns::create_topic(account, id, &name)).await?;
            let topic = sns::topic(snapshot.policy(), account, &name)?;
            sns::created_topic(arns, topic, request_id)
        }
        Operation::GetTopicAttributes { topic } => sns::topic_attributes(
            policy,
            arns,
            sns::topic(policy, account, &topic)?,
            request_id,
        ),
        Operation::Subscribe {
            topic,
            endpoint,
            return_arn,
        } => {
            let found = sns::topic(policy, account, &topic)?;
            // Subscribed already: its ARN, or, while it is pending, its
            // confirmation posted again.
            let (policy, subscriber) = match sns::subscriber_at(policy, found, &endpoint) {
                Some(subscriber) => (ses.policy.load(), subscriber.id),
                None => {
                    let mut token = [0; 32];
                    aws_lc_rs::rand::fill(&mut token)
                        .map_err(|_| Refused::busy("No randomness for a token; try again"))?;
                    let id = SubscriptionId(ses.new_id());
                    let change = sns::subscribe(account, id, &topic, &endpoint, token);
                    (changed(ses, change).await?, id)
                }
            };
            let policy = policy.policy();
            let topic = sns::topic(policy, account, &topic)?;
            let subscriber = policy
                .subscriber(subscriber)
                .ok_or_else(|| Refused::busy("Try again"))?;
            if !subscriber.confirmed {
                confirm_by_post(ses, sns, arns, topic, subscriber);
            }
            sns::subscribed(arns, topic, subscriber, return_arn, request_id)
        }
        Operation::ConfirmSubscription { topic, token } => {
            let snapshot = changed(ses, sns::confirm(account, &topic, token)).await?;
            let policy = snapshot.policy();
            let found = sns::topic(policy, account, &topic)?;
            let subscriber = policy
                .subscribers()
                .find(|subscriber| subscriber.topic == found.id && subscriber.token == token)
                .ok_or_else(|| Refused::busy("Try again"))?;
            sns::confirmed(arns, found, subscriber, request_id)
        }
        Operation::Unsubscribe {
            subscription,
            token,
            ..
        } => {
            let change = sns::unsubscribe(policy, account, subscription, token.as_ref())?;
            changed(ses, change).await?;
            sns::unsubscribed(request_id)
        }
        Operation::ListSubscriptionsByTopic { topic, after } => sns::subscriptions(
            policy,
            arns,
            sns::topic(policy, account, &topic)?,
            after,
            request_id,
        ),
    })
}

/// Commits `change`, and returns the policy it made, which the store
/// publishes before it answers.
async fn changed(ses: &Ses, change: Change) -> Result<Arc<Snapshot>, Refused> {
    match ses
        .acceptance
        .store
        .ask(Command::ChangePolicy(change))
        .await
    {
        Some(Answer::Policy(Commit::Committed(_))) => Ok(ses.policy.load()),
        Some(Answer::Policy(Commit::Refused(refusal))) => Err(sns::refused(&refusal)),
        _ => Err(Refused::busy(
            "Storage could not say whether it changed; try again",
        )),
    }
}

/// Posts `subscriber` its `SubscriptionConfirmation`, once, on a task of
/// its own: one it does not take is posted again when it subscribes again,
/// as SNS's are.
fn confirm_by_post(
    ses: &Arc<Ses>,
    sns: &Arc<Sns>,
    arns: Arns<'_>,
    topic: &engine_core::policy::Topic,
    subscriber: &engine_core::policy::Subscriber,
) {
    let topic_arn = arns.topic(&topic.name);
    let token = sns::token_text(&subscriber.token);
    let subscribe_url = format!(
        "{}/?Action=ConfirmSubscription&TopicArn={}&Token={token}",
        sns.url,
        encoded(&topic_arn)
    );
    let message_id = format!("{:016x}", ses.new_id().as_u64());
    let timestamp = engine_api::inspect::rfc3339(ses.clock.now().wall);
    let body = engine_events::sns::confirmation(
        &sns.signing().signer,
        &engine_events::sns::Confirmation {
            message_id: &message_id,
            topic_arn: &topic_arn,
            token: &token,
            subscribe_url: &subscribe_url,
            timestamp: &timestamp,
        },
    );
    let headers = vec![
        (
            engine_events::sns::MESSAGE_TYPE,
            "SubscriptionConfirmation".to_owned(),
        ),
        (engine_events::sns::MESSAGE_ID, message_id),
        (engine_events::sns::TOPIC_ARN, topic_arn),
    ];
    let endpoint = subscriber.endpoint.clone();
    let network = ses.network.clone();
    tokio::spawn(async move {
        let posted = crate::events::post_once(
            &network,
            &endpoint,
            engine_events::sns::CONTENT_TYPE,
            &headers,
            Bytes::from(body),
        )
        .await;
        // The endpoint itself is never logged: its path or query may hold
        // a secret of the subscriber's.
        if let Err(why) = posted {
            tracing::warn!(%why, "a subscriber was not posted its confirmation");
        }
    });
}

/// Text as a URL's query holds it.
fn encoded(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn respond(status: u16, content_type: &'static str, body: String) -> http::Response<BoxBody> {
    let mut response = http::Response::new(to_boxed(body));
    *response.status_mut() =
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::BAD_REQUEST);
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    response
}
