//! The SNS subset: the topics SES-shaped event destinations
//! publish to, and their subscribers, over AWS Query, a form whose `Action`
//! names the operation, posted to `/` and answered in XML.
//!
//! `CreateTopic`, `GetTopicAttributes`, `Subscribe`, `ConfirmSubscription`,
//! `Unsubscribe` and `ListSubscriptionsByTopic`, for a key that manages its
//! account. A subscriber is an `http` or `https` endpoint, and is posted
//! nothing but its confirmation until it confirms, by `ConfirmSubscription`
//! with its token or by visiting the `SubscribeURL` it was posted, which
//! carries the token: that, and the `UnsubscribeURL` each notification
//! carries, need no signature, as SNS's own do not. Any other operation, and
//! any attribute the engine does not carry out, is refused by name.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use engine_core::id::{AccountId, Id, SubscriptionId, TopicId};
use engine_core::policy::{Change, Policy, PolicyRefusal, Subscriber, Target, Topic};

use crate::sigv4;

/// The service SNS's clients sign for.
pub const SERVICE: &str = "sns";

/// The namespace SNS's answers are in.
const NAMESPACE: &str = "http://sns.amazonaws.com/doc/2010-03-31/";

/// The most subscriptions one page of `ListSubscriptionsByTopic` holds, as
/// SNS's does.
const PAGE: usize = 100;

/// A request's parameters, from its form or its query.
pub struct Request {
    parameters: BTreeMap<String, String>,
}

impl Request {
    /// The parameters of a form, `application/x-www-form-urlencoded`, as a
    /// POST's body or a GET's query holds them.
    pub fn parse(form: &[u8]) -> Self {
        let form = String::from_utf8_lossy(form);
        let parameters = form
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                let decode = |text: &str| sigv4::decode(&text.replace('+', " "));
                (decode(name), decode(value))
            })
            .collect();
        Self { parameters }
    }

    pub fn action(&self) -> Option<&str> {
        self.get("Action")
    }

    /// The account the ARN it names is in: what an unsigned request,
    /// authorised by a token, is answered for.
    pub fn account(&self) -> Option<AccountId> {
        let arn = self
            .get("TopicArn")
            .or_else(|| self.get("SubscriptionArn"))?;
        let mut parts = arn.split(':');
        let account = parts.nth(4)?;
        (account.len() >= 12 && account.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| account.parse().ok())
            .flatten()
            .and_then(Id::from_u64)
            .map(AccountId)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.parameters.get(name).map(String::as_str)
    }

    fn required(&self, name: &str) -> Result<&str, Refused> {
        self.get(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Refused::invalid(&format!("{name} is required")))
    }

    /// Whether it gives any parameter starting `prefix`: an attribute or a
    /// tag, which the engine refuses rather than ignores.
    fn gives(&self, prefix: &str) -> bool {
        self.parameters.keys().any(|name| name.starts_with(prefix))
    }
}

/// An account's topics and subscriptions as AWS names them:
/// `arn:aws:sns:<region>:<account>:<topic>`, and a subscription's the
/// topic's with its ID after it.
#[derive(Clone, Copy, Debug)]
pub struct Arns<'a> {
    pub region: &'a str,
    pub account: AccountId,
}

impl Arns<'_> {
    pub fn topic(&self, name: &str) -> String {
        format!(
            "arn:aws:sns:{}:{:012}:{name}",
            self.region,
            self.account.0.as_u64()
        )
    }

    pub fn subscription(&self, topic: &Topic, subscriber: &Subscriber) -> String {
        format!(
            "{}:{:016x}",
            self.topic(&topic.name),
            subscriber.id.0.as_u64()
        )
    }

    /// The topic `arn` names, if it is one of this region's and account's.
    pub fn topic_name<'b>(&self, arn: &'b str) -> Option<&'b str> {
        let name = arn.strip_prefix(self.topic("").as_str())?;
        (!name.is_empty() && !name.contains(':')).then_some(name)
    }

    /// The topic and subscription `arn` names.
    fn subscription_of<'b>(&self, arn: &'b str) -> Option<(&'b str, SubscriptionId)> {
        let (topic, id) = arn.rsplit_once(':')?;
        let id = u64::from_str_radix(id, 16).ok().and_then(Id::from_u64)?;
        Some((self.topic_name(topic)?, SubscriptionId(id)))
    }
}

/// A token as SNS shows one: in hex.
pub fn token_text(token: &[u8; 32]) -> String {
    token.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn token_of(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut token = [0; 32];
    for (at, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).ok()?;
    }
    Some(token)
}

/// What a request asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Operation {
    CreateTopic {
        name: String,
    },
    GetTopicAttributes {
        topic: String,
    },
    Subscribe {
        topic: String,
        endpoint: String,
        /// Whether its answer gives the subscription's ARN while it is
        /// pending, as `ReturnSubscriptionArn` asks.
        return_arn: bool,
    },
    ConfirmSubscription {
        topic: String,
        token: [u8; 32],
    },
    Unsubscribe {
        topic: String,
        subscription: SubscriptionId,
        /// The token an `UnsubscribeURL` carries, which authorises it with
        /// no signature.
        token: Option<[u8; 32]>,
    },
    ListSubscriptionsByTopic {
        topic: String,
        after: Option<SubscriptionId>,
    },
}

impl Operation {
    /// Whether it may be asked with no signature: the `SubscribeURL` and
    /// `UnsubscribeURL` a subscriber is posted, which carry its token.
    pub fn authorised_by_token(&self) -> bool {
        matches!(
            self,
            Self::ConfirmSubscription { .. } | Self::Unsubscribe { token: Some(_), .. }
        )
    }
}

/// Why a request was refused, as SNS answers it.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl Refused {
    fn invalid(message: &str) -> Self {
        Self {
            status: 400,
            code: "InvalidParameter",
            message: message.to_owned(),
        }
    }

    pub fn not_found(message: &str) -> Self {
        Self {
            status: 404,
            code: "NotFound",
            message: message.to_owned(),
        }
    }

    /// A signature that does not sign its request, as SNS answers one: in
    /// AWS Query's codes, which SDKs act on, a skewed clock's by correcting
    /// it and signing again.
    pub fn denied(failure: &sigv4::Failure) -> Self {
        let code = match failure {
            sigv4::Failure::Missing => "MissingAuthenticationToken",
            sigv4::Failure::Malformed(_) => "IncompleteSignature",
            sigv4::Failure::UnknownKey => "InvalidClientTokenId",
            sigv4::Failure::Skewed | sigv4::Failure::WrongScope | sigv4::Failure::Signature => {
                "SignatureDoesNotMatch"
            }
        };
        Self {
            status: failure.status(),
            code,
            message: failure.message().to_owned(),
        }
    }

    /// What the listener refuses before it knows a request is SNS's, as SNS
    /// words it: throttling as AWS Query's `Throttling`, which SDKs try
    /// again, and anything else a parameter it cannot take.
    pub fn early(refused: &crate::ses::ErrorResponse) -> Self {
        Self {
            status: refused.status,
            code: if refused.status == 429 {
                "Throttling"
            } else {
                "InvalidParameter"
            },
            message: refused.message.clone(),
        }
    }

    /// A request its key may not make, or a token that does not authorise
    /// it.
    pub fn not_authorised(message: &str) -> Self {
        Self {
            status: 403,
            code: "AuthorizationError",
            message: message.to_owned(),
        }
    }

    /// For now: the store could not say, or IDs collided.
    pub fn busy(message: &str) -> Self {
        Self {
            status: 400,
            code: "Throttled",
            message: message.to_owned(),
        }
    }
}

/// The operation `request` asks for, in `arns`' account.
pub fn operation(request: &Request, arns: Arns<'_>) -> Result<Operation, Refused> {
    let topic = |name: &str| -> Result<String, Refused> {
        let arn = request.required(name)?;
        arns.topic_name(arn)
            .map(str::to_owned)
            .ok_or_else(|| Refused::not_found(&format!("Topic does not exist: {arn}")))
    };
    let token = || -> Result<[u8; 32], Refused> {
        token_of(request.required("Token")?).ok_or_else(|| Refused::invalid("Invalid token"))
    };
    Ok(match request.action() {
        Some("CreateTopic") => {
            if request.gives("Attributes.") || request.gives("Tags.") {
                return Err(Refused::invalid(
                    "Attributes and Tags are not supported on topics",
                ));
            }
            Operation::CreateTopic {
                name: request.required("Name")?.to_owned(),
            }
        }
        Some("GetTopicAttributes") => Operation::GetTopicAttributes {
            topic: topic("TopicArn")?,
        },
        Some("Subscribe") => {
            if request.gives("Attributes.") {
                return Err(Refused::invalid(
                    "Attributes are not supported on subscriptions: each is posted SNS's JSON",
                ));
            }
            let protocol = request.required("Protocol")?;
            let endpoint = request.get("Endpoint").unwrap_or_default();
            let matches = matches!(protocol, "http" | "https")
                && endpoint.starts_with(&format!("{protocol}://"));
            if !matches {
                return Err(Refused::invalid(
                    "Only http and https endpoints are supported, each a URL of its protocol",
                ));
            }
            Operation::Subscribe {
                topic: topic("TopicArn")?,
                endpoint: endpoint.to_owned(),
                return_arn: request.get("ReturnSubscriptionArn") == Some("true"),
            }
        }
        Some("ConfirmSubscription") => Operation::ConfirmSubscription {
            topic: topic("TopicArn")?,
            token: token()?,
        },
        Some("Unsubscribe") => {
            let arn = request.required("SubscriptionArn")?;
            let (topic, subscription) = arns.subscription_of(arn).ok_or_else(|| {
                Refused::not_found(&format!("Subscription does not exist: {arn}"))
            })?;
            Operation::Unsubscribe {
                topic: topic.to_owned(),
                subscription,
                token: request.get("Token").map(|_| token()).transpose()?,
            }
        }
        Some("ListSubscriptionsByTopic") => Operation::ListSubscriptionsByTopic {
            topic: topic("TopicArn")?,
            after: request
                .get("NextToken")
                .map(|token| {
                    u64::from_str_radix(token, 16)
                        .ok()
                        .and_then(Id::from_u64)
                        .map(SubscriptionId)
                        .ok_or_else(|| Refused::invalid("Invalid NextToken"))
                })
                .transpose()?,
        },
        Some(other) => {
            return Err(Refused {
                status: 400,
                code: "InvalidAction",
                message: format!("NitroMTA does not implement this SNS operation ({other})."),
            });
        }
        None => return Err(Refused::invalid("Action is required")),
    })
}

/// `CreateTopic`'s change.
pub fn create_topic(account: AccountId, id: TopicId, name: &str) -> Change {
    Change::Topic {
        id,
        account,
        name: name.to_owned(),
    }
}

/// `Subscribe`'s change: a pending subscriber with its new token.
pub fn subscribe(
    account: AccountId,
    id: SubscriptionId,
    topic: &str,
    endpoint: &str,
    token: [u8; 32],
) -> Change {
    Change::Subscribe {
        id,
        account,
        topic: topic.to_owned(),
        endpoint: endpoint.to_owned(),
        token,
    }
}

/// `ConfirmSubscription`'s change.
pub fn confirm(account: AccountId, topic: &str, token: [u8; 32]) -> Change {
    Change::Confirm {
        account,
        topic: topic.to_owned(),
        token,
    }
}

/// `Unsubscribe`'s change, once its token, if it gives one, is the
/// subscriber's.
pub fn unsubscribe(
    policy: &Policy,
    account: AccountId,
    subscription: SubscriptionId,
    token: Option<&[u8; 32]>,
) -> Result<Change, Refused> {
    let subscriber = policy
        .subscriber(subscription)
        .filter(|subscriber| subscriber.account == account)
        .ok_or_else(|| Refused::not_found("Subscription does not exist"))?;
    if token.is_some_and(|token| *token != subscriber.token) {
        return Err(Refused::not_authorised(
            "The token is not this subscription's",
        ));
    }
    Ok(Change::Remove(Target::Subscriber {
        account,
        id: subscription,
    }))
}

/// What a committed change's refusal is answered as.
pub fn refused(refusal: &PolicyRefusal) -> Refused {
    match refusal {
        PolicyRefusal::Unknown {
            kind: "topic",
            name,
        } => Refused::not_found(&format!("Topic does not exist: {name}")),
        PolicyRefusal::Unknown { .. } => {
            Refused::not_authorised("The token does not confirm a subscription of this topic")
        }
        PolicyRefusal::InvalidName => Refused::invalid(
            "A topic's name is 1 to 256 letters, digits, hyphens and underscores, and an endpoint a URL",
        ),
        _ => Refused::busy("Try again"),
    }
}

/// The account's topic `name`, or SNS's refusal.
pub fn topic<'a>(policy: &'a Policy, account: AccountId, name: &str) -> Result<&'a Topic, Refused> {
    policy
        .topic_named(account, name)
        .ok_or_else(|| Refused::not_found(&format!("Topic does not exist: {name}")))
}

/// The subscriber of `topic` at `endpoint`, if there is one.
pub fn subscriber_at<'a>(
    policy: &'a Policy,
    topic: &Topic,
    endpoint: &str,
) -> Option<&'a Subscriber> {
    policy
        .subscribers()
        .find(|subscriber| subscriber.topic == topic.id && subscriber.endpoint == endpoint)
}

/// An answer: its status and its XML.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub body: String,
}

/// `action`'s answer, its result's members `result` (XML already), under
/// `request_id`.
fn answered(action: &str, result: &str, request_id: &str) -> Answer {
    let mut body = format!("<{action}Response xmlns=\"{NAMESPACE}\">");
    if result.is_empty() {
        let _ = write!(body, "<{action}Result/>");
    } else {
        let _ = write!(body, "<{action}Result>{result}</{action}Result>");
    }
    let _ = write!(
        body,
        "<ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{action}Response>",
        escape(request_id)
    );
    Answer { status: 200, body }
}

/// A refusal's answer.
pub fn refusal(refused: &Refused, request_id: &str) -> Answer {
    Answer {
        status: refused.status,
        body: format!(
            "<ErrorResponse xmlns=\"{NAMESPACE}\"><Error><Type>Sender</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>{}</RequestId></ErrorResponse>",
            refused.code,
            escape(&refused.message),
            escape(request_id)
        ),
    }
}

pub fn created_topic(arns: Arns<'_>, topic: &Topic, request_id: &str) -> Answer {
    answered(
        "CreateTopic",
        &element("TopicArn", &arns.topic(&topic.name)),
        request_id,
    )
}

/// `GetTopicAttributes`' answer: the attributes SNS gives that the engine
/// has.
pub fn topic_attributes(
    policy: &Policy,
    arns: Arns<'_>,
    topic: &Topic,
    request_id: &str,
) -> Answer {
    let subscribers: Vec<&Subscriber> = policy
        .subscribers()
        .filter(|subscriber| subscriber.topic == topic.id)
        .collect();
    let confirmed = subscribers
        .iter()
        .filter(|subscriber| subscriber.confirmed)
        .count();
    let attributes = [
        ("TopicArn", arns.topic(&topic.name)),
        ("Owner", format!("{:012}", arns.account.0.as_u64())),
        ("DisplayName", String::new()),
        ("SubscriptionsConfirmed", confirmed.to_string()),
        (
            "SubscriptionsPending",
            (subscribers.len() - confirmed).to_string(),
        ),
        ("SubscriptionsDeleted", "0".to_owned()),
    ];
    let entries: String = attributes
        .iter()
        .map(|(key, value)| {
            format!(
                "<entry>{}{}</entry>",
                element("key", key),
                element("value", value)
            )
        })
        .collect();
    answered(
        "GetTopicAttributes",
        &format!("<Attributes>{entries}</Attributes>"),
        request_id,
    )
}

/// What a subscription's ARN shows: its ARN once it has confirmed, or, as
/// SNS shows it until then, that it is pending.
fn shown_arn(arns: Arns<'_>, topic: &Topic, subscriber: &Subscriber, always: bool) -> String {
    if subscriber.confirmed || always {
        arns.subscription(topic, subscriber)
    } else {
        "pending confirmation".to_owned()
    }
}

pub fn subscribed(
    arns: Arns<'_>,
    topic: &Topic,
    subscriber: &Subscriber,
    return_arn: bool,
    request_id: &str,
) -> Answer {
    answered(
        "Subscribe",
        &element(
            "SubscriptionArn",
            &shown_arn(arns, topic, subscriber, return_arn),
        ),
        request_id,
    )
}

pub fn confirmed(
    arns: Arns<'_>,
    topic: &Topic,
    subscriber: &Subscriber,
    request_id: &str,
) -> Answer {
    answered(
        "ConfirmSubscription",
        &element("SubscriptionArn", &arns.subscription(topic, subscriber)),
        request_id,
    )
}

pub fn unsubscribed(request_id: &str) -> Answer {
    answered("Unsubscribe", "", request_id)
}

/// `ListSubscriptionsByTopic`: the topic's subscribers in the order of
/// their IDs, a page at a time.
pub fn subscriptions(
    policy: &Policy,
    arns: Arns<'_>,
    topic: &Topic,
    after: Option<SubscriptionId>,
    request_id: &str,
) -> Answer {
    let mut subscribers = policy
        .subscribers()
        .filter(|subscriber| subscriber.topic == topic.id)
        .filter(|subscriber| after.is_none_or(|after| subscriber.id > after));
    let page: Vec<&Subscriber> = subscribers.by_ref().take(PAGE).collect();
    let more = subscribers.next().is_some();
    let members: String = page
        .iter()
        .map(|subscriber| {
            let protocol = subscriber
                .endpoint
                .split_once("://")
                .map_or("https", |(protocol, _)| protocol);
            let arn = if subscriber.confirmed {
                arns.subscription(topic, subscriber)
            } else {
                "PendingConfirmation".to_owned()
            };
            format!(
                "<member>{}{}{}{}{}</member>",
                element("TopicArn", &arns.topic(&topic.name)),
                element("Protocol", protocol),
                element("SubscriptionArn", &arn),
                element("Owner", &format!("{:012}", arns.account.0.as_u64())),
                element("Endpoint", &subscriber.endpoint),
            )
        })
        .collect();
    let mut result = format!("<Subscriptions>{members}</Subscriptions>");
    if let (true, Some(last)) = (more, page.last()) {
        result.push_str(&element(
            "NextToken",
            &format!("{:016x}", last.id.0.as_u64()),
        ));
    }
    answered("ListSubscriptionsByTopic", &result, request_id)
}

fn element(name: &str, value: &str) -> String {
    format!("<{name}>{}</{name}>", escape(value))
}

/// Text as XML holds it.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            c => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountId = AccountId(Id::from_u64(1).unwrap());

    fn arns() -> Arns<'static> {
        Arns {
            region: "us-east-1",
            account: ACCOUNT,
        }
    }

    #[test]
    fn a_form_is_read_as_aws_query_writes_one_and_its_operation_named() {
        let topic = "arn%3Aaws%3Asns%3Aus-east-1%3A000000000001%3Afeedback";
        let form = format!(
            "Action=Subscribe&TopicArn={topic}&Protocol=https&Endpoint=https%3A%2F%2Fhooks.example.test%2Fses%3Fa%3Db+c&Version=2010-03-31"
        );
        assert_eq!(
            operation(&Request::parse(form.as_bytes()), arns()),
            Ok(Operation::Subscribe {
                topic: "feedback".to_owned(),
                endpoint: "https://hooks.example.test/ses?a=b c".to_owned(),
                return_arn: false,
            })
        );
        let refused = |form: &str| operation(&Request::parse(form.as_bytes()), arns()).unwrap_err();
        assert_eq!(refused("Action=Publish").code, "InvalidAction");
        let other_account = "Action=GetTopicAttributes&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A000000000002%3Afeedback";
        assert_eq!(refused(other_account).code, "NotFound");
        let email = format!("Action=Subscribe&TopicArn={topic}&Protocol=email&Endpoint=a%40b.test");
        assert_eq!(refused(&email).code, "InvalidParameter");
        let raw = format!(
            "Action=Subscribe&TopicArn={topic}&Protocol=https&Endpoint=https%3A%2F%2Fh.test&Attributes.entry.1.key=RawMessageDelivery"
        );
        assert_eq!(refused(&raw).code, "InvalidParameter");
        let token = token_text(&[0xab; 32]);
        let confirm = format!("Action=ConfirmSubscription&TopicArn={topic}&Token={token}");
        let confirmation = operation(&Request::parse(confirm.as_bytes()), arns()).unwrap();
        assert!(confirmation.authorised_by_token());
        assert_eq!(
            confirmation,
            Operation::ConfirmSubscription {
                topic: "feedback".to_owned(),
                token: [0xab; 32],
            }
        );
    }

    #[test]
    fn a_refusal_and_an_answer_are_snss_xml_with_their_text_escaped() {
        let answer = refusal(&Refused::not_found("Topic does not exist: <a&b>"), "r-1");
        assert_eq!(answer.status, 404);
        assert_eq!(
            answer.body,
            "<ErrorResponse xmlns=\"http://sns.amazonaws.com/doc/2010-03-31/\"><Error><Type>Sender</Type><Code>NotFound</Code><Message>Topic does not exist: &lt;a&amp;b&gt;</Message></Error><RequestId>r-1</RequestId></ErrorResponse>"
        );
        assert_eq!(
            unsubscribed("r-2").body,
            "<UnsubscribeResponse xmlns=\"http://sns.amazonaws.com/doc/2010-03-31/\"><UnsubscribeResult/><ResponseMetadata><RequestId>r-2</RequestId></ResponseMetadata></UnsubscribeResponse>"
        );
    }
}
