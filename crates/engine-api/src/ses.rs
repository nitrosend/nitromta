//! SES v2: the access keys its requests are signed with,
//! `SendEmail` and `SendBulkEmail` mapped to native acceptance, and SES's
//! answers.
//!
//! A request's options and recipients are checked first. Its From, tenant
//! and configuration set then resolve under policy, and its content is
//! composed from simple parts or taken raw, and prepared exactly as any
//! submitted message is. An option the engine does not support yet is
//! refused by name, never ignored.

use std::net::IpAddr;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::command::{AcceptRefusal, Authority, Commit};
use engine_core::hook::admission::Refused;
use engine_core::id::{MessageId, TemplateId};
use engine_core::message::Mail;
use engine_core::policy::{Credential, Denial, Origin, Policy, Secret};
use engine_core::time::Timestamp;
use engine_message::compose::{self, ComposeError, Parts};
use engine_message::header;
use engine_message::prepare::{self, Limits, Rejection, Stamp};
use engine_ses_v2::error::{
    BadRequestException, MailFromDomainNotVerifiedException, MessageRejected, NotFoundException,
    SendBulkEmailError, SendEmailError, SendingPausedException, TooManyRequestsException,
};
use engine_ses_v2::input::{SendBulkEmailInput, SendEmailInput};
use engine_ses_v2::model::{
    BulkEmailEntry, BulkEmailEntryResult, BulkEmailStatus, Content, Destination, Message,
    MessageHeaderList, MessageTag, Template, TenantName,
};
use engine_ses_v2::output::{SendBulkEmailOutput, SendEmailOutput};

use crate::ses_manage::Arns;
use crate::sigv4::{self, Failure, Request, Scope};
use crate::snapshot::{Snapshot, Tagged, Unprepared, own_from, tag_text, tags_field_refused};
use crate::template;

/// The service SES's clients sign for.
pub const SERVICE: &str = "ses";

/// A listing as SDKs pinned before the engine's model send it, its paging
/// in the query of a `GET`, where the model takes a `POST` with a body:
/// the path and body the generated server
/// decodes in its place, or none for any other request. Its signature is
/// verified against the request as it came, before this.
pub fn older_listing(method: &str, path: &str, query: &str) -> Option<(&'static str, String)> {
    let path = match (method, path) {
        ("GET", "/v2/email/identities") => "/v2/email/list-identities",
        ("GET", "/v2/email/configuration-sets") => "/v2/email/list-configuration-sets",
        _ => return None,
    };
    let mut body = serde_json::Map::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = sigv4::decode(value);
        // A page size that is not a number is the decoder's to refuse.
        let value = match sigv4::decode(name).as_str() {
            "NextToken" => ("NextToken", serde_json::Value::from(value)),
            "PageSize" => (
                "PageSize",
                value
                    .parse::<i64>()
                    .map_or_else(|_| serde_json::Value::from(value), serde_json::Value::from),
            ),
            _ => continue,
        };
        body.insert(value.0.to_owned(), value.1);
    }
    Some((path, serde_json::Value::Object(body).to_string()))
}

/// The credential a request was signed with, once its signature verifies
/// for `service`, SES's or SNS's, in `region`: an access key `policy` holds.
pub fn verify<'a>(
    request: &Request<'_>,
    policy: &'a Policy,
    region: &str,
    service: &str,
    now: Timestamp,
) -> Result<&'a Credential, Failure> {
    let scope = Scope { region, service };
    let id = sigv4::verify(request, &scope, now, |id| {
        match policy.access_key(id).map(|credential| &credential.secret) {
            Some(Secret::AccessKey { secret, .. }) => Some(secret.as_str()),
            _ => None,
        }
    })?;
    policy.access_key(&id).ok_or(Failure::UnknownKey)
}

/// An answer given before a request reaches the SES server, in its
/// restJson1 form: the status, the error code for `X-Amzn-ErrorType`, and
/// the body, and the message it holds.
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub status: u16,
    pub code: &'static str,
    pub body: String,
    pub message: String,
}

impl ErrorResponse {
    /// A request whose signature fails, answered as AWS answers it.
    pub fn denied(failure: &Failure) -> Self {
        Self::new(failure.status(), failure.code(), failure.message())
    }

    /// A request while the engine stops: throttling, which SDKs
    /// try again.
    pub fn shutting_down() -> Self {
        Self::new(
            429,
            "TooManyRequestsException",
            "Service shutting down, try again later.",
        )
    }

    /// A request from an address with too many failed authentications,
    /// refused before its signature is checked.
    pub fn too_many_failures() -> Self {
        Self::new(
            429,
            "TooManyRequestsException",
            "Too many failed authentications from this address; try again later.",
        )
    }

    /// A request while the store cannot take more mail for now:
    /// throttling, which SDKs try again.
    pub fn storage_pressed(reason: &str) -> Self {
        Self::new(
            429,
            "TooManyRequestsException",
            &format!("Not accepting mail for now: {reason}; try again later."),
        )
    }

    /// A request that would take the engine past what it holds of bodies
    /// not yet verified, from every client at once: throttling,
    /// which SDKs try again.
    pub fn busy() -> Self {
        Self::new(
            429,
            "TooManyRequestsException",
            "Too many requests are under way; try again later.",
        )
    }

    /// A request whose body took longer to arrive than the engine waits:
    /// throttling, which every SDK tries again, where some take
    /// a 408 for good.
    pub fn timed_out() -> Self {
        Self::new(
            429,
            "TooManyRequestsException",
            "The request's body took too long to arrive; try again.",
        )
    }

    /// A request for an SES v2 operation the engine does not implement:
    /// refused for good, as a modeled error every operation
    /// lists, so an SDK neither retries it nor takes it for success.
    pub fn not_implemented(method: &str, path: &str) -> Self {
        let path: String = path.chars().take(200).collect();
        Self::new(
            400,
            "BadRequestException",
            &format!("NitroMTA does not implement this SES v2 operation ({method} {path})."),
        )
    }

    /// A request whose access key lacks the permission its operation needs,
    /// refused before it is decoded, as AWS refuses one IAM
    /// does not allow.
    pub fn not_permitted(method: &str, path: &str, sending: bool) -> Self {
        let path: String = path.chars().take(200).collect();
        let may = if sending {
            "send: it only manages"
        } else {
            "manage its account: it only sends"
        };
        Self::new(
            403,
            "AccessDeniedException",
            &format!(
                "This access key is not authorized to perform {method} {path}: it may not {may}."
            ),
        )
    }

    /// A request larger than any message the engine accepts would make.
    pub fn too_large() -> Self {
        Self::new(400, "MessageRejected", TOO_LARGE)
    }

    fn new(status: u16, code: &'static str, message: &str) -> Self {
        let mut body = String::with_capacity(message.len() + 16);
        body.push_str("{\"message\":\"");
        for c in message.chars() {
            match c {
                '"' => body.push_str("\\\""),
                '\\' => body.push_str("\\\\"),
                c if c.is_control() => body.push_str(&format!("\\u{:04x}", u32::from(c))),
                c => body.push(c),
            }
        }
        body.push_str("\"}");
        Self {
            status,
            code,
            body,
            message: message.to_owned(),
        }
    }
}

const TOO_LARGE: &str = "Message length is more than the engine accepts.";

/// Checks what needs no work to check, and returns the request's envelope
/// recipients: To, then Cc, then Bcc, of its Destination, or, for raw
/// content with none, of the message's own fields, as SES reads them.
///
/// `EmailTags` only label events: SES-shaped events carry them.
pub fn check(
    input: &SendEmailInput,
    max_recipients: usize,
) -> Result<Vec<Address>, SendEmailError> {
    if let Some(option) = unsupported(input) {
        return Err(bad(format!("{option} is not supported")));
    }
    tags_checked(input.email_tags.as_deref())?;
    if let Some(simple) = &input.content.simple {
        header_tags_checked(simple.headers.as_ref())?;
    }
    if let Some(template) = &input.content.template {
        header_tags_checked(template.headers.as_ref())?;
    }
    let recipients: Vec<Address> = match (&input.destination, &input.content.raw) {
        (Some(destination), _) => [
            &destination.to_addresses,
            &destination.cc_addresses,
            &destination.bcc_addresses,
        ]
        .into_iter()
        .flatten()
        .flatten()
        .map(|value| {
            prepare::mailbox(value.as_bytes())
                .ok_or_else(|| bad(format!("Invalid recipient address: {value}")))
        })
        .collect::<Result<_, _>>()?,
        (None, Some(raw)) => {
            let mut recipients = Vec::new();
            for name in ["To", "Cc", "Bcc"] {
                for value in header::values(raw.data.as_ref(), name) {
                    recipients.extend(prepare::mailboxes(value).ok_or_else(|| {
                        bad(format!(
                            "The message's {name} field names an address that cannot be read"
                        ))
                    })?);
                }
            }
            recipients
        }
        (None, None) => return Err(bad("Destination is required")),
    };
    if recipients.is_empty() {
        return Err(bad("Destination must name at least one recipient"));
    }
    if recipients.len() > max_recipients {
        return Err(bad(format!("Recipient count exceeds {max_recipients}.")));
    }
    Ok(recipients)
}

/// The message as it will be sent, and the authority it is accepted under.
/// Its identity is FromEmailAddress's, or a raw message's own From's, and
/// its tenant and configuration set are those the request names. It is
/// composed from simple parts or taken raw, then prepared as that identity,
/// and signed when it signs. Its Message-ID, where it has none of its own,
/// carries `id`, as the answer does.
#[allow(clippy::too_many_arguments, reason = "one request's whole context")]
pub fn content(
    input: &SendEmailInput,
    snapshot: &Snapshot,
    credential: &Credential,
    id: MessageId,
    now: Timestamp,
    limits: Limits,
    to: To<'_>,
    arns: Arns<'_>,
    admit: impl FnOnce(Option<&str>, u64) -> bool,
) -> Result<(Authority, Bytes, Option<Mail>), SendEmailError> {
    let To {
        recipients,
        source_ip,
    } = to;
    // Built only for a message whose copy is kept.
    let tagged = || Tagged {
        operation: "SendEmail",
        caller: caller(credential),
        source_ip,
        given: input
            .email_tags
            .iter()
            .flatten()
            .map(|tag| (tag.name.clone(), tag.value.clone()))
            .collect(),
    };
    let email = &input.content;
    let tenant = input.tenant_name.as_ref().map(TenantName::as_str);
    let configuration = input.configuration_set_name.as_deref();
    let named = input
        .from_email_address
        .as_deref()
        .map(|from| {
            prepare::mailbox(from.as_bytes())
                .ok_or_else(|| bad(format!("Invalid FromEmailAddress: {from}")))
        })
        .transpose()?;
    let shown = message_id(id);
    let stamp = Stamp {
        date: now,
        id: &shown,
    };
    match (&email.simple, &email.raw, &email.template) {
        (Some(_), None, None) | (None, None, Some(_)) => {
            let from = named.ok_or_else(|| {
                bad("FromEmailAddress is required for simple and template content")
            })?;
            let (mut authority, sender) = snapshot
                .sending(credential, &from, None, tenant, configuration)
                .map_err(denied)?;
            let composed = match (&email.simple, &email.template) {
                (Some(simple), _) => composed(input, simple, &shown, limits.max_bytes)?,
                (None, Some(template)) => {
                    let parts =
                        template_parts(template, snapshot.policy(), arns, &authority.origin)?;
                    // Checked again at commit, should its tenant lose it.
                    authority.template = parts.kept;
                    templated(input, template, parts, &shown, limits.max_bytes)?
                }
                (None, None) => {
                    return Err(bad(
                        "Content must have exactly one of Simple, Raw and Template",
                    ));
                }
            };
            // Its rates are charged what it comes to as composed, headers
            // and encoding included, before preparation adds its Date,
            // Message-ID and signature, as bulk's and SMTP's are.
            if !admit(tenant, composed.len() as u64) {
                return Err(too_fast());
            }
            let content = prepare::check(&composed, limits)
                .and_then(|checked| checked.sent_as(sender, stamp))
                .map_err(|rejection| refused(&rejection))?;
            let mail = snapshot.mail(&authority, &composed, &content, recipients, || {
                Some((from.clone(), tagged()))
            });
            Ok((authority, content, mail))
        }
        (None, Some(raw), None) => {
            if input.reply_to_addresses.is_some() {
                return Err(bad(
                    "ReplyToAddresses is for simple content: a raw message carries its own Reply-To",
                ));
            }
            // Its Bcc field is taken out whoever it is sent to, the
            // addresses it names or those the request does, so no recipient
            // sees who else was sent it blind.
            let raw = header::without(raw.data.as_ref(), &["Bcc"]);
            let (authority, content) = snapshot
                .prepare(
                    &raw,
                    limits,
                    credential,
                    named.as_ref(),
                    tenant,
                    configuration,
                    stamp,
                    admit,
                )
                .map_err(|unprepared| match unprepared {
                    Unprepared::Rejected(rejection) => refused(&rejection),
                    Unprepared::Denied(denial) => denied(denial),
                    Unprepared::Tags(refusal) => bad(refusal),
                    Unprepared::TooFast => too_fast(),
                })?;
            let mail = snapshot.mail(&authority, &raw, &content, recipients, || {
                Some((named.or_else(|| own_from(&content))?, tagged()))
            });
            Ok((authority, content, mail))
        }
        _ => Err(bad(
            "Content must have exactly one of Simple, Raw and Template",
        )),
    }
}

/// Who a message is sent to, and the address of the client that sent it,
/// which SES-shaped events say.
#[derive(Clone, Copy)]
pub struct To<'a> {
    pub recipients: &'a [Address],
    pub source_ip: IpAddr,
}

/// An entry's content as it is sent, and what SES-shaped events will say
/// of it.
pub type Prepared = (Bytes, Option<Mail>);

/// The access key a request was signed with, or the login a message was
/// submitted with: SES's `ses:caller-identity`.
pub fn caller(credential: &Credential) -> &str {
    match &credential.secret {
        Secret::AccessKey { id, .. } => id,
        Secret::Login { user, .. } => user,
    }
}

/// The answer once an acceptance's commit is known. Success is answered
/// only for a committed acceptance, with the message's ID.
pub fn answered(
    commit: &Commit<(), AcceptRefusal>,
    id: MessageId,
) -> Result<SendEmailOutput, SendEmailError> {
    match commit {
        Commit::Committed(()) => Ok(SendEmailOutput {
            message_id: Some(message_id(id)),
        }),
        // Generated IDs collided: a new attempt draws new ones.
        Commit::Refused(AcceptRefusal::Conflict) => Err(busy("Try again")),
        Commit::Refused(AcceptRefusal::Unauthorised(denial)) => Err(denied(*denial)),
        Commit::Refused(AcceptRefusal::QuotaExceeded) => Err(busy(QUOTA_EXCEEDED)),
        Commit::Refused(_) => Err(rejected("Not accepted")),
        Commit::Unknown => Err(busy(
            "Storage failed as it was accepted; sending it again may deliver it twice",
        )),
        Commit::Unavailable => Err(busy("Storage is unavailable")),
    }
}

/// The answer to a message the admission hook refused: for
/// good, as SES refuses content it will not send; for now, as throttling,
/// which SDKs try again.
pub fn admission_refused(refused: &Refused) -> SendEmailError {
    if refused.permanent {
        rejected(refused.reason.as_str())
    } else {
        busy(&format!("{}; try again later", refused.reason))
    }
}

/// The answer when the engine cannot take the request on at all.
pub fn unavailable() -> SendEmailError {
    busy("Try again later")
}

/// The answer when a request would pass its account's or tenant's rate.
pub fn too_fast() -> SendEmailError {
    busy(RATE_EXCEEDED)
}

/// SES's own wording for its sending limits, which applications match on.
const RATE_EXCEEDED: &str = "Maximum sending rate exceeded.";
const QUOTA_EXCEEDED: &str = "Daily message quota exceeded.";

/// The first option a request names that the engine does not support yet.
/// Each changes what SES would do, so a request naming one is refused
/// rather than sent without it.
fn unsupported(input: &SendEmailInput) -> Option<&'static str> {
    [
        (
            "FromEmailAddressIdentityArn",
            input.from_email_address_identity_arn.is_some(),
        ),
        (
            "FeedbackForwardingEmailAddress",
            input.feedback_forwarding_email_address.is_some(),
        ),
        (
            "FeedbackForwardingEmailAddressIdentityArn",
            input
                .feedback_forwarding_email_address_identity_arn
                .is_some(),
        ),
        ("EndpointId", input.endpoint_id.is_some()),
        (
            "ListManagementOptions",
            input.list_management_options.is_some(),
        ),
        (
            "ConfigurationOverrides",
            input.configuration_overrides.is_some(),
        ),
    ]
    .into_iter()
    .find_map(|(option, named)| named.then_some(option))
}

fn composed(
    input: &SendEmailInput,
    simple: &Message,
    id: &str,
    most: usize,
) -> Result<Vec<u8>, SendEmailError> {
    if simple
        .attachments
        .as_ref()
        .is_some_and(|list| !list.is_empty())
    {
        return Err(bad("Attachments are not supported"));
    }
    let from = input
        .from_email_address
        .as_deref()
        .ok_or_else(|| bad("FromEmailAddress is required for simple content"))?;
    let none = Vec::new();
    let destination = input.destination.as_ref();
    let headers: Vec<(String, String)> = simple
        .headers
        .as_ref()
        .map(|list| {
            list.inner()
                .iter()
                .map(|header| {
                    (
                        header.name.as_str().to_owned(),
                        header.value.as_str().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let parts = Parts {
        from,
        to: destination
            .and_then(|d| d.to_addresses.as_ref())
            .unwrap_or(&none),
        cc: destination
            .and_then(|d| d.cc_addresses.as_ref())
            .unwrap_or(&none),
        reply_to: input.reply_to_addresses.as_ref().unwrap_or(&none),
        subject: utf8(&simple.subject)?,
        text: simple.body.text.as_ref().map(utf8).transpose()?,
        html: simple.body.html.as_ref().map(utf8).transpose()?,
        headers: &headers,
        id,
        most,
    };
    compose::compose(&parts).map_err(|error| match error {
        ComposeError::NoBody => bad("Body must have Text, Html or both"),
        ComposeError::Header(problem) => bad(problem),
        ComposeError::TooLarge => rejected(TOO_LARGE),
    })
}

/// Simple content's text, which is sent as UTF-8: a request naming another
/// character set is refused rather than sent in one it did not ask for.
fn utf8(content: &Content) -> Result<&str, SendEmailError> {
    let named = |name: &str| {
        content
            .charset
            .as_deref()
            .is_some_and(|charset| charset.eq_ignore_ascii_case(name))
    };
    let ascii = (named("US-ASCII") || named("ASCII")) && content.data.is_ascii();
    if content.charset.is_none() || named("UTF-8") || named("UTF8") || ascii {
        return Ok(&content.data);
    }
    Err(bad(format!(
        "Charset {} is not supported: content is sent as UTF-8",
        content.charset.as_deref().unwrap_or_default()
    )))
}

fn refused(rejection: &Rejection) -> SendEmailError {
    match rejection {
        Rejection::TooLarge => rejected(TOO_LARGE),
        Rejection::NulStart => rejected("The message must begin with a header field"),
        Rejection::BareLineFeed | Rejection::LineTooLong => {
            rejected("Every line must end in CRLF and fit in 998 characters")
        }
        Rejection::From | Rejection::FromUnreadable => {
            rejected("The message needs exactly one readable From address")
        }
        Rejection::FromNotAllowed => rejected(NOT_VERIFIED),
        Rejection::Signing(_) => busy("The message could not be signed"),
    }
}

/// The answer to a request policy does not allow.
fn denied(denial: Denial) -> SendEmailError {
    match denial {
        Denial::UnknownIdentity => rejected(NOT_VERIFIED),
        Denial::Unverified => rejected(UNVERIFIED),
        Denial::MailFromUnverified => SendEmailError::MailFromDomainNotVerifiedException(
            MailFromDomainNotVerifiedException {
                message: Some(
                    "The identity's MAIL FROM domain is not verified, and it says to reject its mail until it is"
                        .to_owned(),
                ),
            },
        ),
        // An access key that only manages is refused before its request is
        // decoded; this is its message's own refusal.
        Denial::NotSending => rejected("This access key may not send: it only manages"),
        Denial::IdentityNotPermitted => rejected("This key may not send as that identity"),
        Denial::DifferentFrom => rejected(
            "FromEmailAddress and the message's From header must be addresses of the same identity",
        ),
        Denial::UnknownTenant => not_found("The tenant does not exist"),
        Denial::UnknownConfiguration => not_found("The configuration set does not exist"),
        Denial::TenantNotPermitted => rejected(
            "This key may not send for that tenant, or must name one of the tenants it sends for",
        ),
        // SES's own opening, which applications match on to repair the
        // association.
        Denial::NotAssociated => bad(
            "Tenant not associated with resources: the identity or the configuration set is not associated with the tenant",
        ),
        // The key was removed while its request was under way.
        Denial::UnknownCredential => busy("Try again"),
        // As SES pauses an account's or a configuration set's sending.
        Denial::Paused => SendEmailError::SendingPausedException(SendingPausedException {
            message: Some("Sending is paused for this mail".to_owned()),
        }),
    }
}

/// SES's own opening, which applications match on.
const NOT_VERIFIED: &str =
    "Email address is not verified. The From address is not an identity of this account.";
const UNVERIFIED: &str = "Email address is not verified. The From address's identity is not yet verified: its DKIM record has not been found.";

/// A message's ID as callers see it: in SES's answers and SMTP's replies,
/// and its Message-ID's part before the `@`.
pub fn message_id(id: MessageId) -> String {
    format!("{:016x}", id.0.as_u64())
}

fn bad(message: impl Into<String>) -> SendEmailError {
    SendEmailError::BadRequestException(BadRequestException {
        message: Some(message.into()),
    })
}

fn not_found(message: &str) -> SendEmailError {
    SendEmailError::NotFoundException(NotFoundException {
        message: Some(message.to_owned()),
    })
}

fn rejected(message: &str) -> SendEmailError {
    SendEmailError::MessageRejected(MessageRejected {
        message: Some(message.to_owned()),
    })
}

/// A request refused at its commit for the reason a request is refused
/// when it comes, and answered as that one is: throttling.
pub fn pressed(reason: &str) -> SendEmailError {
    busy(&format!(
        "Not accepting mail for now: {reason}; try again later."
    ))
}

/// A failure where nothing was accepted, or nothing is known to be. SDKs
/// retry this code with backoff on their own, as SMTP clients retry a 4xx.
fn busy(message: &str) -> SendEmailError {
    SendEmailError::TooManyRequestsException(TooManyRequestsException {
        message: Some(message.to_owned()),
    })
}

/// The most entries one `SendBulkEmail` request carries, as SES allows.
pub const MAX_BULK_ENTRIES: usize = 50;

/// What is decided of each bulk entry before it is accepted: its own
/// result, if it is not sent.
pub type Entry<T> = Result<T, BulkEmailEntryResult>;

/// Checks a bulk request whole, and each of its entries: their recipients,
/// To, then Cc, then Bcc, or each entry's own refusal. A request is a
/// template's inline content (`TemplateContent`) with entries that fill
/// it; a stored template is refused, as is anything else the engine does
/// not support.
pub fn bulk_check(
    input: &SendBulkEmailInput,
    max_recipients: usize,
) -> Result<Vec<Entry<Vec<Address>>>, SendBulkEmailError> {
    if let Some(option) = bulk_unsupported(input) {
        return Err(bulk(bad(format!("{option} is not supported"))));
    }
    let template = input
        .default_content
        .template
        .as_ref()
        .ok_or_else(|| bulk(bad("DefaultContent must have a Template")))?;
    if template
        .attachments
        .as_ref()
        .is_some_and(|list| !list.is_empty())
    {
        return Err(bulk(bad("Attachments are not supported")));
    }
    if input.from_email_address.is_none() {
        return Err(bulk(bad("FromEmailAddress is required")));
    }
    tags_checked(input.default_email_tags.as_deref()).map_err(bulk)?;
    header_tags_checked(template.headers.as_ref()).map_err(bulk)?;
    let entries = &input.bulk_email_entries;
    if entries.is_empty() {
        return Err(bulk(bad("BulkEmailEntries must have at least one entry")));
    }
    if entries.len() > MAX_BULK_ENTRIES {
        return Err(bulk(bad(format!(
            "BulkEmailEntries has more than {MAX_BULK_ENTRIES} entries"
        ))));
    }
    Ok(entries
        .iter()
        .map(|entry| {
            tags_checked(entry.replacement_tags.as_deref())
                .and_then(|()| header_tags_checked(entry.replacement_headers.as_ref()))
                .and_then(|()| entry_recipients(&entry.destination, max_recipients))
                .map_err(failed)
        })
        .collect())
}

/// A request's header fields, refused if one is an `X-SES-MESSAGE-TAGS`
/// whose tags SES would not take, as a raw message's is.
fn header_tags_checked(list: Option<&MessageHeaderList>) -> Result<(), SendEmailError> {
    match list
        .into_iter()
        .flat_map(|list| list.inner())
        .filter(|header| {
            header
                .name
                .as_str()
                .eq_ignore_ascii_case("X-SES-MESSAGE-TAGS")
        })
        .find_map(|header| tags_field_refused(header.value.as_str().as_bytes()))
    {
        Some(refused) => Err(bad(refused)),
        None => Ok(()),
    }
}

/// A request's tags, refused if one is not as SES takes a tag: its name and
/// value each one to 256 ASCII letters, digits, underscores and dashes.
fn tags_checked(tags: Option<&[MessageTag]>) -> Result<(), SendEmailError> {
    match tags
        .unwrap_or_default()
        .iter()
        .find(|tag| !(tag_text(&tag.name) && tag_text(&tag.value)))
    {
        Some(tag) => Err(bad(format!(
            "Invalid tag {}={}: a tag's name and value may hold ASCII letters, digits, '_' and '-', at most 256 characters",
            tag.name, tag.value
        ))),
        None => Ok(()),
    }
}

/// An entry's recipients: To, then Cc, then Bcc.
fn entry_recipients(
    destination: &Destination,
    max_recipients: usize,
) -> Result<Vec<Address>, SendEmailError> {
    let recipients: Vec<Address> = [
        &destination.to_addresses,
        &destination.cc_addresses,
        &destination.bcc_addresses,
    ]
    .into_iter()
    .flatten()
    .flatten()
    .map(|value| {
        prepare::mailbox(value.as_bytes())
            .ok_or_else(|| bad(format!("Invalid recipient address: {value}")))
    })
    .collect::<Result<_, _>>()?;
    if recipients.is_empty() {
        return Err(bad("Destination must name at least one recipient"));
    }
    if recipients.len() > max_recipients {
        return Err(bad(format!("Recipient count exceeds {max_recipients}.")));
    }
    Ok(recipients)
}

/// The authority a bulk request is accepted under, decided once for all
/// its entries, and each entry's message as it will be sent: the template
/// rendered with its default data and the entry's own laid over it, its
/// headers and the entry's, an entry's winning by name, composed, and
/// prepared as the request's identity; or the entry's refusal. `ids` are
/// the entries' message IDs, in order. Every message is composed before
/// any is signed, and `admit` is asked whether their bytes fit the
/// sender's rates: a request over its rate costs no signing.
///
/// Each entry's rendered parts come to at most the largest message, and
/// the request's messages together to at most the largest request: the
/// entry that would pass it is refused, and every entry after it, rendering
/// nothing more.
#[allow(clippy::too_many_arguments)]
pub fn bulk_content(
    input: &SendBulkEmailInput,
    snapshot: &Snapshot,
    credential: &Credential,
    entries: &[Entry<Vec<Address>>],
    ids: &[MessageId],
    now: Timestamp,
    limits: Limits,
    source_ip: IpAddr,
    arns: Arns<'_>,
    admit: impl FnOnce(u64) -> bool,
) -> Result<(Authority, Vec<Entry<Prepared>>), SendBulkEmailError> {
    let from_text = input.from_email_address.as_deref().unwrap_or_default();
    let from = prepare::mailbox(from_text.as_bytes())
        .ok_or_else(|| bulk(bad(format!("Invalid FromEmailAddress: {from_text}"))))?;
    let tenant = input.tenant_name.as_ref().map(TenantName::as_str);
    let configuration = input.configuration_set_name.as_deref();
    let (mut authority, sender) = snapshot
        .sending(credential, &from, None, tenant, configuration)
        .map_err(|denial| bulk(denied(denial)))?;
    let Some(template) = &input.default_content.template else {
        return Err(bulk(bad("DefaultContent must have a Template")));
    };
    let content =
        template_parts(template, snapshot.policy(), arns, &authority.origin).map_err(bulk)?;
    // Checked again at commit, should its tenant lose it.
    authority.template = content.kept;
    let defaults = headers_of(template.headers.as_ref());
    // Once an entry would take them past the largest request, it and
    // every entry after it are refused.
    let mut left = Some(max_request_bytes(limits));
    let shown: Vec<String> = ids.iter().copied().map(message_id).collect();
    let composed: Vec<Entry<Vec<u8>>> = entries
        .iter()
        .zip(&input.bulk_email_entries)
        .zip(&shown)
        .map(|((checked, entry), id)| {
            checked.as_ref().map_err(Clone::clone)?;
            let room = left.ok_or_else(|| failed(rejected(TOO_LARGE_TOGETHER)))?;
            let composed = entry_message(
                input,
                entry,
                content,
                template.template_data.as_ref().map(|data| data.as_str()),
                &defaults,
                id,
                limits.max_bytes,
            )
            .map_err(failed)?;
            left = room.checked_sub(composed.len());
            left.ok_or_else(|| failed(rejected(TOO_LARGE_TOGETHER)))?;
            Ok(composed)
        })
        .collect();
    let bytes = composed
        .iter()
        .flatten()
        .map(|composed| composed.len() as u64)
        .sum();
    if !admit(bytes) {
        return Err(bulk(too_fast()));
    }
    let prepared = composed
        .into_iter()
        .zip(entries)
        .zip(&input.bulk_email_entries)
        .zip(&shown)
        .map(|(((composed, checked), entry), id)| {
            let (composed, recipients) = (composed?, checked.as_ref().map_err(Clone::clone)?);
            let stamp = Stamp { date: now, id };
            let content = prepare::check(&composed, limits)
                .and_then(|checked| checked.sent_as(sender, stamp))
                .map_err(|rejection| failed(refused(&rejection)))?;
            let mail = snapshot.mail(&authority, &composed, &content, recipients, || {
                // An entry's tag takes the place of the default's of its
                // name.
                let own = entry.replacement_tags.iter().flatten();
                let given = input
                    .default_email_tags
                    .iter()
                    .flatten()
                    .filter(|tag| !own.clone().any(|theirs| theirs.name == tag.name))
                    .chain(own.clone())
                    .map(|tag| (tag.name.clone(), tag.value.clone()))
                    .collect();
                let tagged = Tagged {
                    operation: "SendBulkEmail",
                    caller: caller(credential),
                    source_ip,
                    given,
                };
                Some((from.clone(), tagged))
            });
            Ok((content, mail))
        })
        .collect();
    Ok((authority, prepared))
}

/// Why an entry is refused whose message would take a bulk request's
/// messages past the largest request together.
const TOO_LARGE_TOGETHER: &str =
    "The request's messages together come to more than the engine accepts in one request.";

/// The largest request read: the largest message base64-encoded, as raw
/// content arrives, with a mebibyte for the rest of the request. A bulk
/// request's rendered messages come to no more together.
pub fn max_request_bytes(limits: Limits) -> usize {
    limits.max_bytes.div_ceil(3) * 4 + (1 << 20)
}

/// One entry's message, composed from the template, its rendered parts
/// coming to at most `most` bytes.
#[allow(clippy::too_many_arguments)]
fn entry_message(
    input: &SendBulkEmailInput,
    entry: &BulkEmailEntry,
    content: TemplateParts<'_>,
    default_data: Option<&str>,
    defaults: &[(String, String)],
    id: &str,
    most: usize,
) -> Result<Vec<u8>, SendEmailError> {
    let own_data = entry
        .replacement_email_content
        .as_ref()
        .and_then(|replacement| replacement.replacement_template.as_ref())
        .and_then(|replacement| replacement.replacement_template_data.as_ref())
        .map(|data| data.as_str());
    let data = template::data(default_data, own_data).map_err(bad)?;
    let mut left = most;
    let mut render = |part: &str| {
        let rendered = template::render(part, &data, left).map_err(|error| match error {
            template::RenderError::TooLarge => rejected(TOO_LARGE),
            error => rejected(&error.to_string()),
        })?;
        left -= rendered.len();
        Ok::<_, SendEmailError>(rendered)
    };
    let subject = render(content.subject)?;
    let text = content.text.map(&mut render).transpose()?;
    let html = content.html.map(&mut render).transpose()?;
    // An entry's header takes the place of the template's of its name.
    let own = headers_of(entry.replacement_headers.as_ref());
    let mut headers: Vec<(String, String)> = defaults
        .iter()
        .filter(|(name, _)| {
            !own.iter()
                .any(|(theirs, _)| theirs.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect();
    headers.extend(own);
    let none = Vec::new();
    let destination = &entry.destination;
    let parts = Parts {
        from: input.from_email_address.as_deref().unwrap_or_default(),
        to: destination.to_addresses.as_ref().unwrap_or(&none),
        cc: destination.cc_addresses.as_ref().unwrap_or(&none),
        reply_to: input.reply_to_addresses.as_ref().unwrap_or(&none),
        subject: &subject,
        text: text.as_deref(),
        html: html.as_deref(),
        headers: &headers,
        id,
        most,
    };
    compose::compose(&parts).map_err(|error| match error {
        ComposeError::NoBody => bad("The template must have Text, Html or both"),
        ComposeError::Header(problem) => bad(problem),
        ComposeError::TooLarge => rejected(TOO_LARGE),
    })
}

/// A template's parts, as a request gives them or as the account keeps
/// them under the name it gives.
#[derive(Clone, Copy)]
struct TemplateParts<'a> {
    subject: &'a str,
    text: Option<&'a str>,
    html: Option<&'a str>,
    /// The kept template they are, if one is.
    kept: Option<TemplateId>,
}

/// The parts of the template a request names: its own content, or the
/// account's template of the name it gives, or that its ARN, of this
/// account and region, names, or both when they name the same. Sent under
/// `origin`, a kept template must be one its tenant may send with.
fn template_parts<'a>(
    template: &'a Template,
    policy: &'a Policy,
    arns: Arns<'_>,
    origin: &Origin,
) -> Result<TemplateParts<'a>, SendEmailError> {
    let by_arn = template
        .template_arn
        .as_ref()
        .map(|arn| {
            arns.template_named(arn.as_str()).ok_or_else(|| {
                bad(format!(
                    "{} is not a template of this account and region",
                    arn.as_str()
                ))
            })
        })
        .transpose()?;
    let by_name = template.template_name.as_ref().map(|name| name.as_str());
    let name = match (&template.template_content, by_name, by_arn) {
        (Some(content), None, None) => {
            return Ok(TemplateParts {
                subject: content.subject.as_deref().unwrap_or_default(),
                text: content.text.as_deref(),
                html: content.html.as_deref(),
                kept: None,
            });
        }
        (None, Some(name), None) | (None, None, Some(name)) => name,
        (None, Some(name), Some(named)) if name == named => name,
        (None, None, None) => {
            return Err(bad(
                "The Template must have TemplateName, TemplateArn or TemplateContent",
            ));
        }
        _ => {
            return Err(bad(
                "Give the Template's TemplateContent, or its TemplateName or TemplateArn naming one template",
            ));
        }
    };
    let stored = policy.template_named(arns.account, name).ok_or_else(|| {
        SendEmailError::NotFoundException(NotFoundException {
            message: Some(format!("Template {name} does not exist.")),
        })
    })?;
    policy.uses(origin, arns.account, stored.id).map_err(|_| {
        bad(format!(
            "Tenant not associated with resources [{}].",
            arns.template(name)
        ))
    })?;
    Ok(TemplateParts {
        subject: &stored.content.subject,
        text: stored.content.text.as_deref(),
        html: stored.content.html.as_deref(),
        kept: Some(stored.id),
    })
}

/// A message composed from a template's parts, each filled from the
/// request's data, as `composed` composes simple content.
fn templated(
    input: &SendEmailInput,
    template: &Template,
    parts: TemplateParts<'_>,
    id: &str,
    most: usize,
) -> Result<Vec<u8>, SendEmailError> {
    if template
        .attachments
        .as_ref()
        .is_some_and(|list| !list.is_empty())
    {
        return Err(bad("Attachments are not supported"));
    }
    let data = template::data(
        template.template_data.as_ref().map(|data| data.as_str()),
        None,
    )
    .map_err(bad)?;
    let mut left = most;
    let mut render = |part: &str| {
        let rendered = template::render(part, &data, left).map_err(|error| match error {
            template::RenderError::TooLarge => rejected(TOO_LARGE),
            error => rejected(&error.to_string()),
        })?;
        left -= rendered.len();
        Ok::<_, SendEmailError>(rendered)
    };
    let subject = render(parts.subject)?;
    let text = parts.text.map(&mut render).transpose()?;
    let html = parts.html.map(&mut render).transpose()?;
    let headers = headers_of(template.headers.as_ref());
    let none = Vec::new();
    let destination = input.destination.as_ref();
    let parts = Parts {
        from: input.from_email_address.as_deref().unwrap_or_default(),
        to: destination
            .and_then(|d| d.to_addresses.as_ref())
            .unwrap_or(&none),
        cc: destination
            .and_then(|d| d.cc_addresses.as_ref())
            .unwrap_or(&none),
        reply_to: input.reply_to_addresses.as_ref().unwrap_or(&none),
        subject: &subject,
        text: text.as_deref(),
        html: html.as_deref(),
        headers: &headers,
        id,
        most,
    };
    compose::compose(&parts).map_err(|error| match error {
        ComposeError::NoBody => bad("The template must have Text, Html or both"),
        ComposeError::Header(problem) => bad(problem),
        ComposeError::TooLarge => rejected(TOO_LARGE),
    })
}

/// A header list's fields, by name and value.
fn headers_of(list: Option<&MessageHeaderList>) -> Vec<(String, String)> {
    list.map(|list| {
        list.inner()
            .iter()
            .map(|header| {
                (
                    header.name.as_str().to_owned(),
                    header.value.as_str().to_owned(),
                )
            })
            .collect()
    })
    .unwrap_or_default()
}

fn bulk_unsupported(input: &SendBulkEmailInput) -> Option<&'static str> {
    [
        (
            "FromEmailAddressIdentityArn",
            input.from_email_address_identity_arn.is_some(),
        ),
        (
            "FeedbackForwardingEmailAddress",
            input.feedback_forwarding_email_address.is_some(),
        ),
        (
            "FeedbackForwardingEmailAddressIdentityArn",
            input
                .feedback_forwarding_email_address_identity_arn
                .is_some(),
        ),
        ("EndpointId", input.endpoint_id.is_some()),
        (
            "ConfigurationOverrides",
            input.configuration_overrides.is_some(),
        ),
    ]
    .into_iter()
    .find_map(|(option, named)| named.then_some(option))
}

/// An entry accepted, with its message's ID.
pub fn entry_sent(id: MessageId) -> BulkEmailEntryResult {
    BulkEmailEntryResult {
        status: Some(BulkEmailStatus::Success),
        error: None,
        message_id: Some(message_id(id)),
    }
}

/// An entry not sent, for the reason `SendEmail` would have refused it,
/// with the status of SES's that says so.
pub fn failed(error: SendEmailError) -> BulkEmailEntryResult {
    let (status, message) = match error {
        SendEmailError::BadRequestException(error) => {
            (BulkEmailStatus::InvalidParameter, error.message)
        }
        SendEmailError::ValidationException(error) => {
            (BulkEmailStatus::InvalidParameter, Some(error.message))
        }
        SendEmailError::MessageRejected(error) => (BulkEmailStatus::MessageRejected, error.message),
        SendEmailError::MailFromDomainNotVerifiedException(error) => {
            (BulkEmailStatus::MailFromDomainNotVerified, error.message)
        }
        SendEmailError::AccountSuspendedException(error) => {
            (BulkEmailStatus::AccountSuspended, error.message)
        }
        SendEmailError::SendingPausedException(error) => {
            (BulkEmailStatus::AccountSendingPaused, error.message)
        }
        SendEmailError::TooManyRequestsException(error)
            if error.message.as_deref() == Some(QUOTA_EXCEEDED) =>
        {
            (BulkEmailStatus::AccountDailyQuotaExceeded, error.message)
        }
        SendEmailError::TooManyRequestsException(error) => {
            (BulkEmailStatus::TransientFailure, error.message)
        }
        SendEmailError::NotFoundException(error) => (BulkEmailStatus::Failed, error.message),
        SendEmailError::LimitExceededException(error) => (BulkEmailStatus::Failed, error.message),
    };
    BulkEmailEntryResult {
        status: Some(status),
        error: message,
        message_id: None,
    }
}

/// `SendEmail`'s refusal of a whole request, as `SendBulkEmail`'s.
pub fn bulk(error: SendEmailError) -> SendBulkEmailError {
    match error {
        SendEmailError::AccountSuspendedException(error) => {
            SendBulkEmailError::AccountSuspendedException(error)
        }
        SendEmailError::BadRequestException(error) => {
            SendBulkEmailError::BadRequestException(error)
        }
        SendEmailError::LimitExceededException(error) => {
            SendBulkEmailError::LimitExceededException(error)
        }
        SendEmailError::MailFromDomainNotVerifiedException(error) => {
            SendBulkEmailError::MailFromDomainNotVerifiedException(error)
        }
        SendEmailError::MessageRejected(error) => SendBulkEmailError::MessageRejected(error),
        SendEmailError::NotFoundException(error) => SendBulkEmailError::NotFoundException(error),
        SendEmailError::SendingPausedException(error) => {
            SendBulkEmailError::SendingPausedException(error)
        }
        SendEmailError::TooManyRequestsException(error) => {
            SendBulkEmailError::TooManyRequestsException(error)
        }
        SendEmailError::ValidationException(error) => {
            SendBulkEmailError::ValidationException(error)
        }
    }
}

/// The answer to a bulk request: each entry's result, in the order its
/// entries came.
pub fn bulk_answered(results: Vec<BulkEmailEntryResult>) -> SendBulkEmailOutput {
    SendBulkEmailOutput {
        bulk_email_entry_results: results,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use engine_core::id::{
        AccountId, ConfigurationId, CredentialId, Id, IdentityId, TemplateId, TenantId,
    };
    use engine_core::policy::{
        Configuration, Identity, Permissions, Record, Scope, Signing, Template as Kept,
        TemplateContent, Tenant,
    };
    use engine_ses_v2::model::{
        Attachment, AttachmentFileName, Body, Destination, EmailContent, RawMessage, Template,
    };
    use engine_ses_v2::types::Blob;

    use super::*;

    const LIMITS: Limits = Limits { max_bytes: 1 << 20 };

    fn id_of(value: u64) -> Id {
        Id::from_u64(value).unwrap()
    }

    /// A policy with one signing identity, bench.test, a configuration set
    /// and a tenant that may send with both, and the access key that sends;
    /// and alice@bench.test with a key that may send as her alone.
    fn snapshot() -> (Snapshot, Credential) {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = STANDARD.encode(pair.as_der().unwrap().as_ref());
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{der}\n-----END PRIVATE KEY-----\n");
        let account = AccountId(id_of(1));
        let records = [
            Record::Identity(Identity {
                id: IdentityId(id_of(2)),
                account,
                name: "bench.test".to_owned(),
                signing: Some(Signing {
                    selector: "s1".to_owned(),
                    key: pem,
                    headers: vec!["From".to_owned(), "To".to_owned()],
                }),
                signs: true,
                configuration: None,
                tags: Vec::new(),
                verification: None,
                mail_from: None,
            }),
            Record::Configuration(Configuration {
                id: ConfigurationId(id_of(3)),
                account,
                name: "receipts".to_owned(),
                pool: None,
                tags: Vec::new(),
                reputation_metrics: false,
            }),
            Record::Configuration(Configuration {
                id: ConfigurationId(id_of(4)),
                account,
                name: "marketing".to_owned(),
                pool: None,
                tags: Vec::new(),
                reputation_metrics: false,
            }),
            Record::Tenant(Tenant {
                id: TenantId(id_of(5)),
                account,
                name: "acme".to_owned(),
                identities: BTreeSet::from([IdentityId(id_of(2))]),
                templates: BTreeSet::from([TemplateId(id_of(9))]),
                configurations: BTreeSet::from([ConfigurationId(id_of(3))]),
                limits: engine_core::policy::Limits::default(),
                tags: Vec::new(),
                created: None,
            }),
            Record::Credential(Credential {
                id: CredentialId(id_of(6)),
                account,
                secret: Secret::AccessKey {
                    id: "AKIDBENCH".to_owned(),
                    secret: "secret".to_owned(),
                },
                identities: Scope::Any,
                tenants: Scope::Any,
                permissions: Permissions::SENDS,
            }),
            Record::Identity(Identity {
                id: IdentityId(id_of(7)),
                account,
                name: "alice@bench.test".to_owned(),
                signing: None,
                signs: true,
                configuration: None,
                tags: Vec::new(),
                verification: None,
                mail_from: None,
            }),
            Record::Credential(Credential {
                id: CredentialId(id_of(8)),
                account,
                secret: Secret::AccessKey {
                    id: "AKIDALICE".to_owned(),
                    secret: "secret".to_owned(),
                },
                identities: Scope::Only(BTreeSet::from([IdentityId(id_of(7))])),
                tenants: Scope::Any,
                permissions: Permissions::SENDS,
            }),
            Record::Template(Kept {
                id: TemplateId(id_of(9)),
                account,
                name: "welcome".to_owned(),
                content: TemplateContent {
                    subject: "Welcome, {{name}}".to_owned(),
                    text: Some("Hello {{name}}, from the stored template".to_owned()),
                    html: None,
                },
                created: now(),
            }),
            Record::Template(Kept {
                id: TemplateId(id_of(19)),
                account,
                name: "private".to_owned(),
                content: TemplateContent {
                    subject: "Private".to_owned(),
                    text: Some("Not for tenants".to_owned()),
                    html: None,
                },
                created: now(),
            }),
        ];
        let revision = engine_core::message::PolicyRevision(records.len() as u64);
        let policy = Policy::from_records(revision, records.to_vec()).unwrap();
        let credential = policy.access_key("AKIDBENCH").unwrap().clone();
        (Snapshot::new(Arc::new(policy), None).unwrap(), credential)
    }

    fn text(data: &str) -> Content {
        Content {
            data: data.to_owned(),
            charset: None,
        }
    }

    fn simple(from: &str) -> SendEmailInput {
        SendEmailInput {
            from_email_address: Some(from.to_owned()),
            from_email_address_identity_arn: None,
            destination: Some(Destination {
                to_addresses: Some(vec!["Ann <a@sink.test>".to_owned()]),
                cc_addresses: Some(vec!["c@sink.test".to_owned()]),
                bcc_addresses: Some(vec!["b@sink.test".to_owned()]),
            }),
            reply_to_addresses: None,
            feedback_forwarding_email_address: None,
            feedback_forwarding_email_address_identity_arn: None,
            content: EmailContent {
                simple: Some(Message {
                    subject: text("Hello"),
                    body: Body {
                        text: Some(text("Hi Ann")),
                        html: None,
                    },
                    headers: None,
                    attachments: None,
                }),
                raw: None,
                template: None,
            },
            email_tags: None,
            configuration_set_name: None,
            endpoint_id: None,
            tenant_name: None,
            list_management_options: None,
            configuration_overrides: None,
        }
    }

    fn raw(data: &[u8]) -> SendEmailInput {
        let mut input = simple("load@bench.test");
        input.from_email_address = None;
        input.content = EmailContent {
            simple: None,
            raw: Some(RawMessage {
                data: Blob::new(data),
            }),
            template: None,
        };
        input
    }

    fn id() -> MessageId {
        MessageId(Id::from_u64(0x2a).unwrap())
    }

    fn now() -> Timestamp {
        Timestamp::from_micros(1_800_000_000_000_000)
    }

    fn message(error: SendEmailError) -> (&'static str, String) {
        match error {
            SendEmailError::BadRequestException(e) => ("BadRequest", e.message.unwrap()),
            SendEmailError::MessageRejected(e) => ("MessageRejected", e.message.unwrap()),
            SendEmailError::NotFoundException(e) => ("NotFound", e.message.unwrap()),
            SendEmailError::TooManyRequestsException(e) => ("TooManyRequests", e.message.unwrap()),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The account's resources, as the shell names them.
    fn arns() -> Arns<'static> {
        Arns {
            region: "us-east-1",
            account: AccountId(id_of(1)),
        }
    }

    /// Sent to nobody in particular, from loopback.
    fn nobody() -> To<'static> {
        To {
            recipients: &[],
            source_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        }
    }

    #[test]
    fn an_older_sdks_listing_is_read_as_the_models_own() {
        assert_eq!(
            older_listing(
                "GET",
                "/v2/email/identities",
                "NextToken=1.YQ%3D%3D&PageSize=2"
            ),
            Some((
                "/v2/email/list-identities",
                r#"{"NextToken":"1.YQ==","PageSize":2}"#.to_owned()
            ))
        );
        assert_eq!(
            older_listing("GET", "/v2/email/configuration-sets", ""),
            Some(("/v2/email/list-configuration-sets", "{}".to_owned()))
        );
        // A page size that is not a number goes on as it is, for the
        // decoder to refuse; anything else is not an older listing.
        assert_eq!(
            older_listing("GET", "/v2/email/identities", "PageSize=many&Other=1"),
            Some((
                "/v2/email/list-identities",
                r#"{"PageSize":"many"}"#.to_owned()
            ))
        );
        assert_eq!(older_listing("POST", "/v2/email/identities", ""), None);
        assert_eq!(
            older_listing("GET", "/v2/email/identities/a.test", ""),
            None
        );
    }

    #[test]
    fn a_simple_send_is_charged_what_it_comes_to_headers_and_all() {
        let (snapshot, credential) = snapshot();
        let mut input = simple("load@bench.test");
        // A tiny body under ten thousand bytes of its own header fields.
        let value = "x".repeat(900);
        let headers: Vec<_> = (0..11)
            .map(|n| engine_ses_v2::model::MessageHeader {
                name: format!("X-Note-{n}").try_into().unwrap(),
                value: value.clone().try_into().unwrap(),
            })
            .collect();
        if let Some(simple) = input.content.simple.as_mut() {
            simple.headers = Some(headers.try_into().unwrap());
        }
        let mut charged = 0;
        let sent = content(
            &input,
            &snapshot,
            &credential,
            id(),
            now(),
            LIMITS,
            nobody(),
            arns(),
            |_, bytes| {
                charged = bytes;
                true
            },
        );
        assert!(sent.is_ok());
        assert!(charged > 9_900, "charged {charged}");
        // Over its rate, it is refused before it is signed.
        let refused = content(
            &input,
            &snapshot,
            &credential,
            id(),
            now(),
            LIMITS,
            nobody(),
            arns(),
            |_, _| false,
        );
        assert!(refused.is_err());
    }

    #[test]
    fn a_simple_message_is_composed_signed_and_carries_its_id() {
        let (snapshot, credential) = snapshot();
        let input = simple("Load <load@bench.test>");
        let recipients = check(&input, 50).unwrap();
        let addresses: Vec<&str> = recipients.iter().map(Address::as_str).collect();
        assert_eq!(addresses, ["a@sink.test", "c@sink.test", "b@sink.test"]);
        let (authority, content, _) = content(
            &input,
            &snapshot,
            &credential,
            id(),
            now(),
            LIMITS,
            nobody(),
            arns(),
            |_, _| true,
        )
        .unwrap();
        assert_eq!(authority.origin.identity, IdentityId(id_of(2)));
        assert_eq!(authority.revision, snapshot.policy().revision());
        let content = std::str::from_utf8(&content).unwrap();
        assert!(content.starts_with("DKIM-Signature: v=1; a=rsa-sha256;"));
        assert!(content.contains("\r\nTo: Ann <a@sink.test>\r\n"));
        assert!(content.contains("\r\nCc: c@sink.test\r\n"));
        assert!(content.contains("\r\nMessage-ID: <000000000000002a@bench.test>\r\n"));
        assert!(!content.contains("b@sink.test"), "Bcc stays off the header");
        assert_eq!(
            answered(&Commit::Committed(()), id()).unwrap().message_id,
            Some("000000000000002a".to_owned())
        );
    }

    #[test]
    fn a_message_is_sent_by_a_kept_templates_name_or_by_its_own() {
        let (snapshot, credential) = snapshot();
        let by = |template: Template| {
            let mut input = simple("load@bench.test");
            input.content.simple = None;
            input.content.template = Some(template);
            content(
                &input,
                &snapshot,
                &credential,
                id(),
                now(),
                LIMITS,
                nobody(),
                arns(),
                |_, _| true,
            )
        };
        let named = |name: Option<&str>, arn: Option<&str>| Template {
            template_name: name.map(|name| name.to_owned().try_into().unwrap()),
            template_arn: arn.map(|arn| arn.to_owned().try_into().unwrap()),
            template_content: None,
            template_data: Some(r#"{"name":"Ann"}"#.to_owned().try_into().unwrap()),
            headers: None,
            attachments: None,
        };
        let arn = "arn:aws:ses:us-east-1:000000000001:template/welcome";
        for template in [named(Some("welcome"), None), named(None, Some(arn))] {
            let (_, content, _) = by(template).unwrap();
            let content = std::str::from_utf8(&content).unwrap();
            assert!(content.starts_with("DKIM-Signature: "), "{content}");
            assert!(
                content.contains("\r\nSubject: Welcome, Ann\r\n"),
                "{content}"
            );
            assert!(
                content.contains("Hello Ann, from the stored template"),
                "{content}"
            );
        }
        // One the account does not keep is not found.
        let missing = by(named(Some("other"), None)).unwrap_err();
        assert_eq!(
            message(missing),
            ("NotFound", "Template other does not exist.".to_owned())
        );
        // Its own content, as SendBulkEmail takes it.
        let own = Template {
            template_content: Some(engine_ses_v2::model::EmailTemplateContent {
                subject: Some("Hi {{name}}".to_owned()),
                text: Some("inline".to_owned()),
                html: None,
            }),
            ..named(None, None)
        };
        let (_, content, _) = by(own).unwrap();
        assert!(
            std::str::from_utf8(&content)
                .unwrap()
                .contains("\r\nSubject: Hi Ann\r\n")
        );
        // An ARN of another account or region, or none at all, names none
        // of this account's.
        for arn in [
            "arn:aws:ses:us-east-1:000000000002:template/welcome",
            "arn:aws:ses:eu-west-1:000000000001:template/welcome",
            "garbage:template/welcome",
        ] {
            let (kind, text) = message(by(named(None, Some(arn))).unwrap_err());
            assert_eq!(kind, "BadRequest", "{arn}: {text}");
        }
        // A name and an ARN together name one template of this account's,
        // and content goes alone.
        let both = |arn: &str| named(Some("welcome"), Some(arn));
        assert!(by(both("arn:aws:ses:us-east-1:000000000001:template/welcome")).is_ok());
        for template in [
            both("arn:aws:ses:eu-west-1:000000000001:template/welcome"),
            both("arn:aws:ses:us-east-1:000000000001:template/private"),
            Template {
                template_content: Some(engine_ses_v2::model::EmailTemplateContent {
                    subject: Some("Hi".to_owned()),
                    text: Some("inline".to_owned()),
                    html: None,
                }),
                ..named(Some("welcome"), None)
            },
        ] {
            let (kind, text) = message(by(template).unwrap_err());
            assert_eq!(kind, "BadRequest", "{text}");
        }
        // Sent for a tenant, the template is one associated with it.
        let for_tenant = |name: &str| {
            let mut input = simple("load@bench.test");
            input.content.simple = None;
            input.content.template = Some(named(Some(name), None));
            input.tenant_name = Some(TenantName::try_from("acme".to_owned()).unwrap());
            super::content(
                &input,
                &snapshot,
                &credential,
                id(),
                now(),
                LIMITS,
                nobody(),
                arns(),
                |_, _| true,
            )
        };
        assert!(for_tenant("welcome").is_ok());
        let (kind, text) = message(for_tenant("private").unwrap_err());
        assert_eq!(kind, "BadRequest");
        assert_eq!(
            text,
            "Tenant not associated with resources [arn:aws:ses:us-east-1:000000000001:template/private]."
        );
        // A template's header fields may not set SES's own tags.
        let mut forged = simple("load@bench.test");
        forged.content.simple = None;
        forged.content.template = Some(Template {
            headers: Some(
                vec![engine_ses_v2::model::MessageHeader {
                    name: "X-SES-MESSAGE-TAGS".to_owned().try_into().unwrap(),
                    value: "ses:tenant=other".to_owned().try_into().unwrap(),
                }]
                .try_into()
                .unwrap(),
            ),
            ..named(Some("welcome"), None)
        });
        assert_eq!(message(check(&forged, 50).unwrap_err()).0, "BadRequest");
    }

    #[test]
    fn a_raw_message_is_signed_given_the_date_and_message_id_it_lacks_and_otherwise_kept() {
        let (snapshot, credential) = snapshot();
        let data = b"From: load@bench.test\r\nTo: a@sink.test\r\nSubject: hi\r\n\r\nbody\r\n";
        let (_, content, _) = content(
            &raw(data),
            &snapshot,
            &credential,
            id(),
            now(),
            LIMITS,
            nobody(),
            arns(),
            |_, _| true,
        )
        .unwrap();
        assert!(content.starts_with(b"DKIM-Signature: "));
        assert!(content.ends_with(data));
        // Its Message-ID is the ID the answer gives.
        let text = String::from_utf8(content.to_vec()).unwrap();
        let stamped = format!(
            "\r\nMessage-ID: <{}@bench.test>\r\nFrom: load@bench.test\r\n",
            message_id(id())
        );
        assert!(text.contains(&stamped), "{text}");
        assert_eq!(text.matches("\r\nDate: ").count(), 1, "{text}");
    }

    #[test]
    fn a_raw_messages_bcc_field_is_never_sent_whoever_it_is_sent_to() {
        let (snapshot, credential) = snapshot();
        let data = b"From: load@bench.test\r\nTo: a@sink.test\r\nBcc: hidden@sink.test\r\nSubject: hi\r\n\r\nbody\r\n";
        // Sent to the addresses the request names, and to its own.
        let mut own = raw(data);
        own.destination = None;
        for input in [raw(data), own] {
            let (_, content, _) = content(
                &input,
                &snapshot,
                &credential,
                id(),
                now(),
                LIMITS,
                nobody(),
                arns(),
                |_, _| true,
            )
            .unwrap();
            let content = std::str::from_utf8(&content).unwrap();
            assert!(!content.contains("hidden@sink.test"), "{content}");
            assert!(content.contains("\r\nTo: a@sink.test\r\n"), "{content}");
        }
    }

    #[test]
    fn a_tag_is_taken_only_as_ses_takes_one_and_never_passes_for_its_own() {
        let tag = |name: &str, value: &str| engine_ses_v2::model::MessageTag {
            name: name.to_owned(),
            value: value.to_owned(),
        };
        let mut input = simple("load@bench.test");
        input.email_tags = Some(vec![tag("campaign", "autumn-2026_a")]);
        assert!(check(&input, 50).is_ok());
        for (name, value) in [
            ("ses:configuration-set", "other"),
            ("campaign", "a.b"),
            ("", "x"),
            ("campaign", &"x".repeat(257)),
        ] {
            input.email_tags = Some(vec![tag(name, value)]);
            assert_eq!(
                message(check(&input, 50).unwrap_err()).0,
                "BadRequest",
                "{name}={value}"
            );
        }
        // In simple content's header fields, as in a raw message's.
        let header = |value: &str| engine_ses_v2::model::MessageHeader {
            name: "X-SES-MESSAGE-TAGS".to_owned().try_into().unwrap(),
            value: value.to_owned().try_into().unwrap(),
        };
        input.email_tags = None;
        for (value, kind) in [
            ("campaign=autumn", None),
            ("ses:configuration-set=other", Some("BadRequest")),
        ] {
            if let Some(simple) = input.content.simple.as_mut() {
                simple.headers = Some(vec![header(value)].try_into().unwrap());
            }
            assert_eq!(
                check(&input, 50).err().map(|error| message(error).0),
                kind,
                "{value}"
            );
        }
        // In the message's own field too, whatever its configuration.
        let (snapshot, credential) = snapshot();
        let data = b"From: load@bench.test\r\nTo: a@sink.test\r\nX-SES-MESSAGE-TAGS: campaign=autumn, ses:configuration-set=other\r\n\r\nbody\r\n";
        let refused = content(
            &raw(data),
            &snapshot,
            &credential,
            id(),
            now(),
            LIMITS,
            nobody(),
            arns(),
            |_, _| true,
        )
        .unwrap_err();
        let (kind, text) = message(refused);
        assert_eq!(kind, "BadRequest");
        assert!(text.contains("ses:configuration-set=other"), "{text}");
        let taken = b"From: load@bench.test\r\nTo: a@sink.test\r\nX-SES-MESSAGE-TAGS: campaign=autumn\r\n\r\nbody\r\n";
        assert!(
            content(
                &raw(taken),
                &snapshot,
                &credential,
                id(),
                now(),
                LIMITS,
                nobody(),
                arns(),
                |_, _| true
            )
            .is_ok()
        );
    }

    #[test]
    fn options_and_shapes_the_engine_does_not_support_are_refused_by_name() {
        let mut input = simple("load@bench.test");
        input.endpoint_id = Some("endpoint".to_owned());
        assert_eq!(
            message(check(&input, 50).unwrap_err()),
            ("BadRequest", "EndpointId is not supported".to_owned())
        );

        let mut input = simple("load@bench.test");
        input.destination = None;
        assert_eq!(message(check(&input, 50).unwrap_err()).0, "BadRequest");
        assert_eq!(
            message(check(&simple("load@bench.test"), 2).unwrap_err()).1,
            "Recipient count exceeds 2."
        );

        let (snapshot, credential) = snapshot();
        let refused = |input: &SendEmailInput| {
            message(
                content(
                    input,
                    &snapshot,
                    &credential,
                    id(),
                    now(),
                    LIMITS,
                    nobody(),
                    arns(),
                    |_, _| true,
                )
                .unwrap_err(),
            )
        };
        let mut input = simple("load@bench.test");
        input.content.template = Some(Template {
            template_name: None,
            template_arn: None,
            template_content: None,
            template_data: None,
            headers: None,
            attachments: None,
        });
        assert_eq!(
            refused(&input).1,
            "Content must have exactly one of Simple, Raw and Template"
        );
        input.content.simple = None;
        assert_eq!(
            refused(&input).1,
            "The Template must have TemplateName, TemplateArn or TemplateContent"
        );

        let mut input = raw(b"From: load@bench.test\r\n\r\nbody\r\n");
        input.reply_to_addresses = Some(vec!["r@bench.test".to_owned()]);
        assert_eq!(refused(&input).0, "BadRequest");

        let mut input = simple("load@bench.test");
        if let Some(message) = &mut input.content.simple {
            message.attachments = Some(vec![Attachment {
                raw_content: Blob::new(b"x".as_slice()),
                content_disposition: None,
                file_name: AttachmentFileName::try_from("x.txt".to_owned()).unwrap(),
                content_description: None,
                content_id: None,
                content_transfer_encoding: None,
                content_type: None,
            }]);
        }
        assert_eq!(refused(&input).1, "Attachments are not supported");

        let mut input = simple("load@bench.test");
        if let Some(message) = &mut input.content.simple {
            message.subject.charset = Some("ISO-8859-1".to_owned());
        }
        assert_eq!(refused(&input).0, "BadRequest");
    }

    #[test]
    fn a_from_address_off_the_identity_is_not_verified() {
        let (snapshot, credential) = snapshot();
        let refused = |input: &SendEmailInput| {
            message(
                content(
                    input,
                    &snapshot,
                    &credential,
                    id(),
                    now(),
                    LIMITS,
                    nobody(),
                    arns(),
                    |_, _| true,
                )
                .unwrap_err(),
            )
        };
        let (code, text) = refused(&simple("load@other.test"));
        assert_eq!(code, "MessageRejected");
        assert!(text.starts_with("Email address is not verified."));
        let mut input = raw(b"From: load@bench.test\r\n\r\nbody\r\n");
        input.from_email_address = Some("load@other.test".to_owned());
        assert_eq!(refused(&input).1, text);
        assert_eq!(
            refused(&raw(b"From: load@other.test\r\n\r\nbody\r\n")).1,
            text
        );
    }

    #[test]
    fn a_raw_message_is_sent_as_its_own_from_as_well() {
        let (snapshot, _) = snapshot();
        let alice_only = snapshot.policy().access_key("AKIDALICE").unwrap().clone();
        let send = |from: &str| {
            let data = format!("From: {from}\r\nTo: a@sink.test\r\n\r\nbody\r\n");
            let mut input = raw(data.as_bytes());
            input.from_email_address = Some("alice@bench.test".to_owned());
            content(
                &input,
                &snapshot,
                &alice_only,
                id(),
                now(),
                LIMITS,
                nobody(),
                arns(),
                |_, _| true,
            )
            .map_err(message)
        };
        assert!(send("alice@bench.test").is_ok());
        assert_eq!(
            send("ceo@bench.test").unwrap_err(),
            (
                "MessageRejected",
                "FromEmailAddress and the message's From header must be addresses of the same identity".to_owned()
            )
        );
    }

    #[test]
    fn the_tenant_and_configuration_set_a_request_names_are_resolved() {
        let (snapshot, credential) = snapshot();
        let send = |tenant: Option<&str>, configuration: Option<&str>| {
            let mut input = simple("load@bench.test");
            input.tenant_name = tenant.map(|name| TenantName::try_from(name.to_owned()).unwrap());
            input.configuration_set_name = configuration.map(str::to_owned);
            content(
                &input,
                &snapshot,
                &credential,
                id(),
                now(),
                LIMITS,
                nobody(),
                arns(),
                |_, _| true,
            )
            .map(|(authority, _, _)| authority.origin)
            .map_err(message)
        };
        let origin = send(Some("acme"), Some("receipts")).unwrap();
        assert_eq!(origin.tenant, Some(TenantId(id_of(5))));
        assert_eq!(origin.configuration, Some(ConfigurationId(id_of(3))));
        assert_eq!(send(Some("nobody"), None).unwrap_err().0, "NotFound");
        assert_eq!(send(None, Some("nothing")).unwrap_err().0, "NotFound");
        // A configuration set the tenant is not associated with, refused
        // as SES refuses it, in the words applications repair it by.
        let (kind, text) = send(Some("acme"), Some("marketing")).unwrap_err();
        assert_eq!(kind, "BadRequest");
        assert!(
            text.starts_with("Tenant not associated with resources"),
            "{text}"
        );
        assert_eq!(
            message(
                answered(
                    &Commit::Refused(AcceptRefusal::Unauthorised(Denial::UnknownIdentity)),
                    id()
                )
                .unwrap_err()
            )
            .1,
            NOT_VERIFIED
        );
    }

    #[test]
    fn success_is_answered_only_for_a_committed_acceptance() {
        for commit in [
            Commit::Refused(AcceptRefusal::Conflict),
            Commit::Refused(AcceptRefusal::NoRecipients),
            Commit::Unknown,
            Commit::Unavailable,
        ] {
            assert!(answered(&commit, id()).is_err());
        }
        assert_eq!(
            message(answered(&Commit::Unavailable, id()).unwrap_err()).0,
            "TooManyRequests"
        );
    }

    #[test]
    fn a_bulk_request_renders_within_its_bytes_and_is_charged_what_it_renders() {
        use engine_ses_v2::model::{
            BulkEmailContent, EmailTemplateContent, EmailTemplateData, ReplacementEmailContent,
            ReplacementTemplate,
        };
        let (snapshot, credential) = snapshot();
        let limits = Limits {
            max_bytes: 512 * 1024,
        };
        let data_of = |byte: &str, bytes: usize| {
            EmailTemplateData::try_from(serde_json::json!({"x": byte.repeat(bytes)}).to_string())
                .unwrap()
        };
        let data = |bytes: usize| data_of("a", bytes);
        let entry = |data: Option<EmailTemplateData>| BulkEmailEntry {
            destination: Destination {
                to_addresses: Some(vec!["one@else.test".to_owned()]),
                cc_addresses: None,
                bcc_addresses: None,
            },
            replacement_tags: None,
            replacement_email_content: data.map(|data| ReplacementEmailContent {
                replacement_template: Some(ReplacementTemplate {
                    replacement_template_data: Some(data),
                }),
            }),
            replacement_headers: None,
        };
        // Ten references to the default's 32 KiB value, 320 KiB rendered;
        // the second entry's own value renders past the largest message,
        // and the third's within it, but past it as quoted-printable, each
        // `=` written as three bytes.
        let mut entries = vec![
            entry(None),
            entry(Some(data(64 * 1024))),
            entry(Some(data_of("=", 20 * 1024))),
        ];
        entries.extend((0..8).map(|_| entry(None)));
        let input = SendBulkEmailInput {
            from_email_address: Some("app@bench.test".to_owned()),
            from_email_address_identity_arn: None,
            reply_to_addresses: None,
            feedback_forwarding_email_address: None,
            feedback_forwarding_email_address_identity_arn: None,
            default_email_tags: None,
            default_content: BulkEmailContent {
                template: Some(Template {
                    template_name: None,
                    template_arn: None,
                    template_content: Some(EmailTemplateContent {
                        subject: Some("s".to_owned()),
                        text: Some("{{x}}".repeat(10)),
                        html: None,
                    }),
                    template_data: Some(data(32 * 1024)),
                    headers: None,
                    attachments: None,
                }),
            },
            bulk_email_entries: entries,
            configuration_set_name: None,
            endpoint_id: None,
            tenant_name: None,
            configuration_overrides: None,
        };
        let checked: Vec<Entry<Vec<Address>>> = input
            .bulk_email_entries
            .iter()
            .map(|_| Ok(vec![Address::parse("one@else.test").unwrap()]))
            .collect();
        let ids: Vec<MessageId> = (0..checked.len() as u64)
            .map(|n| MessageId(id_of(100 + n)))
            .collect();
        let now = Timestamp::from_micros(1_700_000_000_000_000);
        let ip = IpAddr::from([127, 0, 0, 1]);
        let mut charged = 0;
        let (_, prepared) = bulk_content(
            &input,
            &snapshot,
            &credential,
            &checked,
            &ids,
            now,
            limits,
            ip,
            arns(),
            |bytes| {
                charged = bytes;
                true
            },
        )
        .unwrap();
        let outcomes: Vec<&str> = prepared
            .iter()
            .map(|entry| match entry {
                Ok(_) => "sent",
                Err(result) if result.error.as_deref() == Some(TOO_LARGE) => "too large",
                Err(result) if result.error.as_deref() == Some(TOO_LARGE_TOGETHER) => "together",
                Err(_) => "refused otherwise",
            })
            .collect();
        // Those that fit the largest request together are sent; the one
        // that would pass it is refused, and every one after it.
        let cut = outcomes
            .iter()
            .position(|outcome| *outcome == "together")
            .unwrap_or_else(|| panic!("{outcomes:?}"));
        assert!(cut > 3, "{outcomes:?}");
        assert!(
            outcomes[..cut].iter().enumerate().all(|(place, outcome)| {
                *outcome
                    == if matches!(place, 1 | 2) {
                        "too large"
                    } else {
                        "sent"
                    }
            }),
            "{outcomes:?}"
        );
        assert!(
            outcomes[cut..].iter().all(|outcome| *outcome == "together"),
            "{outcomes:?}"
        );
        let sent = cut - 2;
        // Charged what its messages came to, not its template's length.
        assert!(charged > sent as u64 * 320 * 1024, "{charged}");
        assert!(charged <= max_request_bytes(limits) as u64);
        // Over its rate, it is refused whole.
        let refused = bulk_content(
            &input,
            &snapshot,
            &credential,
            &checked,
            &ids,
            now,
            limits,
            ip,
            arns(),
            |_| false,
        );
        assert!(
            matches!(
                refused,
                Err(SendBulkEmailError::TooManyRequestsException(_))
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn signature_failures_are_answered_as_aws_answers_them() {
        assert_eq!(
            ErrorResponse::denied(&Failure::Skewed),
            ErrorResponse {
                status: 403,
                code: "InvalidSignatureException",
                body: format!("{{\"message\":\"{}\"}}", Failure::Skewed.message()),
                message: Failure::Skewed.message().to_owned(),
            }
        );
        assert_eq!(
            ErrorResponse::denied(&Failure::Malformed("no X-Amz-Date")).status,
            400
        );
        assert_eq!(
            ErrorResponse::new(400, "MessageRejected", "a \"quoted\"\n\\").body,
            r#"{"message":"a \"quoted\"\u000a\\"}"#
        );
    }
}
