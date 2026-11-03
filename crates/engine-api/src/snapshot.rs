//! What every adapter decides against: one revision of policy, with each
//! identity's sender ready to sign. A message's From, and the
//! tenant and configuration its request names, resolve to its origin and
//! the sender it is signed as, the same way whichever adapter it came
//! through.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::command::Authority;
use engine_core::id::{ConfigurationId, IdentityId};
use engine_core::message::Mail;
use engine_core::policy::{Credential, Denial, Identity, Policy};
use engine_message::dkim::Signer;
use engine_message::header;
use engine_message::prepare::{self, Limits, Rejection, Sender, Stamp};

pub struct Snapshot {
    policy: Arc<Policy>,
    senders: BTreeMap<IdentityId, Arc<Sender>>,
    /// Every identity's own MAIL FROM domain, whatever its check: mail sent
    /// with a return path at one may bounce once it is no longer verified.
    mail_from: BTreeSet<Arc<str>>,
    /// The configurations with an enabled SES-shaped destination, whose
    /// messages keep what those events say of them.
    publishing: BTreeSet<ConfigurationId>,
}

/// What a message's own tags are, beside its header's, and what SES tags
/// it with itself.
pub struct Tagged<'a> {
    /// The operation it came by, as `ses:operation` names it.
    pub operation: &'static str,
    /// The access key or login it was sent with.
    pub caller: &'a str,
    /// The client's address.
    pub source_ip: IpAddr,
    /// Its request's tags, each a name and its value.
    pub given: Vec<(String, String)>,
}

/// Why a message cannot be prepared: its content, its authority, its
/// `X-SES-MESSAGE-TAGS`, which name a tag SES would not take, or its
/// sender's or tenant's rates, which have no room for it.
#[derive(Debug, PartialEq, Eq)]
pub enum Unprepared {
    Rejected(Rejection),
    Denied(Denial),
    Tags(String),
    TooFast,
}

impl Snapshot {
    /// The snapshot of `policy`. A sender is built for each identity whose
    /// record changed since `previous`; the rest are taken from it.
    pub fn new(policy: Arc<Policy>, previous: Option<&Self>) -> Result<Self, String> {
        let mut senders = BTreeMap::new();
        let mut mail_from = BTreeSet::new();
        for identity in policy.identities() {
            if let Some(own) = &identity.mail_from {
                mail_from.insert(Arc::clone(&own.domain));
            }
            let kept = previous.and_then(|previous| {
                let unchanged = previous.policy.identity(identity.id) == Some(identity);
                unchanged
                    .then(|| previous.senders.get(&identity.id).cloned())
                    .flatten()
            });
            let sender = match kept {
                Some(sender) => sender,
                None => Arc::new(sender(identity)?),
            };
            senders.insert(identity.id, sender);
        }
        let publishing = policy
            .destinations()
            .filter(|destination| destination.enabled)
            .map(|destination| destination.configuration)
            .collect();
        Ok(Self {
            policy,
            senders,
            mail_from,
            publishing,
        })
    }

    /// What SES-shaped events will say of a message prepared as `content`,
    /// sent under `authority` to `destination`, if its configuration
    /// publishes them: its header block as it is sent, cut at a field, its
    /// source, and its tags, its request's, then its header's, then SES's
    /// own. `about` gives its source and how it was sent, asked only then:
    /// nothing is built for any other message, whose cost this is not.
    pub fn mail<'a>(
        &self,
        authority: &Authority,
        raw: &[u8],
        content: &[u8],
        destination: &[Address],
        about: impl FnOnce() -> Option<(Address, Tagged<'a>)>,
    ) -> Option<Mail> {
        let configuration = authority.origin.configuration?;
        if !self.publishing.contains(&configuration) {
            return None;
        }
        let (source, tagged) = about()?;
        let (headers, truncated) = header::block(content, Mail::MOST_HEADERS);
        let mut tags = tagged.given;
        tags.extend(message_tags(raw));
        let own = [
            ("ses:operation", tagged.operation.to_owned()),
            (
                "ses:configuration-set",
                self.policy
                    .configuration(configuration)
                    .map(|found| found.name.clone())
                    .unwrap_or_default(),
            ),
            ("ses:source-ip", tagged.source_ip.to_string()),
            ("ses:from-domain", source.domain().to_ascii_lowercase()),
            ("ses:caller-identity", tagged.caller.to_owned()),
        ];
        tags.extend(own.map(|(name, value)| (name.to_owned(), value)));
        // Sent for a tenant, as SES tags it (fixtures/ses).
        if let Some(tenant) = authority
            .origin
            .tenant
            .and_then(|id| self.policy.tenant(id))
        {
            tags.push(("ses:tenant".to_owned(), tenant.name.clone()));
        }
        Some(Mail {
            source: source.as_str().to_owned(),
            destination: destination
                .iter()
                .map(|address| address.as_str().to_owned())
                .collect(),
            headers: Bytes::copy_from_slice(headers),
            truncated,
            tags,
        })
    }

    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }

    /// Whether `domain`, in lowercase, is an identity's own MAIL FROM
    /// domain, which bounces come back to.
    pub fn returns_to(&self, domain: &str) -> bool {
        self.mail_from.contains(domain)
    }

    /// What mail from `from` is sent under for `credential`, with the tenant
    /// and configuration its request names, and the sender it is signed as.
    /// `own` is the message's own From, when it is sent as another address.
    pub fn sending(
        &self,
        credential: &Credential,
        from: &Address,
        own: Option<&Address>,
        tenant: Option<&str>,
        configuration: Option<&str>,
    ) -> Result<(Authority, &Sender), Denial> {
        let origin = self
            .policy
            .origin(credential, from, own, tenant, configuration)?;
        let sender = self
            .senders
            .get(&origin.identity)
            .expect("every identity has its sender");
        let authority = Authority {
            account: credential.account,
            credential: credential.id,
            origin,
            revision: self.policy.revision(),
            template: None,
        };
        Ok((authority, sender))
    }

    /// A submitted message checked, resolved for `credential`, given
    /// `stamp`'s fields where it has none, and signed: as the identity
    /// `from` names, if given, which must be its own From's identity too,
    /// else as its own From. Before it is stamped and signed, `admit`
    /// charges its rates what it comes to, for the tenant it is sent for.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &self,
        raw: &[u8],
        limits: Limits,
        credential: &Credential,
        from: Option<&Address>,
        tenant: Option<&str>,
        configuration: Option<&str>,
        stamp: Stamp<'_>,
        admit: impl FnOnce(Option<&str>, u64) -> bool,
    ) -> Result<(Authority, Bytes), Unprepared> {
        // SES's own fields, honoured as SES honours them over SMTP and in
        // raw content, and taken out before signing, as SES takes them out:
        // the tenant and configuration set they name, when the request
        // names none.
        let (raw, named) = ses_fields(raw).map_err(Unprepared::Tags)?;
        let tenant = tenant.or(named.tenant.as_deref());
        let configuration = configuration.or(named.configuration.as_deref());
        let checked = prepare::check(&raw, limits).map_err(Unprepared::Rejected)?;
        let own = checked.from();
        let (authority, sender) = match from {
            Some(from) => self.sending(credential, from, Some(own), tenant, configuration),
            None => self.sending(credential, own, None, tenant, configuration),
        }
        .map_err(Unprepared::Denied)?;
        if !admit(tenant, raw.len() as u64) {
            return Err(Unprepared::TooFast);
        }
        let content = checked
            .sent_as(sender, stamp)
            .map_err(Unprepared::Rejected)?;
        Ok((authority, content))
    }
}

/// The sender an identity signs as, while it signs. Its key was checked
/// before the change that holds it was made, so it fails only if the stored
/// policy was changed outside the engine.
fn sender(identity: &Identity) -> Result<Sender, String> {
    let Some(signing) = identity.signer() else {
        return Ok(Sender::unsigned(identity.domain()));
    };
    let headers: Vec<&str> = signing.headers.iter().map(String::as_str).collect();
    Signer::from_pem(&signing.key, identity.domain(), &signing.selector, &headers)
        .map(Sender::signing)
        .map_err(|error| format!("identity {}: its DKIM key: {error:?}", identity.name))
}

/// The address a prepared message's own From names.
pub fn own_from(content: &[u8]) -> Option<Address> {
    header::values(content, "From")
        .first()
        .and_then(|value| prepare::mailbox(value))
}

/// The tags a message's `X-SES-MESSAGE-TAGS` fields give, as SES reads
/// them: `name=value` pairs, separated by commas.
pub fn message_tags(raw: &[u8]) -> Vec<(String, String)> {
    header::values(raw, "X-SES-MESSAGE-TAGS")
        .into_iter()
        .filter_map(|value| std::str::from_utf8(value).ok())
        .flat_map(|value| value.split(','))
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            let (name, value) = (name.trim(), value.trim());
            (!name.is_empty()).then(|| (name.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Whether `text` is a message tag's name or value as SES takes one: one
/// to 256 ASCII letters, digits, underscores and dashes. A colon is never
/// one, so a tag can never pass for SES's own, `ses:configuration-set`.
pub fn tag_text(text: &str) -> bool {
    (1..=256).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Why a message's `X-SES-MESSAGE-TAGS` fields are refused, if they are.
fn header_tags_refused(raw: &[u8]) -> Option<String> {
    header::values(raw, "X-SES-MESSAGE-TAGS")
        .into_iter()
        .find_map(tags_field_refused)
}

/// Why an `X-SES-MESSAGE-TAGS` field's value is refused, if it is: a pair
/// that is not `name=value`, or a name or value SES would not take.
pub fn tags_field_refused(value: &[u8]) -> Option<String> {
    value.split(|&byte| byte == b',').find_map(|pair| {
        let text = String::from_utf8_lossy(pair);
        let valid = text
            .split_once('=')
            .is_some_and(|(name, value)| tag_text(name.trim()) && tag_text(value.trim()));
        (!valid).then(|| format!("Invalid X-SES-MESSAGE-TAGS tag: {}", text.trim()))
    })
}

/// What a message's own SES fields name.
#[derive(Default)]
struct Named {
    tenant: Option<String>,
    configuration: Option<String>,
}

/// SES's own header fields (`X-SES-TENANT`, `X-SES-CONFIGURATION-SET`,
/// `X-SES-MESSAGE-TAGS`, and sending authorisation's `X-SES-SOURCE-ARN`,
/// `X-SES-FROM-ARN` and `X-SES-RETURN-PATH-ARN`), which SES takes out before
/// it sends: the message without them, and the tenant and configuration set
/// the first two name; or why its message tags are refused. One pass over
/// the header block for a message with none, which is left uncopied.
/// Message tags are read for the message's copy, from the message as it
/// came; authorisation is the engine's own policy, whatever ARN is named.
fn ses_fields(raw: &[u8]) -> Result<(std::borrow::Cow<'_, [u8]>, Named), String> {
    if !header::has_prefixed(raw, "x-ses-") {
        return Ok((std::borrow::Cow::Borrowed(raw), Named::default()));
    }
    if let Some(refused) = header_tags_refused(raw) {
        return Err(refused);
    }
    let first = |name| {
        header::values(raw, name)
            .first()
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|value| !value.is_empty())
    };
    let named = Named {
        tenant: first("X-SES-TENANT"),
        configuration: first("X-SES-CONFIGURATION-SET"),
    };
    let raw = header::without(
        raw,
        &[
            "X-SES-TENANT",
            "X-SES-CONFIGURATION-SET",
            "X-SES-MESSAGE-TAGS",
            "X-SES-SOURCE-ARN",
            "X-SES-FROM-ARN",
            "X-SES-RETURN-PATH-ARN",
        ],
    );
    Ok((raw, named))
}
