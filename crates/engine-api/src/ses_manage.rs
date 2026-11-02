//! SES's managing operations, for an access
//! key that manages its account: its identities, configuration
//! sets and tenants, their associations, their reputation entities and the
//! account itself.
//!
//! An identity created here brings its own DKIM key (BYODKIM) and sends
//! once the engine finds its key's record, as SES's does. One the operator
//! put is the operator's word, and answers as verified. A status SES judges
//! by its own scoring is rendered from holds, and AWS's hidden scoring
//! is not reproduced. What SES offers beyond this is refused by name, never
//! ignored: Easy DKIM, whose keys SES makes; email address identities,
//! which SES verifies by mailing a link, where an address at a verified
//! domain sends as its domain; feedback forwarding by email, which is never
//! on; and each option of a configuration set or tenant the engine does not
//! carry out. Tags are kept, and change nothing.

use std::collections::BTreeSet;

use aws_lc_rs::rsa::KeyPair;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use engine_core::address::Address;
use engine_core::command::{Command, Suppress, Unsuppress};
use engine_core::event::EventKind;
use engine_core::id::{
    AccountId, ConfigurationId, DestinationId, HoldId, IdentityId, PoolId, TemplateId, TenantId,
};
use engine_core::policy::{
    Amendment, Change, Configuration, Egress, Hold, Identity, OnMxFailure, Paused, Policy,
    PolicyRefusal, Resource, Signing, Tag, Target, Template, TemplateContent, Tenant, Verification,
};
use engine_core::suppression::{List, Page, Reason, Suppressed};
use engine_core::time::Timestamp;
use engine_ses_v2::error::{
    AlreadyExistsException, BadRequestException, CreateConfigurationSetError,
    CreateConfigurationSetEventDestinationError, CreateDedicatedIpPoolError,
    CreateEmailIdentityError, CreateEmailTemplateError, CreateTenantError,
    CreateTenantResourceAssociationError, DeleteConfigurationSetEventDestinationError,
    DeleteEmailIdentityError, DeleteEmailTemplateError, DeleteSuppressedDestinationError,
    DeleteTenantResourceAssociationError, GetAccountError, GetConfigurationSetError,
    GetConfigurationSetEventDestinationsError, GetDedicatedIpError, GetDedicatedIpsError,
    GetEmailIdentityError, GetEmailTemplateError, GetReputationEntityError,
    GetSuppressedDestinationError, GetTenantError, InvalidNextTokenException,
    LimitExceededException, ListConfigurationSetsError, ListEmailIdentitiesError,
    ListEmailTemplatesError, ListResourceTenantsError, ListSuppressedDestinationsError,
    ListTenantResourcesError, ListTenantsError, NotFoundException,
    PutConfigurationSetDeliveryOptionsError, PutConfigurationSetReputationOptionsError,
    PutDedicatedIpInPoolError, PutEmailIdentityDkimAttributesError,
    PutEmailIdentityDkimSigningAttributesError, PutEmailIdentityFeedbackAttributesError,
    PutEmailIdentityMailFromAttributesError, PutSuppressedDestinationError,
    TooManyRequestsException, UpdateConfigurationSetEventDestinationError,
    UpdateEmailTemplateError, UpdateReputationEntityCustomerManagedStatusError,
};
use engine_ses_v2::input::{
    CreateConfigurationSetInput, CreateDedicatedIpPoolInput, CreateEmailIdentityInput,
    CreateEmailTemplateInput, CreateTenantInput, DeleteSuppressedDestinationInput,
    GetDedicatedIpInput, GetDedicatedIpsInput, GetReputationEntityInput,
    GetSuppressedDestinationInput, ListConfigurationSetsInput, ListEmailIdentitiesInput,
    ListEmailTemplatesInput, ListResourceTenantsInput, ListSuppressedDestinationsInput,
    ListTenantResourcesInput, ListTenantsInput, PutConfigurationSetDeliveryOptionsInput,
    PutDedicatedIpInPoolInput, PutEmailIdentityDkimSigningAttributesInput,
    PutEmailIdentityMailFromAttributesInput, PutSuppressedDestinationInput,
    UpdateEmailTemplateInput, UpdateReputationEntityCustomerManagedStatusInput,
};
use engine_ses_v2::model::{
    self, AmazonResourceName, BehaviorOnMxFailure, DedicatedIp, DeliveryOptions, DkimAttributes,
    DkimSigningAttributes, DkimSigningAttributesOrigin, DkimStatus, EmailTemplateContent,
    EmailTemplateMetadata, EmailTemplateName, EventDestination, EventDestinationDefinition,
    EventType, Identity as IdentityName, IdentityInfo, IdentityType, MailFromAttributes,
    MailFromDomainStatus, RecommendationImpact, ReputationEntity, ReputationEntityReference,
    ReputationEntityType, ReputationOptions, ResourceTenantMetadata, ResourceType, ScalingMode,
    SendQuota, SendingOptions, SendingStatus, SnsDestination, StatusCause, StatusRecord,
    SuppressedDestination, SuppressedDestinationSummary, SuppressionListReason, TenantInfo,
    TenantName, TenantResource, TlsPolicy, VerificationStatus, WarmupStatus,
};
use engine_ses_v2::output::{
    CreateEmailIdentityOutput, CreateTenantOutput, GetAccountOutput,
    GetConfigurationSetEventDestinationsOutput, GetConfigurationSetOutput, GetDedicatedIpOutput,
    GetDedicatedIpsOutput, GetEmailIdentityOutput, GetEmailTemplateOutput,
    GetReputationEntityOutput, GetSuppressedDestinationOutput, GetTenantOutput,
    ListConfigurationSetsOutput, ListEmailIdentitiesOutput, ListEmailTemplatesOutput,
    ListResourceTenantsOutput, ListSuppressedDestinationsOutput, ListTenantResourcesOutput,
    ListTenantsOutput, PutEmailIdentityDkimSigningAttributesOutput,
};
use engine_ses_v2::types::DateTime;

use crate::{native, sns};

/// Why a managing request was refused, as SES answers it.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    BadRequest(String),
    NotFound(String),
    AlreadyExists(String),
    /// A paging token the engine did not issue.
    InvalidNextToken(String),
    /// For now: the store could not say, or IDs collided.
    Busy(String),
    /// Past what the account may keep.
    LimitExceeded(String),
}

/// An account's resources as AWS names them:
/// `arn:aws:ses:<region>:<account>:<kind>/<name>`, the account in at least
/// twelve digits, as AWS's are.
#[derive(Clone, Copy, Debug)]
pub struct Arns<'a> {
    pub region: &'a str,
    pub account: AccountId,
}

/// What an ARN of the account's own names.
#[derive(Debug, PartialEq, Eq)]
enum Arn<'a> {
    Identity(&'a str),
    Configuration(&'a str),
    Template(&'a str),
    Tenant { name: &'a str, id: &'a str },
}

impl Arns<'_> {
    fn prefix(&self) -> String {
        format!(
            "arn:aws:ses:{}:{:012}:",
            self.region,
            self.account.0.as_u64()
        )
    }

    pub fn identity(&self, name: &str) -> String {
        format!("{}identity/{name}", self.prefix())
    }

    pub fn configuration(&self, name: &str) -> String {
        format!("{}configuration-set/{name}", self.prefix())
    }

    pub fn template(&self, name: &str) -> String {
        format!("{}template/{name}", self.prefix())
    }

    /// The template `arn` names, if it is one of this region's and
    /// account's.
    pub fn template_named<'b>(&self, arn: &'b str) -> Option<&'b str> {
        match self.named(arn)? {
            Arn::Template(name) => Some(name),
            _ => None,
        }
    }

    pub fn tenant(&self, tenant: &Tenant) -> String {
        format!(
            "{}tenant/{}/{}",
            self.prefix(),
            tenant.name,
            tenant_id(tenant)
        )
    }

    /// What `arn` names, if it is one of this region's and account's.
    fn named<'b>(&self, arn: &'b str) -> Option<Arn<'b>> {
        let rest = arn.strip_prefix(self.prefix().as_str())?;
        let (kind, name) = rest.split_once('/')?;
        match kind {
            "identity" => Some(Arn::Identity(name)),
            "configuration-set" => Some(Arn::Configuration(name)),
            "template" => Some(Arn::Template(name)),
            "tenant" => {
                let (name, id) = name.split_once('/')?;
                Some(Arn::Tenant { name, id })
            }
            _ => None,
        }
    }

    /// The identity or configuration set `arn` names, as a tenant's
    /// resource.
    fn resource(&self, arn: &str) -> Result<Resource, Refused> {
        match self.named(arn) {
            Some(Arn::Identity(name)) => Ok(Resource::Identity(name.to_owned())),
            Some(Arn::Configuration(name)) => Ok(Resource::Configuration(name.to_owned())),
            Some(Arn::Template(name)) => Ok(Resource::Template(name.to_owned())),
            _ => Err(no_resource(arn)),
        }
    }

    /// The tenant, identity or configuration set `arn` names in `policy`,
    /// as a hold names it.
    fn target(&self, policy: &Policy, arn: &str) -> Result<Target, Refused> {
        let account = self.account;
        let target = match self.named(arn).ok_or_else(|| no_resource(arn))? {
            Arn::Identity(name) => {
                identity(policy, account, name)?;
                Target::Identity {
                    account,
                    name: name.to_owned(),
                }
            }
            Arn::Configuration(name) => {
                configuration(policy, account, name)?;
                Target::Configuration {
                    account,
                    name: name.to_owned(),
                }
            }
            Arn::Tenant { name, id } => {
                let found = tenant(policy, account, name)?;
                if tenant_id(found) != id {
                    return Err(no_resource(arn));
                }
                Target::Tenant {
                    account,
                    name: name.to_owned(),
                }
            }
            Arn::Template(_) => return Err(no_resource(arn)),
        };
        Ok(target)
    }
}

/// A tenant's ID, as SES shows one.
pub fn tenant_id(tenant: &Tenant) -> String {
    format!("tn-{:016x}", tenant.id.0.as_u64())
}

/// Tags as the engine keeps them: policy refuses any SES would not take.
fn kept(tags: Option<&[model::Tag]>) -> Vec<Tag> {
    tags.unwrap_or_default()
        .iter()
        .map(|tag| Tag {
            key: tag.key.clone(),
            value: tag.value.clone(),
        })
        .collect()
}

fn shown(tags: &[Tag]) -> Vec<model::Tag> {
    tags.iter()
        .map(|tag| model::Tag {
            key: tag.key.clone(),
            value: tag.value.clone(),
        })
        .collect()
}

/// The hold that refuses new mail on what `paused` names, if one does.
fn refusing(policy: &Policy, account: AccountId, paused: Paused) -> Option<&Hold> {
    policy.held(account, paused).filter(|hold| !hold.accepting)
}

/// A status SES judges, rendered from holds: disabled while one
/// refuses new mail.
fn sending_status(policy: &Policy, account: AccountId, paused: Paused) -> SendingStatus {
    match refusing(policy, account, paused) {
        Some(_) => SendingStatus::Disabled,
        None => SendingStatus::Enabled,
    }
}

/// The change `CreateEmailIdentity` asks for: a domain identity with its own
/// key, pending from `at`.
pub fn create(
    input: &CreateEmailIdentityInput,
    account: AccountId,
    id: IdentityId,
    at: Timestamp,
) -> Result<Change, Refused> {
    let name = input.email_identity.as_str();
    if name.contains('@') {
        return Err(bad(
            "NitroMTA creates domain identities alone: an address at a verified domain sends as its domain",
        ));
    }
    let attributes = input.dkim_signing_attributes.as_ref().ok_or_else(|| {
        bad("NitroMTA verifies a domain by its own DKIM key: give DkimSigningAttributes (Bring Your Own DKIM)")
    })?;
    if attributes
        .domain_signing_attributes_origin
        .as_ref()
        .is_some_and(|origin| *origin != DkimSigningAttributesOrigin::External)
    {
        return Err(easy_dkim());
    }
    Ok(Change::NewIdentity {
        id,
        account,
        name: name.to_owned(),
        signing: signing(name, attributes)?,
        configuration: input.configuration_set_name.clone(),
        tags: kept(input.tags.as_deref()),
        at,
    })
}

/// The change `PutEmailIdentityDkimSigningAttributes` asks for: a new key,
/// checked from `at`.
pub fn new_key(
    input: &PutEmailIdentityDkimSigningAttributesInput,
    account: AccountId,
    at: Timestamp,
) -> Result<Change, Refused> {
    if input.signing_attributes_origin != DkimSigningAttributesOrigin::External {
        return Err(easy_dkim());
    }
    let name = input.email_identity.as_str();
    let attributes = input
        .signing_attributes
        .as_ref()
        .ok_or_else(|| bad("SigningAttributes are needed for an EXTERNAL key"))?;
    // The origin is the request's own; one given again inside it is
    // another option, which this operation does not take.
    if attributes.domain_signing_attributes_origin.is_some() {
        return Err(bad(
            "SigningAttributes.DomainSigningAttributesOrigin is not supported here: give SigningAttributesOrigin EXTERNAL",
        ));
    }
    Ok(Change::Amend {
        account,
        name: name.to_owned(),
        amendment: Amendment::Signing {
            signing: signing(name, attributes)?,
            at,
        },
    })
}

/// The change `PutEmailIdentityDkimAttributes` asks for, of an identity
/// that has a key to sign with.
pub fn signs(
    policy: &Policy,
    account: AccountId,
    name: &str,
    signs: bool,
) -> Result<Change, Refused> {
    let identity = identity(policy, account, name)?;
    if signs && identity.signing.is_none() {
        return Err(bad(
            "The identity has no DKIM key to sign with: put one with PutEmailIdentityDkimSigningAttributes",
        ));
    }
    Ok(Change::Amend {
        account,
        name: name.to_owned(),
        amendment: Amendment::Signs(signs),
    })
}

/// The change `PutEmailIdentityMailFromAttributes` asks for: the identity's
/// own MAIL FROM domain, checked from `at`, or none. Its MX must name
/// `bounce_host`, where bounces arrive: an installation that takes none has
/// no MAIL FROM domain to give.
pub fn mail_from(
    input: &PutEmailIdentityMailFromAttributesInput,
    account: AccountId,
    bounce_host: Option<&str>,
    at: Timestamp,
) -> Result<Change, Refused> {
    let behavior = match input.behavior_on_mx_failure {
        None | Some(BehaviorOnMxFailure::UseDefaultValue) => OnMxFailure::UseDefault,
        Some(BehaviorOnMxFailure::RejectMessage) => OnMxFailure::Reject,
    };
    let domain = input
        .mail_from_domain
        .as_deref()
        .filter(|domain| !domain.is_empty());
    if domain.is_some() && bounce_host.is_none() {
        return Err(bad(
            "This installation takes no bounces ([feedback] is not configured), so no MAIL FROM domain can point at it",
        ));
    }
    Ok(Change::Amend {
        account,
        name: input.email_identity.as_str().to_owned(),
        amendment: Amendment::MailFrom {
            mail_from: domain.map(|domain| (domain.to_owned(), behavior)),
            at,
        },
    })
}

/// `DeleteEmailIdentity`'s change.
pub fn delete(account: AccountId, name: &str) -> Change {
    Change::Remove(Target::Identity {
        account,
        name: name.to_owned(),
    })
}

/// `PutEmailIdentityFeedbackAttributes`: feedback arrives as events, never
/// forwarded by email, so it is already off, and is never turned on.
pub fn feedback(
    policy: &Policy,
    account: AccountId,
    name: &str,
    forwarding: bool,
) -> Result<(), Refused> {
    identity(policy, account, name)?;
    if forwarding {
        return Err(bad(
            "NitroMTA never forwards feedback by email: it arrives as events",
        ));
    }
    Ok(())
}

/// The identity `name` names in `account`, or SES's refusal.
pub fn identity<'a>(
    policy: &'a Policy,
    account: AccountId,
    name: &str,
) -> Result<&'a Identity, Refused> {
    policy
        .identity_named(account, name)
        .and_then(|id| policy.identity(id))
        .ok_or_else(|| no_identity(name))
}

/// What a committed change's refusal of the identity `name` is answered
/// as.
pub fn identity_refused(refusal: PolicyRefusal, name: &str) -> Refused {
    match refusal {
        PolicyRefusal::Taken => {
            Refused::AlreadyExists(format!("Email identity {name} already exists."))
        }
        PolicyRefusal::Unknown {
            kind: "configuration",
            name: configuration,
        } => Refused::NotFound(format!("Configuration set {configuration} does not exist.")),
        PolicyRefusal::Unknown { .. } => no_identity(name),
        PolicyRefusal::InvalidName => bad(format!(
            "{name} is not a domain, or its selector is not a DNS label, or its MAIL FROM domain is not a subdomain of it"
        )),
        PolicyRefusal::Conflict | PolicyRefusal::Outdated | PolicyRefusal::Limit => {
            Refused::Busy("Try again".to_owned())
        }
    }
}

/// The answer to `CreateEmailIdentity`, from the identity as it was made.
pub fn created(identity: &Identity) -> CreateEmailIdentityOutput {
    CreateEmailIdentityOutput {
        identity_type: Some(identity_type(identity)),
        verified_for_sending_status: identity.verified(),
        dkim_attributes: Some(dkim(identity)),
    }
}

/// The answer to `PutEmailIdentityDkimSigningAttributes`.
pub fn keyed(identity: &Identity) -> PutEmailIdentityDkimSigningAttributesOutput {
    let dkim = dkim(identity);
    PutEmailIdentityDkimSigningAttributesOutput {
        dkim_status: dkim.status,
        dkim_tokens: dkim.tokens,
        signing_hosted_zone: None,
    }
}

/// The answer to `GetEmailIdentity`.
pub fn got(policy: &Policy, identity: &Identity) -> GetEmailIdentityOutput {
    GetEmailIdentityOutput {
        identity_type: Some(identity_type(identity)),
        feedback_forwarding_status: false,
        verified_for_sending_status: identity.verified(),
        dkim_attributes: Some(dkim(identity)),
        mail_from_attributes: identity.mail_from.as_ref().map(|own| MailFromAttributes {
            mail_from_domain: own.domain.to_string(),
            mail_from_domain_status: match own.check.status {
                Verification::Pending => MailFromDomainStatus::Pending,
                Verification::Success => MailFromDomainStatus::Success,
                Verification::TemporaryFailure => MailFromDomainStatus::TemporaryFailure,
                Verification::Failed => MailFromDomainStatus::Failed,
            },
            behavior_on_mx_failure: match own.behavior {
                OnMxFailure::UseDefault => BehaviorOnMxFailure::UseDefaultValue,
                OnMxFailure::Reject => BehaviorOnMxFailure::RejectMessage,
            },
        }),
        policies: None,
        tags: Some(shown(&identity.tags)),
        configuration_set_name: identity
            .configuration
            .and_then(|id| policy.configuration(id))
            .map(|configuration| configuration.name.clone()),
        verification_status: Some(verification_status(identity)),
        verification_info: None,
    }
}

/// The most one page holds, and as many as a page holds when its request
/// names no size.
const MAX_PAGE: usize = 1000;
const PAGE: usize = 100;

/// The version a token's first part names, so a token from another
/// version of the engine is refused rather than read wrongly.
const TOKEN_VERSION: &str = "1";

/// How many a page holds, from the request's `PageSize`.
fn page_size(size: Option<i32>) -> Result<usize, Refused> {
    match size {
        None => Ok(PAGE),
        Some(size) => Ok(usize::try_from(size)
            .ok()
            .filter(|size| *size <= MAX_PAGE)
            .ok_or_else(|| bad("PageSize is 0 to 1000"))?
            .max(1)),
    }
}

/// A page of `items`, which come in the order of what `name` gives: at most
/// `size`, and the token for the next if any remain. A token names the last
/// of its page, so one created or deleted while the pages are read is
/// listed if it comes after the page being read, and not otherwise.
fn paged<T>(
    mut items: impl Iterator<Item = T>,
    size: usize,
    name: impl Fn(&T) -> &str,
) -> (Vec<T>, Option<String>) {
    let page: Vec<T> = items.by_ref().take(size).collect();
    let next = match (page.last(), items.next()) {
        (Some(last), Some(_)) => Some(format!(
            "{TOKEN_VERSION}.{}",
            URL_SAFE_NO_PAD.encode(name(last))
        )),
        _ => None,
    };
    (page, next)
}

/// The name a token resumes after.
fn after(token: Option<&str>) -> Result<Option<String>, Refused> {
    token
        .map(|token| {
            token
                .split_once('.')
                .filter(|(version, _)| *version == TOKEN_VERSION)
                .and_then(|(_, name)| URL_SAFE_NO_PAD.decode(name).ok())
                .and_then(|name| String::from_utf8(name).ok())
                .ok_or_else(|| {
                    Refused::InvalidNextToken(
                        "Invalid NextToken: it is not one this engine issued".to_owned(),
                    )
                })
        })
        .transpose()
}

/// A listing's filter, which the engine does not apply: refused if one is
/// `given`.
fn unfiltered(given: bool) -> Result<(), Refused> {
    if given {
        return Err(bad("Filter is not supported: list them all"));
    }
    Ok(())
}

/// `ListEmailIdentities`: the account's identities in the order of their
/// names, a page at a time.
pub fn list(
    policy: &Policy,
    account: AccountId,
    input: &ListEmailIdentitiesInput,
) -> Result<ListEmailIdentitiesOutput, Refused> {
    unfiltered(
        input
            .filter
            .as_ref()
            .is_some_and(|filter| !filter.is_empty()),
    )?;
    let size = page_size(input.page_size)?;
    let after = after(input.next_token.as_deref())?;
    let (page, next_token) = paged(
        policy.identities_after(account, after.as_deref()),
        size,
        |identity| &identity.name,
    );
    Ok(ListEmailIdentitiesOutput {
        email_identities: Some(
            page.into_iter()
                .map(|identity| IdentityInfo {
                    identity_type: Some(identity_type(identity)),
                    identity_name: IdentityName::try_from(identity.name.clone()).ok(),
                    sending_enabled: sending(policy, identity),
                    verification_status: Some(verification_status(identity)),
                })
                .collect(),
        ),
        next_token,
    })
}

/// Whether mail may be sent as `identity` now: it is verified, and no hold
/// on it or its account refuses new mail.
fn sending(policy: &Policy, identity: &Identity) -> bool {
    identity.verified()
        && [Paused::Account, Paused::Identity(identity.id)]
            .into_iter()
            .all(|paused| refusing(policy, identity.account, paused).is_none())
}

fn identity_type(identity: &Identity) -> IdentityType {
    if identity.name.contains('@') {
        IdentityType::EmailAddress
    } else {
        IdentityType::Domain
    }
}

/// Its DKIM attributes: for a key it brought, its selector as the token, as
/// SES lists it for Bring Your Own DKIM.
fn dkim(identity: &Identity) -> DkimAttributes {
    DkimAttributes {
        signing_enabled: identity.signer().is_some(),
        status: Some(match (&identity.signing, identity.verification) {
            (None, _) => DkimStatus::NotStarted,
            (Some(_), None) => DkimStatus::Success,
            (Some(_), Some(check)) => match check.status {
                Verification::Pending => DkimStatus::Pending,
                Verification::Success => DkimStatus::Success,
                Verification::TemporaryFailure => DkimStatus::TemporaryFailure,
                Verification::Failed => DkimStatus::Failed,
            },
        }),
        tokens: identity
            .signing
            .as_ref()
            .map(|signing| vec![signing.selector.clone()]),
        signing_hosted_zone: None,
        signing_attributes_origin: identity
            .signing
            .as_ref()
            .map(|_| DkimSigningAttributesOrigin::External),
        next_signing_key_length: None,
        current_signing_key_length: None,
        last_key_generation_timestamp: None,
    }
}

/// The identity's own status: its DKIM key's, for one the engine checks.
fn verification_status(identity: &Identity) -> VerificationStatus {
    match identity.verification.map(|check| check.status) {
        None | Some(Verification::Success) => VerificationStatus::Success,
        Some(Verification::Pending) => VerificationStatus::Pending,
        Some(Verification::TemporaryFailure) => VerificationStatus::TemporaryFailure,
        Some(Verification::Failed) => VerificationStatus::Failed,
    }
}

/// The signing a request's attributes give: its selector, and its private
/// key in base64, as SES takes it, PKCS #8 or PKCS #1, which must sign.
fn signing(name: &str, attributes: &DkimSigningAttributes) -> Result<Signing, Refused> {
    if attributes.next_signing_key_length.is_some() {
        return Err(easy_dkim());
    }
    let (Some(selector), Some(key)) = (
        &attributes.domain_signing_selector,
        &attributes.domain_signing_private_key,
    ) else {
        return Err(bad(
            "Bring Your Own DKIM needs DomainSigningSelector and DomainSigningPrivateKey",
        ));
    };
    let unarmored: String = key
        .as_str()
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let der = STANDARD
        .decode(unarmored)
        .map_err(|_| bad("DomainSigningPrivateKey is not base64"))?;
    let label = if KeyPair::from_pkcs8(&der).is_ok() {
        "PRIVATE KEY"
    } else if KeyPair::from_der(&der).is_ok() {
        "RSA PRIVATE KEY"
    } else {
        return Err(bad(
            "DomainSigningPrivateKey is not an RSA private key of 2048 bits or more",
        ));
    };
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in STANDARD.encode(&der).as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    native::signing(name, Some(selector.as_str().to_owned()), Some(pem), None)
        .map_err(|refusal| {
            bad(format!(
                "DomainSigningPrivateKey does not sign: {refusal:?}"
            ))
        })?
        .ok_or_else(|| bad("DomainSigningPrivateKey is needed"))
}

fn easy_dkim() -> Refused {
    bad("Easy DKIM is not supported: NitroMTA signs with the key you give it (EXTERNAL)")
}

fn no_identity(name: &str) -> Refused {
    Refused::NotFound(format!("Email identity {name} does not exist."))
}

fn bad(message: impl Into<String>) -> Refused {
    Refused::BadRequest(message.into())
}

/// The change `CreateConfigurationSet` asks for: a configuration set, its
/// pool if its delivery options name one, its tags, and its reputation
/// metrics' setting. Options the engine does not carry out are refused by
/// name.
pub fn create_configuration(
    input: &CreateConfigurationSetInput,
    account: AccountId,
    id: ConfigurationId,
) -> Result<Change, Refused> {
    let unsupported = [
        ("TrackingOptions", input.tracking_options.is_some()),
        ("SuppressionOptions", input.suppression_options.is_some()),
        ("VdmOptions", input.vdm_options.is_some()),
        ("ArchivingOptions", input.archiving_options.is_some()),
        (
            "MessageSecurityOptions",
            input.message_security_options.is_some(),
        ),
        (
            "ReputationOptions.LastFreshStart",
            input
                .reputation_options
                .as_ref()
                .is_some_and(|options| options.last_fresh_start.is_some()),
        ),
        (
            "SendingOptions with SendingEnabled false",
            input
                .sending_options
                .as_ref()
                .is_some_and(|options| !options.sending_enabled),
        ),
    ];
    if let Some((option, _)) = unsupported.iter().find(|(_, given)| *given) {
        return Err(bad(format!("{option} is not supported")));
    }
    let pool = match &input.delivery_options {
        None => None,
        Some(options) => delivery_pool(
            options.tls_policy.as_ref(),
            options.max_delivery_seconds.is_some(),
            options.sending_pool_name.as_ref(),
        )?,
    };
    Ok(Change::NewConfiguration {
        id,
        account,
        name: input.configuration_set_name.clone(),
        pool,
        reputation_metrics: input
            .reputation_options
            .as_ref()
            .is_some_and(|options| options.reputation_metrics_enabled),
        tags: kept(input.tags.as_deref()),
    })
}

/// The pool a configuration set's delivery options name, once what else
/// they say is what the engine does: no required TLS policy, as transport
/// security is the installation's (MTA-STS, DANE), and no delivery time.
fn delivery_pool(
    tls_policy: Option<&TlsPolicy>,
    max_delivery_seconds: bool,
    pool: Option<&String>,
) -> Result<Option<String>, Refused> {
    if tls_policy == Some(&TlsPolicy::Require) {
        return Err(bad(
            "TlsPolicy REQUIRE is not supported: the engine's transport security is the installation's (MTA-STS, DANE)",
        ));
    }
    if max_delivery_seconds {
        return Err(bad("MaxDeliverySeconds is not supported"));
    }
    Ok(pool.cloned())
}

/// The change `PutConfigurationSetDeliveryOptions` asks for.
pub fn delivery_options(
    input: &PutConfigurationSetDeliveryOptionsInput,
    account: AccountId,
) -> Result<Change, Refused> {
    Ok(Change::ConfigurationPool {
        account,
        configuration: input.configuration_set_name.clone(),
        pool: delivery_pool(
            input.tls_policy.as_ref(),
            input.max_delivery_seconds.is_some(),
            input.sending_pool_name.as_ref(),
        )?,
    })
}

/// The journal's kinds of event each of SES's event types names:
/// a bounce is a refusal for good, an expiry or a suppression, as SES
/// reports each; a delivery is one the receiver took, or capture mode did.
fn kinds(event: &EventType) -> Result<&'static [EventKind], Refused> {
    Ok(match event {
        EventType::Send => &[EventKind::Accepted],
        EventType::Delivery => &[EventKind::Delivered, EventKind::Captured],
        EventType::Bounce => &[
            EventKind::Bounced,
            EventKind::Expired,
            EventKind::Suppressed,
        ],
        EventType::Complaint => &[EventKind::Complained],
        EventType::DeliveryDelay => &[EventKind::Deferred],
        other => {
            return Err(bad(format!(
                "{} events are not supported: NitroMTA makes none",
                other.as_str()
            )));
        }
    })
}

/// SES's event types the kinds `held` are, in SES's order.
fn event_types(held: &BTreeSet<EventKind>) -> Vec<EventType> {
    [
        EventType::Send,
        EventType::Delivery,
        EventType::Bounce,
        EventType::Complaint,
        EventType::DeliveryDelay,
    ]
    .into_iter()
    .filter(|event| {
        kinds(event)
            .unwrap_or_default()
            .iter()
            .any(|kind| held.contains(kind))
    })
    .collect()
}

/// The change `CreateConfigurationSetEventDestination`, or with `replaces`
/// `UpdateConfigurationSetEventDestination`, asks for: an SNS destination
/// naming one of the account's topics, by its ARN.
pub fn destination(
    configuration: &str,
    name: &str,
    definition: &EventDestinationDefinition,
    account: AccountId,
    region: &str,
    id: DestinationId,
    replaces: bool,
) -> Result<Change, Refused> {
    let others = [
        (
            "KinesisFirehoseDestination",
            definition.kinesis_firehose_destination.is_some(),
        ),
        (
            "CloudWatchDestination",
            definition.cloud_watch_destination.is_some(),
        ),
        (
            "EventBridgeDestination",
            definition.event_bridge_destination.is_some(),
        ),
        (
            "PinpointDestination",
            definition.pinpoint_destination.is_some(),
        ),
    ];
    if let Some((other, _)) = others.iter().find(|(_, given)| *given) {
        return Err(bad(format!(
            "{other} is not supported: NitroMTA publishes events to its own SNS topics"
        )));
    }
    let topic_arn = definition
        .sns_destination
        .as_ref()
        .ok_or_else(|| bad("An SnsDestination is needed"))?
        .topic_arn
        .as_str();
    let topic = sns::Arns { region, account }
        .topic_name(topic_arn)
        .ok_or_else(|| Refused::NotFound(format!("Topic {topic_arn} does not exist.")))?;
    let mut events = BTreeSet::new();
    for event in definition.matching_event_types.iter().flatten() {
        events.extend(kinds(event)?);
    }
    if events.is_empty() {
        return Err(bad("MatchingEventTypes are needed"));
    }
    Ok(Change::Destination {
        id,
        account,
        configuration: configuration.to_owned(),
        name: name.to_owned(),
        topic: topic.to_owned(),
        events,
        enabled: definition.enabled,
        replaces,
    })
}

/// `GetConfigurationSetEventDestinations`' answer: the configuration set's
/// destinations, each its topic's ARN.
pub fn destinations(
    policy: &Policy,
    configuration: &Configuration,
    region: &str,
) -> GetConfigurationSetEventDestinationsOutput {
    let arns = sns::Arns {
        region,
        account: configuration.account,
    };
    let shown = policy
        .destinations()
        .filter(|destination| destination.configuration == configuration.id)
        .filter_map(|destination| {
            let topic = policy.topic_of(destination.topic)?;
            Some(EventDestination {
                name: destination.name.clone(),
                enabled: destination.enabled,
                matching_event_types: event_types(&destination.events),
                kinesis_firehose_destination: None,
                cloud_watch_destination: None,
                sns_destination: AmazonResourceName::try_from(arns.topic(&topic.name))
                    .ok()
                    .map(|topic_arn| SnsDestination { topic_arn }),
                event_bridge_destination: None,
                pinpoint_destination: None,
            })
        })
        .collect();
    GetConfigurationSetEventDestinationsOutput {
        event_destinations: Some(shown),
    }
}

/// `DeleteConfigurationSetEventDestination`'s change.
pub fn delete_destination(account: AccountId, configuration: &str, name: &str) -> Change {
    Change::Remove(Target::Destination {
        account,
        configuration: configuration.to_owned(),
        name: name.to_owned(),
    })
}

/// What a committed change's refusal of the destination `name` is
/// answered as.
pub fn destination_refused(refusal: PolicyRefusal, configuration: &str, name: &str) -> Refused {
    match refusal {
        PolicyRefusal::Taken => {
            Refused::AlreadyExists(format!("Event destination {name} already exists."))
        }
        PolicyRefusal::Unknown {
            kind: "configuration",
            ..
        } => no_configuration(configuration),
        PolicyRefusal::Unknown {
            kind: "topic",
            name: topic,
        } => Refused::NotFound(format!("Topic {topic} does not exist.")),
        PolicyRefusal::Unknown { .. } => {
            Refused::NotFound(format!("Event destination {name} does not exist."))
        }
        PolicyRefusal::InvalidName => bad(format!(
            "{name} is not 1 to 64 letters, digits, hyphens and underscores"
        )),
        PolicyRefusal::Conflict | PolicyRefusal::Outdated | PolicyRefusal::Limit => {
            Refused::Busy("Try again".to_owned())
        }
    }
}

/// The change `CreateDedicatedIpPool` asks for: a pool of the account's
/// egresses.
pub fn create_pool(
    input: &CreateDedicatedIpPoolInput,
    account: AccountId,
    id: PoolId,
) -> Result<Change, Refused> {
    if input.scaling_mode == Some(ScalingMode::Managed) {
        return Err(bad(
            "ScalingMode MANAGED is not supported: the engine's warmup is its own (engine-warmup)",
        ));
    }
    if input.tags.as_ref().is_some_and(|tags| !tags.is_empty()) {
        return Err(bad("Tags are not supported on dedicated IP pools"));
    }
    Ok(Change::NewPool {
        id,
        account,
        name: input.pool_name.clone(),
    })
}

/// The change `PutDedicatedIpInPool` asks for: an egress of the account,
/// by its address, into the pool.
pub fn into_pool(input: &PutDedicatedIpInPoolInput, account: AccountId) -> Result<Change, Refused> {
    let address = input
        .ip
        .parse()
        .map_err(|_| bad(format!("{} is not an IP address", input.ip)))?;
    Ok(Change::EgressPool {
        account,
        address,
        pool: Some(input.destination_pool_name.clone()),
    })
}

/// `GetDedicatedIp`: an egress of the account, by its address, with how far
/// its warmup has climbed `ladder`, the rule bundle's default.
pub fn dedicated_ip(
    policy: &Policy,
    account: AccountId,
    input: &GetDedicatedIpInput,
    ladder: &[u64],
) -> Result<GetDedicatedIpOutput, Refused> {
    let address: std::net::IpAddr = input
        .ip
        .parse()
        .map_err(|_| bad(format!("{} is not an IP address", input.ip)))?;
    let egress = policy
        .egresses()
        .find(|egress| egress.account == account && egress.address == address)
        .ok_or_else(|| Refused::NotFound(format!("Dedicated IP {} does not exist.", input.ip)))?;
    Ok(GetDedicatedIpOutput {
        dedicated_ip: Some(dedicated(policy, egress, ladder)),
    })
}

/// `GetDedicatedIps`: the account's egresses, or those of its pool the
/// request names, in the order of their addresses, a page at a time.
pub fn dedicated_ips(
    policy: &Policy,
    account: AccountId,
    input: &GetDedicatedIpsInput,
    ladder: &[u64],
) -> Result<GetDedicatedIpsOutput, Refused> {
    let size = page_size(input.page_size)?;
    let after = after(input.next_token.as_deref())?;
    let pool = input
        .pool_name
        .as_ref()
        .map(|name| {
            policy
                .pools()
                .find(|pool| pool.account == account && pool.name == *name)
                .map(|pool| pool.id)
                .ok_or_else(|| Refused::NotFound(format!("Pool {name} does not exist.")))
        })
        .transpose()?;
    let mut egresses: Vec<(String, &Egress)> = policy
        .egresses()
        .filter(|egress| egress.account == account)
        .filter(|egress| pool.is_none_or(|pool| egress.pool == Some(pool)))
        .map(|egress| (egress.address.to_string(), egress))
        .filter(|(address, _)| {
            after
                .as_deref()
                .is_none_or(|after| address.as_str() > after)
        })
        .collect();
    egresses.sort_by(|a, b| a.0.cmp(&b.0));
    let (page, next_token) = paged(egresses.into_iter(), size, |(address, _)| address);
    Ok(GetDedicatedIpsOutput {
        dedicated_ips: Some(
            page.into_iter()
                .map(|(_, egress)| dedicated(policy, egress, ladder))
                .collect(),
        ),
        next_token,
    })
}

/// An egress as SES's dedicated IP: `IN_PROGRESS` at the share of `ladder`
/// its caps have climbed while any is left, `DONE` at 100 once none is.
fn dedicated(policy: &Policy, egress: &Egress, ladder: &[u64]) -> DedicatedIp {
    let climbed = egress.caps.climbed(ladder);
    DedicatedIp {
        ip: egress.address.to_string(),
        warmup_status: match climbed {
            Some(_) => WarmupStatus::InProgress,
            None => WarmupStatus::Done,
        },
        warmup_percentage: climbed.map_or(100, |share| i32::try_from(share).unwrap_or(99)),
        pool_name: egress
            .pool
            .and_then(|id| policy.pool(id))
            .map(|pool| pool.name.clone()),
    }
}

/// What a committed change's refusal of a pool, or of an egress put into
/// one, is answered as.
pub fn pool_refused(refusal: PolicyRefusal, name: &str) -> Refused {
    match refusal {
        PolicyRefusal::Taken => Refused::AlreadyExists(format!("Pool {name} already exists.")),
        PolicyRefusal::Unknown {
            kind: "egress",
            name: address,
        } => Refused::NotFound(format!("Dedicated IP {address} does not exist.")),
        PolicyRefusal::Unknown {
            kind: "configuration",
            name: configuration,
        } => no_configuration(&configuration),
        PolicyRefusal::Unknown { name: pool, .. } => {
            Refused::NotFound(format!("Pool {pool} does not exist."))
        }
        PolicyRefusal::InvalidName => bad(format!(
            "{name} is not 1 to 64 letters, digits, hyphens and underscores"
        )),
        PolicyRefusal::Conflict | PolicyRefusal::Outdated | PolicyRefusal::Limit => {
            Refused::Busy("Try again".to_owned())
        }
    }
}

/// `GetConfigurationSet`'s answer.
pub fn got_configuration(
    policy: &Policy,
    configuration: &Configuration,
) -> GetConfigurationSetOutput {
    let account = configuration.account;
    let paused = Paused::Configuration(configuration.id);
    GetConfigurationSetOutput {
        configuration_set_name: Some(configuration.name.clone()),
        tracking_options: None,
        delivery_options: Some(DeliveryOptions {
            tls_policy: Some(TlsPolicy::Optional),
            sending_pool_name: configuration
                .pool
                .and_then(|id| policy.pool(id))
                .map(|pool| pool.name.clone()),
            max_delivery_seconds: None,
        }),
        reputation_options: Some(ReputationOptions {
            reputation_metrics_enabled: configuration.reputation_metrics,
            last_fresh_start: None,
        }),
        sending_options: Some(SendingOptions {
            sending_enabled: refusing(policy, account, paused).is_none(),
        }),
        tags: Some(shown(&configuration.tags)),
        suppression_options: None,
        vdm_options: None,
        archiving_options: None,
        message_security_options: None,
    }
}

/// What a committed change's refusal of the configuration set `name` is
/// answered as.
pub fn configuration_refused(refusal: PolicyRefusal, name: &str) -> Refused {
    match refusal {
        PolicyRefusal::Taken => {
            Refused::AlreadyExists(format!("Configuration set {name} already exists."))
        }
        PolicyRefusal::Unknown {
            kind: "pool",
            name: pool,
        } => Refused::NotFound(format!("Dedicated IP pool {pool} does not exist.")),
        PolicyRefusal::Unknown { .. } => no_configuration(name),
        PolicyRefusal::InvalidName => bad(format!(
            "{name} is not 1 to 64 letters, digits, hyphens and underscores, or its tags are not as SES takes them"
        )),
        PolicyRefusal::Conflict | PolicyRefusal::Outdated | PolicyRefusal::Limit => {
            Refused::Busy("Try again".to_owned())
        }
    }
}

/// What a committed change's refusal of the tenant `name` is answered as.
pub fn tenant_refused(refusal: PolicyRefusal, name: &str) -> Refused {
    match refusal {
        PolicyRefusal::Taken => Refused::AlreadyExists(format!("Tenant {name} already exists.")),
        PolicyRefusal::Unknown { .. } => {
            Refused::NotFound(format!("Tenant {name} does not exist."))
        }
        PolicyRefusal::InvalidName => bad(format!(
            "{name} is not 1 to 64 letters, digits, hyphens and underscores, or its tags are not as SES takes them"
        )),
        PolicyRefusal::Conflict | PolicyRefusal::Outdated | PolicyRefusal::Limit => {
            Refused::Busy("Try again".to_owned())
        }
    }
}

/// The configuration set `name` names in `account`, or SES's refusal.
pub fn configuration<'a>(
    policy: &'a Policy,
    account: AccountId,
    name: &str,
) -> Result<&'a Configuration, Refused> {
    policy
        .configuration_named(account, name)
        .and_then(|id| policy.configuration(id))
        .ok_or_else(|| no_configuration(name))
}

/// The change `CreateTenant` asks for, at `at`.
pub fn create_tenant(
    input: &CreateTenantInput,
    account: AccountId,
    id: TenantId,
    at: Timestamp,
) -> Result<Change, Refused> {
    if input.suppression_attributes.is_some() {
        return Err(bad(
            "SuppressionAttributes are not supported: a tenant's mail is suppressed by its account's list",
        ));
    }
    Ok(Change::NewTenant {
        id,
        account,
        name: input.tenant_name.as_str().to_owned(),
        tags: kept(input.tags.as_deref()),
        at,
    })
}

/// The tenant `name` names in `account`, or SES's refusal.
pub fn tenant<'a>(
    policy: &'a Policy,
    account: AccountId,
    name: &str,
) -> Result<&'a Tenant, Refused> {
    policy
        .tenant_named(account, name)
        .and_then(|id| policy.tenant(id))
        .ok_or_else(|| Refused::NotFound(format!("Tenant {name} does not exist.")))
}

/// A tenant as SES shows one.
fn shown_tenant(policy: &Policy, arns: Arns<'_>, tenant: &Tenant) -> model::Tenant {
    model::Tenant {
        tenant_name: TenantName::try_from(tenant.name.clone()).ok(),
        tenant_id: Some(tenant_id(tenant)),
        tenant_arn: AmazonResourceName::try_from(arns.tenant(tenant)).ok(),
        created_timestamp: tenant.created.map(date_time),
        tags: Some(shown(&tenant.tags)),
        sending_status: Some(sending_status(
            policy,
            tenant.account,
            Paused::Tenant(tenant.id),
        )),
        suppression_attributes: None,
    }
}

/// `CreateTenant`'s answer.
pub fn created_tenant(policy: &Policy, arns: Arns<'_>, tenant: &Tenant) -> CreateTenantOutput {
    let shown = shown_tenant(policy, arns, tenant);
    CreateTenantOutput {
        tenant_name: shown.tenant_name,
        tenant_id: shown.tenant_id,
        tenant_arn: shown.tenant_arn,
        created_timestamp: shown.created_timestamp,
        tags: shown.tags,
        sending_status: shown.sending_status,
        suppression_attributes: None,
    }
}

/// `GetTenant`'s answer.
pub fn got_tenant(policy: &Policy, arns: Arns<'_>, tenant: &Tenant) -> GetTenantOutput {
    GetTenantOutput {
        tenant: Some(shown_tenant(policy, arns, tenant)),
    }
}

/// `ListConfigurationSets`: the account's configuration sets in the order
/// of their names, a page at a time.
pub fn list_configurations(
    policy: &Policy,
    account: AccountId,
    input: &ListConfigurationSetsInput,
) -> Result<ListConfigurationSetsOutput, Refused> {
    unfiltered(
        input
            .filter
            .as_ref()
            .is_some_and(|filter| !filter.is_empty()),
    )?;
    let size = page_size(input.page_size)?;
    let after = after(input.next_token.as_deref())?;
    let (page, next_token) = paged(
        policy.configurations_after(account, after.as_deref()),
        size,
        |configuration| &configuration.name,
    );
    Ok(ListConfigurationSetsOutput {
        configuration_sets: Some(
            page.into_iter()
                .map(|configuration| configuration.name.clone())
                .collect(),
        ),
        next_token,
    })
}

/// A template's parts as a request gives them: a subject, and text, HTML or
/// both, together within what a template may hold.
fn template_content(content: &EmailTemplateContent) -> Result<TemplateContent, Refused> {
    let content = TemplateContent {
        subject: content.subject.clone().unwrap_or_default(),
        text: content.text.clone(),
        html: content.html.clone(),
    };
    if content.text.is_none() && content.html.is_none() {
        return Err(bad("The template must have Text, Html or both"));
    }
    if content.bytes() > TemplateContent::MOST_BYTES {
        return Err(bad(format!(
            "The template's parts come to more than {} bytes",
            TemplateContent::MOST_BYTES
        )));
    }
    // One the engine cannot render is refused now, not when mail is sent.
    for part in [
        Some(&content.subject),
        content.text.as_ref(),
        content.html.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        crate::template::checked(part).map_err(|error| bad(error.to_string()))?;
    }
    Ok(content)
}

/// The change `CreateEmailTemplate` asks for, made at `at`.
pub fn create_template(
    input: &CreateEmailTemplateInput,
    account: AccountId,
    id: TemplateId,
    at: Timestamp,
) -> Result<Change, Refused> {
    if input.tags.as_ref().is_some_and(|tags| !tags.is_empty()) {
        return Err(bad("Tags are not kept on templates"));
    }
    Ok(Change::NewTemplate {
        id,
        account,
        name: input.template_name.as_str().to_owned(),
        content: template_content(&input.template_content)?,
        at,
    })
}

/// The change `UpdateEmailTemplate` asks for.
pub fn update_template(
    input: &UpdateEmailTemplateInput,
    account: AccountId,
) -> Result<Change, Refused> {
    Ok(Change::TemplateContent {
        account,
        name: input.template_name.as_str().to_owned(),
        content: template_content(&input.template_content)?,
    })
}

/// The account's template of `name`, or SES's refusal of one it does not
/// have.
pub fn template<'a>(
    policy: &'a Policy,
    account: AccountId,
    name: &str,
) -> Result<&'a Template, Refused> {
    policy
        .template_named(account, name)
        .map(|template| &**template)
        .ok_or_else(|| no_template(name))
}

/// The answer to `GetEmailTemplate`.
pub fn got_template(template: &Template) -> Result<GetEmailTemplateOutput, Refused> {
    Ok(GetEmailTemplateOutput {
        template_name: EmailTemplateName::try_from(template.name.clone())
            .map_err(|_| bad("The template's name is not one SES takes"))?,
        template_content: EmailTemplateContent {
            subject: Some(template.content.subject.clone()),
            text: template.content.text.clone(),
            html: template.content.html.clone(),
        },
        tags: None,
    })
}

/// `ListEmailTemplates`: the account's templates in the order of their
/// names, a page at a time.
pub fn list_templates(
    policy: &Policy,
    account: AccountId,
    input: &ListEmailTemplatesInput,
) -> Result<ListEmailTemplatesOutput, Refused> {
    // SES takes 1 to 100 here, 10 when it is not given.
    let size = match input.page_size {
        None => 10,
        Some(size @ 1..=100) => size as usize,
        Some(_) => return Err(bad("PageSize is 1 to 100")),
    };
    let after = after(input.next_token.as_deref())?;
    let (page, next_token) = paged(
        policy.templates_after(account, after.as_deref()),
        size,
        |template| &template.name,
    );
    Ok(ListEmailTemplatesOutput {
        templates_metadata: Some(
            page.into_iter()
                .map(|template| EmailTemplateMetadata {
                    template_name: EmailTemplateName::try_from(template.name.clone()).ok(),
                    created_timestamp: Some(date_time(template.created)),
                })
                .collect(),
        ),
        next_token,
    })
}

/// What a committed change's refusal of the template `name` is answered as.
pub fn template_refused(refusal: PolicyRefusal, name: &str) -> Refused {
    match refusal {
        PolicyRefusal::Taken => Refused::AlreadyExists(format!("Template {name} already exists.")),
        PolicyRefusal::Unknown { .. } => no_template(name),
        PolicyRefusal::InvalidName => bad(format!(
            "{name} is not 1 to 64 letters, digits, hyphens and underscores"
        )),
        PolicyRefusal::Limit => Refused::LimitExceeded(format!(
            "The account keeps {} templates, the most it may",
            Template::MOST
        )),
        PolicyRefusal::Conflict | PolicyRefusal::Outdated => Refused::Busy("Try again".to_owned()),
    }
}

fn no_template(name: &str) -> Refused {
    Refused::NotFound(format!("Template {name} does not exist."))
}

/// `ListTenants`: the account's tenants in the order of their names, a page
/// at a time.
pub fn list_tenants(
    policy: &Policy,
    arns: Arns<'_>,
    input: &ListTenantsInput,
) -> Result<ListTenantsOutput, Refused> {
    unfiltered(
        input
            .filter
            .as_ref()
            .is_some_and(|filter| !filter.is_empty()),
    )?;
    let size = page_size(input.page_size)?;
    let after = after(input.next_token.as_deref())?;
    let (page, next_token) = paged(
        policy.tenants_after(arns.account, after.as_deref()),
        size,
        |tenant| &tenant.name,
    );
    Ok(ListTenantsOutput {
        tenants: Some(
            page.into_iter()
                .map(|tenant| {
                    let shown = shown_tenant(policy, arns, tenant);
                    TenantInfo {
                        tenant_name: shown.tenant_name,
                        tenant_id: shown.tenant_id,
                        tenant_arn: shown.tenant_arn,
                        created_timestamp: shown.created_timestamp,
                        sending_status: shown.sending_status,
                    }
                })
                .collect(),
        ),
        next_token,
    })
}

/// The change `CreateTenantResourceAssociation`, or with `associate`
/// false `DeleteTenantResourceAssociation`, asks for: of an identity or a
/// configuration set, by its ARN.
pub fn association(
    arns: Arns<'_>,
    tenant: &str,
    resource: &str,
    associate: bool,
) -> Result<Change, Refused> {
    let resource = arns.resource(resource)?;
    let (account, tenant) = (arns.account, tenant.to_owned());
    Ok(if associate {
        Change::Associate {
            account,
            tenant,
            resource,
        }
    } else {
        Change::Dissociate {
            account,
            tenant,
            resource,
        }
    })
}

/// What an association's committed refusal is answered as.
pub fn association_refused(refusal: PolicyRefusal, tenant: &str, resource: &str) -> Refused {
    match refusal {
        PolicyRefusal::Taken => Refused::AlreadyExists(format!(
            "{resource} is already associated with tenant {tenant}."
        )),
        PolicyRefusal::Unknown {
            kind: "association",
            ..
        } => Refused::NotFound(format!(
            "{resource} is not associated with tenant {tenant}."
        )),
        PolicyRefusal::Unknown { kind: "tenant", .. } => {
            Refused::NotFound(format!("Tenant {tenant} does not exist."))
        }
        PolicyRefusal::Unknown { .. } => no_resource(resource),
        _ => Refused::Busy("Try again".to_owned()),
    }
}

/// `ListTenantResources`: the identities and configuration sets the tenant
/// may send with, in the order of their ARNs, a page at a time.
pub fn tenant_resources(
    policy: &Policy,
    arns: Arns<'_>,
    input: &ListTenantResourcesInput,
) -> Result<ListTenantResourcesOutput, Refused> {
    unfiltered(
        input
            .filter
            .as_ref()
            .is_some_and(|filter| !filter.is_empty()),
    )?;
    let size = page_size(input.page_size)?;
    let after = after(input.next_token.as_deref())?;
    let found = tenant(policy, arns.account, input.tenant_name.as_str())?;
    let identities = found
        .identities
        .iter()
        .filter_map(|id| policy.identity(*id))
        .map(|identity| (ResourceType::EmailIdentity, arns.identity(&identity.name)));
    let configurations = found
        .configurations
        .iter()
        .filter_map(|id| policy.configuration(*id))
        .map(|configuration| {
            (
                ResourceType::ConfigurationSet,
                arns.configuration(&configuration.name),
            )
        });
    let templates = found
        .templates
        .iter()
        .filter_map(|id| policy.template_of(*id))
        .map(|template| (ResourceType::EmailTemplate, arns.template(&template.name)));
    let mut resources: Vec<(ResourceType, String)> =
        identities.chain(configurations).chain(templates).collect();
    resources.sort_by(|a, b| a.1.cmp(&b.1));
    let (page, next_token) = paged(
        resources
            .into_iter()
            .filter(|(_, arn)| after.as_ref().is_none_or(|after| arn > after)),
        size,
        |(_, arn)| arn,
    );
    Ok(ListTenantResourcesOutput {
        tenant_resources: Some(
            page.into_iter()
                .map(|(resource_type, arn)| TenantResource {
                    resource_type: Some(resource_type),
                    resource_arn: AmazonResourceName::try_from(arn).ok(),
                })
                .collect(),
        ),
        next_token,
    })
}

/// `ListResourceTenants`: the tenants that may send with an identity or a
/// configuration set, in the order of their names, a page at a time.
pub fn resource_tenants(
    policy: &Policy,
    arns: Arns<'_>,
    input: &ListResourceTenantsInput,
) -> Result<ListResourceTenantsOutput, Refused> {
    let size = page_size(input.page_size)?;
    let after = after(input.next_token.as_deref())?;
    let arn = input.resource_arn.as_str();
    let account = arns.account;
    let associated: Box<dyn Fn(&Tenant) -> bool> = match arns.resource(arn)? {
        Resource::Identity(name) => {
            let id = identity(policy, account, &name)?.id;
            Box::new(move |tenant| tenant.identities.contains(&id))
        }
        Resource::Configuration(name) => {
            let id = configuration(policy, account, &name)?.id;
            Box::new(move |tenant| tenant.configurations.contains(&id))
        }
        Resource::Template(name) => {
            let id = template(policy, account, &name)?.id;
            Box::new(move |tenant| tenant.templates.contains(&id))
        }
    };
    let (page, next_token) = paged(
        policy
            .tenants_after(account, after.as_deref())
            .filter(|tenant| associated(tenant)),
        size,
        |tenant| &tenant.name,
    );
    Ok(ListResourceTenantsOutput {
        resource_tenants: Some(
            page.into_iter()
                .map(|tenant| ResourceTenantMetadata {
                    tenant_name: TenantName::try_from(tenant.name.clone()).ok(),
                    tenant_id: Some(tenant_id(tenant)),
                    resource_arn: AmazonResourceName::try_from(arn.to_owned()).ok(),
                    associated_timestamp: None,
                })
                .collect(),
        ),
        next_token,
    })
}

/// `GetReputationEntity`: a tenant, identity or configuration set by its
/// ARN, its statuses rendered from holds. Nothing stands
/// behind SES's own judgement, so it is enabled and its impact low.
pub fn reputation_entity(
    policy: &Policy,
    arns: Arns<'_>,
    input: &GetReputationEntityInput,
) -> Result<GetReputationEntityOutput, Refused> {
    let reference = input.reputation_entity_reference.as_str();
    let paused = paused(policy, &arns.target(policy, reference)?);
    let hold = paused.and_then(|paused| refusing(policy, arns.account, paused));
    let status = if hold.is_some() {
        SendingStatus::Disabled
    } else {
        SendingStatus::Enabled
    };
    Ok(GetReputationEntityOutput {
        reputation_entity: Some(ReputationEntity {
            reputation_entity_reference: ReputationEntityReference::try_from(reference.to_owned())
                .ok(),
            reputation_entity_type: Some(ReputationEntityType::Resource),
            reputation_management_policy: None,
            customer_managed_status: Some(StatusRecord {
                status: Some(status),
                cause: hold.and_then(|hold| StatusCause::try_from(hold.reason.clone()).ok()),
                last_updated_timestamp: None,
            }),
            aws_ses_managed_status: Some(StatusRecord {
                status: Some(SendingStatus::Enabled),
                cause: None,
                last_updated_timestamp: None,
            }),
            sending_status_aggregate: Some(status),
            reputation_impact: Some(RecommendationImpact::Low),
        }),
    })
}

/// The reason a hold put by `UpdateReputationEntityCustomerManagedStatus`
/// gives.
const DISABLED_THROUGH_SES: &str =
    "disabled through SES's UpdateReputationEntityCustomerManagedStatus";

/// The change `UpdateReputationEntityCustomerManagedStatus` asks for: a
/// hold that refuses new mail on the entity, or, enabled or reinstated,
/// none.
pub fn customer_status(
    policy: &Policy,
    arns: Arns<'_>,
    input: &UpdateReputationEntityCustomerManagedStatusInput,
    id: HoldId,
) -> Result<Option<Change>, Refused> {
    let reference = input.reputation_entity_reference.as_str();
    let target = arns.target(policy, reference)?;
    let paused = paused(policy, &target).ok_or_else(|| no_resource(reference))?;
    let disabled = input.sending_status == SendingStatus::Disabled;
    // Enabled already: nothing to lift.
    if !disabled && policy.held(arns.account, paused).is_none() {
        return Ok(None);
    }
    Ok(Some(Change::CustomerStatus {
        id,
        account: arns.account,
        paused,
        disabled,
        reason: DISABLED_THROUGH_SES.to_owned(),
    }))
}

/// What a hold on `target` pauses.
fn paused(policy: &Policy, target: &Target) -> Option<Paused> {
    Some(match target {
        Target::Identity { account, name } => {
            Paused::Identity(policy.identity_named(*account, name)?)
        }
        Target::Configuration { account, name } => {
            Paused::Configuration(policy.configuration_named(*account, name)?)
        }
        Target::Tenant { account, name } => Paused::Tenant(policy.tenant_named(*account, name)?),
        _ => return None,
    })
}

/// The sending rate `GetAccount` gives an account with no limit on it: SES
/// gives every account a rate, which clients pace their sending by, so it
/// is one the engine can never reach, binding none, and an integer any
/// client can hold.
const NO_RATE_LIMIT: f64 = 1_000_000.0;

/// `GetAccount`: sending as its holds say, its quota from its limits (`-1`
/// for no daily quota, as SES's unlimited quota reads, and
/// [`NO_RATE_LIMIT`] for no rate), and `sent`, the recipients it accepted
/// in the last 24 hours.
pub fn account(policy: &Policy, account: AccountId, sent: u64) -> GetAccountOutput {
    let limits = policy.account(account);
    #[allow(clippy::cast_precision_loss, reason = "SES's quota is a double")]
    let send_quota = SendQuota {
        max24_hour_send: limits
            .and_then(|found| found.daily_quota)
            .map_or(-1.0, |quota| quota as f64),
        max_send_rate: limits
            .and_then(|found| found.limits.recipients_per_second)
            .map_or(NO_RATE_LIMIT, f64::from),
        sent_last24_hours: sent as f64,
    };
    GetAccountOutput {
        dedicated_ip_auto_warmup_enabled: false,
        enforcement_status: Some("HEALTHY".to_owned()),
        production_access_enabled: true,
        send_quota: Some(send_quota),
        sending_enabled: refusing(policy, account, Paused::Account).is_none(),
        suppression_attributes: None,
        details: None,
        vdm_attributes: None,
        pricing_attributes: None,
    }
}

/// The address a suppression operation names, on its account's list: a
/// tenant's own list is not kept, as a tenant's mail is suppressed by its
/// account's.
fn listed_address(address: &str, tenant: Option<&TenantName>) -> Result<Address, Refused> {
    if tenant.is_some() {
        return Err(bad(
            "TenantName is not supported: a tenant's mail is suppressed by its account's list",
        ));
    }
    Address::parse(address).map_err(|_| bad(format!("{address} is not an email address")))
}

/// What `GetSuppressedDestination` reads.
pub fn suppression(
    input: &GetSuppressedDestinationInput,
    account: AccountId,
) -> Result<Command, Refused> {
    let address = listed_address(&input.email_address, input.tenant_name.as_ref())?;
    Ok(Command::Suppression { account, address })
}

/// `GetSuppressedDestination`'s answer: `NotFoundException` when the address
/// is not on the list.
pub fn got_suppression(
    input: &GetSuppressedDestinationInput,
    found: Option<Suppressed>,
) -> Result<GetSuppressedDestinationOutput, Refused> {
    let found = found.ok_or_else(|| {
        Refused::NotFound(format!(
            "Email address {} is not on the suppression list.",
            input.email_address
        ))
    })?;
    Ok(GetSuppressedDestinationOutput {
        suppressed_destination: SuppressedDestination {
            email_address: found.address.as_str().to_owned(),
            reason: list_reason(found.reason),
            last_update_time: date_time(found.at),
            attributes: None,
            tenant_name: None,
        },
    })
}

/// What `PutSuppressedDestination` asks for, at `now`.
pub fn suppress(
    input: &PutSuppressedDestinationInput,
    account: AccountId,
    now: Timestamp,
) -> Result<Command, Refused> {
    let address = listed_address(&input.email_address, input.tenant_name.as_ref())?;
    Ok(Command::Suppress(Suppress {
        account,
        addresses: vec![address],
        reason: match input.reason {
            SuppressionListReason::Bounce => Reason::Bounce,
            SuppressionListReason::Complaint => Reason::Complaint,
        },
        now,
    }))
}

/// What `DeleteSuppressedDestination` asks for.
pub fn unsuppress(
    input: &DeleteSuppressedDestinationInput,
    account: AccountId,
) -> Result<Command, Refused> {
    let address = listed_address(&input.email_address, input.tenant_name.as_ref())?;
    Ok(Command::Unsuppress(Unsuppress {
        account,
        addresses: vec![address],
    }))
}

/// `DeleteSuppressedDestination`'s refusal when the address was not on the
/// list.
pub fn not_suppressed(input: &DeleteSuppressedDestinationInput) -> Refused {
    Refused::NotFound(format!(
        "Email address {} is not on the suppression list.",
        input.email_address
    ))
}

/// The page `ListSuppressedDestinations` asks for.
pub fn suppressions(
    input: &ListSuppressedDestinationsInput,
    account: AccountId,
) -> Result<Command, Refused> {
    if input.tenant_name.is_some() {
        return Err(bad(
            "TenantName is not supported: a tenant's mail is suppressed by its account's list",
        ));
    }
    let reasons = input
        .reasons
        .iter()
        .flatten()
        .map(|reason| match reason {
            SuppressionListReason::Bounce => Reason::Bounce,
            SuppressionListReason::Complaint => Reason::Complaint,
        })
        .collect::<Vec<_>>();
    // An operator's suppression is shown as a bounce, and listed with them.
    let reasons = if reasons.contains(&Reason::Bounce) {
        [reasons, vec![Reason::Operator]].concat()
    } else {
        reasons
    };
    Ok(Command::Suppressions(List {
        account,
        after: after(input.next_token.as_deref())?,
        limit: page_size(input.page_size)?,
        reasons,
        from: input.start_date.as_ref().map(timestamp).transpose()?,
        to: input.end_date.as_ref().map(timestamp).transpose()?,
    }))
}

/// `ListSuppressedDestinations`' answer.
pub fn listed_suppressions(page: Page) -> ListSuppressedDestinationsOutput {
    ListSuppressedDestinationsOutput {
        suppressed_destination_summaries: Some(
            page.suppressed
                .into_iter()
                .map(|found| SuppressedDestinationSummary {
                    email_address: found.address.as_str().to_owned(),
                    reason: list_reason(found.reason),
                    last_update_time: date_time(found.at),
                })
                .collect(),
        ),
        next_token: page
            .next
            .map(|key| format!("{TOKEN_VERSION}.{}", URL_SAFE_NO_PAD.encode(key))),
    }
}

/// A reason as SES names it: an operator's, which SES has no name for, as
/// a bounce.
fn list_reason(reason: Reason) -> SuppressionListReason {
    match reason {
        Reason::Bounce | Reason::Operator => SuppressionListReason::Bounce,
        Reason::Complaint => SuppressionListReason::Complaint,
    }
}

/// A time a request gives, as the engine keeps one.
fn timestamp(at: &DateTime) -> Result<Timestamp, Refused> {
    let seconds = u64::try_from(at.secs()).map_err(|_| bad("A date before 1970"))?;
    Ok(Timestamp::from_micros(
        seconds * 1_000_000 + u64::from(at.subsec_nanos() / 1_000),
    ))
}

/// A time as SES's answers carry one.
fn date_time(at: Timestamp) -> DateTime {
    let micros = at.as_micros();
    let seconds = i64::try_from(micros / 1_000_000).unwrap_or(i64::MAX);
    let nanos = u32::try_from(micros % 1_000_000).unwrap_or_default() * 1_000;
    DateTime::from_secs_and_nanos(seconds, nanos)
}

fn no_configuration(name: &str) -> Refused {
    Refused::NotFound(format!("Configuration set {name} does not exist."))
}

fn no_resource(arn: &str) -> Refused {
    Refused::NotFound(format!(
        "{arn} is not a resource of this account and region."
    ))
}

/// Each operation's errors from a refusal: `TooManyRequestsException` and
/// `BadRequestException`, which every one of them lists, and those named,
/// which it lists too; any other refusal is a bad request.
macro_rules! answered_as {
    ($($error:ident { $($refused:ident => $variant:ident),* })*) => {$(
        impl From<Refused> for $error {
            fn from(refused: Refused) -> Self {
                match refused {
                    $(Refused::$refused(message) => Self::$variant($variant {
                        message: Some(message),
                    }),)*
                    Refused::Busy(message) => {
                        Self::TooManyRequestsException(TooManyRequestsException {
                            message: Some(message),
                        })
                    }
                    #[allow(unreachable_patterns, reason = "those an operation lists are above")]
                    Refused::BadRequest(message)
                    | Refused::NotFound(message)
                    | Refused::AlreadyExists(message)
                    | Refused::InvalidNextToken(message)
                    | Refused::LimitExceeded(message) => {
                        Self::BadRequestException(BadRequestException {
                            message: Some(message),
                        })
                    }
                }
            }
        }
    )*};
}

answered_as! {
    CreateEmailIdentityError {
        AlreadyExists => AlreadyExistsException,
        NotFound => NotFoundException
    }
    GetEmailIdentityError { NotFound => NotFoundException }
    DeleteEmailIdentityError { NotFound => NotFoundException }
    ListEmailIdentitiesError {}
    PutEmailIdentityDkimAttributesError { NotFound => NotFoundException }
    PutEmailIdentityDkimSigningAttributesError { NotFound => NotFoundException }
    PutEmailIdentityFeedbackAttributesError { NotFound => NotFoundException }
    PutEmailIdentityMailFromAttributesError { NotFound => NotFoundException }
    CreateConfigurationSetError {
        AlreadyExists => AlreadyExistsException,
        NotFound => NotFoundException
    }
    GetConfigurationSetError { NotFound => NotFoundException }
    ListConfigurationSetsError {}
    PutConfigurationSetReputationOptionsError { NotFound => NotFoundException }
    CreateTenantError { AlreadyExists => AlreadyExistsException }
    GetTenantError { NotFound => NotFoundException }
    ListTenantsError {}
    CreateTenantResourceAssociationError {
        AlreadyExists => AlreadyExistsException,
        NotFound => NotFoundException
    }
    DeleteTenantResourceAssociationError { NotFound => NotFoundException }
    ListTenantResourcesError { NotFound => NotFoundException }
    ListResourceTenantsError { NotFound => NotFoundException }
    GetReputationEntityError { NotFound => NotFoundException }
    UpdateReputationEntityCustomerManagedStatusError {}
    GetAccountError {}
    GetSuppressedDestinationError { NotFound => NotFoundException }
    PutSuppressedDestinationError {}
    DeleteSuppressedDestinationError { NotFound => NotFoundException }
    ListSuppressedDestinationsError {
        InvalidNextToken => InvalidNextTokenException
    }
    CreateDedicatedIpPoolError { AlreadyExists => AlreadyExistsException }
    CreateConfigurationSetEventDestinationError {
        AlreadyExists => AlreadyExistsException,
        NotFound => NotFoundException
    }
    GetConfigurationSetEventDestinationsError { NotFound => NotFoundException }
    UpdateConfigurationSetEventDestinationError { NotFound => NotFoundException }
    DeleteConfigurationSetEventDestinationError { NotFound => NotFoundException }
    PutDedicatedIpInPoolError { NotFound => NotFoundException }
    GetDedicatedIpError { NotFound => NotFoundException }
    GetDedicatedIpsError { NotFound => NotFoundException }
    PutConfigurationSetDeliveryOptionsError { NotFound => NotFoundException }
    CreateEmailTemplateError {
        AlreadyExists => AlreadyExistsException,
        LimitExceeded => LimitExceededException
    }
    GetEmailTemplateError { NotFound => NotFoundException }
    UpdateEmailTemplateError { NotFound => NotFoundException }
    DeleteEmailTemplateError { NotFound => NotFoundException }
    ListEmailTemplatesError {}
}
