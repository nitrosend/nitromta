//! Policy: the identities each account sends as,
//! its tenants and configurations, the credentials that may submit for it,
//! the subscriptions its configurations' events are sent to, and the pools
//! of egresses its mail goes out from.
//!
//! A [`Policy`] is a snapshot at one revision, and every change advances the
//! revision. Admission decides against the snapshot it holds, and the
//! commit owner rechecks only a decision taken under an older revision.
//! Each delivery carries its message's [`Origin`], which dispatch checks
//! against the current snapshot, so mail whose authority is withdrawn after
//! it was accepted is never sent.
//!
//! Records are named within their account. A change names what it refers
//! to, and the names are resolved as it is applied, against the policy every
//! change before it left, so a run of changes can name what an earlier one
//! created. A change that names an existing identity, tenant or
//! configuration replaces it and keeps its ID, so mail already accepted
//! under it is unaffected. A credential or a subscription is never replaced:
//! another is issued and the old one removed. Removing a record also removes
//! every reference to it, and a configuration's subscriptions with it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use crate::address::{self, Address};
use crate::budget::{Counts, Signal};
use crate::event::EventKind;
use crate::id::{
    AccountId, ConfigurationId, CredentialId, DeliveryId, DestinationId, EgressId, HoldId, Id,
    IdentityId, PoolId, SubscriptionId, TemplateId, TenantId, TopicId,
};
use crate::journal::Entry;
use crate::message::PolicyRevision;
use crate::time::Timestamp;

/// What a message was sent under: the identity it was sent as, and the
/// tenant and configuration its request named, or its identity's default
/// configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub identity: IdentityId,
    pub tenant: Option<TenantId>,
    pub configuration: Option<ConfigurationId>,
}

/// A domain, or a single address, that an account sends as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub id: IdentityId,
    pub account: AccountId,
    /// The domain or the address, in lowercase.
    pub name: String,
    /// Its DKIM key. An identity whose application signs its own mail has
    /// none.
    pub signing: Option<Signing>,
    /// Whether its mail is signed with its key, as SES's `SigningEnabled`
    /// says: so unless it is turned off.
    pub signs: bool,
    /// The configuration its mail is sent under when a request names none.
    pub configuration: Option<ConfigurationId>,
    pub tags: Vec<Tag>,
    /// Where the check of its DKIM record stands. One the
    /// operator put has none: it is the operator's word, never checked.
    pub verification: Option<Check>,
    /// Its own MAIL FROM domain, if it has one.
    pub mail_from: Option<MailFrom>,
}

impl Identity {
    /// The domain it sends and signs for.
    pub fn domain(&self) -> &str {
        self.name
            .rsplit_once('@')
            .map_or(self.name.as_str(), |(_, domain)| domain)
    }

    /// Whether mail may be sent under it: the operator's word, or its DKIM
    /// record found, at its last check or since.
    pub fn verified(&self) -> bool {
        self.verification
            .is_none_or(|check| check.status.verified())
    }

    /// The key its mail is signed with, while it signs.
    pub fn signer(&self) -> Option<&Signing> {
        self.signing.as_ref().filter(|_| self.signs)
    }

    /// The domain its mail's return path is at, if not the installation's:
    /// its MAIL FROM domain, while that is found to point at the bounce
    /// host.
    pub fn return_domain(&self) -> Option<&Arc<str>> {
        self.mail_from
            .as_ref()
            .filter(|mail_from| mail_from.check.status == Verification::Success)
            .map(|mail_from| &mail_from.domain)
    }
}

/// An identity's own MAIL FROM domain, a subdomain of its domain, and what
/// its mail does while that domain is not found to point at the bounce host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailFrom {
    /// In lowercase.
    pub domain: Arc<str>,
    pub behavior: OnMxFailure,
    pub check: Check,
}

impl MailFrom {
    /// The longest domain taken: a return path at it is the engine's token,
    /// under fifty characters, and `@` before it, and the whole must be an
    /// address of at most 254.
    pub const MOST: usize = 200;
}

/// SES's `BehaviorOnMxFailure`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnMxFailure {
    /// Mail goes out with the installation's return path.
    UseDefault,
    /// Mail is refused.
    Reject,
}

/// Where a check of an identity's DNS stands, and since when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Check {
    pub status: Verification,
    pub since: Timestamp,
}

/// SES's names for where a check stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// Not yet found.
    Pending,
    Success,
    /// Found before, and not at the last check.
    TemporaryFailure,
    /// Not found in time.
    Failed,
}

impl Verification {
    /// Whether mail may be sent while a check stands here.
    pub fn verified(self) -> bool {
        matches!(self, Self::Success | Self::TemporaryFailure)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signing {
    pub selector: String,
    /// The private key, in PEM. The shell checks that it signs before a
    /// change carries it.
    pub key: String,
    /// The header fields it signs, when present.
    pub headers: Vec<String>,
}

/// The rates an account or a tenant is admitted at, each
/// unlimited when absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Recipients a second, as SES's maximum send rate counts them.
    pub recipients_per_second: Option<u32>,
    /// Bytes of messages a second, as they were submitted: a raw message,
    /// simple content's subject and bodies, or a bulk request's messages as
    /// its template renders them.
    pub bytes_per_second: Option<u64>,
}

/// An account's own limits. An account with no record of its own is
/// unlimited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub limits: Limits,
    /// The recipients it may have accepted in any 24 hours, as
    /// SES's maximum 24-hour send.
    pub daily_quota: Option<u64>,
}

/// A tenant within an account, the identities and configurations it may
/// send with, and its own rates, so one tenant cannot crowd out the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub id: TenantId,
    pub account: AccountId,
    pub name: String,
    pub identities: BTreeSet<IdentityId>,
    pub configurations: BTreeSet<ConfigurationId>,
    /// The templates it may send with, as SES associates them.
    pub templates: BTreeSet<TemplateId>,
    pub limits: Limits,
    pub tags: Vec<Tag>,
    /// When it was created through SES's API: one the operator put has
    /// none.
    pub created: Option<Timestamp>,
}

/// How a set of messages is sent and reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub id: ConfigurationId,
    pub account: AccountId,
    pub name: String,
    /// The pool its mail goes out from, as SES's `SendingPoolName` names
    /// one; the account's egresses in no pool when absent.
    pub pool: Option<PoolId>,
    pub tags: Vec<Tag>,
    /// SES's `ReputationMetricsEnabled`, kept as it was put: the engine's
    /// metrics are kept whatever it says.
    pub reputation_metrics: bool,
}

/// A key and its value an application tags an identity, tenant or
/// configuration with, kept as SES keeps them: they change nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

impl Tag {
    /// The most one record holds, as SES allows.
    pub const MOST: usize = 50;
}

/// Whether `tags` are as SES takes them: at most [`Tag::MOST`], each key 1
/// to 128 characters and each value at most 256, and no key twice.
fn valid_tags(tags: &[Tag]) -> bool {
    let mut keys = BTreeSet::new();
    tags.len() <= Tag::MOST
        && tags.iter().all(|tag| {
            (1..=128).contains(&tag.key.chars().count())
                && tag.value.chars().count() <= 256
                && keys.insert(tag.key.as_str())
        })
}

/// Where a delivery may go out from.
#[derive(Debug, PartialEq, Eq)]
pub enum Sources<'a> {
    /// The host's own address, under its hostname.
    Host,
    /// One of these egresses. With none, the mail waits.
    Egresses(Vec<&'a Egress>),
}

/// A named set of egresses: the unit of stream separation, as
/// SES's dedicated IP pools are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub id: PoolId,
    pub account: AccountId,
    pub name: String,
}

/// A source address the host sends from, which one account's mail goes out
/// from, as an SES dedicated IP is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Egress {
    pub id: EgressId,
    pub account: AccountId,
    /// Unique in the installation.
    pub address: IpAddr,
    /// The name it greets with, which its PTR record names.
    pub helo: String,
    pub pool: Option<PoolId>,
    /// Its warmup budget.
    pub caps: Caps,
}

/// The reservations an egress may take for each receiver site in any 24
/// hours: its warmup budget.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// At each site without a cap of its own; unlimited when absent.
    pub daily: Option<u64>,
    /// Sites' own caps, in place of `daily` there: warmup gives one to a
    /// site it judges on its own, and an operator may put one. Unlimited at
    /// a site whose cap is absent.
    pub sites: BTreeMap<Arc<str>, Option<u64>>,
    /// Warmup's last judgment of the egress.
    pub warmed: Option<Warmed>,
    /// The policy revision that last changed them: a judgment decided from
    /// earlier caps is refused, even once they read the same again.
    pub changed: PolicyRevision,
}

impl Caps {
    /// The cap at `site`.
    pub fn at(&self, site: &str) -> Option<u64> {
        if self.sites.is_empty() {
            return self.daily;
        }
        self.sites.get(site).copied().unwrap_or(self.daily)
    }

    /// Whether any site is capped: whether the egress is warming up.
    pub fn any(&self) -> bool {
        self.daily.is_some() || self.sites.values().any(Option::is_some)
    }

    /// How far up `ladder` its caps have climbed, in percent, as SES's
    /// `WarmupPercentage` gives it: the rungs below its own cap, of all the
    /// ladder's, or the least of its sites' while it has none of its own;
    /// none once no cap is left, when its warmup is done.
    pub fn climbed(&self, ladder: &[u64]) -> Option<u64> {
        let rungs = u64::try_from(ladder.len().max(1)).unwrap_or(u64::MAX);
        let share = |cap: u64| {
            let below = u64::try_from(ladder.iter().filter(|rung| **rung < cap).count())
                .unwrap_or(u64::MAX);
            // Capped is never done.
            (below * 100 / rungs).min(99)
        };
        match self.daily {
            Some(cap) => Some(share(cap)),
            None => self.sites.values().flatten().map(|cap| share(*cap)).min(),
        }
    }

    /// An operator's cap in place of what it was, `site`'s or the egress's
    /// own, at policy revision `revision`: the judgment that set
    /// the old one no longer explains it, and one decided from before is
    /// refused, though the day it judged stays judged.
    pub fn set(&mut self, site: Option<&str>, cap: Option<u64>, revision: PolicyRevision) {
        match site {
            Some(site) => {
                self.sites.insert(site.into(), cap);
            }
            None => self.daily = cap,
        }
        if let Some(warmed) = &mut self.warmed {
            let judgment = match site {
                Some(site) => warmed.sites.get_mut(site),
                None => Some(&mut warmed.pool),
            };
            if let Some(judgment) = judgment {
                judgment.verdict = Verdict::Set;
            }
        }
        self.changed = revision;
        self.tidy();
    }

    /// Without a cap of its own, a site's cap of none says nothing more,
    /// so it is not kept.
    pub fn tidy(&mut self) {
        if self.daily.is_none() {
            self.sites.retain(|_, cap| cap.is_some());
        }
    }
}

/// Warmup's judgment of an egress on one UTC day: the evidence
/// at each site, and what it did to the site's cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warmed {
    /// Days since the Unix epoch.
    pub day: u64,
    /// The sites judged together, against the egress's own cap.
    pub pool: Judgment,
    /// The sites judged on their own, each against its own cap.
    pub sites: BTreeMap<Arc<str>, Judgment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judgment {
    pub counts: Counts,
    pub verdict: Verdict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Under every threshold, with replies reaching half its cap: up one
    /// rung.
    Raised,
    /// Under every threshold, but too few replies to test its cap.
    Untested,
    /// Over the signal's threshold to hold: where it was.
    Held(Signal),
    /// Over the signal's threshold to lower: down one rung.
    Lowered(Signal),
    /// Set by an operator since, in place of what the judgment made it.
    Set,
    /// A receiver rule disables promotion; adverse signals may still lower it.
    PromotionHeld,
}

/// One egress's caps, in place of `from`, the caps the change was decided
/// from, on `evidence`, each site's counts on the day judged:
/// the store refuses it if either has changed since.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capping {
    pub egress: EgressId,
    pub from: Caps,
    pub to: Caps,
    pub evidence: Vec<(Arc<str>, Counts)>,
}

/// What a hold pauses: all of its account's mail, or the mail
/// sent under one of its tenants, configurations or identities, or what is
/// to go out from one of its egresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Paused {
    Account,
    Tenant(TenantId),
    Configuration(ConfigurationId),
    Identity(IdentityId),
    Egress(EgressId),
}

/// A pause, as opposed to a removal: no attempt starts for the
/// mail it covers until it is lifted, and that mail still expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hold {
    pub id: HoldId,
    pub account: AccountId,
    pub paused: Paused,
    /// Whether new mail it covers is still accepted, to wait; otherwise it
    /// is refused, as SES refuses mail while sending is paused.
    pub accepting: bool,
    /// Why, for the operator, which `explain` gives: clients are never told.
    pub reason: String,
}

impl Hold {
    /// The longest reason kept.
    pub const MAX_REASON: usize = 256;
}

/// A store restored from a backup, fenced: each delivery the
/// copy held unfinished may have been delivered after the copy was taken,
/// so none is attempted until the operator decides. Every ID the copy had
/// issued is at or below its high-water mark, and every later one above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fence {
    /// The copy's high-water mark.
    pub below: Id,
    /// When the copy was taken, and when it was restored.
    pub taken: Timestamp,
    pub restored: Timestamp,
    /// The decision, once made to discard them: each is cancelled as it
    /// falls due, as mail whose authority was withdrawn is. Until then,
    /// each is held.
    pub discarding: bool,
}

impl Fence {
    /// Whether it covers `delivery`, one the copy held.
    pub fn covers(&self, delivery: DeliveryId) -> bool {
        delivery.0 <= self.below
    }
}

/// Where the events of a configuration's mail are sent: the
/// kinds it owes, and the key its batches are signed with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub id: SubscriptionId,
    pub account: AccountId,
    pub name: String,
    pub configuration: ConfigurationId,
    /// Where batches of events are posted: an `https` or `http` URL, at an
    /// address the outbound network policy allows.
    pub url: String,
    pub events: BTreeSet<EventKind>,
    /// The key its batches are signed with, which the engine issued.
    pub secret: [u8; 32],
}

impl Subscription {
    /// Whether it owes the event `entry` makes.
    pub fn owes(&self, entry: &Entry) -> bool {
        entry.configuration() == Some(self.configuration)
            && self.events.contains(&EventKind::of(entry))
    }
}

/// One of an account's email templates, as SES keeps them: mail is sent by
/// its name, its parts filled from the data each message gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub id: TemplateId,
    pub account: AccountId,
    /// Unique in its account: 1 to 64 letters, digits, hyphens and
    /// underscores.
    pub name: String,
    pub content: TemplateContent,
    pub created: Timestamp,
}

/// A template's parts, each with the `{{name}}` references its data fills.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateContent {
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
}

impl TemplateContent {
    /// The most bytes a template's parts come to together.
    pub const MOST_BYTES: usize = 512 * 1024;

    pub fn bytes(&self) -> usize {
        self.subject.len()
            + self.text.as_ref().map_or(0, String::len)
            + self.html.as_ref().map_or(0, String::len)
    }
}

impl Template {
    /// The most templates an account keeps. Each is held in memory with
    /// policy, so this and `TemplateContent::MOST_BYTES` bound what
    /// templates take.
    pub const MOST: usize = 10_000;
}

/// One of an account's topics, which SES-shaped event destinations publish
/// to, as SNS's topics are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topic {
    pub id: TopicId,
    pub account: AccountId,
    /// Unique in its account.
    pub name: String,
}

/// An endpoint subscribed to a topic: posted the events its
/// topic's destinations publish, one a request, once it has confirmed. A
/// feed of events, as a subscription is, under the same kind of ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscriber {
    pub id: SubscriptionId,
    pub account: AccountId,
    pub topic: TopicId,
    /// An `https` or `http` URL, as a subscription's is.
    pub endpoint: String,
    /// What its confirmation names, which the engine issued.
    pub token: [u8; 32],
    pub confirmed: bool,
}

/// Where a configuration's events are published in SES's shape: one of its
/// account's topics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub id: DestinationId,
    pub account: AccountId,
    pub configuration: ConfigurationId,
    /// Unique among its configuration's destinations.
    pub name: String,
    pub topic: TopicId,
    pub events: BTreeSet<EventKind>,
    pub enabled: bool,
}

/// What a feed of events is: a subscription's batches, or a
/// topic subscriber's events.
#[derive(Clone, Copy, Debug)]
pub enum Feed<'a> {
    Webhook(&'a Subscription),
    Topic(&'a Subscriber),
}

/// A credential that may submit for its account, within its scopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub id: CredentialId,
    pub account: AccountId,
    pub secret: Secret,
    /// The identities it may send as.
    pub identities: Scope<IdentityId>,
    /// The tenants it may send for. A credential limited to some tenants
    /// must name one of them.
    pub tenants: Scope<TenantId>,
    pub permissions: Permissions,
}

/// What a credential may do: send, manage its account's
/// identities, configurations, tenants and suppression through SES's API,
/// or both. An SMTP login only sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub sends: bool,
    pub manages: bool,
}

impl Permissions {
    /// A credential's unless it is created otherwise.
    pub const SENDS: Self = Self {
        sends: true,
        manages: false,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Secret {
    /// An SMTP login: its user, unique in the installation, and the SHA-256
    /// of its password.
    Login {
        user: String,
        password_sha256: [u8; 32],
    },
    /// An SES access key: its ID, unique in the installation, and the
    /// secret requests are signed with.
    AccessKey { id: String, secret: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope<T> {
    /// Every one in the account, now and later.
    Any,
    Only(BTreeSet<T>),
}

impl<T: Ord> Scope<T> {
    pub fn includes(&self, item: &T) -> bool {
        match self {
            Self::Any => true,
            Self::Only(items) => items.contains(item),
        }
    }

    fn remove(&mut self, item: &T) -> bool {
        match self {
            Self::Any => false,
            Self::Only(items) => items.remove(item),
        }
    }
}

/// A policy record, as the store keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Account(Account),
    Identity(Identity),
    Tenant(Tenant),
    Configuration(Configuration),
    Credential(Credential),
    Subscription(Subscription),
    Pool(Pool),
    Egress(Egress),
    Hold(Hold),
    Topic(Topic),
    Subscriber(Subscriber),
    Destination(Destination),
    Template(Template),
}

impl Record {
    pub fn id(&self) -> Id {
        match self {
            Self::Account(account) => account.id.0,
            Self::Identity(identity) => identity.id.0,
            Self::Tenant(tenant) => tenant.id.0,
            Self::Configuration(configuration) => configuration.id.0,
            Self::Credential(credential) => credential.id.0,
            Self::Subscription(subscription) => subscription.id.0,
            Self::Topic(topic) => topic.id.0,
            Self::Subscriber(subscriber) => subscriber.id.0,
            Self::Destination(destination) => destination.id.0,
            Self::Pool(pool) => pool.id.0,
            Self::Egress(egress) => egress.id.0,
            Self::Hold(hold) => hold.id.0,
            Self::Template(template) => template.id.0,
        }
    }

    fn kind(&self) -> Kind {
        match self {
            Self::Account(_) => Kind::Account,
            Self::Identity(_) => Kind::Identity,
            Self::Tenant(_) => Kind::Tenant,
            Self::Configuration(_) => Kind::Configuration,
            Self::Credential(_) => Kind::Credential,
            Self::Subscription(_) => Kind::Subscription,
            Self::Pool(_) => Kind::Pool,
            Self::Egress(_) => Kind::Egress,
            Self::Hold(_) => Kind::Hold,
            Self::Topic(_) => Kind::Topic,
            Self::Subscriber(_) => Kind::Subscriber,
            Self::Destination(_) => Kind::Destination,
            Self::Template(_) => Kind::Template,
        }
    }
}

/// The kinds of record, in the order a stored policy is read: each refers
/// only to kinds before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Account,
    Template,
    Pool,
    Configuration,
    Egress,
    Identity,
    Tenant,
    Credential,
    Subscription,
    Topic,
    Subscriber,
    Destination,
    Hold,
}

/// A change to policy, naming what it refers to. A put carries the ID its
/// record takes if it is new.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// An account's limits, in place of those it had.
    Account(Account),
    /// An identity the operator puts, which sends on the operator's word.
    Identity {
        id: IdentityId,
        account: AccountId,
        name: String,
        signing: Option<Signing>,
        configuration: Option<String>,
    },
    /// An identity created through SES's API, whose name must not be in use
    /// in its account, and which sends once its DKIM record is found: its
    /// check pending from `at`.
    NewIdentity {
        id: IdentityId,
        account: AccountId,
        name: String,
        signing: Signing,
        configuration: Option<String>,
        tags: Vec<Tag>,
        at: Timestamp,
    },
    /// A configuration created through SES's API, whose name must not be in
    /// use in its account, and the pool it names, if any.
    NewConfiguration {
        id: ConfigurationId,
        account: AccountId,
        name: String,
        pool: Option<String>,
        reputation_metrics: bool,
        tags: Vec<Tag>,
    },
    /// A configuration's `ReputationMetricsEnabled`.
    ReputationMetrics {
        account: AccountId,
        configuration: String,
        enabled: bool,
    },
    /// A tenant created through SES's API at `at`, whose name must not be in
    /// use in its account, associated with nothing yet.
    NewTenant {
        id: TenantId,
        account: AccountId,
        name: String,
        tags: Vec<Tag>,
        at: Timestamp,
    },
    /// The tenant may send with the resource, which it may not already.
    Associate {
        account: AccountId,
        tenant: String,
        resource: Resource,
    },
    /// The tenant may no longer send with the resource, which it may now.
    Dissociate {
        account: AccountId,
        tenant: String,
        resource: Resource,
    },
    /// One part of an identity the account has, changed.
    Amend {
        account: AccountId,
        name: String,
        amendment: Amendment,
    },
    Configuration {
        id: ConfigurationId,
        account: AccountId,
        name: String,
        pool: Option<String>,
    },
    Pool {
        id: PoolId,
        account: AccountId,
        name: String,
    },
    /// A pool created through SES's API, whose name must not be in use in
    /// its account.
    NewPool {
        id: PoolId,
        account: AccountId,
        name: String,
    },
    /// An egress of the account, by its address, into the pool named, or
    /// into none.
    EgressPool {
        account: AccountId,
        address: IpAddr,
        pool: Option<String>,
    },
    /// The pool a configuration's mail goes out from, or none: the
    /// account's egresses in no pool.
    ConfigurationPool {
        account: AccountId,
        configuration: String,
        pool: Option<String>,
    },
    /// An egress, put under its address, which no other account's may hold.
    /// One already there keeps its caps and warmup's judgment: `daily_cap`
    /// starts warmup on an egress that has neither, and only `Change::Cap`
    /// changes a cap after that.
    Egress {
        id: EgressId,
        account: AccountId,
        address: IpAddr,
        helo: String,
        pool: Option<String>,
        daily_cap: Option<u64>,
    },
    /// Egresses' caps, each in place of what it had: warmup's
    /// judgment of a day, in one revision. Refused whole if any egress's
    /// caps are no longer those it was decided from, or warmup has judged
    /// that egress on that day or a later one.
    Caps(Vec<Capping>),
    /// An operator's cap on the account's egress at `address`,
    /// in place of what it had: the egress's own, or the site's `site`
    /// names, unlimited when `cap` is absent. Warmup's judgment of it reads
    /// as set, and its next one starts from what this sets.
    Cap {
        account: AccountId,
        address: IpAddr,
        site: Option<String>,
        cap: Option<u64>,
    },
    Tenant {
        id: TenantId,
        account: AccountId,
        name: String,
        identities: Vec<String>,
        configurations: Vec<String>,
        limits: Limits,
    },
    /// A new credential, whose login or key ID must not be in use. Its
    /// scopes are any identity and tenant of its account when absent.
    Credential {
        id: CredentialId,
        account: AccountId,
        secret: Secret,
        identities: Option<Vec<String>>,
        tenants: Option<Vec<String>>,
        permissions: Permissions,
    },
    /// A new subscription to a configuration's events, whose name must not
    /// be in use in its account.
    Subscription {
        id: SubscriptionId,
        account: AccountId,
        name: String,
        configuration: String,
        url: String,
        events: BTreeSet<EventKind>,
        secret: [u8; 32],
    },
    /// A topic, put under its name: one already of that name keeps its ID,
    /// as SNS's `CreateTopic` answers with the topic that is there.
    Topic {
        id: TopicId,
        account: AccountId,
        name: String,
    },
    /// A template created through SES's API, whose name must not be in use
    /// in its account, as it was at `at`.
    NewTemplate {
        id: TemplateId,
        account: AccountId,
        name: String,
        content: TemplateContent,
        at: Timestamp,
    },
    /// The template named, with these parts in place of what it had.
    TemplateContent {
        account: AccountId,
        name: String,
        content: TemplateContent,
    },
    /// An endpoint subscribed to the topic named, not yet confirmed, which
    /// must not be subscribed to it already.
    Subscribe {
        id: SubscriptionId,
        account: AccountId,
        topic: String,
        endpoint: String,
        token: [u8; 32],
    },
    /// The subscriber to the topic named whose token is `token` has
    /// confirmed.
    Confirm {
        account: AccountId,
        topic: String,
        token: [u8; 32],
    },
    /// A destination of the configuration named, publishing to the topic
    /// named: new, unless `replaces`, when it must exist and keeps its ID.
    Destination {
        id: DestinationId,
        account: AccountId,
        configuration: String,
        name: String,
        topic: String,
        events: BTreeSet<EventKind>,
        enabled: bool,
        replaces: bool,
    },
    /// A hold on what `target` names: an account, or one of its tenants,
    /// configurations, identities or egresses. One already on it
    /// is replaced, keeping its ID.
    Hold {
        id: HoldId,
        target: Target,
        accepting: bool,
        reason: String,
    },
    /// Lifts the hold on what `target` names.
    Release(Target),
    /// A hold that refuses new mail on what `paused` names, with `disabled`,
    /// or none, as SES's customer-managed status disables or enables a
    /// reputation entity: by the record's ID, so one removed and made again
    /// since is never held, or released, in its place.
    CustomerStatus {
        id: HoldId,
        account: AccountId,
        paused: Paused,
        disabled: bool,
        reason: String,
    },
    Remove(Target),
}

/// What a tenant may send with, named in its account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    Identity(String),
    Configuration(String),
    Template(String),
}

/// A change to one part of an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Amendment {
    /// A new DKIM key, as one put through SES's API is: its check pending
    /// from `at`, so the identity sends again once the new key's record is
    /// found.
    Signing { signing: Signing, at: Timestamp },
    /// Whether its mail is signed.
    Signs(bool),
    /// What a check found of the DKIM key `selector` and `key` name, which
    /// applies only while `identity` is still the identity of that name,
    /// that is still its key, and its check is still `from`, the one the
    /// verifier read: a check of a key since replaced, or of an identity
    /// since removed and made again, or begun again since, changes nothing.
    Checked {
        identity: IdentityId,
        selector: String,
        key: String,
        from: Check,
        check: Check,
    },
    /// Its own MAIL FROM domain, checked from `at`, and what its mail does
    /// until it is found; or none, so its mail's return path is the
    /// installation's.
    MailFrom {
        mail_from: Option<(String, OnMxFailure)>,
        at: Timestamp,
    },
    /// What a check found of the MAIL FROM domain `domain`, which applies
    /// only while `identity` still has it and its check is still `from`.
    MailFromChecked {
        identity: IdentityId,
        domain: String,
        from: Check,
        check: Check,
    },
}

/// A record to remove, as it is named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Account(AccountId),
    Identity {
        account: AccountId,
        name: String,
    },
    Configuration {
        account: AccountId,
        name: String,
    },
    Tenant {
        account: AccountId,
        name: String,
    },
    Login(String),
    AccessKey(String),
    Subscription {
        account: AccountId,
        name: String,
    },
    Pool {
        account: AccountId,
        name: String,
    },
    Egress(IpAddr),
    /// An endpoint subscribed to a topic, by its ID.
    Subscriber {
        account: AccountId,
        id: SubscriptionId,
    },
    Destination {
        account: AccountId,
        configuration: String,
        name: String,
    },
    Template {
        account: AccountId,
        name: String,
    },
}

impl Change {
    /// The ID a put creates if its record is new, which the store's
    /// high-water mark must cover. An account's ID is its operator's, not
    /// one the engine issued, so it raises nothing.
    pub fn created(&self) -> Option<Id> {
        match self {
            Self::Identity { id, .. } | Self::NewIdentity { id, .. } => Some(id.0),
            Self::Configuration { id, .. } | Self::NewConfiguration { id, .. } => Some(id.0),
            Self::Tenant { id, .. } | Self::NewTenant { id, .. } => Some(id.0),
            Self::Credential { id, .. } => Some(id.0),
            Self::Subscription { id, .. } => Some(id.0),
            Self::Pool { id, .. } | Self::NewPool { id, .. } => Some(id.0),
            Self::Egress { id, .. } => Some(id.0),
            Self::Hold { id, .. } | Self::CustomerStatus { id, .. } => Some(id.0),
            Self::Topic { id, .. } => Some(id.0),
            Self::NewTemplate { id, .. } => Some(id.0),
            Self::Subscribe { id, .. } => Some(id.0),
            Self::Destination { id, .. } => Some(id.0),
            Self::Account(_)
            | Self::Amend { .. }
            | Self::ReputationMetrics { .. }
            | Self::EgressPool { .. }
            | Self::Caps(_)
            | Self::Cap { .. }
            | Self::ConfigurationPool { .. }
            | Self::Confirm { .. }
            | Self::Associate { .. }
            | Self::Dissociate { .. }
            | Self::TemplateContent { .. }
            | Self::Release(_)
            | Self::Remove(_) => None,
        }
    }
}

/// What a change wrote: the records the store keeps in their new form, and
/// the IDs of those it removes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changed {
    pub written: Vec<Record>,
    pub removed: Vec<Id>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyRefusal {
    /// The name is not a domain or address (an identity), or not 1 to 64
    /// letters, digits, hyphens and underscores (a tenant, configuration or
    /// subscription), or its tags are not as SES takes them, or the login or key ID is empty or holds spaces, or a
    /// login may do more than send, or an access key nothing, or a
    /// subscription's URL is not `http` or `https` or it names no events,
    /// or a hold's reason is empty, longer than `Hold::MAX_REASON` or not
    /// printable ASCII, or it names what cannot be held.
    InvalidName,
    /// It names a record the account does not have.
    Unknown { kind: &'static str, name: String },
    /// The login or key ID is already a credential's, the name already a
    /// subscription's or a new identity's, or the address another
    /// account's egress.
    Taken,
    /// Its ID is already another record's.
    Conflict,
    /// A check it records is of a key the identity no longer has checked,
    /// or caps it sets were decided from caps since changed or from a day
    /// already judged, or a tenant it creates was decided from policy since
    /// changed, and has no key while per-tenant keys are on.
    Outdated,
    /// A template's parts come to more than `TemplateContent::MOST_BYTES`,
    /// or its account keeps `Template::MOST` already.
    Limit,
}

/// Why mail may not be accepted or sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    UnknownCredential,
    /// The credential may not send: it only manages.
    NotSending,
    /// No identity of the account matches its From address.
    UnknownIdentity,
    /// Its identity's DKIM record has not been found.
    Unverified,
    /// Its identity's MAIL FROM domain has not been found to point at the
    /// bounce host, and its mail is refused until it is.
    MailFromUnverified,
    /// The credential may not send as the identity.
    IdentityNotPermitted,
    /// The message's own From is another identity than the address it is
    /// sent as.
    DifferentFrom,
    UnknownTenant,
    /// The credential may not send for the tenant, or must name one.
    TenantNotPermitted,
    /// The tenant may not send with the identity, the configuration or the
    /// template.
    NotAssociated,
    UnknownConfiguration,
    /// A hold on the account, or on the tenant, configuration or identity
    /// it is sent under, refuses new mail.
    Paused,
}

/// The policy at one revision.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    revision: PolicyRevision,
    accounts: BTreeMap<AccountId, Account>,
    identities: BTreeMap<IdentityId, Identity>,
    tenants: BTreeMap<TenantId, Tenant>,
    configurations: BTreeMap<ConfigurationId, Configuration>,
    credentials: BTreeMap<CredentialId, Credential>,
    identity_names: BTreeMap<(AccountId, String), IdentityId>,
    tenant_names: BTreeMap<(AccountId, String), TenantId>,
    configuration_names: BTreeMap<(AccountId, String), ConfigurationId>,
    logins: BTreeMap<String, CredentialId>,
    access_keys: BTreeMap<String, CredentialId>,
    subscriptions: BTreeMap<SubscriptionId, Subscription>,
    subscription_names: BTreeMap<(AccountId, String), SubscriptionId>,
    pools: BTreeMap<PoolId, Pool>,
    pool_names: BTreeMap<(AccountId, String), PoolId>,
    /// Shared, so a transaction carries its egress without a copy.
    egresses: BTreeMap<EgressId, Arc<Egress>>,
    egress_addresses: BTreeMap<IpAddr, EgressId>,
    holds: BTreeMap<HoldId, Hold>,
    /// Each hold, by what it pauses: at most one each.
    held: BTreeMap<(AccountId, Paused), HoldId>,
    topics: BTreeMap<TopicId, Topic>,
    topic_names: BTreeMap<(AccountId, String), TopicId>,
    /// Shared, so policy's copy on a change copies none of their parts.
    templates: BTreeMap<TemplateId, Arc<Template>>,
    template_names: BTreeMap<(AccountId, String), TemplateId>,
    subscribers: BTreeMap<SubscriptionId, Subscriber>,
    destinations: BTreeMap<DestinationId, Destination>,
    destination_names: BTreeMap<(ConfigurationId, String), DestinationId>,
    /// The store's fence, while it has one: the store keeps it apart from
    /// policy's records, and gives it here.
    fence: Option<Fence>,
}

/// When a check restarted at `at` begins: strictly after the check it
/// replaces began, so no two of an identity's checks share their start,
/// even while the clock is held back, and a result for the one replaced
/// is always told from the one now running.
fn restarted(previous: Option<Timestamp>, at: Timestamp) -> Timestamp {
    previous.map_or(at, |previous| {
        at.max(previous.saturating_add(std::time::Duration::from_micros(1)))
    })
}

/// Stored policy that no sequence of changes produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImpossiblePolicy;

impl Policy {
    /// Policy read back from storage, which must be exactly what changes
    /// could have made.
    pub fn from_records(
        revision: PolicyRevision,
        records: Vec<Record>,
    ) -> Result<Self, ImpossiblePolicy> {
        let mut policy = Self {
            revision,
            ..Self::default()
        };
        // Referenced records first, so each reference can be checked as it
        // is read.
        let mut records = records;
        records.sort_by_key(Record::kind);
        for record in records {
            let id = record.id();
            match policy.check(record) {
                Ok(record) if record.id() == id => policy.insert(record),
                _ => return Err(ImpossiblePolicy),
            }
        }
        Ok(policy)
    }

    pub fn revision(&self) -> PolicyRevision {
        self.revision
    }

    /// Applies `change` at the next revision, and returns what it wrote.
    /// A refused change changes nothing.
    pub fn apply(&mut self, change: Change) -> Result<Changed, PolicyRefusal> {
        let changed = match self.resolve(change)? {
            Resolved::Put(record) => {
                let record = self.check(record)?;
                self.insert(record.clone());
                Changed {
                    written: vec![record],
                    removed: Vec::new(),
                }
            }
            // Each is checked before any is kept.
            Resolved::PutAll(records) => {
                let written = records
                    .into_iter()
                    .map(|record| self.check(record))
                    .collect::<Result<Vec<_>, _>>()?;
                for record in &written {
                    self.insert(record.clone());
                }
                Changed {
                    written,
                    removed: Vec::new(),
                }
            }
            Resolved::Remove(id) => self.remove(id),
        };
        self.revision = PolicyRevision(self.revision.0 + 1);
        Ok(changed)
    }

    /// `change` with its names resolved to the records they name.
    /// The revision the change being resolved makes.
    fn next(&self) -> PolicyRevision {
        PolicyRevision(self.revision.0 + 1)
    }

    fn resolve(&self, change: Change) -> Result<Resolved, PolicyRefusal> {
        let unknown = |kind, name: &str| PolicyRefusal::Unknown {
            kind,
            name: name.to_owned(),
        };
        let identity = |account, name: &String| {
            self.identity_named(account, name)
                .ok_or_else(|| unknown("identity", name))
        };
        let configuration = |account, name: &String| {
            self.configuration_named(account, name)
                .ok_or_else(|| unknown("configuration", name))
        };
        let tenant = |account, name: &String| {
            self.tenant_named(account, name)
                .ok_or_else(|| unknown("tenant", name))
        };
        let pool = |account, name: &String| {
            self.pool_names
                .get(&(account, name.clone()))
                .copied()
                .ok_or_else(|| unknown("pool", name))
        };
        Ok(Resolved::Put(match change {
            Change::Account(account) => Record::Account(account),
            Change::Identity {
                id,
                account,
                name,
                signing,
                configuration: default,
            } => Record::Identity(Identity {
                id,
                account,
                configuration: default
                    .map(|name| configuration(account, &name))
                    .transpose()?,
                name,
                signing,
                signs: true,
                tags: Vec::new(),
                verification: None,
                mail_from: None,
            }),
            Change::NewIdentity {
                id,
                account,
                name,
                signing,
                configuration: default,
                tags,
                at,
            } => {
                if self.identity_named(account, &name).is_some() {
                    return Err(PolicyRefusal::Taken);
                }
                Record::Identity(Identity {
                    id,
                    account,
                    configuration: default
                        .map(|name| configuration(account, &name))
                        .transpose()?,
                    name,
                    signing: Some(signing),
                    signs: true,
                    tags,
                    verification: Some(Check {
                        status: Verification::Pending,
                        since: at,
                    }),
                    mail_from: None,
                })
            }
            Change::Amend {
                account,
                name,
                amendment,
            } => {
                let mut amended = self.identities[&identity(account, &name)?].clone();
                match amendment {
                    Amendment::Signing { signing, at } => {
                        amended.signing = Some(signing);
                        amended.verification = Some(Check {
                            status: Verification::Pending,
                            since: restarted(amended.verification.map(|check| check.since), at),
                        });
                    }
                    Amendment::Signs(signs) => amended.signs = signs,
                    Amendment::Checked {
                        identity,
                        selector,
                        key,
                        from,
                        check,
                    } => {
                        let checked = amended.id == identity
                            && amended.verification == Some(from)
                            && amended.signing.as_ref().is_some_and(|signing| {
                                signing.selector == selector && signing.key == key
                            });
                        if !checked {
                            return Err(PolicyRefusal::Outdated);
                        }
                        amended.verification = Some(check);
                    }
                    Amendment::MailFrom { mail_from, at } => {
                        let since = restarted(
                            amended
                                .mail_from
                                .as_ref()
                                .map(|mail_from| mail_from.check.since),
                            at,
                        );
                        amended.mail_from = mail_from.map(|(domain, behavior)| MailFrom {
                            domain: domain.to_ascii_lowercase().into(),
                            behavior,
                            check: Check {
                                status: Verification::Pending,
                                since,
                            },
                        });
                    }
                    Amendment::MailFromChecked {
                        identity,
                        domain,
                        from,
                        check,
                    } => {
                        let same = amended.id == identity;
                        let Some(mail_from) = amended.mail_from.as_mut().filter(|mail_from| {
                            same && *mail_from.domain == *domain && mail_from.check == from
                        }) else {
                            return Err(PolicyRefusal::Outdated);
                        };
                        mail_from.check = check;
                    }
                }
                Record::Identity(amended)
            }
            Change::Configuration {
                id,
                account,
                name,
                pool: named,
            } => Record::Configuration(Configuration {
                id,
                account,
                name,
                pool: named.map(|name| pool(account, &name)).transpose()?,
                tags: Vec::new(),
                reputation_metrics: false,
            }),
            Change::NewConfiguration {
                id,
                account,
                name,
                pool: named,
                reputation_metrics,
                tags,
            } => {
                if self.configuration_named(account, &name).is_some() {
                    return Err(PolicyRefusal::Taken);
                }
                Record::Configuration(Configuration {
                    id,
                    account,
                    name,
                    pool: named.map(|name| pool(account, &name)).transpose()?,
                    tags,
                    reputation_metrics,
                })
            }
            Change::ReputationMetrics {
                account,
                configuration: name,
                enabled,
            } => {
                let mut changed = self.configurations[&configuration(account, &name)?].clone();
                changed.reputation_metrics = enabled;
                Record::Configuration(changed)
            }
            Change::Pool { id, account, name } => Record::Pool(Pool { id, account, name }),
            Change::NewPool { id, account, name } => {
                if self.pool_names.contains_key(&(account, name.clone())) {
                    return Err(PolicyRefusal::Taken);
                }
                Record::Pool(Pool { id, account, name })
            }
            Change::EgressPool {
                account,
                address,
                pool: named,
            } => {
                let mut moved = self
                    .egress_addresses
                    .get(&address)
                    .and_then(|id| self.egresses.get(id))
                    .filter(|egress| egress.account == account)
                    .ok_or_else(|| unknown("egress", &address.to_string()))?
                    .as_ref()
                    .clone();
                moved.pool = named.map(|name| pool(account, &name)).transpose()?;
                Record::Egress(moved)
            }
            Change::ConfigurationPool {
                account,
                configuration: name,
                pool: named,
            } => {
                let mut changed = self.configurations[&configuration(account, &name)?].clone();
                changed.pool = named.map(|named| pool(account, &named)).transpose()?;
                Record::Configuration(changed)
            }
            Change::Egress {
                id,
                account,
                address,
                helo,
                pool: named,
                daily_cap,
            } => {
                let mut caps = self
                    .egress_addresses
                    .get(&address)
                    .and_then(|id| self.egresses.get(id))
                    .map(|egress| egress.caps.clone())
                    .unwrap_or_default();
                if daily_cap.is_some() && !caps.any() && caps.warmed.is_none() {
                    caps.set(None, daily_cap, self.next());
                }
                Record::Egress(Egress {
                    id,
                    account,
                    address,
                    helo,
                    pool: named.map(|name| pool(account, &name)).transpose()?,
                    caps,
                })
            }
            Change::Caps(cappings) => {
                let mut written = Vec::with_capacity(cappings.len());
                for capping in cappings {
                    let mut capped = self
                        .egresses
                        .get(&capping.egress)
                        .ok_or_else(|| unknown("egress", &capping.egress.0.as_u64().to_string()))?
                        .as_ref()
                        .clone();
                    // Decided from the caps as they are, by the revision
                    // that last changed them, and a judgment of its own is
                    // of a later day.
                    let judged = |caps: &Caps| caps.warmed.as_ref().map(|warmed| warmed.day);
                    let again = capping.to.warmed != capping.from.warmed
                        && judged(&capping.to) <= judged(&capping.from);
                    if capped.caps != capping.from || again {
                        return Err(PolicyRefusal::Outdated);
                    }
                    capped.caps = Caps {
                        changed: self.next(),
                        ..capping.to
                    };
                    written.push(Record::Egress(capped));
                }
                return Ok(Resolved::PutAll(written));
            }
            Change::Cap {
                account,
                address,
                site,
                cap,
            } => {
                let mut capped = self
                    .egress_addresses
                    .get(&address)
                    .and_then(|id| self.egresses.get(id))
                    .filter(|egress| egress.account == account)
                    .ok_or_else(|| unknown("egress", &address.to_string()))?
                    .as_ref()
                    .clone();
                if site.as_deref() == Some("") {
                    return Err(PolicyRefusal::InvalidName);
                }
                capped.caps.set(site.as_deref(), cap, self.next());
                Record::Egress(capped)
            }
            Change::Tenant {
                id,
                account,
                name,
                identities,
                configurations,
                limits,
            } => Record::Tenant(Tenant {
                // Associated through SES's API alone, they stay.
                templates: self
                    .tenant_named(account, &name)
                    .and_then(|id| self.tenants.get(&id))
                    .map(|tenant| tenant.templates.clone())
                    .unwrap_or_default(),
                id,
                account,
                name,
                identities: identities
                    .iter()
                    .map(|name| identity(account, name))
                    .collect::<Result<_, _>>()?,
                configurations: configurations
                    .iter()
                    .map(|name| configuration(account, name))
                    .collect::<Result<_, _>>()?,
                limits,
                tags: Vec::new(),
                created: None,
            }),
            Change::NewTenant {
                id,
                account,
                name,
                tags,
                at,
            } => {
                if self.tenant_named(account, &name).is_some() {
                    return Err(PolicyRefusal::Taken);
                }
                Record::Tenant(Tenant {
                    id,
                    account,
                    name,
                    identities: BTreeSet::new(),
                    configurations: BTreeSet::new(),
                    templates: BTreeSet::new(),
                    limits: Limits::default(),
                    tags,
                    created: Some(at),
                })
            }
            Change::Associate {
                account,
                tenant: named,
                resource,
            } => {
                let mut changed = self.tenants[&tenant(account, &named)?].clone();
                let added = match &resource {
                    Resource::Identity(name) => changed.identities.insert(identity(account, name)?),
                    Resource::Configuration(name) => {
                        changed.configurations.insert(configuration(account, name)?)
                    }
                    Resource::Template(name) => {
                        let template = self
                            .template_named(account, name)
                            .ok_or_else(|| unknown("template", name))?;
                        changed.templates.insert(template.id)
                    }
                };
                if !added {
                    return Err(PolicyRefusal::Taken);
                }
                Record::Tenant(changed)
            }
            Change::Dissociate {
                account,
                tenant: named,
                resource,
            } => {
                let mut changed = self.tenants[&tenant(account, &named)?].clone();
                let removed = match &resource {
                    Resource::Identity(name) => {
                        changed.identities.remove(&identity(account, name)?)
                    }
                    Resource::Configuration(name) => changed
                        .configurations
                        .remove(&configuration(account, name)?),
                    Resource::Template(name) => {
                        let template = self
                            .template_named(account, name)
                            .ok_or_else(|| unknown("template", name))?;
                        changed.templates.remove(&template.id)
                    }
                };
                if !removed {
                    return Err(unknown("association", &named));
                }
                Record::Tenant(changed)
            }
            Change::Credential {
                id,
                account,
                secret,
                identities,
                tenants,
                permissions,
            } => {
                let taken = match &secret {
                    Secret::Login { user, .. } => self.logins.contains_key(user),
                    Secret::AccessKey { id, .. } => self.access_keys.contains_key(id),
                };
                if taken {
                    return Err(PolicyRefusal::Taken);
                }
                let identities = match identities {
                    None => Scope::Any,
                    Some(names) => Scope::Only(
                        names
                            .iter()
                            .map(|name| identity(account, name))
                            .collect::<Result<_, _>>()?,
                    ),
                };
                let tenants = match tenants {
                    None => Scope::Any,
                    Some(names) => Scope::Only(
                        names
                            .iter()
                            .map(|name| tenant(account, name))
                            .collect::<Result<_, _>>()?,
                    ),
                };
                Record::Credential(Credential {
                    id,
                    account,
                    secret,
                    identities,
                    tenants,
                    permissions,
                })
            }
            Change::Subscription {
                id,
                account,
                name,
                configuration: named,
                url,
                events,
                secret,
            } => Record::Subscription(Subscription {
                id,
                account,
                configuration: configuration(account, &named)?,
                name,
                url,
                events,
                secret,
            }),
            Change::Topic { id, account, name } => Record::Topic(Topic { id, account, name }),
            Change::NewTemplate {
                id,
                account,
                name,
                content,
                at,
            } => {
                if self.template_named(account, &name).is_some() {
                    return Err(PolicyRefusal::Taken);
                }
                let kept = self
                    .template_names
                    .range((account, String::new())..)
                    .take_while(|((of, _), _)| *of == account)
                    .count();
                if kept >= Template::MOST {
                    return Err(PolicyRefusal::Limit);
                }
                Record::Template(Template {
                    id,
                    account,
                    name,
                    content,
                    created: at,
                })
            }
            Change::TemplateContent {
                account,
                name,
                content,
            } => {
                let template = self
                    .template_named(account, &name)
                    .ok_or_else(|| unknown("template", &name))?;
                Record::Template(Template {
                    content,
                    ..Template::clone(template)
                })
            }
            Change::Subscribe {
                id,
                account,
                topic: named,
                endpoint,
                token,
            } => {
                let topic = self.topic(account, &named)?;
                let subscribed = self
                    .subscribers
                    .values()
                    .any(|subscriber| subscriber.topic == topic && subscriber.endpoint == endpoint);
                if subscribed {
                    return Err(PolicyRefusal::Taken);
                }
                Record::Subscriber(Subscriber {
                    id,
                    account,
                    topic,
                    endpoint,
                    token,
                    confirmed: false,
                })
            }
            Change::Confirm {
                account,
                topic: named,
                token,
            } => {
                let topic = self.topic(account, &named)?;
                let mut confirmed = self
                    .subscribers
                    .values()
                    .find(|subscriber| subscriber.topic == topic && same(&subscriber.token, &token))
                    .ok_or_else(|| unknown("subscription", &named))?
                    .clone();
                confirmed.confirmed = true;
                Record::Subscriber(confirmed)
            }
            Change::Destination {
                id,
                account,
                configuration: owner,
                name,
                topic: named,
                events,
                enabled,
                replaces,
            } => {
                let configuration = configuration(account, &owner)?;
                let held = self
                    .destination_names
                    .get(&(configuration, name.clone()))
                    .copied();
                let id = match (held, replaces) {
                    (Some(_), false) => return Err(PolicyRefusal::Taken),
                    (None, true) => return Err(unknown("destination", &name)),
                    (Some(held), true) => held,
                    (None, false) => id,
                };
                Record::Destination(Destination {
                    id,
                    account,
                    configuration,
                    name,
                    topic: self.topic(account, &named)?,
                    events,
                    enabled,
                })
            }
            Change::Hold {
                id,
                target,
                accepting,
                reason,
            } => {
                let (account, paused) = self.paused(&target)?;
                Record::Hold(Hold {
                    id,
                    account,
                    paused,
                    accepting,
                    reason,
                })
            }
            Change::Release(target) => {
                let paused = self.paused(&target)?;
                let id = self
                    .held
                    .get(&paused)
                    .ok_or_else(|| unknown("hold", &held_name(&target)))?;
                return Ok(Resolved::Remove(id.0));
            }
            Change::CustomerStatus {
                id,
                account,
                paused,
                disabled,
                reason,
            } => {
                let present = match paused {
                    Paused::Tenant(tenant) => self
                        .tenants
                        .get(&tenant)
                        .is_some_and(|found| found.account == account),
                    Paused::Identity(identity) => self
                        .identities
                        .get(&identity)
                        .is_some_and(|found| found.account == account),
                    Paused::Configuration(configuration) => self
                        .configurations
                        .get(&configuration)
                        .is_some_and(|found| found.account == account),
                    Paused::Account | Paused::Egress(_) => false,
                };
                if !present {
                    return Err(unknown("reputation entity", "the one named"));
                }
                if !disabled {
                    let held = self
                        .held
                        .get(&(account, paused))
                        .ok_or_else(|| unknown("hold", "the reputation entity's"))?;
                    return Ok(Resolved::Remove(held.0));
                }
                Record::Hold(Hold {
                    id,
                    account,
                    paused,
                    accepting: false,
                    reason,
                })
            }
            Change::Remove(target) => {
                let id = match &target {
                    Target::Account(id) => self
                        .accounts
                        .contains_key(id)
                        .then_some(id.0)
                        .ok_or_else(|| unknown("account", &id.0.as_u64().to_string()))?,
                    Target::Identity { account, name } => identity(*account, name)?.0,
                    Target::Configuration { account, name } => configuration(*account, name)?.0,
                    Target::Tenant { account, name } => tenant(*account, name)?.0,
                    Target::Login(user) => {
                        self.logins
                            .get(user)
                            .ok_or_else(|| unknown("login", user))?
                            .0
                    }
                    Target::AccessKey(key) => {
                        self.access_keys
                            .get(key)
                            .ok_or_else(|| unknown("access key", key))?
                            .0
                    }
                    Target::Subscription { account, name } => {
                        self.subscription_names
                            .get(&(*account, name.clone()))
                            .ok_or_else(|| unknown("subscription", name))?
                            .0
                    }
                    Target::Pool { account, name } => pool(*account, name)?.0,
                    Target::Egress(address) => {
                        self.egress_addresses
                            .get(address)
                            .ok_or_else(|| unknown("egress", &address.to_string()))?
                            .0
                    }
                    Target::Subscriber { account, id } => {
                        self.subscribers
                            .get(id)
                            .filter(|subscriber| subscriber.account == *account)
                            .ok_or_else(|| unknown("subscription", &id.0.as_u64().to_string()))?
                            .id
                            .0
                    }
                    Target::Destination {
                        account,
                        configuration: owner,
                        name,
                    } => {
                        let configuration = configuration(*account, owner)?;
                        self.destination_names
                            .get(&(configuration, name.clone()))
                            .ok_or_else(|| unknown("destination", name))?
                            .0
                    }
                    Target::Template { account, name } => {
                        self.template_named(*account, name)
                            .ok_or_else(|| unknown("template", name))?
                            .id
                            .0
                    }
                };
                return Ok(Resolved::Remove(id));
            }
        }))
    }

    /// The account, and what in it, that `target` names to hold.
    fn paused(&self, target: &Target) -> Result<(AccountId, Paused), PolicyRefusal> {
        let unknown = |kind, name: &str| PolicyRefusal::Unknown {
            kind,
            name: name.to_owned(),
        };
        Ok(match target {
            Target::Account(account) => (*account, Paused::Account),
            Target::Identity { account, name } => {
                let id = self
                    .identity_named(*account, name)
                    .ok_or_else(|| unknown("identity", name))?;
                (*account, Paused::Identity(id))
            }
            Target::Configuration { account, name } => {
                let id = self
                    .configuration_named(*account, name)
                    .ok_or_else(|| unknown("configuration", name))?;
                (*account, Paused::Configuration(id))
            }
            Target::Tenant { account, name } => {
                let id = self
                    .tenant_named(*account, name)
                    .ok_or_else(|| unknown("tenant", name))?;
                (*account, Paused::Tenant(id))
            }
            Target::Egress(address) => {
                let egress = self
                    .egress_addresses
                    .get(address)
                    .and_then(|id| self.egresses.get(id))
                    .ok_or_else(|| unknown("egress", &address.to_string()))?;
                (egress.account, Paused::Egress(egress.id))
            }
            Target::Login(_)
            | Target::AccessKey(_)
            | Target::Subscription { .. }
            | Target::Pool { .. }
            | Target::Subscriber { .. }
            | Target::Destination { .. }
            | Target::Template { .. } => return Err(PolicyRefusal::InvalidName),
        })
    }

    /// The hold that pauses mail of `account` sent under `origin` and to go
    /// out from `egress`, if one does: nothing to look up while
    /// no hold is in force.
    pub fn hold(
        &self,
        account: AccountId,
        origin: &Origin,
        egress: Option<EgressId>,
    ) -> Option<&Hold> {
        if self.holds.is_empty() {
            return None;
        }
        [
            Some(Paused::Account),
            Some(Paused::Identity(origin.identity)),
            origin.tenant.map(Paused::Tenant),
            origin.configuration.map(Paused::Configuration),
            egress.map(Paused::Egress),
        ]
        .into_iter()
        .flatten()
        .find_map(|paused| self.held.get(&(account, paused)))
        .and_then(|id| self.holds.get(id))
    }

    /// Every hold in force.
    pub fn holds(&self) -> impl Iterator<Item = &Hold> {
        self.holds.values()
    }

    /// The store's fence, while it has one.
    pub fn fence(&self) -> Option<&Fence> {
        self.fence.as_ref()
    }

    /// Sets the store's fence, as the store keeps it: at the next revision,
    /// unless it is as it was, when the fence read at open is given.
    pub fn set_fence(&mut self, fence: Option<Fence>, at_next: bool) {
        self.fence = fence;
        if at_next {
            self.revision = PolicyRevision(self.revision.0 + 1);
        }
    }

    /// Whether `delivery`, mail of `account` sent under `origin` and to go
    /// out from `egress`, waits: the store's fence holds it, or, unless the
    /// fence's decision is to discard it, a hold covers it. One branch while
    /// neither is in force.
    pub fn holds_back(
        &self,
        delivery: DeliveryId,
        account: AccountId,
        origin: &Origin,
        egress: Option<EgressId>,
    ) -> bool {
        match self.fence {
            // Discarded whatever holds it: a hold waits to send, and this is
            // never sent.
            Some(fence) if fence.covers(delivery) => !fence.discarding,
            _ => self.hold(account, origin, egress).is_some(),
        }
    }

    /// Whether the fence's decision is to discard `delivery`.
    pub fn discards(&self, delivery: DeliveryId) -> bool {
        self.fence
            .is_some_and(|fence| fence.discarding && fence.covers(delivery))
    }

    /// What `hold` is on, as a release names it.
    pub fn held_by_name(&self, hold: &Hold) -> Option<Target> {
        let account = hold.account;
        Some(match hold.paused {
            Paused::Account => Target::Account(account),
            Paused::Tenant(id) => Target::Tenant {
                account,
                name: self.tenants.get(&id)?.name.clone(),
            },
            Paused::Configuration(id) => Target::Configuration {
                account,
                name: self.configurations.get(&id)?.name.clone(),
            },
            Paused::Identity(id) => Target::Identity {
                account,
                name: self.identities.get(&id)?.name.clone(),
            },
            Paused::Egress(id) => Target::Egress(self.egresses.get(&id)?.address),
        })
    }

    /// Whether new mail of `account` sent under `origin` is accepted: not
    /// while any hold on it refuses new mail, whatever others accept, nor
    /// while one does on every egress it may go out from.
    fn accepting(&self, account: AccountId, origin: &Origin) -> Result<(), Denial> {
        if self.holds.is_empty() {
            return Ok(());
        }
        let refusing = |paused| {
            self.held
                .get(&(account, paused))
                .and_then(|id| self.holds.get(id))
                .is_some_and(|hold| !hold.accepting)
        };
        let refused = [
            Some(Paused::Account),
            Some(Paused::Identity(origin.identity)),
            origin.tenant.map(Paused::Tenant),
            origin.configuration.map(Paused::Configuration),
        ]
        .into_iter()
        .flatten()
        .any(refusing);
        let unsendable = match self.sources(account, origin.configuration) {
            Sources::Egresses(egresses) if !egresses.is_empty() => egresses
                .iter()
                .all(|egress| refusing(Paused::Egress(egress.id))),
            _ => false,
        };
        if refused || unsendable {
            Err(Denial::Paused)
        } else {
            Ok(())
        }
    }

    /// Whether mail sent under `origin` for `account` may still be sent:
    /// its identity, tenant and configuration exist in the account, its
    /// identity is verified, and its tenant may send with both.
    pub fn allows(&self, account: AccountId, origin: &Origin) -> Result<(), Denial> {
        let identity = self
            .identities
            .get(&origin.identity)
            .filter(|identity| identity.account == account)
            .ok_or(Denial::UnknownIdentity)?;
        if !identity.verified() {
            return Err(Denial::Unverified);
        }
        let refused = identity.mail_from.as_ref().is_some_and(|mail_from| {
            mail_from.behavior == OnMxFailure::Reject
                && mail_from.check.status != Verification::Success
        });
        if refused {
            return Err(Denial::MailFromUnverified);
        }
        if let Some(id) = origin.configuration {
            self.configurations
                .get(&id)
                .filter(|configuration| configuration.account == account)
                .ok_or(Denial::UnknownConfiguration)?;
        }
        if let Some(id) = origin.tenant {
            let tenant = self
                .tenants
                .get(&id)
                .filter(|tenant| tenant.account == account)
                .ok_or(Denial::UnknownTenant)?;
            let configured = origin
                .configuration
                .is_none_or(|id| tenant.configurations.contains(&id));
            if !tenant.identities.contains(&origin.identity) || !configured {
                return Err(Denial::NotAssociated);
            }
        }
        Ok(())
    }

    /// Whether `credential` may submit mail for `account` under `origin`.
    pub fn admits(
        &self,
        credential: CredentialId,
        account: AccountId,
        origin: &Origin,
    ) -> Result<(), Denial> {
        let credential = self
            .credentials
            .get(&credential)
            .filter(|credential| credential.account == account)
            .ok_or(Denial::UnknownCredential)?;
        if !credential.permissions.sends {
            return Err(Denial::NotSending);
        }
        self.allows(account, origin)?;
        Self::in_scope(credential, origin)?;
        self.accepting(account, origin)
    }

    /// Whether mail sent under `origin` may be rendered from the kept
    /// `template`: its account's, and, sent for a tenant, one associated
    /// with it, as SES has it.
    pub fn uses(
        &self,
        origin: &Origin,
        account: AccountId,
        template: TemplateId,
    ) -> Result<(), Denial> {
        let kept = self
            .templates
            .get(&template)
            .filter(|kept| kept.account == account)
            .ok_or(Denial::NotAssociated)?;
        match origin.tenant {
            None => Ok(()),
            Some(tenant) => self
                .tenants
                .get(&tenant)
                .filter(|tenant| tenant.templates.contains(&kept.id))
                .map(|_| ())
                .ok_or(Denial::NotAssociated),
        }
    }

    /// What mail from `from` is sent under for `credential`, with the tenant
    /// and configuration its request names, if any: the address's own
    /// identity, else its domain's. Mail sent as `from` whose own From is
    /// `own` must be the same identity, so the one origin, checked again at
    /// commit and at reservation, covers the address its recipients see.
    pub fn origin(
        &self,
        credential: &Credential,
        from: &Address,
        own: Option<&Address>,
        tenant: Option<&str>,
        configuration: Option<&str>,
    ) -> Result<Origin, Denial> {
        if !credential.permissions.sends {
            return Err(Denial::NotSending);
        }
        let account = credential.account;
        let identity = self.sender(account, from).ok_or(Denial::UnknownIdentity)?;
        if let Some(own) = own {
            let theirs = self.sender(account, own).ok_or(Denial::UnknownIdentity)?;
            if theirs.id != identity.id {
                return Err(Denial::DifferentFrom);
            }
        }
        let tenant = match tenant {
            Some(name) => Some(
                self.tenant_named(account, name)
                    .ok_or(Denial::UnknownTenant)?,
            ),
            None => None,
        };
        let configuration = match configuration {
            Some(name) => Some(
                self.configuration_named(account, name)
                    .ok_or(Denial::UnknownConfiguration)?,
            ),
            None => identity.configuration,
        };
        let origin = Origin {
            identity: identity.id,
            tenant,
            configuration,
        };
        Self::in_scope(credential, &origin)?;
        self.allows(account, &origin)?;
        self.accepting(account, &origin)?;
        Ok(origin)
    }

    fn in_scope(credential: &Credential, origin: &Origin) -> Result<(), Denial> {
        if !credential.identities.includes(&origin.identity) {
            return Err(Denial::IdentityNotPermitted);
        }
        let tenant_permitted = match (&credential.tenants, origin.tenant) {
            (Scope::Any, _) => true,
            (Scope::Only(tenants), Some(tenant)) => tenants.contains(&tenant),
            (Scope::Only(_), None) => false,
        };
        if !tenant_permitted {
            return Err(Denial::TenantNotPermitted);
        }
        Ok(())
    }

    /// The identity `from` is sent as within `account`: the address's own,
    /// else its domain's.
    pub fn sender(&self, account: AccountId, from: &Address) -> Option<&Identity> {
        let address = from.as_str().to_ascii_lowercase();
        let domain = from.domain().to_ascii_lowercase();
        [address, domain]
            .into_iter()
            .find_map(|name| self.identity_names.get(&(account, name)))
            .and_then(|id| self.identities.get(id))
    }

    pub fn identity(&self, id: IdentityId) -> Option<&Identity> {
        self.identities.get(&id)
    }

    pub fn account(&self, id: AccountId) -> Option<&Account> {
        self.accounts.get(&id)
    }

    pub fn tenant(&self, id: TenantId) -> Option<&Tenant> {
        self.tenants.get(&id)
    }

    /// The account's identity of exactly this domain or address, whatever
    /// its case.
    pub fn identity_named(&self, account: AccountId, name: &str) -> Option<IdentityId> {
        self.identity_names
            .get(&(account, name.to_ascii_lowercase()))
            .copied()
    }

    pub fn tenant_named(&self, account: AccountId, name: &str) -> Option<TenantId> {
        self.tenant_names.get(&(account, name.to_owned())).copied()
    }

    pub fn configuration_named(&self, account: AccountId, name: &str) -> Option<ConfigurationId> {
        self.configuration_names
            .get(&(account, name.to_owned()))
            .copied()
    }

    pub fn identities(&self) -> impl Iterator<Item = &Identity> {
        self.identities.values()
    }

    /// The account's identities in the order of their names, from the first
    /// after `after`, if given.
    pub fn identities_after<'a>(
        &'a self,
        account: AccountId,
        after: Option<&str>,
    ) -> impl Iterator<Item = &'a Identity> + 'a {
        use std::ops::Bound;
        let from = match after {
            Some(name) => Bound::Excluded((account, name.to_ascii_lowercase())),
            None => Bound::Included((account, String::new())),
        };
        self.identity_names
            .range((from, Bound::Unbounded))
            .take_while(move |((held, _), _)| *held == account)
            .filter_map(|(_, id)| self.identities.get(id))
    }

    /// The account's tenants in the order of their names, from the first
    /// after `after`, if given.
    pub fn tenants_after<'a>(
        &'a self,
        account: AccountId,
        after: Option<&str>,
    ) -> impl Iterator<Item = &'a Tenant> + 'a {
        use std::ops::Bound;
        let from = match after {
            Some(name) => Bound::Excluded((account, name.to_owned())),
            None => Bound::Included((account, String::new())),
        };
        self.tenant_names
            .range((from, Bound::Unbounded))
            .take_while(move |((held, _), _)| *held == account)
            .filter_map(|(_, id)| self.tenants.get(id))
    }

    /// The account's configuration sets in the order of their names, from
    /// the first after `after`, if given.
    pub fn configurations_after<'a>(
        &'a self,
        account: AccountId,
        after: Option<&str>,
    ) -> impl Iterator<Item = &'a Configuration> + 'a {
        use std::ops::Bound;
        let from = match after {
            Some(name) => Bound::Excluded((account, name.to_owned())),
            None => Bound::Included((account, String::new())),
        };
        self.configuration_names
            .range((from, Bound::Unbounded))
            .take_while(move |((held, _), _)| *held == account)
            .filter_map(|(_, id)| self.configurations.get(id))
    }

    /// The hold on what `paused` names in `account`, if one is in force.
    pub fn held(&self, account: AccountId, paused: Paused) -> Option<&Hold> {
        self.held
            .get(&(account, paused))
            .and_then(|id| self.holds.get(id))
    }

    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    pub fn tenants(&self) -> impl Iterator<Item = &Tenant> {
        self.tenants.values()
    }

    pub fn configuration(&self, id: ConfigurationId) -> Option<&Configuration> {
        self.configurations.get(&id)
    }

    pub fn configurations(&self) -> impl Iterator<Item = &Configuration> {
        self.configurations.values()
    }

    pub fn credentials(&self) -> impl Iterator<Item = &Credential> {
        self.credentials.values()
    }

    pub fn pool(&self, id: PoolId) -> Option<&Pool> {
        self.pools.get(&id)
    }

    pub fn pools(&self) -> impl Iterator<Item = &Pool> {
        self.pools.values()
    }

    pub fn egresses(&self) -> impl Iterator<Item = &Egress> {
        self.egresses.values().map(AsRef::as_ref)
    }

    pub fn credential(&self, id: CredentialId) -> Option<&Credential> {
        self.credentials.get(&id)
    }

    /// The credential an SMTP login names.
    pub fn login(&self, user: &str) -> Option<&Credential> {
        self.logins
            .get(user)
            .and_then(|id| self.credentials.get(id))
    }

    /// The credential an SES access key ID names.
    pub fn access_key(&self, id: &str) -> Option<&Credential> {
        self.access_keys
            .get(id)
            .and_then(|id| self.credentials.get(id))
    }

    pub fn subscription(&self, id: SubscriptionId) -> Option<&Subscription> {
        self.subscriptions.get(&id)
    }

    pub fn subscription_named(&self, account: AccountId, name: &str) -> Option<SubscriptionId> {
        self.subscription_names
            .get(&(account, name.to_owned()))
            .copied()
    }

    /// The feed of events `name` names in `account`: a subscription, by
    /// its name, or a topic's subscriber, by its subscription ARN or the ID
    /// that ends it.
    pub fn feed_named(&self, account: AccountId, name: &str) -> Option<SubscriptionId> {
        // An ARN names a subscriber alone, of the topic it names; a bare
        // name, a subscription first.
        let (topic, id) = match name.rsplit_once(':') {
            Some((arn, id)) => (Some(arn.rsplit(':').next()?), id),
            None => match self.subscription_named(account, name) {
                Some(subscription) => return Some(subscription),
                None => (None, name),
            },
        };
        let id = u64::from_str_radix(id, 16).ok().and_then(Id::from_u64)?;
        self.subscribers
            .get(&SubscriptionId(id))
            .filter(|subscriber| subscriber.account == account)
            .filter(|subscriber| {
                topic.is_none_or(|topic| {
                    self.topics
                        .get(&subscriber.topic)
                        .is_some_and(|held| held.name == topic)
                })
            })
            .map(|subscriber| subscriber.id)
    }

    pub fn subscriptions(&self) -> impl Iterator<Item = &Subscription> {
        self.subscriptions.values()
    }

    pub fn egress(&self, id: EgressId) -> Option<&Egress> {
        self.egresses.get(&id).map(AsRef::as_ref)
    }

    /// The egress `id`, shared: what a transaction carries.
    pub fn shared_egress(&self, id: EgressId) -> Option<Arc<Egress>> {
        self.egresses.get(&id).cloned()
    }

    /// Where mail of `account` under `configuration` may go out from: its
    /// configuration's pool's egresses, or the account's in no pool, or,
    /// with no pool named and no egress in none, the host's own address. A
    /// pool with no egress sends from none: its mail waits rather than go
    /// out from another address.
    pub fn sources(
        &self,
        account: AccountId,
        configuration: Option<ConfigurationId>,
    ) -> Sources<'_> {
        let pool = configuration
            .and_then(|id| self.configurations.get(&id))
            .filter(|configuration| configuration.account == account)
            .and_then(|configuration| configuration.pool);
        let egresses: Vec<&Egress> = self
            .egresses()
            .filter(|egress| egress.account == account && egress.pool == pool)
            .collect();
        if pool.is_none() && egresses.is_empty() {
            Sources::Host
        } else {
            Sources::Egresses(egresses)
        }
    }

    /// Whether mail of `account` under `configuration` may go out from
    /// `egress`, or from the host's own address when that is `None`.
    pub fn sends_from(
        &self,
        account: AccountId,
        configuration: Option<ConfigurationId>,
        egress: Option<EgressId>,
    ) -> bool {
        match (self.sources(account, configuration), egress) {
            (Sources::Host, None) => true,
            (Sources::Egresses(egresses), Some(id)) => {
                egresses.iter().any(|egress| egress.id == id)
            }
            _ => false,
        }
    }

    /// The ID a record put under its name is kept under: an existing
    /// record's, or its own. Each name, login and key ID belongs to one
    /// record of one kind and account.
    fn id_for(&self, record: &Record) -> Result<Id, PolicyRefusal> {
        let existing = match record {
            Record::Account(_) => None,
            Record::Identity(identity) => self
                .identity_names
                .get(&(identity.account, identity.name.to_ascii_lowercase()))
                .map(|id| id.0),
            Record::Tenant(tenant) => self
                .tenant_names
                .get(&(tenant.account, tenant.name.clone()))
                .map(|id| id.0),
            Record::Configuration(configuration) => self
                .configuration_names
                .get(&(configuration.account, configuration.name.clone()))
                .map(|id| id.0),
            Record::Credential(credential) => match &credential.secret {
                Secret::Login { user, .. } => self.logins.get(user),
                Secret::AccessKey { id, .. } => self.access_keys.get(id),
            }
            .map(|id| id.0),
            Record::Subscription(subscription) => self
                .subscription_names
                .get(&(subscription.account, subscription.name.clone()))
                .map(|id| id.0),
            Record::Pool(pool) => self
                .pool_names
                .get(&(pool.account, pool.name.clone()))
                .map(|id| id.0),
            Record::Egress(egress) => self.egress_addresses.get(&egress.address).map(|id| id.0),
            Record::Hold(hold) => self.held.get(&(hold.account, hold.paused)).map(|id| id.0),
            Record::Topic(topic) => self
                .topic_names
                .get(&(topic.account, topic.name.clone()))
                .map(|id| id.0),
            Record::Template(template) => self
                .template_names
                .get(&(template.account, template.name.clone()))
                .map(|id| id.0),
            Record::Subscriber(subscriber) => self
                .subscribers
                .contains_key(&subscriber.id)
                .then_some(subscriber.id.0),
            Record::Destination(destination) => self
                .destination_names
                .get(&(destination.configuration, destination.name.clone()))
                .map(|id| id.0),
        };
        let Some(existing) = existing else {
            // A record new to its name takes an ID no record holds; only an
            // account is named by its ID.
            let id = record.id();
            if !matches!(record, Record::Account(_)) && self.kind_of(id).is_some() {
                return Err(PolicyRefusal::Conflict);
            }
            return Ok(id);
        };
        // A login or key ID is the installation's, and neither a credential
        // nor a subscription is ever replaced.
        if matches!(record, Record::Credential(_) | Record::Subscription(_)) {
            return Err(PolicyRefusal::Taken);
        }
        // An address is the installation's, and one account's.
        if let Record::Egress(egress) = record
            && self
                .egresses
                .get(&EgressId(existing))
                .is_some_and(|held| held.account != egress.account)
        {
            return Err(PolicyRefusal::Taken);
        }
        Ok(existing)
    }

    /// `record` checked and normalised, under the ID it is kept under.
    fn check(&self, record: Record) -> Result<Record, PolicyRefusal> {
        let id = self.id_for(&record)?;
        if self.kind_of(id).is_some_and(|kind| kind != record.kind()) {
            return Err(PolicyRefusal::Conflict);
        }
        Ok(match record {
            Record::Account(account) => Record::Account(account),
            Record::Identity(mut identity) => {
                identity.id = IdentityId(id);
                identity.name = identity.name.to_ascii_lowercase();
                let valid = if identity.name.contains('@') {
                    Address::parse(&identity.name).is_ok()
                } else {
                    address::domain(&identity.name).is_ok()
                };
                let signing_valid = identity
                    .signing
                    .as_ref()
                    .is_none_or(|signing| address::domain(&signing.selector).is_ok());
                // What is checked is its DKIM record.
                let checkable = identity.verification.is_none() || identity.signing.is_some();
                // A MAIL FROM domain is under the identity's own.
                let mail_from_valid = identity.mail_from.as_ref().is_none_or(|mail_from| {
                    mail_from.domain.len() <= MailFrom::MOST
                        && address::domain(&mail_from.domain).is_ok()
                        && *mail_from.domain == mail_from.domain.to_ascii_lowercase()
                        && mail_from
                            .domain
                            .strip_suffix(identity.domain())
                            .is_some_and(|label| label.len() > 1 && label.ends_with('.'))
                });
                if !valid || !signing_valid || !checkable || !mail_from_valid {
                    return Err(PolicyRefusal::InvalidName);
                }
                if !valid_tags(&identity.tags) {
                    return Err(PolicyRefusal::InvalidName);
                }
                if let Some(configuration) = identity.configuration {
                    self.owned_configuration(identity.account, configuration)?;
                }
                Record::Identity(identity)
            }
            Record::Tenant(mut tenant) => {
                tenant.id = TenantId(id);
                if !valid_name(&tenant.name) || !valid_tags(&tenant.tags) {
                    return Err(PolicyRefusal::InvalidName);
                }
                for identity in &tenant.identities {
                    self.owned_identity(tenant.account, *identity)?;
                }
                for configuration in &tenant.configurations {
                    self.owned_configuration(tenant.account, *configuration)?;
                }
                for template in &tenant.templates {
                    self.templates
                        .get(template)
                        .filter(|kept| kept.account == tenant.account)
                        .ok_or_else(|| missing("template", template.0))?;
                }
                Record::Tenant(tenant)
            }
            Record::Configuration(mut configuration) => {
                configuration.id = ConfigurationId(id);
                if !valid_name(&configuration.name) || !valid_tags(&configuration.tags) {
                    return Err(PolicyRefusal::InvalidName);
                }
                if let Some(pool) = configuration.pool {
                    self.owned_pool(configuration.account, pool)?;
                }
                Record::Configuration(configuration)
            }
            Record::Pool(mut pool) => {
                pool.id = PoolId(id);
                if !valid_name(&pool.name) {
                    return Err(PolicyRefusal::InvalidName);
                }
                Record::Pool(pool)
            }
            Record::Egress(mut egress) => {
                egress.id = EgressId(id);
                egress.helo = egress.helo.to_ascii_lowercase();
                let valid = address::domain(&egress.helo).is_ok()
                    && !egress.address.is_unspecified()
                    && !egress.address.is_multicast();
                if !valid {
                    return Err(PolicyRefusal::InvalidName);
                }
                if let Some(pool) = egress.pool {
                    self.owned_pool(egress.account, pool)?;
                }
                Record::Egress(egress)
            }
            Record::Credential(mut credential) => {
                credential.id = CredentialId(id);
                let handle = match &credential.secret {
                    Secret::Login { user, .. } => user,
                    Secret::AccessKey { id, .. } => id,
                };
                let valid = !handle.is_empty()
                    && handle.len() <= 128
                    && handle.bytes().all(|byte| byte.is_ascii_graphic());
                let permitted = match credential.secret {
                    Secret::Login { .. } => credential.permissions == Permissions::SENDS,
                    Secret::AccessKey { .. } => {
                        credential.permissions.sends || credential.permissions.manages
                    }
                };
                if !valid || !permitted {
                    return Err(PolicyRefusal::InvalidName);
                }
                if let Scope::Only(identities) = &credential.identities {
                    for identity in identities {
                        self.owned_identity(credential.account, *identity)?;
                    }
                }
                if let Scope::Only(tenants) = &credential.tenants {
                    for tenant in tenants {
                        self.tenants
                            .get(tenant)
                            .filter(|held| held.account == credential.account)
                            .ok_or_else(|| missing("tenant", tenant.0))?;
                    }
                }
                Record::Credential(credential)
            }
            Record::Subscription(mut subscription) => {
                subscription.id = SubscriptionId(id);
                let valid = valid_name(&subscription.name)
                    && valid_url(&subscription.url)
                    && !subscription.events.is_empty();
                if !valid {
                    return Err(PolicyRefusal::InvalidName);
                }
                self.owned_configuration(subscription.account, subscription.configuration)?;
                Record::Subscription(subscription)
            }
            Record::Hold(mut hold) => {
                hold.id = HoldId(id);
                let valid = !hold.reason.trim().is_empty()
                    && hold.reason.len() <= Hold::MAX_REASON
                    && hold
                        .reason
                        .bytes()
                        .all(|byte| byte == b' ' || byte.is_ascii_graphic());
                if !valid {
                    return Err(PolicyRefusal::InvalidName);
                }
                match hold.paused {
                    Paused::Account => {}
                    Paused::Identity(identity) => self.owned_identity(hold.account, identity)?,
                    Paused::Configuration(configuration) => {
                        self.owned_configuration(hold.account, configuration)?;
                    }
                    Paused::Tenant(tenant) => {
                        self.tenants
                            .get(&tenant)
                            .filter(|held| held.account == hold.account)
                            .ok_or_else(|| missing("tenant", tenant.0))?;
                    }
                    Paused::Egress(egress) => {
                        self.egresses
                            .get(&egress)
                            .filter(|held| held.account == hold.account)
                            .ok_or_else(|| missing("egress", egress.0))?;
                    }
                }
                Record::Hold(hold)
            }
            Record::Topic(mut topic) => {
                topic.id = TopicId(id);
                if !valid_topic(&topic.name) {
                    return Err(PolicyRefusal::InvalidName);
                }
                Record::Topic(topic)
            }
            Record::Template(mut template) => {
                template.id = TemplateId(id);
                if !valid_name(&template.name) {
                    return Err(PolicyRefusal::InvalidName);
                }
                if template.content.bytes() > TemplateContent::MOST_BYTES {
                    return Err(PolicyRefusal::Limit);
                }
                Record::Template(template)
            }
            Record::Subscriber(subscriber) => {
                if !valid_url(&subscriber.endpoint) {
                    return Err(PolicyRefusal::InvalidName);
                }
                self.owned_topic(subscriber.account, subscriber.topic)?;
                Record::Subscriber(subscriber)
            }
            Record::Destination(mut destination) => {
                destination.id = DestinationId(id);
                if !valid_name(&destination.name) || destination.events.is_empty() {
                    return Err(PolicyRefusal::InvalidName);
                }
                self.owned_configuration(destination.account, destination.configuration)?;
                self.owned_topic(destination.account, destination.topic)?;
                Record::Destination(destination)
            }
        })
    }

    fn owned_topic(&self, account: AccountId, id: TopicId) -> Result<(), PolicyRefusal> {
        self.topics
            .get(&id)
            .filter(|topic| topic.account == account)
            .map(|_| ())
            .ok_or_else(|| missing("topic", id.0))
    }

    /// The account's topic `name` names.
    fn topic(&self, account: AccountId, name: &str) -> Result<TopicId, PolicyRefusal> {
        self.topic_names
            .get(&(account, name.to_owned()))
            .copied()
            .ok_or_else(|| PolicyRefusal::Unknown {
                kind: "topic",
                name: name.to_owned(),
            })
    }

    pub fn topic_named(&self, account: AccountId, name: &str) -> Option<&Topic> {
        self.topic_names
            .get(&(account, name.to_owned()))
            .and_then(|id| self.topics.get(id))
    }

    pub fn topic_of(&self, id: TopicId) -> Option<&Topic> {
        self.topics.get(&id)
    }

    pub fn template_of(&self, id: TemplateId) -> Option<&Arc<Template>> {
        self.templates.get(&id)
    }

    /// The account's template of `name`, shared.
    pub fn template_named(&self, account: AccountId, name: &str) -> Option<&Arc<Template>> {
        self.template_names
            .get(&(account, name.to_owned()))
            .and_then(|id| self.templates.get(id))
    }

    /// The account's templates named after `after`, in name order.
    pub fn templates_after<'a>(
        &'a self,
        account: AccountId,
        after: Option<&str>,
    ) -> impl Iterator<Item = &'a Arc<Template>> + 'a {
        use std::ops::Bound;
        let from = match after {
            Some(name) => Bound::Excluded((account, name.to_owned())),
            None => Bound::Included((account, String::new())),
        };
        self.template_names
            .range((from, Bound::Unbounded))
            .take_while(move |((held, _), _)| *held == account)
            .filter_map(|(_, id)| self.templates.get(id))
    }

    pub fn subscribers(&self) -> impl Iterator<Item = &Subscriber> {
        self.subscribers.values()
    }

    pub fn subscriber(&self, id: SubscriptionId) -> Option<&Subscriber> {
        self.subscribers.get(&id)
    }

    pub fn destinations(&self) -> impl Iterator<Item = &Destination> {
        self.destinations.values()
    }

    /// The feed of events `id` names: a subscription's, or a topic
    /// subscriber's.
    pub fn feed(&self, id: SubscriptionId) -> Option<Feed<'_>> {
        match self.subscriptions.get(&id) {
            Some(subscription) => Some(Feed::Webhook(subscription)),
            None => self.subscribers.get(&id).map(Feed::Topic),
        }
    }

    /// The topics the event `entry` makes is published to: those of its
    /// configuration's enabled destinations that take its kind, in order,
    /// each once. Decided as the entry is written, so a
    /// destination changed later never changes what was published; nothing
    /// is looked up when there are no destinations.
    pub fn publishes(&self, entry: &Entry) -> Vec<TopicId> {
        let Some(configuration) = entry
            .configuration()
            .filter(|_| !self.destinations.is_empty())
        else {
            return Vec::new();
        };
        let kind = EventKind::of(entry);
        let mut topics: Vec<TopicId> = self
            .destination_names
            .range((configuration, String::new())..)
            .take_while(|((of, _), _)| *of == configuration)
            .filter_map(|(_, id)| self.destinations.get(id))
            .filter(|destination| destination.enabled && destination.events.contains(&kind))
            .map(|destination| destination.topic)
            .collect();
        topics.sort_unstable();
        topics.dedup();
        topics
    }

    /// Whether `feed` owes the event `entry` makes, which was published to
    /// `published` as it was written: a subscription, those of its
    /// configuration and kinds; a confirmed subscriber, those published to
    /// its topic.
    pub fn owes(feed: Feed<'_>, entry: &Entry, published: &[TopicId]) -> bool {
        match feed {
            Feed::Webhook(subscription) => subscription.owes(entry),
            Feed::Topic(subscriber) => {
                subscriber.confirmed && published.contains(&subscriber.topic)
            }
        }
    }

    fn owned_identity(&self, account: AccountId, id: IdentityId) -> Result<(), PolicyRefusal> {
        self.identities
            .get(&id)
            .filter(|identity| identity.account == account)
            .map(|_| ())
            .ok_or_else(|| missing("identity", id.0))
    }

    fn owned_pool(&self, account: AccountId, id: PoolId) -> Result<(), PolicyRefusal> {
        self.pools
            .get(&id)
            .filter(|pool| pool.account == account)
            .map(|_| ())
            .ok_or_else(|| missing("pool", id.0))
    }

    fn owned_configuration(
        &self,
        account: AccountId,
        id: ConfigurationId,
    ) -> Result<(), PolicyRefusal> {
        self.configurations
            .get(&id)
            .filter(|configuration| configuration.account == account)
            .map(|_| ())
            .ok_or_else(|| missing("configuration", id.0))
    }

    /// Which kind of record `id` is, if it is one.
    fn kind_of(&self, id: Id) -> Option<Kind> {
        if self.accounts.contains_key(&AccountId(id)) {
            Some(Kind::Account)
        } else if self.identities.contains_key(&IdentityId(id)) {
            Some(Kind::Identity)
        } else if self.tenants.contains_key(&TenantId(id)) {
            Some(Kind::Tenant)
        } else if self.configurations.contains_key(&ConfigurationId(id)) {
            Some(Kind::Configuration)
        } else if self.credentials.contains_key(&CredentialId(id)) {
            Some(Kind::Credential)
        } else if self.subscriptions.contains_key(&SubscriptionId(id)) {
            Some(Kind::Subscription)
        } else if self.pools.contains_key(&PoolId(id)) {
            Some(Kind::Pool)
        } else if self.egresses.contains_key(&EgressId(id)) {
            Some(Kind::Egress)
        } else if self.holds.contains_key(&HoldId(id)) {
            Some(Kind::Hold)
        } else if self.topics.contains_key(&TopicId(id)) {
            Some(Kind::Topic)
        } else if self.subscribers.contains_key(&SubscriptionId(id)) {
            Some(Kind::Subscriber)
        } else if self.destinations.contains_key(&DestinationId(id)) {
            Some(Kind::Destination)
        } else if self.templates.contains_key(&TemplateId(id)) {
            Some(Kind::Template)
        } else {
            None
        }
    }

    /// Inserts a resolved record, replacing the one with its ID.
    fn insert(&mut self, record: Record) {
        let id = record.id();
        if self.kind_of(id).is_some() {
            self.unindex(id);
        }
        match record {
            Record::Account(account) => {
                self.accounts.insert(account.id, account);
            }
            Record::Identity(identity) => {
                self.identity_names
                    .insert((identity.account, identity.name.clone()), identity.id);
                self.identities.insert(identity.id, identity);
            }
            Record::Tenant(tenant) => {
                self.tenant_names
                    .insert((tenant.account, tenant.name.clone()), tenant.id);
                self.tenants.insert(tenant.id, tenant);
            }
            Record::Configuration(configuration) => {
                self.configuration_names.insert(
                    (configuration.account, configuration.name.clone()),
                    configuration.id,
                );
                self.configurations.insert(configuration.id, configuration);
            }
            Record::Credential(credential) => {
                match &credential.secret {
                    Secret::Login { user, .. } => self.logins.insert(user.clone(), credential.id),
                    Secret::AccessKey { id, .. } => {
                        self.access_keys.insert(id.clone(), credential.id)
                    }
                };
                self.credentials.insert(credential.id, credential);
            }
            Record::Subscription(subscription) => {
                self.subscription_names.insert(
                    (subscription.account, subscription.name.clone()),
                    subscription.id,
                );
                self.subscriptions.insert(subscription.id, subscription);
            }
            Record::Pool(pool) => {
                self.pool_names
                    .insert((pool.account, pool.name.clone()), pool.id);
                self.pools.insert(pool.id, pool);
            }
            Record::Egress(egress) => {
                self.egress_addresses.insert(egress.address, egress.id);
                self.egresses.insert(egress.id, Arc::new(egress));
            }
            Record::Hold(hold) => {
                self.held.insert((hold.account, hold.paused), hold.id);
                self.holds.insert(hold.id, hold);
            }
            Record::Topic(topic) => {
                self.topic_names
                    .insert((topic.account, topic.name.clone()), topic.id);
                self.topics.insert(topic.id, topic);
            }
            Record::Template(template) => {
                self.template_names
                    .insert((template.account, template.name.clone()), template.id);
                self.templates.insert(template.id, Arc::new(template));
            }
            Record::Subscriber(subscriber) => {
                self.subscribers.insert(subscriber.id, subscriber);
            }
            Record::Destination(destination) => {
                self.destination_names.insert(
                    (destination.configuration, destination.name.clone()),
                    destination.id,
                );
                self.destinations.insert(destination.id, destination);
            }
        }
    }

    /// Removes the record with `id` from the maps and indexes.
    fn unindex(&mut self, id: Id) {
        if self.accounts.remove(&AccountId(id)).is_some() {
            return;
        }
        if let Some(identity) = self.identities.remove(&IdentityId(id)) {
            self.identity_names
                .remove(&(identity.account, identity.name));
        } else if let Some(tenant) = self.tenants.remove(&TenantId(id)) {
            self.tenant_names.remove(&(tenant.account, tenant.name));
        } else if let Some(configuration) = self.configurations.remove(&ConfigurationId(id)) {
            self.configuration_names
                .remove(&(configuration.account, configuration.name));
        } else if let Some(credential) = self.credentials.remove(&CredentialId(id)) {
            match credential.secret {
                Secret::Login { user, .. } => self.logins.remove(&user),
                Secret::AccessKey { id, .. } => self.access_keys.remove(&id),
            };
        } else if let Some(subscription) = self.subscriptions.remove(&SubscriptionId(id)) {
            self.subscription_names
                .remove(&(subscription.account, subscription.name));
        } else if let Some(pool) = self.pools.remove(&PoolId(id)) {
            self.pool_names.remove(&(pool.account, pool.name));
        } else if let Some(egress) = self.egresses.remove(&EgressId(id)) {
            self.egress_addresses.remove(&egress.address);
        } else if let Some(hold) = self.holds.remove(&HoldId(id)) {
            self.held.remove(&(hold.account, hold.paused));
        } else if let Some(topic) = self.topics.remove(&TopicId(id)) {
            self.topic_names.remove(&(topic.account, topic.name));
        } else if let Some(destination) = self.destinations.remove(&DestinationId(id)) {
            self.destination_names
                .remove(&(destination.configuration, destination.name));
        } else if let Some(template) = self.templates.remove(&TemplateId(id)) {
            self.template_names
                .remove(&(template.account, template.name.clone()));
        } else {
            self.subscribers.remove(&SubscriptionId(id));
        }
    }

    /// Removes the record with `id`, which exists, and every reference to
    /// it.
    fn remove(&mut self, id: Id) -> Changed {
        self.unindex(id);
        let mut removed = vec![id];
        // A configuration's subscriptions and destinations go with it, and
        // a topic's subscribers and the destinations that name it.
        let owed: Vec<Id> = self
            .subscriptions
            .values()
            .filter(|subscription| subscription.configuration == ConfigurationId(id))
            .map(|subscription| subscription.id.0)
            .chain(
                self.destinations
                    .values()
                    .filter(|destination| {
                        destination.configuration == ConfigurationId(id)
                            || destination.topic == TopicId(id)
                    })
                    .map(|destination| destination.id.0),
            )
            .chain(
                self.subscribers
                    .values()
                    .filter(|subscriber| subscriber.topic == TopicId(id))
                    .map(|subscriber| subscriber.id.0),
            )
            .collect();
        for subscription in owed {
            self.unindex(subscription);
            removed.push(subscription);
        }
        // A hold on what is removed is lifted with it.
        let lifted: Vec<Id> = self
            .holds
            .values()
            .filter(|hold| match hold.paused {
                Paused::Account => false,
                Paused::Tenant(tenant) => tenant.0 == id,
                Paused::Configuration(configuration) => configuration.0 == id,
                Paused::Identity(identity) => identity.0 == id,
                Paused::Egress(egress) => egress.0 == id,
            })
            .map(|hold| hold.id.0)
            .collect();
        for hold in lifted {
            self.unindex(hold);
            removed.push(hold);
        }
        let mut written = Vec::new();
        for tenant in self.tenants.values_mut() {
            let referred = tenant.identities.remove(&IdentityId(id))
                | tenant.configurations.remove(&ConfigurationId(id))
                | tenant.templates.remove(&TemplateId(id));
            if referred {
                written.push(Record::Tenant(tenant.clone()));
            }
        }
        for identity in self.identities.values_mut() {
            if identity.configuration == Some(ConfigurationId(id)) {
                identity.configuration = None;
                written.push(Record::Identity(identity.clone()));
            }
        }
        for credential in self.credentials.values_mut() {
            let referred = credential.identities.remove(&IdentityId(id))
                | credential.tenants.remove(&TenantId(id));
            if referred {
                written.push(Record::Credential(credential.clone()));
            }
        }
        // A pool's configurations and egresses are left in none.
        for configuration in self.configurations.values_mut() {
            if configuration.pool == Some(PoolId(id)) {
                configuration.pool = None;
                written.push(Record::Configuration(configuration.clone()));
            }
        }
        for egress in self.egresses.values_mut() {
            if egress.pool == Some(PoolId(id)) {
                let egress = Arc::make_mut(egress);
                egress.pool = None;
                written.push(Record::Egress(egress.clone()));
            }
        }
        Changed { written, removed }
    }
}

/// A change with its names resolved.
#[allow(
    clippy::large_enum_variant,
    reason = "one lives for the length of one policy change"
)]
enum Resolved {
    Put(Record),
    PutAll(Vec<Record>),
    Remove(Id),
}

/// How a release names the hold it finds none of.
fn held_name(target: &Target) -> String {
    match target {
        Target::Account(account) => format!("account {}", account.0.as_u64()),
        Target::Identity { name, .. } => format!("identity {name}"),
        Target::Configuration { name, .. } => format!("configuration {name}"),
        Target::Tenant { name, .. } => format!("tenant {name}"),
        Target::Egress(address) => format!("egress {address}"),
        Target::Login(name) | Target::AccessKey(name) => name.clone(),
        Target::Subscription { name, .. }
        | Target::Pool { name, .. }
        | Target::Destination { name, .. }
        | Target::Template { name, .. } => name.clone(),
        Target::Subscriber { id, .. } => format!("subscription {}", id.0.as_u64()),
    }
}

/// Whether two tokens are the same, in time that does not depend on where
/// they differ.
fn same(one: &[u8; 32], other: &[u8; 32]) -> bool {
    one.iter()
        .zip(other)
        .fold(0, |differs, (a, b)| differs | (a ^ b))
        == 0
}

/// A stored record's reference to one that does not exist, which only a
/// store changed outside the engine holds.
fn missing(kind: &'static str, id: Id) -> PolicyRefusal {
    PolicyRefusal::Unknown {
        kind,
        name: id.as_u64().to_string(),
    }
}

/// A subscription's URL: `https` or `http`, of at most 2,048 bytes and
/// with no spaces or control characters.
fn valid_url(url: &str) -> bool {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    host.is_some_and(|rest| !rest.is_empty())
        && url.len() <= 2048
        && url.bytes().all(|byte| byte.is_ascii_graphic())
}

/// A topic's name: 1 to 256 letters, digits, hyphens and underscores, as
/// SNS allows.
fn valid_topic(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// A tenant's, configuration's or subscription's name: 1 to 64 letters,
/// digits, hyphens and underscores, as SES allows.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u64) -> Id {
        Id::from_u64(value).unwrap()
    }

    const ACCOUNT: AccountId = AccountId(Id::from_u64(1).unwrap());
    const OTHER: AccountId = AccountId(Id::from_u64(2).unwrap());

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|&name| name.to_owned()).collect()
    }

    fn identity(value: u64, name: &str) -> Change {
        Change::Identity {
            id: IdentityId(id(value)),
            account: ACCOUNT,
            name: name.to_owned(),
            signing: None,
            configuration: None,
        }
    }

    fn configuration(value: u64, name: &str) -> Change {
        Change::Configuration {
            id: ConfigurationId(id(value)),
            account: ACCOUNT,
            name: name.to_owned(),
            pool: None,
        }
    }

    fn tenant(value: u64, name: &str, identities: &[&str], configurations: &[&str]) -> Change {
        Change::Tenant {
            id: TenantId(id(value)),
            account: ACCOUNT,
            name: name.to_owned(),
            identities: names(identities),
            configurations: names(configurations),
            limits: Limits::default(),
        }
    }

    fn login(
        value: u64,
        user: &str,
        identities: Option<&[&str]>,
        tenants: Option<&[&str]>,
    ) -> Change {
        Change::Credential {
            id: CredentialId(id(value)),
            account: ACCOUNT,
            secret: Secret::Login {
                user: user.to_owned(),
                password_sha256: [0; 32],
            },
            identities: identities.map(names),
            tenants: tenants.map(names),
            permissions: Permissions::SENDS,
        }
    }

    fn removal(target: Target) -> Change {
        Change::Remove(target)
    }

    fn subscription(value: u64, name: &str, configuration: &str, url: &str) -> Change {
        Change::Subscription {
            id: SubscriptionId(id(value)),
            account: ACCOUNT,
            name: name.to_owned(),
            configuration: configuration.to_owned(),
            url: url.to_owned(),
            events: BTreeSet::from([EventKind::Delivered, EventKind::Bounced]),
            secret: [7; 32],
        }
    }

    fn named(name: &str) -> String {
        name.to_owned()
    }

    fn with(changes: Vec<Change>) -> Policy {
        let mut policy = Policy::default();
        for change in changes {
            policy.apply(change).unwrap();
        }
        policy
    }

    fn from(text: &str) -> Address {
        Address::parse(text).unwrap()
    }

    #[test]
    fn a_run_of_changes_names_what_earlier_ones_made_each_a_revision() {
        let mut policy = with(vec![
            configuration(12, "receipts"),
            identity(10, "one.test"),
            tenant(30, "acme", &["one.test"], &["receipts"]),
        ]);
        assert_eq!(policy.revision(), PolicyRevision(3));
        let refused = policy.apply(tenant(31, "other", &["missing.test"], &[]));
        assert_eq!(
            refused,
            Err(PolicyRefusal::Unknown {
                kind: "identity",
                name: named("missing.test")
            })
        );
        assert_eq!(
            policy.revision(),
            PolicyRevision(3),
            "a refusal changes nothing"
        );
        let changed = policy
            .apply(removal(Target::Identity {
                account: ACCOUNT,
                name: named("ONE.test"),
            }))
            .unwrap();
        assert_eq!(changed.removed, vec![id(10)]);
        assert_eq!(changed.written.len(), 1, "the tenant, without it");
        assert_eq!(policy.revision(), PolicyRevision(4));
    }

    #[test]
    fn mail_is_sent_as_its_address_or_else_its_domain() {
        let policy = with(vec![
            identity(10, "Example.TEST"),
            identity(11, "ceo@example.test"),
            login(20, "app", None, None),
        ]);
        let credential = policy.login("app").unwrap();
        let sent_as = |text: &str| {
            policy
                .origin(credential, &from(text), None, None, None)
                .map(|origin| origin.identity)
        };
        assert_eq!(sent_as("CEO@example.test"), Ok(IdentityId(id(11))));
        assert_eq!(sent_as("news@EXAMPLE.test"), Ok(IdentityId(id(10))));
        assert_eq!(sent_as("news@other.test"), Err(Denial::UnknownIdentity));
        // Sent as one address with its own From another, both are one
        // identity, or it is not sent.
        let with_own = |own: &str| {
            policy
                .origin(
                    credential,
                    &from("news@example.test"),
                    Some(&from(own)),
                    None,
                    None,
                )
                .map(|origin| origin.identity)
        };
        assert_eq!(with_own("sales@example.test"), Ok(IdentityId(id(10))));
        assert_eq!(with_own("ceo@example.test"), Err(Denial::DifferentFrom));
        assert_eq!(with_own("ceo@other.test"), Err(Denial::UnknownIdentity));
    }

    fn signing(selector: &str) -> Signing {
        Signing {
            selector: selector.to_owned(),
            key: format!("the key of {selector}"),
            headers: names(&["From"]),
        }
    }

    #[test]
    fn an_identity_made_through_ses_sends_once_its_key_is_found_and_while_it_still_is() {
        let at = |micros| Timestamp::from_micros(micros);
        let new = |value, name: &str| Change::NewIdentity {
            id: IdentityId(id(value)),
            account: ACCOUNT,
            name: named(name),
            signing: signing("one"),
            configuration: None,
            tags: Vec::new(),
            at: at(0),
        };
        let amend = |name: &str, amendment| Change::Amend {
            account: ACCOUNT,
            name: named(name),
            amendment,
        };
        // A check of the identity of `name` as `policy` holds it.
        let checked = |policy: &Policy, name: &str, selector: &str, status| {
            let found = policy
                .identity_named(ACCOUNT, name)
                .and_then(|id| policy.identity(id));
            let pending = Check {
                status: Verification::Pending,
                since: at(0),
            };
            amend(
                name,
                Amendment::Checked {
                    identity: found.map_or(IdentityId(id(1)), |found| found.id),
                    selector: named(selector),
                    key: format!("the key of {selector}"),
                    from: found
                        .and_then(|found| found.verification)
                        .unwrap_or(pending),
                    check: Check {
                        status,
                        since: at(1),
                    },
                },
            )
        };
        let mut policy = with(vec![
            identity(10, "vouched.test"),
            new(11, "checked.test"),
            login(20, "app", None, None),
        ]);
        // A name SES's API creates is new, unlike one the operator puts.
        for name in ["checked.test", "VOUCHED.test"] {
            assert_eq!(policy.apply(new(12, name)), Err(PolicyRefusal::Taken));
        }
        let sent = |policy: &Policy, name: &str| {
            let credential = policy.login("app").unwrap();
            policy
                .origin(credential, &from(&format!("news@{name}")), None, None, None)
                .map(|_| ())
        };
        assert_eq!(sent(&policy, "vouched.test"), Ok(()));
        assert_eq!(sent(&policy, "checked.test"), Err(Denial::Unverified));
        policy
            .apply(checked(
                &policy,
                "checked.test",
                "one",
                Verification::Success,
            ))
            .unwrap();
        assert_eq!(sent(&policy, "checked.test"), Ok(()));
        policy
            .apply(checked(
                &policy,
                "checked.test",
                "one",
                Verification::TemporaryFailure,
            ))
            .unwrap();
        assert_eq!(
            sent(&policy, "checked.test"),
            Ok(()),
            "it sends while it lapses"
        );
        // A new key is checked from the start, and a check of the old one,
        // or of an identity never checked, changes nothing.
        policy
            .apply(amend(
                "checked.test",
                Amendment::Signing {
                    signing: signing("two"),
                    at: at(2),
                },
            ))
            .unwrap();
        assert_eq!(sent(&policy, "checked.test"), Err(Denial::Unverified));
        for (name, selector) in [("checked.test", "one"), ("vouched.test", "one")] {
            assert_eq!(
                policy.apply(checked(&policy, name, selector, Verification::Success)),
                Err(PolicyRefusal::Outdated)
            );
        }
        policy
            .apply(checked(
                &policy,
                "checked.test",
                "two",
                Verification::Success,
            ))
            .unwrap();
        // Signing turned off leaves it verified, its key kept.
        policy
            .apply(amend("checked.test", Amendment::Signs(false)))
            .unwrap();
        let identity = &policy.identities[&IdentityId(id(11))];
        assert!(identity.signer().is_none() && identity.signing.is_some());
        assert_eq!(sent(&policy, "checked.test"), Ok(()));
        assert_eq!(
            policy.revision(),
            PolicyRevision(8),
            "a refusal changes nothing"
        );
        // A check of an identity removed and made again, by the same name
        // and key, changes nothing.
        policy.apply(new(14, "again.test")).unwrap();
        let stale = checked(&policy, "again.test", "one", Verification::Failed);
        let again = Target::Identity {
            account: ACCOUNT,
            name: named("again.test"),
        };
        policy.apply(removal(again)).unwrap();
        policy.apply(new(15, "again.test")).unwrap();
        assert_eq!(policy.apply(stale), Err(PolicyRefusal::Outdated));
        let fresh = checked(&policy, "again.test", "one", Verification::Success);
        policy.apply(fresh).unwrap();
        // Its key changed and changed back at the one instant, as a clock
        // held back gives: a check of the first key, still running, is the
        // replaced check's, and changes nothing.
        let rekey = |selector| {
            amend(
                "again.test",
                Amendment::Signing {
                    signing: signing(selector),
                    at: at(5),
                },
            )
        };
        policy.apply(rekey("one")).unwrap();
        let running = checked(&policy, "again.test", "one", Verification::Success);
        policy.apply(rekey("two")).unwrap();
        policy.apply(rekey("one")).unwrap();
        assert_eq!(policy.apply(running), Err(PolicyRefusal::Outdated));
    }

    #[test]
    fn a_mail_from_domain_is_under_its_identity_and_used_or_refused_by_its_check() {
        let at = Timestamp::from_micros;
        let amend = |amendment| Change::Amend {
            account: ACCOUNT,
            name: named("one.test"),
            amendment,
        };
        let mail_from = |domain: &str, behavior| {
            amend(Amendment::MailFrom {
                mail_from: Some((named(domain), behavior)),
                at: at(0),
            })
        };
        // A check of the MAIL FROM domain as `policy` holds it.
        let checked = |policy: &Policy, domain: &str, status| {
            let found = &policy.identities[&IdentityId(id(10))];
            amend(Amendment::MailFromChecked {
                identity: found.id,
                domain: named(domain),
                from: found.mail_from.as_ref().map_or(
                    Check {
                        status: Verification::Pending,
                        since: at(0),
                    },
                    |own| own.check,
                ),
                check: Check {
                    status,
                    since: at(1),
                },
            })
        };
        let mut policy = with(vec![identity(10, "one.test"), login(20, "app", None, None)]);
        let long = format!("{}.one.test", vec!["a".repeat(60); 4].join("."));
        for outside in [
            "one.test",
            "bounces.two.test",
            "xone.test",
            "bad_label.one.test",
            long.as_str(),
        ] {
            assert_eq!(
                policy.apply(mail_from(outside, OnMxFailure::UseDefault)),
                Err(PolicyRefusal::InvalidName),
                "{outside}"
            );
        }
        let sent = |policy: &Policy| {
            let credential = policy.login("app").unwrap();
            policy
                .origin(credential, &from("news@one.test"), None, None, None)
                .map(|_| ())
        };
        let returns = |policy: &Policy| {
            policy.identities[&IdentityId(id(10))]
                .return_domain()
                .map(|domain| domain.to_string())
        };
        // Until it is found, mail goes with the installation's return path,
        // or is refused if it says so.
        policy
            .apply(mail_from("Bounces.One.test", OnMxFailure::UseDefault))
            .unwrap();
        assert_eq!((sent(&policy), returns(&policy)), (Ok(()), None));
        policy
            .apply(mail_from("bounces.one.test", OnMxFailure::Reject))
            .unwrap();
        assert_eq!(sent(&policy), Err(Denial::MailFromUnverified));
        policy
            .apply(checked(&policy, "bounces.one.test", Verification::Success))
            .unwrap();
        assert_eq!(
            (sent(&policy), returns(&policy)),
            (Ok(()), Some(named("bounces.one.test")))
        );
        // A check of a domain since replaced changes nothing.
        policy
            .apply(mail_from("mail.one.test", OnMxFailure::Reject))
            .unwrap();
        assert_eq!(
            policy.apply(checked(&policy, "bounces.one.test", Verification::Success)),
            Err(PolicyRefusal::Outdated)
        );
        assert_eq!(sent(&policy), Err(Denial::MailFromUnverified));
        policy
            .apply(amend(Amendment::MailFrom {
                mail_from: None,
                at: at(2),
            }))
            .unwrap();
        assert_eq!((sent(&policy), returns(&policy)), (Ok(()), None));
    }

    #[test]
    fn tenants_and_configurations_made_through_ses_are_new_and_associate_once_each() {
        let tag = |key: &str, value: &str| Tag {
            key: named(key),
            value: named(value),
        };
        let tenant = |value, name: &str, tags: Vec<Tag>| Change::NewTenant {
            id: TenantId(id(value)),
            account: ACCOUNT,
            name: named(name),
            tags,
            at: Timestamp::from_micros(5),
        };
        let configuration = |value, name: &str| Change::NewConfiguration {
            id: ConfigurationId(id(value)),
            account: ACCOUNT,
            name: named(name),
            pool: None,
            reputation_metrics: true,
            tags: vec![tag("Application", "nitrosend")],
        };
        let associate = |resource| Change::Associate {
            account: ACCOUNT,
            tenant: named("cohort-a"),
            resource,
        };
        let dissociate = |resource| Change::Dissociate {
            account: ACCOUNT,
            tenant: named("cohort-a"),
            resource,
        };
        let mut policy = with(vec![
            identity(10, "one.test"),
            tenant(30, "cohort-a", vec![tag("DeliverabilityCohort", "a")]),
            configuration(12, "cohort-a-events"),
        ]);
        assert_eq!(
            policy.apply(tenant(31, "cohort-a", Vec::new())),
            Err(PolicyRefusal::Taken)
        );
        assert_eq!(
            policy.apply(configuration(13, "cohort-a-events")),
            Err(PolicyRefusal::Taken)
        );
        // A key twice, or more tags than SES takes, is refused.
        let twice = vec![tag("a", "1"), tag("a", "2")];
        let many = (0..=Tag::MOST).map(|n| tag(&n.to_string(), "")).collect();
        for tags in [twice, many] {
            assert_eq!(
                policy.apply(tenant(32, "cohort-b", tags)),
                Err(PolicyRefusal::InvalidName)
            );
        }
        let made = &policy.tenants[&TenantId(id(30))];
        assert_eq!(made.created, Some(Timestamp::from_micros(5)));
        assert!(made.identities.is_empty() && made.configurations.is_empty());
        for resource in [
            Resource::Identity(named("ONE.test")),
            Resource::Configuration(named("cohort-a-events")),
        ] {
            policy.apply(associate(resource.clone())).unwrap();
            assert_eq!(
                policy.apply(associate(resource.clone())),
                Err(PolicyRefusal::Taken)
            );
            policy.apply(dissociate(resource.clone())).unwrap();
            assert!(matches!(
                policy.apply(dissociate(resource)),
                Err(PolicyRefusal::Unknown {
                    kind: "association",
                    ..
                })
            ));
        }
        policy
            .apply(Change::ReputationMetrics {
                account: ACCOUNT,
                configuration: named("cohort-a-events"),
                enabled: false,
            })
            .unwrap();
        let kept = &policy.configurations[&ConfigurationId(id(12))];
        assert!(!kept.reputation_metrics);
        assert_eq!(kept.tags, [tag("Application", "nitrosend")]);
    }

    #[test]
    fn a_pool_made_through_ses_is_new_and_takes_the_accounts_egresses_and_configurations() {
        let new = |value, name: &str| Change::NewPool {
            id: PoolId(id(value)),
            account: ACCOUNT,
            name: named(name),
        };
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut policy = with(vec![
            configuration(12, "receipts"),
            egress(40, "192.0.2.1", None),
            new(50, "transactional"),
        ]);
        assert_eq!(
            policy.apply(new(51, "transactional")),
            Err(PolicyRefusal::Taken)
        );
        let into = |pool: Option<&str>| Change::EgressPool {
            account: ACCOUNT,
            address,
            pool: pool.map(named),
        };
        policy.apply(into(Some("transactional"))).unwrap();
        assert_eq!(
            policy.egresses[&EgressId(id(40))].pool,
            Some(PoolId(id(50)))
        );
        assert!(matches!(
            policy.apply(into(Some("missing"))),
            Err(PolicyRefusal::Unknown { kind: "pool", .. })
        ));
        // Another account's egress is not this one's to move.
        let theirs = Change::EgressPool {
            account: OTHER,
            address,
            pool: None,
        };
        assert!(matches!(
            policy.apply(theirs),
            Err(PolicyRefusal::Unknown { kind: "egress", .. })
        ));
        policy
            .apply(Change::ConfigurationPool {
                account: ACCOUNT,
                configuration: named("receipts"),
                pool: Some(named("transactional")),
            })
            .unwrap();
        assert_eq!(sources(&policy, Some(12)), Some(vec![40]));
        policy.apply(into(None)).unwrap();
        assert_eq!(
            sources(&policy, Some(12)),
            Some(vec![]),
            "a pool with none sends from none"
        );
    }

    #[test]
    fn a_template_is_kept_by_its_name_within_its_bounds() {
        let content = |subject: &str| TemplateContent {
            subject: named(subject),
            text: Some(named("Hello {{name}}")),
            html: None,
        };
        let create = |value, name: &str| Change::NewTemplate {
            id: TemplateId(id(value)),
            account: ACCOUNT,
            name: named(name),
            content: content("Welcome"),
            at: Timestamp::from_micros(7),
        };
        let mut policy = Policy::default();
        policy
            .apply(Change::Account(Account {
                id: ACCOUNT,
                limits: Limits::default(),
                daily_quota: None,
            }))
            .unwrap();
        policy.apply(create(70, "welcome")).unwrap();
        assert_eq!(
            policy.apply(create(71, "welcome")),
            Err(PolicyRefusal::Taken)
        );
        assert_eq!(
            policy.apply(create(72, "not a name")),
            Err(PolicyRefusal::InvalidName)
        );
        // Its parts replaced, it keeps its ID and when it was made.
        policy
            .apply(Change::TemplateContent {
                account: ACCOUNT,
                name: named("welcome"),
                content: content("Welcome, {{name}}"),
            })
            .unwrap();
        let kept = policy.template_named(ACCOUNT, "welcome").unwrap();
        assert_eq!(
            (kept.id, kept.created, kept.content.subject.as_str()),
            (
                TemplateId(id(70)),
                Timestamp::from_micros(7),
                "Welcome, {{name}}"
            )
        );
        assert!(matches!(
            policy.apply(Change::TemplateContent {
                account: ACCOUNT,
                name: named("other"),
                content: content("x"),
            }),
            Err(PolicyRefusal::Unknown {
                kind: "template",
                ..
            })
        ));
        // Parts past the most a template takes are refused.
        let large = Change::NewTemplate {
            id: TemplateId(id(73)),
            account: ACCOUNT,
            name: named("large"),
            content: TemplateContent {
                subject: "x".repeat(TemplateContent::MOST_BYTES + 1),
                text: None,
                html: None,
            },
            at: Timestamp::from_micros(8),
        };
        assert_eq!(policy.apply(large), Err(PolicyRefusal::Limit));
        // Listed in name order, a page at a time.
        policy.apply(create(74, "alpha")).unwrap();
        let names = |after, limit| -> Vec<String> {
            policy
                .templates_after(ACCOUNT, after)
                .take(limit)
                .map(|template| template.name.clone())
                .collect()
        };
        assert_eq!(names(None, 1), ["alpha"]);
        assert_eq!(names(Some("alpha"), 5), ["welcome"]);
        // Removed by its name.
        policy
            .apply(Change::Remove(Target::Template {
                account: ACCOUNT,
                name: named("welcome"),
            }))
            .unwrap();
        assert!(policy.template_named(ACCOUNT, "welcome").is_none());
    }

    #[test]
    fn a_topics_confirmed_subscriber_owes_what_its_enabled_destinations_publish() {
        let topic = |value, name: &str| Change::Topic {
            id: TopicId(id(value)),
            account: ACCOUNT,
            name: named(name),
        };
        let subscribe = |value, endpoint: &str, token| Change::Subscribe {
            id: SubscriptionId(id(value)),
            account: ACCOUNT,
            topic: named("feedback"),
            endpoint: named(endpoint),
            token,
        };
        let destination = |value, name: &str, enabled, replaces| Change::Destination {
            id: DestinationId(id(value)),
            account: ACCOUNT,
            configuration: named("receipts"),
            name: named(name),
            topic: named("feedback"),
            events: BTreeSet::from([EventKind::Bounced, EventKind::Complained]),
            enabled,
            replaces,
        };
        let mut policy = with(vec![
            configuration(12, "receipts"),
            topic(60, "feedback"),
            subscribe(70, "https://hooks.example.test/ses", [7; 32]),
            destination(80, "receipts-feedback", true, false),
        ]);
        // A topic put again is the one there, as CreateTopic answers.
        policy.apply(topic(61, "feedback")).unwrap();
        assert_eq!(
            policy.topic_named(ACCOUNT, "feedback").unwrap().id,
            TopicId(id(60))
        );
        assert_eq!(
            policy.apply(subscribe(71, "https://hooks.example.test/ses", [8; 32])),
            Err(PolicyRefusal::Taken)
        );
        assert_eq!(
            policy.apply(destination(81, "receipts-feedback", true, false)),
            Err(PolicyRefusal::Taken)
        );
        let bounced = Entry::Suppressed {
            delivery: DeliveryId(id(90)),
            account: ACCOUNT,
            configuration: Some(ConfigurationId(id(12))),
            at: Timestamp::from_micros(0),
        };
        let complained = Entry::Complained {
            delivery: DeliveryId(id(90)),
            account: ACCOUNT,
            configuration: Some(ConfigurationId(id(12))),
            report: crate::id::ReportId(id(91)),
            feedback_type: named("abuse"),
            authenticated: false,
            at: Timestamp::from_micros(0),
        };
        // As an entry written now would be owed.
        let owes = |policy: &Policy, entry: &Entry| {
            let published = policy.publishes(entry);
            Policy::owes(
                policy.feed(SubscriptionId(id(70))).unwrap(),
                entry,
                &published,
            )
        };
        assert!(!owes(&policy, &complained), "not yet confirmed");
        let confirm = |token| Change::Confirm {
            account: ACCOUNT,
            topic: named("feedback"),
            token,
        };
        assert!(matches!(
            policy.apply(confirm([9; 32])),
            Err(PolicyRefusal::Unknown { .. })
        ));
        policy.apply(confirm([7; 32])).unwrap();
        assert!(owes(&policy, &complained));
        // Named for its parked events by its subscription ARN or the ID
        // that ends it, in its own account alone.
        let hex = format!("{:016x}", id(70).as_u64());
        for name in [
            format!("arn:aws:sns:us-east-1:000000000001:feedback:{hex}"),
            hex.clone(),
        ] {
            assert_eq!(
                policy.feed_named(ACCOUNT, &name),
                Some(SubscriptionId(id(70)))
            );
        }
        assert_eq!(policy.feed_named(AccountId(id(999)), &hex), None);
        assert_eq!(
            policy.feed_named(
                ACCOUNT,
                &format!("arn:aws:sns:us-east-1:000000000001:other:{hex}")
            ),
            None,
            "another topic's"
        );
        assert!(
            !owes(&policy, &bounced),
            "a suppression is not among its kinds"
        );
        assert_eq!(policy.publishes(&complained), [TopicId(id(60))]);
        let written = policy.publishes(&complained);
        // Disabled, by its replacement, it publishes nothing more; what it
        // published as it was enabled stays owed.
        policy
            .apply(destination(82, "receipts-feedback", false, true))
            .unwrap();
        assert!(!owes(&policy, &complained));
        assert!(Policy::owes(
            policy.feed(SubscriptionId(id(70))).unwrap(),
            &complained,
            &written
        ));
        assert!(matches!(
            policy.apply(destination(83, "other", true, true)),
            Err(PolicyRefusal::Unknown {
                kind: "destination",
                ..
            })
        ));
        // Its configuration's removal takes its destinations with it.
        let changed = policy
            .apply(removal(Target::Configuration {
                account: ACCOUNT,
                name: named("receipts"),
            }))
            .unwrap();
        assert!(changed.removed.contains(&id(80)));
        assert_eq!(policy.destinations().count(), 0);
        policy
            .apply(removal(Target::Subscriber {
                account: ACCOUNT,
                id: SubscriptionId(id(70)),
            }))
            .unwrap();
        assert!(policy.feed(SubscriptionId(id(70))).is_none());
    }

    #[test]
    fn a_customer_status_holds_the_record_it_names_and_never_one_made_again() {
        let made = |value| Change::NewTenant {
            id: TenantId(id(value)),
            account: ACCOUNT,
            name: named("cohort-a"),
            tags: Vec::new(),
            at: Timestamp::from_micros(0),
        };
        let status = |value, tenant, disabled| Change::CustomerStatus {
            id: HoldId(id(value)),
            account: ACCOUNT,
            paused: Paused::Tenant(TenantId(id(tenant))),
            disabled,
            reason: named("disabled through SES"),
        };
        let mut policy = with(vec![made(30)]);
        policy.apply(status(40, 30, true)).unwrap();
        assert!(
            policy
                .held(ACCOUNT, Paused::Tenant(TenantId(id(30))))
                .is_some()
        );
        policy.apply(status(41, 30, false)).unwrap();
        assert!(policy.holds().next().is_none());
        // Enabled already: no hold to lift.
        assert!(matches!(
            policy.apply(status(42, 30, false)),
            Err(PolicyRefusal::Unknown { kind: "hold", .. })
        ));
        // Removed and made again, the old ID names nothing.
        let gone = Target::Tenant {
            account: ACCOUNT,
            name: named("cohort-a"),
        };
        policy.apply(removal(gone)).unwrap();
        policy.apply(made(31)).unwrap();
        assert!(matches!(
            policy.apply(status(43, 30, true)),
            Err(PolicyRefusal::Unknown { .. })
        ));
        assert!(policy.holds().next().is_none());
    }

    #[test]
    fn a_key_that_only_manages_sends_nothing_and_a_login_only_sends() {
        let key = |value, user: &str, permissions| Change::Credential {
            id: CredentialId(id(value)),
            account: ACCOUNT,
            secret: Secret::AccessKey {
                id: named(user),
                secret: named("secret"),
            },
            identities: None,
            tenants: None,
            permissions,
        };
        let manages = Permissions {
            sends: false,
            manages: true,
        };
        let mut policy = with(vec![identity(10, "one.test"), key(20, "MANAGER", manages)]);
        let credential = policy.access_key("MANAGER").unwrap();
        assert_eq!(
            policy.origin(credential, &from("a@one.test"), None, None, None),
            Err(Denial::NotSending)
        );
        let nothing = Permissions {
            sends: false,
            manages: false,
        };
        assert_eq!(
            policy.apply(key(21, "IDLE", nothing)),
            Err(PolicyRefusal::InvalidName)
        );
        let managing_login = Change::Credential {
            id: CredentialId(id(22)),
            account: ACCOUNT,
            secret: Secret::Login {
                user: named("app"),
                password_sha256: [0; 32],
            },
            identities: None,
            tenants: None,
            permissions: manages,
        };
        assert_eq!(
            policy.apply(managing_login),
            Err(PolicyRefusal::InvalidName)
        );
    }

    #[test]
    fn a_credential_sends_only_within_its_scopes() {
        let policy = with(vec![
            identity(10, "one.test"),
            identity(11, "two.test"),
            tenant(30, "acme", &["one.test"], &[]),
            login(20, "app", Some(&["one.test"]), None),
            login(21, "tenanted", None, Some(&["acme"])),
        ]);
        let credential = policy.login("app").unwrap();
        assert!(
            policy
                .origin(credential, &from("a@one.test"), None, None, None)
                .is_ok()
        );
        assert_eq!(
            policy.origin(credential, &from("a@two.test"), None, None, None),
            Err(Denial::IdentityNotPermitted)
        );
        let credential = policy.login("tenanted").unwrap();
        let sent = |tenant| policy.origin(credential, &from("a@one.test"), None, tenant, None);
        assert_eq!(sent(None), Err(Denial::TenantNotPermitted));
        assert!(sent(Some("acme")).is_ok());
        assert_eq!(sent(Some("nobody")), Err(Denial::UnknownTenant));
    }

    #[test]
    fn a_tenant_sends_only_with_what_it_is_associated_with() {
        let policy = with(vec![
            identity(10, "one.test"),
            identity(11, "two.test"),
            configuration(12, "marketing"),
            configuration(13, "receipts"),
            tenant(30, "acme", &["one.test"], &["marketing"]),
            login(20, "app", None, None),
        ]);
        let credential = policy.login("app").unwrap();
        let sent = |address: &str, configuration| {
            policy.origin(
                credential,
                &from(address),
                None,
                Some("acme"),
                configuration,
            )
        };
        assert!(sent("a@one.test", Some("marketing")).is_ok());
        assert_eq!(
            sent("a@one.test", Some("receipts")),
            Err(Denial::NotAssociated)
        );
        assert_eq!(sent("a@two.test", None), Err(Denial::NotAssociated));
        assert_eq!(
            sent("a@one.test", Some("missing")),
            Err(Denial::UnknownConfiguration)
        );
    }

    #[test]
    fn an_identity_brings_its_default_configuration() {
        let policy = with(vec![
            configuration(12, "receipts"),
            Change::Identity {
                id: IdentityId(id(10)),
                account: ACCOUNT,
                name: named("one.test"),
                signing: None,
                configuration: Some(named("receipts")),
            },
            login(20, "app", None, None),
        ]);
        let credential = policy.login("app").unwrap();
        let origin = policy
            .origin(credential, &from("a@one.test"), None, None, None)
            .unwrap();
        assert_eq!(origin.configuration, Some(ConfigurationId(id(12))));
    }

    #[test]
    fn a_name_put_again_keeps_its_record_and_id() {
        let mut policy = with(vec![identity(10, "one.test")]);
        let changed = policy.apply(identity(99, "ONE.test")).unwrap();
        let Record::Identity(kept) = &changed.written[0] else {
            panic!("an identity");
        };
        assert_eq!(
            (kept.id, kept.name.as_str()),
            (IdentityId(id(10)), "one.test")
        );
        assert!(policy.identity(IdentityId(id(99))).is_none());
        policy
            .apply(Change::Identity {
                id: IdentityId(id(98)),
                account: OTHER,
                name: named("one.test"),
                signing: None,
                configuration: None,
            })
            .unwrap();
        assert!(
            policy.identity(IdentityId(id(98))).is_some(),
            "another account's own"
        );
    }

    #[test]
    fn a_login_or_key_is_issued_once_in_the_installation() {
        let mut policy = with(vec![login(20, "app", None, None)]);
        assert_eq!(
            policy.apply(login(21, "app", None, None)),
            Err(PolicyRefusal::Taken)
        );
        let theirs = Change::Credential {
            id: CredentialId(id(22)),
            account: OTHER,
            secret: Secret::Login {
                user: named("app"),
                password_sha256: [1; 32],
            },
            identities: None,
            tenants: None,
            permissions: Permissions::SENDS,
        };
        assert_eq!(policy.apply(theirs), Err(PolicyRefusal::Taken));
        policy.apply(removal(Target::Login(named("app")))).unwrap();
        assert!(
            policy.apply(login(23, "app", None, None)).is_ok(),
            "once the old one is gone"
        );
    }

    #[test]
    fn bad_names_unknown_names_and_reused_ids_are_refused() {
        let mut policy = Policy::default();
        for change in [
            identity(10, "not a domain"),
            identity(10, "@example.test"),
            configuration(12, ""),
            configuration(12, "has space"),
            login(20, "has space", None, None),
        ] {
            assert_eq!(policy.apply(change), Err(PolicyRefusal::InvalidName));
        }
        assert!(matches!(
            policy.apply(removal(Target::Tenant {
                account: ACCOUNT,
                name: named("acme"),
            })),
            Err(PolicyRefusal::Unknown { kind: "tenant", .. })
        ));
        let mut policy = with(vec![configuration(12, "marketing")]);
        assert_eq!(
            policy.apply(identity(12, "one.test")),
            Err(PolicyRefusal::Conflict),
            "an ID is one record's"
        );
        assert_eq!(
            policy.apply(configuration(12, "receipts")),
            Err(PolicyRefusal::Conflict),
            "a new name takes a new ID"
        );
        let theirs = Change::Configuration {
            id: ConfigurationId(id(12)),
            account: OTHER,
            name: named("marketing"),
            pool: None,
        };
        assert_eq!(
            policy.apply(theirs),
            Err(PolicyRefusal::Conflict),
            "even in another account"
        );
    }

    #[test]
    fn a_put_starts_warmup_and_never_changes_it() {
        let mut policy = with(Vec::new());
        let put = |cap| {
            let mut put = egress(60, "203.0.113.1", None);
            if let Change::Egress { daily_cap, .. } = &mut put {
                *daily_cap = cap;
            }
            put
        };
        let egress_id = EgressId(id(60));
        let caps = |policy: &Policy| policy.egress(egress_id).unwrap().caps.clone();
        policy.apply(put(None)).unwrap();
        assert!(!caps(&policy).any(), "made with none");
        policy.apply(put(Some(50))).unwrap();
        assert_eq!(caps(&policy).daily, Some(50), "one with none starts");
        policy.apply(put(None)).unwrap();
        assert_eq!(caps(&policy).daily, Some(50), "naming none keeps it");
        policy.apply(put(Some(100))).unwrap();
        assert_eq!(caps(&policy).daily, Some(50), "naming another keeps it");
        let cap = |cap| Change::Cap {
            account: ACCOUNT,
            address: "203.0.113.1".parse().unwrap(),
            site: None,
            cap,
        };
        policy.apply(cap(Some(200))).unwrap();
        assert_eq!(caps(&policy).daily, Some(200), "an operator's cap does");
        let from = caps(&policy);
        let judged = Caps {
            daily: None,
            warmed: Some(Warmed {
                day: 20_000,
                pool: Judgment {
                    counts: Counts::default(),
                    verdict: Verdict::Raised,
                },
                sites: BTreeMap::new(),
            }),
            ..from.clone()
        };
        policy
            .apply(Change::Caps(vec![Capping {
                egress: egress_id,
                from,
                to: judged,
                evidence: Vec::new(),
            }]))
            .unwrap();
        policy.apply(put(Some(50))).unwrap();
        assert!(!caps(&policy).any(), "done stays done");
    }

    #[test]
    fn an_egress_caps_each_site_by_its_own_cap_or_its_own_and_warmup_judges_a_day_once() {
        let mut policy = with(Vec::new());
        policy.apply(egress(60, "203.0.113.1", None)).unwrap();
        let egress_id = EgressId(id(60));
        let caps = |policy: &Policy| policy.egress(egress_id).unwrap().caps.clone();
        let warmed = |day| Warmed {
            day,
            pool: Judgment {
                counts: Counts::default(),
                verdict: Verdict::Untested,
            },
            sites: BTreeMap::new(),
        };
        let mut judged = caps(&policy);
        judged.sites.insert(Arc::from("Google"), Some(2_000));
        judged.sites.insert(Arc::from("Yahoo"), None);
        judged.warmed = Some(warmed(20_000));
        let first = Capping {
            egress: egress_id,
            from: caps(&policy),
            to: judged.clone(),
            evidence: Vec::new(),
        };
        policy.apply(Change::Caps(vec![first.clone()])).unwrap();
        let now = caps(&policy);
        assert_eq!(now.at("Google"), Some(2_000), "its own");
        assert_eq!(now.at("Yahoo"), None, "done there");
        assert_eq!(now.at("Apple"), Some(1_000), "the egress's own");
        assert!(now.any());

        // Decided from caps since changed, or a day judged already, it is
        // refused whole.
        assert_eq!(
            policy.apply(Change::Caps(vec![first])),
            Err(PolicyRefusal::Outdated)
        );
        let again = Capping {
            egress: egress_id,
            from: now.clone(),
            to: Caps {
                daily: Some(5_000),
                ..now.clone()
            },
            evidence: Vec::new(),
        };
        let mut twice = again.clone();
        twice.to.warmed = Some(Warmed {
            pool: Judgment {
                counts: Counts::default(),
                verdict: Verdict::Raised,
            },
            ..warmed(20_000)
        });
        assert_eq!(
            policy.apply(Change::Caps(vec![twice])),
            Err(PolicyRefusal::Outdated)
        );
        // An operator's caps keep the judgment as it was.
        policy.apply(Change::Caps(vec![again])).unwrap();
        assert_eq!(caps(&policy).daily, Some(5_000));

        // Put again under its address, it keeps its caps and the day judged,
        // whatever cap the put names, so a judgment decided before it holds.
        let kept = caps(&policy);
        for named in [None, Some(50)] {
            let mut put = egress(61, "203.0.113.1", None);
            if let Change::Egress { daily_cap, .. } = &mut put {
                *daily_cap = named;
            }
            policy.apply(put).unwrap();
            assert_eq!(caps(&policy), kept);
        }
        let mut done = kept.clone();
        done.daily = None;
        done.sites.clear();
        policy
            .apply(Change::Caps(vec![Capping {
                egress: egress_id,
                from: kept,
                to: done,
                evidence: Vec::new(),
            }]))
            .unwrap();
        assert!(!caps(&policy).any(), "warmed up");
        let ladder = [50, 100, 200, 500];
        let climbed = |daily, sites: &[Option<u64>]| {
            Caps {
                daily,
                sites: sites
                    .iter()
                    .enumerate()
                    .map(|(index, cap)| (Arc::from(index.to_string()), *cap))
                    .collect(),
                ..Caps::default()
            }
            .climbed(&ladder)
        };
        assert_eq!(climbed(Some(50), &[]), Some(0), "the first rung");
        assert_eq!(climbed(Some(200), &[Some(50)]), Some(50), "its own cap's");
        assert_eq!(climbed(Some(10_000), &[]), Some(99), "capped is never done");
        assert_eq!(
            climbed(None, &[Some(500), Some(100)]),
            Some(25),
            "the least site's"
        );
        assert_eq!(climbed(None, &[None]), None, "done");
        // An operator's cap, by address: the egress's own, or a site's; and
        // a warmup judgment decided before it is refused.
        let before = caps(&policy);
        let cap = |site: Option<&str>, cap| Change::Cap {
            account: ACCOUNT,
            address: "203.0.113.1".parse().unwrap(),
            site: site.map(str::to_owned),
            cap,
        };
        policy.apply(cap(None, Some(200))).unwrap();
        policy.apply(cap(Some("Outlook"), Some(100))).unwrap();
        let set = caps(&policy);
        assert_eq!((set.daily, set.at("Outlook")), (Some(200), Some(100)));
        assert_eq!(
            set.warmed
                .as_ref()
                .map(|warmed| (warmed.day, warmed.pool.verdict)),
            Some((20_000, Verdict::Set)),
            "the day judged kept, the cap the operator's"
        );
        let late = Capping {
            egress: egress_id,
            from: before,
            to: Caps {
                warmed: Some(warmed(20_001)),
                ..Caps::default()
            },
            evidence: Vec::new(),
        };
        assert_eq!(
            policy.apply(Change::Caps(vec![late])),
            Err(PolicyRefusal::Outdated)
        );
        // Changed and changed back, the caps read as they did, and a
        // judgment decided from before is still refused.
        let read = caps(&policy);
        policy.apply(cap(None, Some(300))).unwrap();
        policy.apply(cap(None, Some(200))).unwrap();
        let back = caps(&policy);
        assert_eq!(
            (back.daily, back.sites.clone()),
            (read.daily, read.sites.clone())
        );
        let stale = Capping {
            egress: egress_id,
            to: Caps {
                warmed: Some(warmed(20_001)),
                ..read.clone()
            },
            from: read,
            evidence: Vec::new(),
        };
        assert_eq!(
            policy.apply(Change::Caps(vec![stale])),
            Err(PolicyRefusal::Outdated)
        );
        // Unlimited everywhere, it is done, and keeps no entry of none.
        policy.apply(cap(None, None)).unwrap();
        policy.apply(cap(Some("Outlook"), None)).unwrap();
        assert!(!caps(&policy).any());
        assert!(caps(&policy).sites.is_empty());
        let theirs = Change::Cap {
            account: OTHER,
            address: "203.0.113.1".parse().unwrap(),
            site: None,
            cap: Some(1),
        };
        assert!(matches!(
            policy.apply(theirs),
            Err(PolicyRefusal::Unknown { .. })
        ));
        assert_eq!(
            policy.apply(cap(Some(""), Some(1))),
            Err(PolicyRefusal::InvalidName)
        );
        let unknown = Capping {
            egress: EgressId(id(99)),
            from: Caps::default(),
            to: Caps::default(),
            evidence: Vec::new(),
        };
        assert!(matches!(
            policy.apply(Change::Caps(vec![unknown])),
            Err(PolicyRefusal::Unknown { .. })
        ));
    }

    fn pool(value: u64, name: &str) -> Change {
        Change::Pool {
            id: PoolId(id(value)),
            account: ACCOUNT,
            name: name.to_owned(),
        }
    }

    fn egress(value: u64, address: &str, pool: Option<&str>) -> Change {
        Change::Egress {
            id: EgressId(id(value)),
            account: ACCOUNT,
            address: address.parse().unwrap(),
            helo: format!("mta{value}.example.test"),
            pool: pool.map(str::to_owned),
            daily_cap: Some(1_000),
        }
    }

    fn pooled(value: u64, name: &str, pool: &str) -> Change {
        Change::Configuration {
            id: ConfigurationId(id(value)),
            account: ACCOUNT,
            name: name.to_owned(),
            pool: Some(pool.to_owned()),
        }
    }

    fn sources(policy: &Policy, configuration: Option<u64>) -> Option<Vec<u64>> {
        match policy.sources(
            ACCOUNT,
            configuration.map(|value| ConfigurationId(id(value))),
        ) {
            Sources::Host => None,
            Sources::Egresses(egresses) => {
                Some(egresses.iter().map(|egress| egress.id.0.as_u64()).collect())
            }
        }
    }

    #[test]
    fn mail_goes_out_from_its_pool_or_the_unpooled_egresses_or_the_host() {
        let mut policy = with(vec![configuration(12, "receipts")]);
        assert_eq!(sources(&policy, None), None, "no egress: the host's own");
        assert_eq!(sources(&policy, Some(12)), None);
        policy.apply(pool(50, "transactional")).unwrap();
        policy.apply(pooled(13, "alerts", "transactional")).unwrap();
        assert_eq!(
            sources(&policy, Some(13)),
            Some(vec![]),
            "an empty pool waits"
        );
        policy
            .apply(egress(60, "203.0.113.1", Some("transactional")))
            .unwrap();
        policy.apply(egress(61, "203.0.113.2", None)).unwrap();
        assert_eq!(sources(&policy, Some(13)), Some(vec![60]));
        assert_eq!(
            sources(&policy, Some(12)),
            Some(vec![61]),
            "no pool: the unpooled"
        );
        assert_eq!(sources(&policy, None), Some(vec![61]));

        // Put again under its address, it keeps its ID; another account's
        // may not take it.
        policy
            .apply(egress(62, "203.0.113.2", Some("transactional")))
            .unwrap();
        assert_eq!(sources(&policy, Some(13)), Some(vec![60, 61]));
        let theirs = Change::Egress {
            id: EgressId(id(63)),
            account: OTHER,
            address: "203.0.113.1".parse().unwrap(),
            helo: "mta.other.test".to_owned(),
            pool: None,
            daily_cap: None,
        };
        assert_eq!(policy.apply(theirs), Err(PolicyRefusal::Taken));
        let mut nameless = egress(64, "203.0.113.4", None);
        if let Change::Egress { helo, .. } = &mut nameless {
            *helo = "not a name".to_owned();
        }
        assert_eq!(policy.apply(nameless), Err(PolicyRefusal::InvalidName));

        // Removing the pool leaves its configuration and egresses in none.
        let changed = policy
            .apply(removal(Target::Pool {
                account: ACCOUNT,
                name: named("transactional"),
            }))
            .unwrap();
        assert_eq!(
            changed.written.len(),
            3,
            "the configuration and two egresses"
        );
        assert_eq!(sources(&policy, Some(13)), Some(vec![60, 61]));
        let gone = policy.apply(removal(Target::Egress("203.0.113.1".parse().unwrap())));
        assert!(gone.is_ok());
        assert_eq!(sources(&policy, None), Some(vec![61]));
    }

    #[test]
    fn a_subscription_owes_its_configurations_events_of_its_kinds() {
        let mut policy = with(vec![
            configuration(12, "receipts"),
            configuration(13, "marketing"),
            subscription(40, "hooks", "receipts", "https://hooks.example.test/in"),
        ]);
        let subscribed = policy.subscription(SubscriptionId(id(40))).unwrap().clone();
        let at = crate::time::Timestamp::from_micros(1);
        let expired = |configuration| Entry::Expired {
            delivery: crate::id::DeliveryId(id(90)),
            account: ACCOUNT,
            configuration,
            at,
        };
        let suppressed = Entry::Suppressed {
            delivery: crate::id::DeliveryId(id(91)),
            account: ACCOUNT,
            configuration: Some(ConfigurationId(id(12))),
            at,
        };
        assert!(
            !subscribed.owes(&expired(Some(ConfigurationId(id(12))))),
            "not its kind"
        );
        assert!(!subscribed.owes(&suppressed));
        let mut wider = subscribed.clone();
        wider.events.insert(EventKind::Expired);
        assert!(wider.owes(&expired(Some(ConfigurationId(id(12))))));
        assert!(
            !wider.owes(&expired(Some(ConfigurationId(id(13))))),
            "another configuration's"
        );
        assert!(!wider.owes(&expired(None)));

        assert_eq!(
            policy.apply(subscription(
                41,
                "hooks",
                "marketing",
                "https://other.test/"
            )),
            Err(PolicyRefusal::Taken),
            "never replaced"
        );
        for url in ["ftp://hooks.test/", "https://", "https://a b.test/"] {
            assert_eq!(
                policy.apply(subscription(42, "more", "marketing", url)),
                Err(PolicyRefusal::InvalidName),
                "{url}"
            );
        }
        let changed = policy
            .apply(removal(Target::Configuration {
                account: ACCOUNT,
                name: named("receipts"),
            }))
            .unwrap();
        assert_eq!(
            changed.removed,
            vec![id(12), id(40)],
            "its subscription with it"
        );
        assert!(policy.subscription(SubscriptionId(id(40))).is_none());
        assert!(
            policy
                .apply(subscription(43, "hooks", "marketing", "http://10.0.0.5/in"))
                .is_ok(),
            "its name is free again"
        );
    }

    #[test]
    fn removing_a_record_removes_every_reference_and_what_it_allowed() {
        let policy = with(vec![
            identity(10, "one.test"),
            identity(11, "two.test"),
            configuration(12, "marketing"),
            tenant(30, "acme", &["one.test", "two.test"], &["marketing"]),
            login(20, "app", Some(&["one.test", "two.test"]), None),
        ]);
        let origin = Origin {
            identity: IdentityId(id(10)),
            tenant: Some(TenantId(id(30))),
            configuration: Some(ConfigurationId(id(12))),
        };
        assert_eq!(policy.allows(ACCOUNT, &origin), Ok(()));
        assert_eq!(policy.allows(OTHER, &origin), Err(Denial::UnknownIdentity));
        let mut after = policy.clone();
        let changed = after
            .apply(removal(Target::Identity {
                account: ACCOUNT,
                name: named("one.test"),
            }))
            .unwrap();
        assert_eq!(changed.written.len(), 2, "the tenant and the credential");
        assert_eq!(after.allows(ACCOUNT, &origin), Err(Denial::UnknownIdentity));
        let mut after = policy.clone();
        after
            .apply(removal(Target::Configuration {
                account: ACCOUNT,
                name: named("marketing"),
            }))
            .unwrap();
        assert_eq!(
            after.allows(ACCOUNT, &origin),
            Err(Denial::UnknownConfiguration)
        );
        let credential = CredentialId(id(20));
        let two = Origin {
            identity: IdentityId(id(11)),
            tenant: None,
            configuration: None,
        };
        assert_eq!(policy.admits(credential, ACCOUNT, &two), Ok(()));
        let mut after = policy.clone();
        after.apply(removal(Target::Login(named("app")))).unwrap();
        assert_eq!(
            after.admits(credential, ACCOUNT, &two),
            Err(Denial::UnknownCredential)
        );
    }

    #[test]
    fn an_account_record_is_its_account_and_raises_no_high_water_mark() {
        let limited = Account {
            id: ACCOUNT,
            limits: Limits {
                recipients_per_second: Some(14),
                bytes_per_second: None,
            },
            daily_quota: Some(50_000),
        };
        let change = Change::Account(limited.clone());
        assert_eq!(change.created(), None);
        let mut policy = with(vec![change]);
        assert_eq!(policy.account(ACCOUNT), Some(&limited));
        assert_eq!(policy.account(OTHER), None, "unlimited");
        let changed = policy.apply(removal(Target::Account(ACCOUNT))).unwrap();
        assert_eq!(changed.removed, vec![ACCOUNT.0]);
        assert_eq!(policy.account(ACCOUNT), None);
    }

    fn hold(value: u64, target: Target, accepting: bool) -> Change {
        Change::Hold {
            id: HoldId(id(value)),
            target,
            accepting,
            reason: named("investigating complaints"),
        }
    }

    #[test]
    fn a_hold_pauses_what_it_names_and_refuses_new_mail_only_if_it_says_so() {
        let mut policy = with(vec![
            identity(10, "one.test"),
            configuration(12, "receipts"),
            tenant(30, "acme", &["one.test"], &["receipts"]),
            login(20, "app", None, None),
            egress(40, "192.0.2.1", None),
        ]);
        let origin = |tenant| Origin {
            identity: IdentityId(id(10)),
            tenant,
            configuration: Some(ConfigurationId(id(12))),
        };
        let acme = Some(TenantId(id(30)));
        assert!(policy.hold(ACCOUNT, &origin(acme), None).is_none());
        let tenant_target = || Target::Tenant {
            account: ACCOUNT,
            name: named("acme"),
        };
        policy.apply(hold(50, tenant_target(), true)).unwrap();
        let held = policy.hold(ACCOUNT, &origin(acme), None).unwrap();
        assert_eq!(held.paused, Paused::Tenant(TenantId(id(30))));
        assert!(policy.hold(ACCOUNT, &origin(None), None).is_none());
        assert!(policy.hold(OTHER, &origin(acme), None).is_none());
        let credential = policy.login("app").unwrap().clone();
        let sent = |policy: &Policy| {
            policy.origin(
                &credential,
                &from("a@one.test"),
                None,
                Some("acme"),
                Some("receipts"),
            )
        };
        assert!(sent(&policy).is_ok(), "an accepting hold takes new mail");
        // Held again, it keeps its ID and refuses new mail, at preparation
        // and at a stale acceptance's commit.
        policy.apply(hold(51, tenant_target(), false)).unwrap();
        assert_eq!(policy.holds().count(), 1);
        assert_eq!(policy.holds().next().unwrap().id, HoldId(id(50)));
        assert_eq!(sent(&policy), Err(Denial::Paused));
        assert_eq!(
            policy.admits(CredentialId(id(20)), ACCOUNT, &origin(acme)),
            Err(Denial::Paused)
        );
        // Mail it covers may still be sent once it is released: a hold is
        // not a removal.
        assert!(policy.allows(ACCOUNT, &origin(acme)).is_ok());
        policy.apply(Change::Release(tenant_target())).unwrap();
        assert!(sent(&policy).is_ok());
        assert_eq!(
            policy.apply(Change::Release(tenant_target())),
            Err(PolicyRefusal::Unknown {
                kind: "hold",
                name: named("tenant acme")
            })
        );

        // An egress's hold covers what goes out from it; an account's, all
        // of its mail.
        let address = "192.0.2.1".parse().unwrap();
        policy
            .apply(hold(52, Target::Egress(address), true))
            .unwrap();
        assert!(policy.hold(ACCOUNT, &origin(None), None).is_none());
        assert!(
            policy
                .hold(ACCOUNT, &origin(None), Some(EgressId(id(40))))
                .is_some()
        );
        policy
            .apply(hold(53, Target::Account(ACCOUNT), true))
            .unwrap();
        assert!(policy.hold(ACCOUNT, &origin(None), None).is_some());
        // Removing what a hold names lifts the hold.
        let changed = policy.apply(removal(Target::Egress(address))).unwrap();
        assert!(changed.removed.contains(&id(52)));
        assert_eq!(policy.holds().count(), 1);
        assert_eq!(
            policy.apply(hold(54, Target::Login(named("app")), true)),
            Err(PolicyRefusal::InvalidName)
        );
        let unreasoned = Change::Hold {
            id: HoldId(id(55)),
            target: Target::Account(ACCOUNT),
            accepting: true,
            reason: named("  "),
        };
        assert_eq!(policy.apply(unreasoned), Err(PolicyRefusal::InvalidName));
    }

    #[test]
    fn any_hold_that_refuses_new_mail_refuses_it_whatever_others_accept() {
        let mut policy = with(vec![
            identity(10, "one.test"),
            pool(13, "outbound"),
            pooled(12, "receipts", "outbound"),
            tenant(30, "acme", &["one.test"], &["receipts"]),
            login(20, "app", None, None),
            egress(40, "192.0.2.1", Some("outbound")),
            egress(41, "192.0.2.2", Some("outbound")),
        ]);
        let credential = policy.login("app").unwrap().clone();
        let sent = |policy: &Policy| {
            policy.origin(
                &credential,
                &from("a@one.test"),
                None,
                Some("acme"),
                Some("receipts"),
            )
        };
        policy
            .apply(hold(50, Target::Account(ACCOUNT), true))
            .unwrap();
        let acme = Target::Tenant {
            account: ACCOUNT,
            name: named("acme"),
        };
        policy.apply(hold(51, acme.clone(), false)).unwrap();
        assert_eq!(sent(&policy), Err(Denial::Paused), "the tenant's refuses");
        policy.apply(Change::Release(acme)).unwrap();
        assert!(sent(&policy).is_ok());
        // An egress's refusing hold refuses mail only it could go out from.
        let first = Target::Egress("192.0.2.1".parse().unwrap());
        policy.apply(hold(52, first, false)).unwrap();
        assert!(sent(&policy).is_ok(), "the other egress is free");
        let second = Target::Egress("192.0.2.2".parse().unwrap());
        policy.apply(hold(53, second, false)).unwrap();
        assert_eq!(sent(&policy), Err(Denial::Paused));
    }

    #[test]
    fn stored_policy_reads_back_exactly_or_not_at_all() {
        let stored = |value, name: &str| {
            Record::Identity(Identity {
                id: IdentityId(id(value)),
                account: ACCOUNT,
                name: name.to_owned(),
                signing: None,
                signs: true,
                configuration: None,
                tags: Vec::new(),
                verification: None,
                mail_from: None,
            })
        };
        let records = vec![
            Record::Credential(Credential {
                id: CredentialId(id(20)),
                account: ACCOUNT,
                secret: Secret::Login {
                    user: named("app"),
                    password_sha256: [0; 32],
                },
                identities: Scope::Only(BTreeSet::from([IdentityId(id(10))])),
                tenants: Scope::Any,
                permissions: Permissions::SENDS,
            }),
            Record::Tenant(Tenant {
                id: TenantId(id(30)),
                account: ACCOUNT,
                name: named("acme"),
                identities: BTreeSet::from([IdentityId(id(10))]),
                templates: BTreeSet::new(),
                configurations: BTreeSet::from([ConfigurationId(id(12))]),
                limits: Limits::default(),
                tags: Vec::new(),
                created: None,
            }),
            stored(10, "one.test"),
            Record::Configuration(Configuration {
                id: ConfigurationId(id(12)),
                account: ACCOUNT,
                name: named("marketing"),
                pool: None,
                tags: Vec::new(),
                reputation_metrics: false,
            }),
        ];
        let read = Policy::from_records(PolicyRevision(4), records.clone()).unwrap();
        assert_eq!(read.revision(), PolicyRevision(4));
        assert!(read.login("app").is_some());
        let dangling = records[..2].to_vec();
        assert_eq!(
            Policy::from_records(PolicyRevision(4), dangling).err(),
            Some(ImpossiblePolicy)
        );
        let mut unheld = records.clone();
        if let Record::Tenant(tenant) = &mut unheld[1] {
            tenant.templates.insert(TemplateId(id(40)));
        }
        assert_eq!(
            Policy::from_records(PolicyRevision(4), unheld).err(),
            Some(ImpossiblePolicy),
            "a tenant's template the policy does not hold"
        );
        let renamed = vec![stored(10, "one.test"), stored(11, "ONE.test")];
        assert_eq!(
            Policy::from_records(PolicyRevision(2), renamed).err(),
            Some(ImpossiblePolicy),
            "two records of one name"
        );
    }
}
