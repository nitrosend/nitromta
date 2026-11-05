//! The native API: native commands as JSON, one object to a line, each
//! answered by one line in the order they came. The admin socket serves it
//! and the CLI writes it.
//!
//! Every answer is `{"ok": ...}` or `{"error": {"code", "message"}}`, so a
//! client can tell success from failure without knowing the operation.
//!
//! Policy is named as operators name it: identities by their domain or
//! address, tenants and configurations by name, credentials by their login
//! or access key ID. The commit owner resolves the names as it applies each
//! request, so requests may be sent without waiting for the one before, and
//! a later one may name what an earlier one creates. A record put under a
//! name it already has is replaced and keeps its ID, so mail already
//! accepted under it is unaffected.
//!
//! Secrets are the engine's own. A login's password, an access key's ID and
//! secret, and a subscription's signing secret are issued as the record is
//! created, from randomness the shell draws, and shown once, in the answer.
//! A credential or subscription is replaced by creating another
//! and removing it.

use std::convert::Infallible;

use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use engine_core::address::{Address, AddressError};
use engine_core::command::{Answer, Command, Commit, Suppress, Unsuppress};
use engine_core::event::EventKind;
use engine_core::id::{
    AccountId, ConfigurationId, CredentialId, EgressId, HoldId, Id, IdentityId, PoolId,
    SubscriptionId, TenantId,
};
use engine_core::message::PolicyRevision;
use engine_core::policy::{
    Account, Change, Limits, Permissions, PolicyRefusal, Secret, Signing, Target,
};
use engine_core::suppression::Reason;
use engine_core::time::Timestamp;
use engine_message::dkim::Signer;
use serde::{Deserialize, Serialize};

/// The longest request line read, newline aside. A longer one is refused
/// and ends its session, since what follows cannot be trusted to start a
/// line.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// Addresses in one request at most, so a request is one bounded write
/// within its commit group. Larger lists are sent as several requests.
pub const MAX_ADDRESSES: usize = 10_000;

/// The header fields an identity signs when its request names none: those
/// receivers check, the one-click unsubscribe pair among them, as Gmail and
/// Yahoo require of bulk mail (RFC 8058). One a message lacks is left out.
pub(crate) const SIGNED_HEADERS: [&str; 7] = [
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
];

/// Random bytes for one secret, drawn by the shell from the operating
/// system.
pub type Entropy = [u8; 32];

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    /// Adds addresses to an account's suppression list, or replaces their
    /// reason.
    Suppress {
        account: u64,
        addresses: Vec<String>,
        reason: WireReason,
    },
    /// Removes addresses from an account's suppression list.
    Unsuppress {
        account: u64,
        addresses: Vec<String>,
    },
    /// An account's rates and daily quota, each unlimited when absent.
    PutAccount {
        account: u64,
        recipients_per_second: Option<u32>,
        bytes_per_second: Option<u64>,
        daily_quota: Option<u64>,
    },
    /// A domain or address the account sends as, with its DKIM key unless
    /// its application signs its own mail, and the configuration its mail
    /// takes when a request names none.
    PutIdentity {
        account: u64,
        name: String,
        selector: Option<String>,
        private_key: Option<String>,
        signed_headers: Option<Vec<String>>,
        configuration: Option<String>,
    },
    /// A configuration, and the pool its mail goes out from: the account's
    /// egresses in no pool when it names none.
    PutConfiguration {
        account: u64,
        name: String,
        pool: Option<String>,
    },
    /// A named set of egresses, as SES's dedicated IP pools are.
    PutPool {
        account: u64,
        name: String,
    },
    /// A source address the host sends from, the name it greets with, its
    /// pool, and the daily cap for each receiver site that starts its
    /// warmup, unlimited when absent. One already capped, or ever judged,
    /// keeps its caps, which `PutCap` changes.
    PutEgress {
        account: u64,
        address: String,
        helo: String,
        pool: Option<String>,
        daily_cap: Option<u64>,
    },
    /// One of an egress's warmup caps, in place of what it had:
    /// its own, or the site's `site` names, as `queue` and `explain` name
    /// sites; unlimited when absent. Warmup's next judgment starts from it.
    PutCap {
        account: u64,
        address: String,
        site: Option<String>,
        daily_cap: Option<u64>,
    },
    /// A tenant, the identities and configurations it may send with, and
    /// its rates, each unlimited when absent.
    PutTenant {
        account: u64,
        name: String,
        #[serde(default)]
        identities: Vec<String>,
        #[serde(default)]
        configurations: Vec<String>,
        recipients_per_second: Option<u32>,
        bytes_per_second: Option<u64>,
    },
    /// An SMTP login with a new password. It may send as the identities
    /// and for the tenants named, or as any of the account's when none are.
    CreateLogin {
        account: u64,
        user: String,
        identities: Option<Vec<String>>,
        tenants: Option<Vec<String>>,
    },
    /// A new SES access key, scoped as a login is, that sends unless its
    /// permissions say otherwise.
    CreateAccessKey {
        account: u64,
        identities: Option<Vec<String>>,
        tenants: Option<Vec<String>>,
        permissions: Option<Vec<Permission>>,
    },
    /// A new subscription to a configuration's events of the kinds named,
    /// posted to `url` in signed batches.
    CreateSubscription {
        account: u64,
        name: String,
        configuration: String,
        url: String,
        events: Vec<String>,
    },
    /// Removing an identity, tenant or configuration withdraws the authority
    /// of mail sent under it that has not yet been sent.
    RemoveAccount {
        account: u64,
    },
    RemoveIdentity {
        account: u64,
        name: String,
    },
    RemoveConfiguration {
        account: u64,
        name: String,
    },
    RemoveTenant {
        account: u64,
        name: String,
    },
    RemoveLogin {
        user: String,
    },
    RemoveAccessKey {
        access_key_id: String,
    },
    RemoveSubscription {
        account: u64,
        name: String,
    },
    /// Removing a pool leaves its configurations and egresses in none.
    RemovePool {
        account: u64,
        name: String,
    },
    RemoveEgress {
        address: String,
    },
    /// Pauses an account's mail, or one of its tenants', configurations',
    /// identities' or egresses', named as their removals name them:
    /// no attempt starts for it until it is released, and it still
    /// expires. New mail it covers is accepted to wait, or refused as SES
    /// refuses mail while sending is paused when `accepting` is false. A
    /// hold put again replaces the one there.
    Hold {
        account: u64,
        tenant: Option<String>,
        configuration: Option<String>,
        identity: Option<String>,
        egress: Option<String>,
        #[serde(default = "accepting")]
        accepting: bool,
        reason: String,
    },
    /// Lifts the hold on what it names.
    Release {
        account: u64,
        tenant: Option<String>,
        configuration: Option<String>,
        identity: Option<String>,
        egress: Option<String>,
    },
}

/// What a hold names: at most one of a tenant, configuration, identity or
/// egress, or with none, its whole account.
struct Held {
    tenant: Option<String>,
    configuration: Option<String>,
    identity: Option<String>,
    egress: Option<String>,
}

/// A hold accepts new mail unless it says otherwise.
fn accepting() -> bool {
    true
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Permission {
    Send,
    Manage,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireReason {
    Bounce,
    Complaint,
    Operator,
}

impl From<WireReason> for Reason {
    fn from(reason: WireReason) -> Self {
        match reason {
            WireReason::Bounce => Self::Bounce,
            WireReason::Complaint => Self::Complaint,
            WireReason::Operator => Self::Operator,
        }
    }
}

/// A request read: the command it asks for, and the secret it issues,
/// which its answer shows once the command commits.
#[derive(Debug)]
pub struct Parsed {
    pub command: Command,
    pub issued: Option<Issued>,
}

/// A secret the engine issued, as its answer shows it.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Issued {
    Login {
        user: String,
        password: String,
    },
    AccessKey {
        access_key_id: String,
        secret_access_key: String,
    },
    Subscription {
        signing_secret: String,
    },
}

/// Why a request was refused before it reached the store.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not JSON, or not a request this API knows.
    Malformed(String),
    /// Longer than [`MAX_REQUEST_BYTES`].
    TooLarge,
    TooManyAddresses,
    InvalidAccount,
    InvalidAddress {
        index: usize,
        problem: AddressError,
    },
    /// Its DKIM key does not sign, or its selector and key are not given
    /// together.
    InvalidKey(String),
    /// No randomness could be drawn for its secret.
    NoEntropy,
    /// It names a kind of event there is not.
    UnknownEvent(String),
    /// Its address is not an IP address.
    InvalidIp(String),
}

/// The command a request line asks for, made at `now`. A record it creates
/// takes an ID from `new_id`, and a secret it issues is made from
/// `entropy`.
pub fn command(
    line: &[u8],
    now: Timestamp,
    mut new_id: impl FnMut() -> Id,
    mut entropy: impl FnMut() -> Option<Entropy>,
) -> Result<Parsed, Refusal> {
    let request: Request =
        serde_json::from_slice(line).map_err(|error| Refusal::Malformed(error.to_string()))?;
    let policy = |change| Command::ChangePolicy(change);
    let mut issued = None;
    let command = match request {
        Request::Suppress {
            account,
            addresses,
            reason,
        } => Command::Suppress(Suppress {
            account: account_id(account)?,
            addresses: parse(&addresses)?,
            reason: reason.into(),
            now,
        }),
        Request::Unsuppress { account, addresses } => Command::Unsuppress(Unsuppress {
            account: account_id(account)?,
            addresses: parse(&addresses)?,
        }),
        Request::PutAccount {
            account,
            recipients_per_second,
            bytes_per_second,
            daily_quota,
        } => policy(Change::Account(Account {
            id: account_id(account)?,
            limits: Limits {
                recipients_per_second,
                bytes_per_second,
            },
            daily_quota,
        })),
        Request::PutIdentity {
            account,
            name,
            selector,
            private_key,
            signed_headers,
            configuration,
        } => policy(Change::Identity {
            id: IdentityId(new_id()),
            account: account_id(account)?,
            signing: signing(&name, selector, private_key, signed_headers)?,
            name,
            configuration,
        }),
        Request::PutConfiguration {
            account,
            name,
            pool,
        } => policy(Change::Configuration {
            id: ConfigurationId(new_id()),
            account: account_id(account)?,
            name,
            pool,
        }),
        Request::PutPool { account, name } => policy(Change::Pool {
            id: PoolId(new_id()),
            account: account_id(account)?,
            name,
        }),
        Request::PutEgress {
            account,
            address,
            helo,
            pool,
            daily_cap,
        } => policy(Change::Egress {
            id: EgressId(new_id()),
            account: account_id(account)?,
            address: ip(&address)?,
            helo,
            pool,
            daily_cap,
        }),
        Request::PutCap {
            account,
            address,
            site,
            daily_cap,
        } => policy(Change::Cap {
            account: account_id(account)?,
            address: ip(&address)?,
            site,
            cap: daily_cap,
        }),
        Request::PutTenant {
            account,
            name,
            identities,
            configurations,
            recipients_per_second,
            bytes_per_second,
        } => policy(Change::Tenant {
            id: TenantId(new_id()),
            account: account_id(account)?,
            name,
            identities,
            configurations,
            limits: Limits {
                recipients_per_second,
                bytes_per_second,
            },
        }),
        Request::CreateLogin {
            account,
            user,
            identities,
            tenants,
        } => {
            let password = hex(&entropy().ok_or(Refusal::NoEntropy)?);
            let mut password_sha256 = [0; 32];
            password_sha256.copy_from_slice(digest(&SHA256, password.as_bytes()).as_ref());
            let secret = Secret::Login {
                user: user.clone(),
                password_sha256,
            };
            issued = Some(Issued::Login { user, password });
            let sends = Permissions::SENDS;
            policy(credential(
                new_id(),
                account,
                secret,
                identities,
                tenants,
                sends,
            )?)
        }
        Request::CreateAccessKey {
            account,
            identities,
            tenants,
            permissions,
        } => {
            let key = entropy().ok_or(Refusal::NoEntropy)?;
            let secret = entropy().ok_or(Refusal::NoEntropy)?;
            // Shaped as AWS's are: 20 capitals and digits, and a secret
            // longer than its 40 characters.
            let access_key_id = format!("NMTA{}", hex(&key[..8]).to_ascii_uppercase());
            let secret_access_key = hex(&secret);
            let wire = Secret::AccessKey {
                id: access_key_id.clone(),
                secret: secret_access_key.clone(),
            };
            issued = Some(Issued::AccessKey {
                access_key_id,
                secret_access_key,
            });
            let permissions = permissions.map_or(Permissions::SENDS, |named| Permissions {
                sends: named.contains(&Permission::Send),
                manages: named.contains(&Permission::Manage),
            });
            policy(credential(
                new_id(),
                account,
                wire,
                identities,
                tenants,
                permissions,
            )?)
        }
        Request::CreateSubscription {
            account,
            name,
            configuration,
            url,
            events,
        } => {
            let events = events
                .iter()
                .map(|name| {
                    EventKind::named(name).ok_or_else(|| Refusal::UnknownEvent(name.clone()))
                })
                .collect::<Result<_, _>>()?;
            let secret = entropy().ok_or(Refusal::NoEntropy)?;
            // As Standard Webhooks gives one, which the batches are signed
            // as (engine-events' `sign`).
            issued = Some(Issued::Subscription {
                signing_secret: format!("whsec_{}", STANDARD.encode(secret)),
            });
            policy(Change::Subscription {
                id: SubscriptionId(new_id()),
                account: account_id(account)?,
                name,
                configuration,
                url,
                events,
                secret,
            })
        }
        Request::RemoveAccount { account } => {
            policy(Change::Remove(Target::Account(account_id(account)?)))
        }
        Request::RemoveIdentity { account, name } => policy(Change::Remove(Target::Identity {
            account: account_id(account)?,
            name,
        })),
        Request::RemoveConfiguration { account, name } => {
            policy(Change::Remove(Target::Configuration {
                account: account_id(account)?,
                name,
            }))
        }
        Request::RemoveTenant { account, name } => policy(Change::Remove(Target::Tenant {
            account: account_id(account)?,
            name,
        })),
        Request::RemoveLogin { user } => policy(Change::Remove(Target::Login(user))),
        Request::RemoveAccessKey { access_key_id } => {
            policy(Change::Remove(Target::AccessKey(access_key_id)))
        }
        Request::RemoveSubscription { account, name } => {
            policy(Change::Remove(Target::Subscription {
                account: account_id(account)?,
                name,
            }))
        }
        Request::RemovePool { account, name } => policy(Change::Remove(Target::Pool {
            account: account_id(account)?,
            name,
        })),
        Request::RemoveEgress { address } => policy(Change::Remove(Target::Egress(ip(&address)?))),
        Request::Hold {
            account,
            tenant,
            configuration,
            identity,
            egress,
            accepting,
            reason,
        } => policy(Change::Hold {
            id: HoldId(new_id()),
            target: held(
                account,
                Held {
                    tenant,
                    configuration,
                    identity,
                    egress,
                },
            )?,
            accepting,
            reason,
        }),
        Request::Release {
            account,
            tenant,
            configuration,
            identity,
            egress,
        } => policy(Change::Release(held(
            account,
            Held {
                tenant,
                configuration,
                identity,
                egress,
            },
        )?)),
    };
    Ok(Parsed { command, issued })
}

/// What a hold request names, in its account.
fn held(account: u64, on: Held) -> Result<Target, Refusal> {
    let account = account_id(account)?;
    let named = [&on.tenant, &on.configuration, &on.identity, &on.egress]
        .iter()
        .filter(|name| name.is_some())
        .count();
    if named > 1 {
        return Err(Refusal::Malformed(
            "a hold names one tenant, configuration, identity or egress, or none for its whole account"
                .to_owned(),
        ));
    }
    Ok(if let Some(name) = on.tenant {
        Target::Tenant { account, name }
    } else if let Some(name) = on.configuration {
        Target::Configuration { account, name }
    } else if let Some(name) = on.identity {
        Target::Identity { account, name }
    } else if let Some(address) = on.egress {
        Target::Egress(ip(&address)?)
    } else {
        Target::Account(account)
    })
}

fn ip(address: &str) -> Result<std::net::IpAddr, Refusal> {
    address
        .parse()
        .map_err(|_| Refusal::InvalidIp(address.to_owned()))
}

fn credential(
    id: Id,
    account: u64,
    secret: Secret,
    identities: Option<Vec<String>>,
    tenants: Option<Vec<String>>,
    permissions: Permissions,
) -> Result<Change, Refusal> {
    Ok(Change::Credential {
        id: CredentialId(id),
        account: account_id(account)?,
        secret,
        identities,
        tenants,
        permissions,
    })
}

/// An identity's signing, once its key is known to sign for it.
pub(crate) fn signing(
    name: &str,
    selector: Option<String>,
    key: Option<String>,
    headers: Option<Vec<String>>,
) -> Result<Option<Signing>, Refusal> {
    let (selector, key) = match (selector, key) {
        (Some(selector), Some(key)) => (selector, key),
        (None, None) if headers.is_none() => return Ok(None),
        _ => {
            return Err(Refusal::InvalidKey(
                "selector, private_key and signed_headers go together".to_owned(),
            ));
        }
    };
    let headers =
        headers.unwrap_or_else(|| SIGNED_HEADERS.iter().map(|&name| name.to_owned()).collect());
    let domain = name.rsplit_once('@').map_or(name, |(_, domain)| domain);
    let fields: Vec<&str> = headers.iter().map(String::as_str).collect();
    Signer::from_pem(&key, domain, &selector, &fields)
        .map_err(|error| Refusal::InvalidKey(format!("{error:?}")))?;
    Ok(Some(Signing {
        selector,
        key,
        headers,
    }))
}

/// An account's ID: above zero, which no record's ID is.
fn account_id(value: u64) -> Result<AccountId, Refusal> {
    Id::from_u64(value)
        .filter(|id| id.as_u64() > 0)
        .map(AccountId)
        .ok_or(Refusal::InvalidAccount)
}

/// Every address, or the first that is not one.
fn parse(addresses: &[String]) -> Result<Vec<Address>, Refusal> {
    if addresses.len() > MAX_ADDRESSES {
        return Err(Refusal::TooManyAddresses);
    }
    addresses
        .iter()
        .enumerate()
        .map(|(index, text)| {
            Address::parse(text).map_err(|problem| Refusal::InvalidAddress { index, problem })
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reply<T> {
    Ok(T),
    Error { code: &'static str, message: String },
}

#[derive(Serialize)]
struct Changed {
    changed: u64,
}

#[derive(Serialize)]
struct Revised<'a> {
    revision: u64,
    #[serde(flatten)]
    issued: Option<&'a Issued>,
}

/// The line answering a command, given the store's answer (`None` when the
/// store has stopped) and the secret the request issued, shown only if the
/// command committed.
pub fn reply(answer: Option<Answer>, issued: Option<&Issued>) -> Vec<u8> {
    match answer {
        Some(Answer::Suppressions(commit)) => changed(commit),
        Some(Answer::Policy(commit)) => revised(commit, issued),
        None => uncommitted(&Commit::<(), ()>::Unavailable),
        Some(other) => error(
            "internal",
            format!("the store answered with something else: {other:?}"),
        ),
    }
}

/// How many suppressions a change added, replaced or removed.
fn changed(commit: Commit<u64, Infallible>) -> Vec<u8> {
    match commit {
        Commit::Committed(changed) => line(&Reply::Ok(Changed { changed })),
        Commit::Refused(never) => match never {},
        other => uncommitted(&other),
    }
}

/// The policy revision a change made, and the secret it issued.
fn revised(commit: Commit<PolicyRevision, PolicyRefusal>, issued: Option<&Issued>) -> Vec<u8> {
    match commit {
        Commit::Committed(revision) => line(&Reply::Ok(Revised {
            revision: revision.0,
            issued,
        })),
        Commit::Refused(refusal) => {
            let (code, message) = match refusal {
                PolicyRefusal::InvalidName => (
                    "invalid_name",
                    "an identity is a domain or an address; a tenant or configuration is 1 to 64 letters, digits, hyphens and underscores; a login has no spaces; an access key sends, manages or both".to_owned(),
                ),
                PolicyRefusal::Unknown { kind, name } => {
                    ("unknown", format!("the account has no {kind} {name}"))
                }
                PolicyRefusal::Taken => (
                    "taken",
                    "that login or access key ID is in use".to_owned(),
                ),
                PolicyRefusal::Conflict => (
                    "conflict",
                    "its ID is another record's".to_owned(),
                ),
                PolicyRefusal::Outdated => (
                    "outdated",
                    "the identity's key has changed since it was checked".to_owned(),
                ),
                PolicyRefusal::Limit => (
                    "limit",
                    "past what the account may keep".to_owned(),
                ),
            };
            error(code, message)
        }
        other => uncommitted(&other),
    }
}

fn uncommitted<T, R>(commit: &Commit<T, R>) -> Vec<u8> {
    match commit {
        Commit::Unknown => error(
            "outcome_unknown",
            "the store failed as the change committed, so it may or may not be durable".to_owned(),
        ),
        _ => error(
            "unavailable",
            "the store has failed or stopped; send the change again once the engine restarts"
                .to_owned(),
        ),
    }
}

/// The line answering a refused request.
pub fn refused(refusal: &Refusal) -> Vec<u8> {
    match refusal {
        Refusal::Malformed(problem) => error("malformed", problem.clone()),
        Refusal::TooLarge => error(
            "too_large",
            format!("a request is {MAX_REQUEST_BYTES} bytes at most"),
        ),
        Refusal::TooManyAddresses => error(
            "too_many_addresses",
            format!("a request names {MAX_ADDRESSES} addresses at most"),
        ),
        Refusal::InvalidAccount => {
            error("invalid_account", "account is an ID above zero".to_owned())
        }
        Refusal::InvalidAddress { index, problem } => {
            error("invalid_address", format!("addresses[{index}]: {problem}"))
        }
        Refusal::InvalidKey(problem) => error("invalid_key", problem.clone()),
        Refusal::NoEntropy => error(
            "unavailable",
            "the engine could not draw randomness for the secret".to_owned(),
        ),
        Refusal::InvalidIp(address) => {
            error("invalid_ip", format!("{address} is not an IP address"))
        }
        Refusal::UnknownEvent(name) => error(
            "unknown_event",
            format!(
                "{name} is not an event; the events are {}",
                EventKind::ALL.map(EventKind::name).join(", ")
            ),
        ),
    }
}

pub(crate) fn error(code: &'static str, message: String) -> Vec<u8> {
    line(&Reply::<()>::Error { code, message })
}

pub(crate) fn line<T: Serialize>(reply: &Reply<T>) -> Vec<u8> {
    let mut line = serde_json::to_vec(reply).expect("a reply always serialises");
    line.push(b'\n');
    line
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use base64::engine::general_purpose::STANDARD;

    use std::collections::BTreeSet;

    use super::*;

    fn at() -> Timestamp {
        Timestamp::from_micros(1_000)
    }

    fn id(value: u64) -> Id {
        Id::from_u64(value).unwrap()
    }

    const ACCOUNT: AccountId = AccountId(Id::from_u64(7).unwrap());

    /// What a line asks for, with IDs from 101 up and each secret's bytes
    /// counting from 1.
    fn read(line: &[u8]) -> Result<Parsed, Refusal> {
        let (mut next, mut drawn) = (100, 0u8);
        command(
            line,
            at(),
            || {
                next += 1;
                id(next)
            },
            || {
                drawn += 1;
                Some([drawn; 32])
            },
        )
    }

    fn change(line: &[u8]) -> Change {
        match read(line) {
            Ok(Parsed {
                command: Command::ChangePolicy(change),
                ..
            }) => change,
            other => panic!("not a policy change: {other:?}"),
        }
    }

    fn pem() -> String {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = STANDARD.encode(pair.as_der().unwrap().as_ref());
        format!("-----BEGIN PRIVATE KEY-----\n{der}\n-----END PRIVATE KEY-----\n")
    }

    #[test]
    fn suppress_names_its_account_addresses_and_reason() {
        let line = br#"{"op":"suppress","account":7,"addresses":["a@example.test","B@Example.test"],"reason":"bounce"}"#;
        let Ok(Parsed {
            command: Command::Suppress(suppress),
            issued: None,
        }) = read(line)
        else {
            panic!("not a suppression");
        };
        assert_eq!(suppress.account, ACCOUNT);
        assert_eq!(suppress.addresses.len(), 2);
        assert_eq!(suppress.addresses[1].as_str(), "B@Example.test");
        assert_eq!(suppress.reason, Reason::Bounce);
        assert_eq!(suppress.now, at());
    }

    #[test]
    fn unknown_operations_and_fields_are_refused() {
        for line in [
            &br#"{"op":"delete_everything"}"#[..],
            br#"{"op":"suppress","account":7,"addresses":[],"reason":"bounce","tenant":1}"#,
            br#"{"op":"suppress","account":7,"addresses":[],"reason":"typo"}"#,
            br#"{"op":"unsuppress","account":7,"addresses":[],"reason":"bounce"}"#,
            br#"{"op":"create_login","account":7,"user":"app","password":"chosen"}"#,
            br#"{"account":7}"#,
            b"not json",
        ] {
            assert!(matches!(read(line), Err(Refusal::Malformed(_))));
        }
    }

    #[test]
    fn requests_are_bounded_and_name_a_real_account() {
        let line = br#"{"op":"suppress","account":7,"addresses":["a@example.test","nobody"],"reason":"operator"}"#;
        assert!(matches!(
            read(line),
            Err(Refusal::InvalidAddress { index: 1, .. })
        ));
        let addresses = vec!["a@example.test"; MAX_ADDRESSES + 1];
        let line = format!(
            r#"{{"op":"unsuppress","account":7,"addresses":{}}}"#,
            serde_json::to_string(&addresses).unwrap()
        );
        assert_eq!(read(line.as_bytes()).err(), Some(Refusal::TooManyAddresses));
        for line in [
            &br#"{"op":"unsuppress","account":18446744073709551615,"addresses":[]}"#[..],
            br#"{"op":"put_account","account":0,"daily_quota":5}"#,
        ] {
            assert_eq!(read(line).err(), Some(Refusal::InvalidAccount));
        }
    }

    #[test]
    fn a_hold_names_one_thing_in_its_account_or_the_whole_account() {
        let line = br#"{"op":"hold","account":7,"tenant":"acme","reason":"complaints"}"#;
        let Change::Hold {
            target, accepting, ..
        } = change(line)
        else {
            panic!("not a hold");
        };
        assert_eq!(
            target,
            Target::Tenant {
                account: ACCOUNT,
                name: "acme".to_owned()
            }
        );
        assert!(
            accepting,
            "a hold accepts new mail unless it says otherwise"
        );
        let line = br#"{"op":"hold","account":7,"accepting":false,"reason":"billing"}"#;
        assert!(matches!(
            change(line),
            Change::Hold {
                target: Target::Account(ACCOUNT),
                accepting: false,
                ..
            }
        ));
        let line = br#"{"op":"release","account":7,"egress":"192.0.2.1"}"#;
        assert_eq!(
            change(line),
            Change::Release(Target::Egress("192.0.2.1".parse().unwrap()))
        );
        for line in [
            &br#"{"op":"hold","account":7,"tenant":"acme","identity":"example.test","reason":"x"}"#
                [..],
            br#"{"op":"hold","account":7,"tenant":"acme"}"#,
            br#"{"op":"release","account":7,"reason":"x"}"#,
        ] {
            assert!(matches!(read(line), Err(Refusal::Malformed(_))), "{line:?}");
        }
    }

    #[test]
    fn names_travel_with_the_change_for_the_commit_owner_to_resolve() {
        let line = br#"{"op":"put_tenant","account":7,"name":"acme","identities":["example.test"],"configurations":["receipts"],"recipients_per_second":5}"#;
        assert_eq!(
            change(line),
            Change::Tenant {
                id: TenantId(id(101)),
                account: ACCOUNT,
                name: "acme".to_owned(),
                identities: vec!["example.test".to_owned()],
                configurations: vec!["receipts".to_owned()],
                limits: Limits {
                    recipients_per_second: Some(5),
                    bytes_per_second: None,
                },
            }
        );
        assert_eq!(
            change(br#"{"op":"remove_identity","account":7,"name":"example.test"}"#),
            Change::Remove(Target::Identity {
                account: ACCOUNT,
                name: "example.test".to_owned(),
            })
        );
    }

    #[test]
    fn an_identity_signs_only_with_a_key_that_signs() {
        let line = serde_json::json!({
            "op": "put_identity",
            "account": 7,
            "name": "Example.test",
            "selector": "s1",
            "private_key": pem(),
            "configuration": "receipts",
        });
        let Change::Identity {
            signing,
            configuration,
            ..
        } = change(line.to_string().as_bytes())
        else {
            panic!("not an identity");
        };
        assert_eq!(configuration.as_deref(), Some("receipts"));
        // By default a signature covers one-click unsubscribe's two fields
        // with the rest (RFC 8058).
        let headers = signing.unwrap().headers;
        assert_eq!(headers.len(), SIGNED_HEADERS.len());
        let named: Vec<&str> = headers.iter().map(String::as_str).collect();
        let signer =
            engine_message::dkim::Signer::from_pem(&pem(), "example.test", "s1", &named).unwrap();
        let signature = signer
            .sign(
                b"From: a@example.test\r\nList-Unsubscribe: <https://example.test/u>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
                b"hello\r\n",
            )
            .unwrap();
        let signature = String::from_utf8(signature).unwrap();
        assert!(
            signature.contains("h=from:list-unsubscribe:list-unsubscribe-post;"),
            "{signature}"
        );
        for line in [
            &br#"{"op":"put_identity","account":7,"name":"example.test","selector":"s1"}"#[..],
            br#"{"op":"put_identity","account":7,"name":"example.test","selector":"s1","private_key":"not a key"}"#,
        ] {
            assert!(matches!(read(line), Err(Refusal::InvalidKey(_))));
        }
    }

    #[test]
    fn a_login_password_is_issued_and_only_its_digest_kept() {
        let line =
            br#"{"op":"create_login","account":7,"user":"app","identities":["example.test"]}"#;
        let Parsed {
            command:
                Command::ChangePolicy(Change::Credential {
                    secret:
                        Secret::Login {
                            user,
                            password_sha256,
                        },
                    identities,
                    tenants,
                    ..
                }),
            issued: Some(Issued::Login { password, .. }),
        } = read(line).unwrap()
        else {
            panic!("not a login");
        };
        assert_eq!(user, "app");
        assert_eq!(password, hex(&[1; 32]), "64 hex digits of drawn randomness");
        assert_eq!(
            &password_sha256[..],
            digest(&SHA256, password.as_bytes()).as_ref()
        );
        assert_eq!(identities, Some(vec!["example.test".to_owned()]));
        assert_eq!(tenants, None);

        let key = read(br#"{"op":"create_access_key","account":7}"#).unwrap();
        let Some(Issued::AccessKey {
            access_key_id,
            secret_access_key,
        }) = key.issued
        else {
            panic!("no key issued");
        };
        assert_eq!(access_key_id, "NMTA0101010101010101");
        assert_eq!(secret_access_key, hex(&[2; 32]));
        let none = command(
            br#"{"op":"create_login","account":7,"user":"app"}"#,
            at(),
            || id(1),
            || None,
        );
        assert_eq!(none.err(), Some(Refusal::NoEntropy));
    }

    #[test]
    fn a_subscription_names_its_events_and_is_issued_its_signing_secret() {
        let line = br#"{"op":"create_subscription","account":7,"name":"hooks","configuration":"receipts","url":"https://hooks.example.test/in","events":["delivered","bounced"]}"#;
        let created = read(line).unwrap();
        let Command::ChangePolicy(Change::Subscription {
            name,
            configuration,
            events,
            secret,
            ..
        }) = created.command
        else {
            panic!("not a subscription: {:?}", created.command);
        };
        assert_eq!(
            (name.as_str(), configuration.as_str()),
            ("hooks", "receipts")
        );
        assert_eq!(
            events,
            BTreeSet::from([EventKind::Delivered, EventKind::Bounced])
        );
        assert_eq!(
            created.issued,
            Some(Issued::Subscription {
                signing_secret: format!("whsec_{}", STANDARD.encode(secret)),
            })
        );
        let unknown = br#"{"op":"create_subscription","account":7,"name":"hooks","configuration":"receipts","url":"https://hooks.example.test/in","events":["opened"]}"#;
        assert_eq!(
            read(unknown).err(),
            Some(Refusal::UnknownEvent("opened".to_owned()))
        );
        let removed = read(br#"{"op":"remove_subscription","account":7,"name":"hooks"}"#).unwrap();
        assert!(matches!(
            removed.command,
            Command::ChangePolicy(Change::Remove(Target::Subscription { .. }))
        ));
    }

    #[test]
    fn every_answer_is_one_line_saying_ok_or_error_and_secrets_show_once_committed() {
        assert_eq!(
            reply(Some(Answer::Suppressions(Commit::Committed(3))), None),
            b"{\"ok\":{\"changed\":3}}\n".to_vec()
        );
        let issued = Issued::Login {
            user: "app".to_owned(),
            password: "secret".to_owned(),
        };
        assert_eq!(
            reply(
                Some(Answer::Policy(Commit::Committed(PolicyRevision(2)))),
                Some(&issued)
            ),
            b"{\"ok\":{\"revision\":2,\"user\":\"app\",\"password\":\"secret\"}}\n".to_vec()
        );
        for reply in [
            reply(Some(Answer::Suppressions(Commit::Unknown)), None),
            reply(
                Some(Answer::Policy(Commit::Refused(PolicyRefusal::Taken))),
                Some(&issued),
            ),
            reply(None, Some(&issued)),
            refused(&Refusal::TooLarge),
            refused(&Refusal::Malformed("line 1 \"quoted\"\n".to_owned())),
        ] {
            assert!(reply.starts_with(b"{\"error\":{\"code\":\""));
            assert!(!String::from_utf8_lossy(&reply).contains("secret\""));
            assert_eq!(reply.iter().filter(|&&byte| byte == b'\n').count(), 1);
            assert_eq!(reply.last(), Some(&b'\n'));
        }
    }
}
