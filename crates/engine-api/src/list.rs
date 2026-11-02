//! The operator's `list` on the admin socket:
//! `{"op":"list","kind":"identities"}`, or with `"account"`, policy's
//! records of one kind, named as operators name them and never with their
//! secrets: a login by its user, an access key by its ID, a subscription by
//! its name and the scheme and host it posts to, and an identity with the
//! public half of its DKIM key, which its DNS record publishes.
//!
//! The kinds are `accounts`, `identities`, `tenants`, `configurations`,
//! `pools`, `egresses`, `logins`, `access_keys`, `subscriptions` and
//! `holds`.

use engine_core::id::{AccountId, Id};
use engine_core::policy::{
    Check, Credential, OnMxFailure, Policy, Scope, Secret, Target, Verification,
};
use engine_message::dkim::Signer;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::inspect::{judged, rfc3339};
use crate::native::{Reply, error, line};

/// A kind of record `list` shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Accounts,
    Identities,
    Tenants,
    Configurations,
    Pools,
    Egresses,
    Logins,
    AccessKeys,
    Subscriptions,
    Holds,
}

/// What a `list` request asks: one kind, in one account or all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asked {
    pub kind: Kind,
    pub account: Option<AccountId>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    List { kind: Kind, account: Option<u64> },
}

#[derive(Deserialize)]
struct Op<'a> {
    op: &'a str,
}

/// The listing `line` asks for, or `None` if it asks for something else.
/// One it cannot read is refused with its reply line.
pub fn asked(line: &[u8]) -> Option<Result<Asked, Vec<u8>>> {
    let op: Op = serde_json::from_slice(line).ok()?;
    if op.op != "list" {
        return None;
    }
    let request: Request = match serde_json::from_slice(line) {
        Ok(request) => request,
        Err(problem) => return Some(Err(error("malformed", problem.to_string()))),
    };
    let Request::List { kind, account } = request;
    let account = match account {
        Some(account) => match Id::from_u64(account) {
            Some(id) => Some(AccountId(id)),
            None => {
                return Some(Err(error(
                    "invalid_account",
                    format!("{account} is not an account"),
                )));
            }
        },
        None => None,
    };
    Some(Ok(Asked { kind, account }))
}

/// The line answering `list`: the records of `asked`'s kind in `policy`,
/// under the kind's name.
pub fn listed(policy: &Policy, asked: Asked) -> Vec<u8> {
    let Asked { kind, account } = asked;
    let ours = |of: AccountId| account.is_none_or(|account| account == of);
    let configuration = |id| policy.configuration(id).map(|found| found.name.clone());
    let pool = |id| policy.pool(id).map(|found| found.name.clone());
    let (name, rows): (&str, Vec<Value>) = match kind {
        Kind::Accounts => (
            "accounts",
            policy
                .accounts()
                .filter(|found| ours(found.id))
                .map(|found| {
                    json!({
                        "account": found.id.0.as_u64(),
                        "daily_quota": found.daily_quota,
                        "recipients_per_second": found.limits.recipients_per_second,
                        "bytes_per_second": found.limits.bytes_per_second,
                    })
                })
                .collect(),
        ),
        Kind::Identities => (
            "identities",
            policy
                .identities()
                .filter(|found| ours(found.account))
                .map(|found| {
                    let mut row = json!({
                        "account": found.account.0.as_u64(),
                        "name": found.name,
                        "configuration": found.configuration.and_then(configuration),
                    });
                    if let Some(signing) = &found.signing {
                        let public =
                            Signer::from_pem(&signing.key, found.domain(), &signing.selector, &[])
                                .map(|signer| signer.public_key())
                                .ok();
                        row["selector"] = json!(signing.selector);
                        row["dkim_public_key"] = json!(public);
                        row["signs"] = json!(found.signs);
                    }
                    // One the operator put is the operator's word, never
                    // checked.
                    row["verification"] = match found.verification {
                        None => json!("vouched"),
                        Some(check) => checked(check),
                    };
                    if let Some(own) = &found.mail_from {
                        let mut mail_from = checked(own.check);
                        mail_from["domain"] = json!(&*own.domain);
                        mail_from["on_mx_failure"] = json!(match own.behavior {
                            OnMxFailure::UseDefault => "use_default",
                            OnMxFailure::Reject => "reject",
                        });
                        row["mail_from"] = mail_from;
                    }
                    row
                })
                .collect(),
        ),
        Kind::Tenants => (
            "tenants",
            policy
                .tenants()
                .filter(|found| ours(found.account))
                .map(|found| {
                    let identities: Vec<_> = found
                        .identities
                        .iter()
                        .filter_map(|id| policy.identity(*id).map(|identity| identity.name.clone()))
                        .collect();
                    let configurations: Vec<_> = found
                        .configurations
                        .iter()
                        .filter_map(|id| configuration(*id))
                        .collect();
                    json!({
                        "account": found.account.0.as_u64(),
                        "name": found.name,
                        "identities": identities,
                        "configurations": configurations,
                    })
                })
                .collect(),
        ),
        Kind::Configurations => (
            "configurations",
            policy
                .configurations()
                .filter(|found| ours(found.account))
                .map(|found| {
                    json!({
                        "account": found.account.0.as_u64(),
                        "name": found.name,
                        "pool": found.pool.and_then(pool),
                    })
                })
                .collect(),
        ),
        Kind::Pools => (
            "pools",
            policy
                .pools()
                .filter(|found| ours(found.account))
                .map(|found| {
                    let egresses: Vec<_> = policy
                        .egresses()
                        .filter(|egress| egress.pool == Some(found.id))
                        .map(|egress| egress.address.to_string())
                        .collect();
                    json!({
                        "account": found.account.0.as_u64(),
                        "name": found.name,
                        "egresses": egresses,
                    })
                })
                .collect(),
        ),
        Kind::Egresses => (
            "egresses",
            policy
                .egresses()
                .filter(|found| ours(found.account))
                .map(|found| {
                    json!({
                        "account": found.account.0.as_u64(),
                        "address": found.address.to_string(),
                        "helo": found.helo,
                        "pool": found.pool.and_then(pool),
                        "daily_cap": found.caps.daily,
                        "site_caps": found
                            .caps
                            .sites
                            .iter()
                            .map(|(site, cap)| (site.to_string(), *cap))
                            .collect::<std::collections::BTreeMap<_, _>>(),
                        "warmup": found.caps.warmed.as_ref().map(|warmed| json!({
                            "pool": judged(warmed.day, &warmed.pool),
                            "sites": warmed
                                .sites
                                .iter()
                                .map(|(site, judgment)| (site.to_string(), judged(warmed.day, judgment)))
                                .collect::<std::collections::BTreeMap<_, _>>(),
                        })),
                    })
                })
                .collect(),
        ),
        Kind::Logins | Kind::AccessKeys => {
            let logins = kind == Kind::Logins;
            let rows = policy
                .credentials()
                .filter(|found| ours(found.account))
                .filter_map(|found| {
                    let mut row = credential(policy, found);
                    match (&found.secret, logins) {
                        (Secret::Login { user, .. }, true) => {
                            row.insert("user".to_owned(), json!(user))
                        }
                        (Secret::AccessKey { id, .. }, false) => {
                            row.insert("access_key_id".to_owned(), json!(id))
                        }
                        _ => return None,
                    };
                    Some(Value::Object(row))
                })
                .collect();
            (if logins { "logins" } else { "access_keys" }, rows)
        }
        Kind::Subscriptions => (
            "subscriptions",
            policy
                .subscriptions()
                .filter(|found| ours(found.account))
                .map(|found| {
                    let events: Vec<_> = found.events.iter().map(|kind| kind.name()).collect();
                    json!({
                        "account": found.account.0.as_u64(),
                        "name": found.name,
                        "configuration": configuration(found.configuration),
                        "endpoint": endpoint(&found.url),
                        "events": events,
                    })
                })
                .collect(),
        ),
        Kind::Holds => (
            "holds",
            policy
                .holds()
                .filter(|found| ours(found.account))
                .map(|found| {
                    let mut row = json!({
                        "account": found.account.0.as_u64(),
                        "reason": found.reason,
                        "accepting": found.accepting,
                    });
                    match policy.held_by_name(found) {
                        Some(Target::Tenant { name, .. }) => row["tenant"] = json!(name),
                        Some(Target::Configuration { name, .. }) => {
                            row["configuration"] = json!(name);
                        }
                        Some(Target::Identity { name, .. }) => row["identity"] = json!(name),
                        Some(Target::Egress(address)) => row["egress"] = json!(address.to_string()),
                        _ => {}
                    }
                    row
                })
                .collect(),
        ),
    };
    let mut listed = Map::new();
    listed.insert(name.to_owned(), Value::Array(rows));
    line(&Reply::Ok(listed))
}

/// Where a check stands, and since when.
fn checked(check: Check) -> Value {
    json!({
        "status": match check.status {
            Verification::Pending => "pending",
            Verification::Success => "success",
            Verification::TemporaryFailure => "temporary_failure",
            Verification::Failed => "failed",
        },
        "since": rfc3339(check.since),
    })
}

/// What a credential may send as and for: `any`, or the names.
fn credential(policy: &Policy, found: &Credential) -> Map<String, Value> {
    let identities = match &found.identities {
        Scope::Any => json!("any"),
        Scope::Only(ids) => json!(
            ids.iter()
                .filter_map(|id| policy.identity(*id).map(|identity| identity.name.clone()))
                .collect::<Vec<_>>()
        ),
    };
    let tenants = match &found.tenants {
        Scope::Any => json!("any"),
        Scope::Only(ids) => json!(
            ids.iter()
                .filter_map(|id| policy.tenant(*id).map(|tenant| tenant.name.clone()))
                .collect::<Vec<_>>()
        ),
    };
    let permissions: Vec<&str> = [
        (found.permissions.sends, "send"),
        (found.permissions.manages, "manage"),
    ]
    .into_iter()
    .filter_map(|(held, name)| held.then_some(name))
    .collect();
    let mut row = Map::new();
    row.insert("account".to_owned(), json!(found.account.0.as_u64()));
    row.insert("identities".to_owned(), identities);
    row.insert("tenants".to_owned(), tenants);
    row.insert("permissions".to_owned(), json!(permissions));
    row
}

/// The scheme and host a subscription posts to, without its path, query or
/// user information, which may hold the receiver's secret.
fn endpoint(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{scheme}://{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscriptions_endpoint_holds_no_path_query_or_user() {
        assert_eq!(
            endpoint("https://user:pass@hooks.example.test:8443/in/abc?token=secret"),
            "https://hooks.example.test:8443"
        );
        assert_eq!(
            endpoint("http://hooks.example.test"),
            "http://hooks.example.test"
        );
    }

    #[test]
    fn a_listing_is_asked_by_kind_and_refused_when_unread() {
        assert_eq!(
            asked(br#"{"op":"list","kind":"access_keys","account":1}"#),
            Some(Ok(Asked {
                kind: Kind::AccessKeys,
                account: Some(AccountId(Id::from_u64(1).unwrap())),
            }))
        );
        assert!(matches!(
            asked(br#"{"op":"list","kind":"secrets"}"#),
            Some(Err(_))
        ));
        assert!(asked(br#"{"op":"queue"}"#).is_none());
        let empty = String::from_utf8(listed(
            &Policy::default(),
            Asked {
                kind: Kind::Egresses,
                account: None,
            },
        ))
        .unwrap();
        assert_eq!(empty, "{\"ok\":{\"egresses\":[]}}\n");
    }
}
