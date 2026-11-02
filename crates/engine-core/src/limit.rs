//! Admission rates: each account's and tenant's token buckets.
//! A bucket holds a second's burst and refills continuously. A request
//! larger than a second's worth is let through when the bucket is full, and
//! the bucket then owes it, so a large request waits its turn rather than
//! never fitting. A rate of zero admits nothing.

use std::collections::BTreeMap;

use crate::id::{AccountId, TenantId};
use crate::message::PolicyRevision;
use crate::policy::{Credential, Limits, Policy};
use crate::time::Monotonic;

/// Tokens are counted in millionths, so a rate refills smoothly however
/// small the step between readings.
const PARTS: i128 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    per_second: u64,
    /// In millionths of a token: at most a second's worth, and below zero
    /// while the bucket owes for a request larger than that.
    level: i128,
    at: Monotonic,
}

impl Bucket {
    /// A full bucket of `per_second` tokens.
    pub fn new(per_second: u64, now: Monotonic) -> Self {
        Self {
            per_second,
            level: i128::from(per_second) * PARTS,
            at: now,
        }
    }

    pub fn per_second(&self) -> u64 {
        self.per_second
    }

    /// Whether `amount` may be taken at `now`.
    pub fn allows(&mut self, amount: u64, now: Monotonic) -> bool {
        self.refill(now);
        let capacity = i128::from(self.per_second) * PARTS;
        self.per_second > 0 && self.level >= (i128::from(amount) * PARTS).min(capacity)
    }

    /// Takes `amount`, which [`Bucket::allows`] has just allowed.
    pub fn take(&mut self, amount: u64) {
        self.level -= i128::from(amount) * PARTS;
    }

    fn refill(&mut self, now: Monotonic) {
        let elapsed = now.saturating_duration_since(self.at).as_micros();
        let capacity = i128::from(self.per_second) * PARTS;
        let earned = i128::try_from(elapsed)
            .unwrap_or(i128::MAX / PARTS)
            .saturating_mul(i128::from(self.per_second));
        self.level = self.level.saturating_add(earned).min(capacity);
        self.at = self.at.max(now);
    }
}

/// What a rate is kept for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Rated {
    Account(AccountId),
    Tenant(TenantId),
}

/// A bucket, and the revision of the policy that set its rate.
type Held = Option<(Bucket, PolicyRevision)>;

/// Each account's and tenant's buckets: recipients, then bytes.
#[derive(Debug, Default)]
pub struct Rates {
    /// The newest revision of policy seen, whose removed accounts and
    /// tenants have no buckets.
    pruned: PolicyRevision,
    by: BTreeMap<Rated, [Held; 2]>,
}

impl Rates {
    /// Whether `recipients` and `bytes` more fit the rates `policy` sets for
    /// `credential`'s account, and for the tenant its request names, and
    /// takes them if so. A tenant the credential may not send for is charged
    /// nothing: its request is refused once it is decided. Each bucket keeps
    /// the revision of the policy that set its rate, and only newer policy
    /// changes or lifts it, so a request decided under older policy is held
    /// to the newer rate.
    pub fn admit(
        &mut self,
        policy: &Policy,
        credential: &Credential,
        tenant: Option<&str>,
        recipients: u64,
        bytes: u64,
        now: Monotonic,
    ) -> bool {
        let revision = policy.revision();
        let account = credential.account;
        let tenant = tenant
            .and_then(|name| policy.tenant_named(account, name))
            .filter(|id| credential.tenants.includes(id));
        // A newer policy may have removed what a bucket was kept for.
        if revision > self.pruned {
            self.by.retain(|rated, _| match rated {
                Rated::Account(account) => policy.account(*account).is_some(),
                Rated::Tenant(tenant) => policy.tenant(*tenant).is_some(),
            });
            self.pruned = revision;
        }
        // Every bucket must allow before any is taken from.
        let mut taking = Vec::new();
        for rated in [Some(Rated::Account(account)), tenant.map(Rated::Tenant)]
            .into_iter()
            .flatten()
        {
            let limits = match rated {
                Rated::Account(id) => policy.account(id).map(|held| held.limits),
                Rated::Tenant(id) => policy.tenant(id).map(|held| held.limits),
            }
            .unwrap_or_default();
            if limits == Limits::default() && !self.by.contains_key(&rated) {
                continue;
            }
            let buckets = self.by.entry(rated).or_default();
            let measures = [
                (limits.recipients_per_second.map(u64::from), recipients),
                (limits.bytes_per_second, bytes),
            ];
            for (slot, (rate, amount)) in measures.into_iter().enumerate() {
                let held = &mut buckets[slot];
                // A rate that newer policy changed starts again, full.
                if held.as_ref().is_none_or(|&(_, set)| revision > set) {
                    match (held.as_mut(), rate) {
                        (Some((bucket, set)), Some(rate)) if bucket.per_second() == rate => {
                            *set = revision;
                        }
                        (_, rate) => *held = rate.map(|rate| (Bucket::new(rate, now), revision)),
                    }
                }
                let Some((bucket, _)) = held else {
                    continue;
                };
                if !bucket.allows(amount, now) {
                    return false;
                }
                taking.push((rated, slot, amount));
            }
            if buckets.iter().all(Option::is_none) {
                self.by.remove(&rated);
            }
        }
        for (rated, slot, amount) in taking {
            if let Some((bucket, _)) = self
                .by
                .get_mut(&rated)
                .and_then(|buckets| buckets[slot].as_mut())
            {
                bucket.take(amount);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{CredentialId, Id};
    use crate::policy::{Account, Change, Permissions, Secret};

    const ACCOUNT: AccountId = AccountId(Id::from_u64(1).unwrap());

    fn at_millis(millis: u64) -> Monotonic {
        Monotonic::from_micros(millis * 1_000)
    }

    fn recipients_per_second(rate: u32) -> Limits {
        Limits {
            recipients_per_second: Some(rate),
            bytes_per_second: None,
        }
    }

    fn account(rate: u32) -> Change {
        Change::Account(Account {
            id: ACCOUNT,
            limits: recipients_per_second(rate),
            daily_quota: None,
        })
    }

    fn tenant(id: u64, name: &str, rate: u32) -> Change {
        Change::Tenant {
            id: TenantId(Id::from_u64(id).unwrap()),
            account: ACCOUNT,
            name: name.to_owned(),
            identities: Vec::new(),
            configurations: Vec::new(),
            limits: recipients_per_second(rate),
        }
    }

    /// A login that may send for `tenants` alone.
    fn login(id: u64, user: &str, tenants: &[&str]) -> Change {
        Change::Credential {
            id: CredentialId(Id::from_u64(id).unwrap()),
            account: ACCOUNT,
            secret: Secret::Login {
                user: user.to_owned(),
                password_sha256: [0; 32],
            },
            identities: None,
            tenants: Some(tenants.iter().map(|&name| name.to_owned()).collect()),
            permissions: Permissions::SENDS,
        }
    }

    fn applied(policy: &Policy, change: Change) -> Policy {
        let mut policy = policy.clone();
        policy.apply(change).unwrap();
        policy
    }

    fn take(bucket: &mut Bucket, amount: u64, now: Monotonic) -> bool {
        let allowed = bucket.allows(amount, now);
        if allowed {
            bucket.take(amount);
        }
        allowed
    }

    #[test]
    fn a_rate_admits_a_seconds_burst_then_refills_smoothly() {
        let mut bucket = Bucket::new(10, at_millis(0));
        assert!((0..10).all(|_| take(&mut bucket, 1, at_millis(0))));
        assert!(!take(&mut bucket, 1, at_millis(0)));
        assert!(!take(&mut bucket, 1, at_millis(99)));
        assert!(
            take(&mut bucket, 1, at_millis(100)),
            "a tenth of a second earns one"
        );
        assert!(take(&mut bucket, 5, at_millis(10_000)));
        assert!(
            (0..5).all(|_| take(&mut bucket, 1, at_millis(10_000))),
            "refilled to a second's worth, no more"
        );
        assert!(!take(&mut bucket, 1, at_millis(10_000)));
    }

    #[test]
    fn a_request_larger_than_a_second_waits_for_a_full_bucket_and_then_owes() {
        let mut bucket = Bucket::new(10, at_millis(0));
        assert!(take(&mut bucket, 50, at_millis(0)));
        assert!(!take(&mut bucket, 1, at_millis(3_999)));
        assert!(
            take(&mut bucket, 1, at_millis(4_100)),
            "the debt is paid after four seconds"
        );
        assert!(!take(&mut bucket, 50, at_millis(4_100)));
    }

    #[test]
    fn a_zero_rate_admits_nothing() {
        let mut bucket = Bucket::new(0, at_millis(0));
        assert!(!take(&mut bucket, 1, at_millis(0)));
        assert!(!take(&mut bucket, 1, at_millis(60_000)));
    }

    #[test]
    fn older_policy_never_starts_a_bucket_again() {
        let mut rates = Rates::default();
        let base = [tenant(30, "acme", 100), login(20, "app", &["acme"])]
            .into_iter()
            .fold(Policy::default(), |policy, change| applied(&policy, change));
        let older = applied(&base, account(100));
        let newer = applied(&older, account(1));
        let credential = newer.login("app").unwrap().clone();
        let now = at_millis(0);
        assert!(rates.admit(&older, &credential, None, 1, 0, now));
        assert!(rates.admit(&newer, &credential, None, 1, 0, now));
        assert!(
            !rates.admit(&older, &credential, None, 1, 0, now),
            "held to the newer rate"
        );
        assert!(
            !rates.admit(&newer, &credential, None, 1, 0, now),
            "and the bucket was not filled again"
        );
    }

    #[test]
    fn older_policy_without_a_rate_is_held_to_the_newer_one() {
        let mut rates = Rates::default();
        let older = applied(&Policy::default(), login(20, "app", &[]));
        let newer = applied(&older, account(1));
        let credential = newer.login("app").unwrap().clone();
        let now = at_millis(0);
        assert!(rates.admit(&newer, &credential, None, 1, 0, now));
        assert!(!rates.admit(&older, &credential, None, 1, 0, now));
    }

    #[test]
    fn a_newer_rate_applies_whatever_another_account_saw_since() {
        let mut rates = Rates::default();
        let first = [login(20, "app", &[]), account(100)]
            .into_iter()
            .fold(Policy::default(), |policy, change| applied(&policy, change));
        let second = applied(&first, account(1));
        let third = applied(
            &second,
            Change::Credential {
                id: CredentialId(Id::from_u64(21).unwrap()),
                account: AccountId(Id::from_u64(2).unwrap()),
                secret: Secret::Login {
                    user: "theirs".to_owned(),
                    password_sha256: [0; 32],
                },
                identities: None,
                tenants: None,
                permissions: Permissions::SENDS,
            },
        );
        let ours = second.login("app").unwrap().clone();
        let theirs = third.login("theirs").unwrap().clone();
        let now = at_millis(0);
        assert!(rates.admit(&first, &ours, None, 1, 0, now));
        assert!(rates.admit(&third, &theirs, None, 1, 0, now));
        assert!(rates.admit(&second, &ours, None, 1, 0, now));
        assert!(
            !rates.admit(&second, &ours, None, 1, 0, now),
            "held to the second policy's rate"
        );
    }

    #[test]
    fn a_tenant_is_charged_only_for_credentials_that_may_send_for_it() {
        let mut rates = Rates::default();
        let policy = [
            tenant(30, "acme", 1),
            tenant(31, "other", 1),
            login(20, "acme-only", &["acme"]),
            login(21, "other-only", &["other"]),
        ]
        .into_iter()
        .fold(Policy::default(), |policy, change| applied(&policy, change));
        let acme_only = policy.login("acme-only").unwrap();
        let other_only = policy.login("other-only").unwrap();
        let now = at_millis(0);
        for _ in 0..3 {
            assert!(rates.admit(&policy, acme_only, Some("other"), 1, 0, now));
        }
        assert!(rates.admit(&policy, other_only, Some("other"), 1, 0, now));
        assert!(
            !rates.admit(&policy, other_only, Some("other"), 1, 0, now),
            "its own rate, untouched until now"
        );
    }
}
