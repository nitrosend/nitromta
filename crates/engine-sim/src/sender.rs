//! The sender simulations send as: one account's identity, and a login
//! that may send as it, created by the same policy changes an operator
//! makes, so the store's checks at acceptance and reservation run as they
//! do in production.

use std::sync::Arc;

use engine_core::command::Authority;
use engine_core::id::{
    AccountId, ConfigurationId, CredentialId, EgressId, IdGenerator, IdentityId, Lane, PoolId,
    Shard,
};
use engine_core::message::PolicyRevision;
use engine_core::policy::{Change, Origin, Permissions, Secret, Target};
use engine_core::time::Timestamp;
use engine_store::keys::Keyring;

/// The domain the sender's identity names.
pub const DOMAIN: &str = "sender.test";

/// The SMTP login its credential holds.
pub const LOGIN: &str = "simulation";

/// The configuration whose mail goes out from its pool's one egress.
pub const POOLED: &str = "pooled";

/// The installation's keys simulations run with: one, the same in every
/// run, so a store opened again after a restart opens its secrets.
pub fn keys() -> Arc<Keyring> {
    Arc::new(Keyring::new(&[(1, [0x5e; 32])]).expect("one key"))
}

/// When the sender's IDs were issued: a day into the IDs' epoch, before
/// any simulation starts.
const ISSUED: Timestamp = Timestamp::from_micros(1_767_312_000_000_000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sender {
    pub account: AccountId,
    pub identity: IdentityId,
    pub credential: CredentialId,
}

impl Sender {
    /// The same in every run, so a store reopened after a restart already
    /// holds it. Its IDs are issued as the engine issues any, so records
    /// naming them are their real size, and before any a simulation's
    /// generators issue.
    pub fn first() -> Self {
        let lane = Lane::new(0).expect("a valid lane");
        let mut ids = IdGenerator::new(Shard::new(0), lane, None);
        let first = Self {
            account: AccountId(ids.next(ISSUED)),
            identity: IdentityId(ids.next(ISSUED)),
            credential: CredentialId(ids.next(ISSUED)),
        };
        assert!(
            first.account.0.as_u64() > 1 << 32,
            "issued in the IDs' epoch"
        );
        first
    }

    /// The changes that create it: its identity, then a login that may send
    /// as any identity of its account.
    pub fn changes(&self) -> [Change; 2] {
        [
            self.identity_change(),
            Change::Credential {
                id: self.credential,
                account: self.account,
                secret: Secret::Login {
                    user: LOGIN.to_owned(),
                    password_sha256: [0; 32],
                },
                identities: None,
                tenants: None,
                permissions: Permissions::SENDS,
            },
        ]
    }

    /// Removes its identity, which withdraws the authority of all mail sent
    /// as it.
    pub fn removal(&self) -> Change {
        Change::Remove(self.target())
    }

    /// Its identity, as a removal or a hold names it.
    pub fn target(&self) -> Target {
        Target::Identity {
            account: self.account,
            name: DOMAIN.to_owned(),
        }
    }

    /// The same sender under a new identity of the same name, once the old
    /// one is removed, and the change that creates it.
    pub fn renewed(self, identity: IdentityId) -> (Self, Change) {
        let renewed = Self { identity, ..self };
        (renewed, renewed.identity_change())
    }

    /// The changes that send its mail under `configuration` from a pool
    /// whose one egress has `daily_cap`.
    pub fn pool_changes(
        &self,
        configuration: ConfigurationId,
        pool: PoolId,
        egress: EgressId,
        daily_cap: Option<u64>,
    ) -> [Change; 3] {
        [
            Change::Pool {
                id: pool,
                account: self.account,
                name: POOLED.to_owned(),
            },
            Change::Configuration {
                id: configuration,
                account: self.account,
                name: POOLED.to_owned(),
                pool: Some(POOLED.to_owned()),
            },
            Change::Egress {
                id: egress,
                account: self.account,
                address: "203.0.113.25".parse().expect("an address"),
                helo: "mta.sender.test".to_owned(),
                pool: Some(POOLED.to_owned()),
                daily_cap,
            },
        ]
    }

    /// What an acceptance from it carries, decided under `revision`.
    pub fn authority(&self, revision: PolicyRevision) -> Authority {
        Authority {
            account: self.account,
            credential: self.credential,
            origin: Origin {
                identity: self.identity,
                tenant: None,
                configuration: None,
            },
            revision,
            template: None,
        }
    }

    fn identity_change(&self) -> Change {
        Change::Identity {
            id: self.identity,
            account: self.account,
            name: DOMAIN.to_owned(),
            signing: None,
            configuration: None,
        }
    }
}
