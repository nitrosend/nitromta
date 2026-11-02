//! The policy snapshot every adapter reads: the store's latest
//! committed policy, replaced whole after each change. Reading it is one
//! clone of a pointer per request.

use std::sync::{Arc, RwLock};

use engine_api::snapshot::Snapshot;
use engine_core::policy::Policy;

pub struct Current {
    snapshot: RwLock<Arc<Snapshot>>,
}

impl Current {
    /// The snapshot of the policy the store opened with. A stored DKIM key
    /// that no longer signs stops the engine from starting.
    pub fn new(policy: Arc<Policy>) -> Result<Self, String> {
        Ok(Self {
            snapshot: RwLock::new(Arc::new(Snapshot::new(policy, None)?)),
        })
    }

    pub fn load(&self) -> Arc<Snapshot> {
        Arc::clone(
            &self
                .snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Replaces the snapshot with `policy`'s, once it has committed, if it
    /// is newer.
    pub fn publish(&self, policy: &Arc<Policy>) {
        let current = self.load();
        if policy.revision() <= current.policy().revision() {
            return;
        }
        match Snapshot::new(Arc::clone(policy), Some(&current)) {
            Ok(snapshot) => {
                *self
                    .snapshot
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(snapshot);
            }
            // Keys are checked before a change carries them, so this means
            // the store was changed outside the engine. Adapters keep the
            // last snapshot, and the commit owner rechecks what they decide.
            Err(problem) => tracing::error!(
                revision = policy.revision().0,
                %problem,
                "a policy revision cannot be used; the last one stands"
            ),
        }
    }
}
