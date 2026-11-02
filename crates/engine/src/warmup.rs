//! Warmup's daily judgment: once a UTC day is over, every capped
//! egress not yet judged on it is judged on its evidence that day, which
//! the store counted, and its new caps are set in one policy change, as an
//! operator's command sets them. The judgment is `engine-warmup`'s; this
//! task only reads, asks and records.
//!
//! The day judged is recorded on each egress, so a restart never judges a
//! day twice, and a day is judged only by a run that saw it end, so one
//! whose midnight passed while the engine was down is not judged late. It
//! is judged once its evidence is in: a settling time past midnight for
//! reports received before it, and once no attempt reserved before it is
//! still unrecorded. A change refused because an operator changed an
//! egress's caps meanwhile, or because evidence of the day was counted
//! since it was read, is judged again at the next look.

use std::sync::Arc;
use std::time::Duration;

use engine_api::inspect::day_text;
use engine_core::budget;
use engine_core::command::{Answer, Command, Commit};
use engine_core::policy::Change;
use engine_rules::Rules;

use crate::clock::SystemClock;
use crate::policy::Current;
use crate::store::Store;

/// How often it looks for a day to judge: a look with nothing to judge
/// reads the policy snapshot alone.
const TICK: Duration = Duration::from_secs(1);

/// How long past midnight a day's reports may still be on their way to the
/// store: a feedback report is recorded once its signatures are checked,
/// whose lookups take seconds at most.
const SETTLE: Duration = Duration::from_secs(300);

pub struct Warmup {
    pub policy: Arc<Current>,
    pub store: Store,
    pub rules: Arc<Rules>,
    pub clock: Arc<SystemClock>,
}

impl Warmup {
    pub async fn run(self) {
        // The day under way as it starts: the first whose end it sees.
        let watching = budget::day(self.clock.now().wall);
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            self.look(watching).await;
        }
    }

    /// Judges the day before today, if this run saw it end, from `watching`
    /// on, and any capped egress waits for it.
    async fn look(&self, watching: u64) {
        let now = self.clock.now().wall;
        let today = budget::day(now);
        let Some(day) = today.checked_sub(1).filter(|day| *day >= watching) else {
            return;
        };
        if now < budget::day_start(today).saturating_add(SETTLE) {
            return;
        }
        let snapshot = self.policy.load();
        let policy = snapshot.policy();
        let waiting = policy.egresses().any(|egress| {
            egress.caps.any()
                && egress
                    .caps
                    .warmed
                    .as_ref()
                    .is_none_or(|warmed| warmed.day < day)
        });
        if !waiting {
            return;
        }
        let Some(Answer::Evidence(Ok(evidence))) = self.store.ask(Command::Evidence { day }).await
        else {
            return;
        };
        // An attempt reserved before midnight, its reply perhaps of the day
        // judged, is waited for.
        if evidence.unrecorded > 0 {
            return;
        }
        let cappings = engine_warmup::judge(policy, &self.rules, day, &evidence.counts);
        if cappings.is_empty() {
            return;
        }
        let egresses = cappings.len();
        match self
            .store
            .ask(Command::ChangePolicy(Change::Caps(cappings)))
            .await
        {
            Some(Answer::Policy(Commit::Committed(revision))) => tracing::info!(
                day = %day_text(day),
                egresses,
                revision = revision.0,
                "warmup judged a day"
            ),
            Some(Answer::Policy(Commit::Refused(refusal))) => tracing::info!(
                day = %day_text(day),
                ?refusal,
                "warmup's judgment was refused; it judges again from current policy"
            ),
            _ => tracing::warn!(
                day = %day_text(day),
                "warmup's judgment could not be recorded; it tries again"
            ),
        }
    }
}
