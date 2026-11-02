//! The scheduler's driver: a task that hands the scheduler its inputs as
//! they arrive, polls it, wakes it when it asks, and carries its outputs to
//! the store, to the resolver, to the dispatch hook and to delivery.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use engine_core::component::Component;
use engine_core::component::Ticket;
use engine_core::hook::dispatch;
use engine_core::time::Timestamp;
use engine_scheduler::{Ended, Input, Inspection, Output, Report, Scheduler};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, watch};

use crate::capture::Transport;
use crate::clock::SystemClock;
use crate::hooks::Runner;
use crate::log::Hex;
use crate::operator::{Counted, Operations};
use crate::store::Store;

/// Inspections asked of the scheduler for the operator, waiting
/// for their reports.
#[derive(Default)]
pub struct Inspections {
    next: AtomicU64,
    waiting: Mutex<BTreeMap<u64, oneshot::Sender<Report>>>,
}

impl Inspections {
    /// Asks the scheduler `inspection`; its report arrives on what this
    /// returns, unless the scheduler has stopped.
    pub fn ask(
        &self,
        scheduler: &UnboundedSender<Input>,
        inspection: Inspection,
    ) -> oneshot::Receiver<Report> {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        let (reply, report) = oneshot::channel();
        self.waiting().insert(ticket, reply);
        let _ = scheduler.send(Input::Inspect {
            ticket: Ticket(ticket),
            inspection,
        });
        report
    }

    fn answer(&self, ticket: Ticket, report: Report) {
        if let Some(reply) = self.waiting().remove(&ticket.0) {
            let _ = reply.send(report);
        }
    }

    fn waiting(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, oneshot::Sender<Report>>> {
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What the scheduler's driver carries its outputs to and reports to.
pub struct Wiring {
    pub store: Store,
    pub transport: Transport,
    pub clock: Arc<SystemClock>,
    /// Set once, asked to drain, it has nothing left under way.
    pub drained: watch::Sender<bool>,
    pub operations: Arc<Operations>,
    pub inspections: Arc<Inspections>,
    /// The build's dispatch hook, if it has one, and the scheduler's own
    /// inbox, for its verdicts.
    pub dispatch: Option<Arc<Runner<dyn dispatch::Hook>>>,
    pub inbox: UnboundedSender<Input>,
}

/// Counts an outcome the scheduler recorded, and at `debug` logs it:
/// by how it ended, its site, egress and tenant, and, for one that
/// delivered or rejected its mail, the time since its delivery's
/// acceptance, which its ID records.
fn count(operations: &Operations, ended: &Ended, now: Timestamp) {
    let site = ended.site.as_ref();
    let counted = Counted {
        provider: site.and_then(engine_rules::Site::provider),
        egress: ended.egress,
        tenant: ended.tenant,
    };
    let since = now.saturating_duration_since(ended.delivery.0.issued_at());
    operations.attempted(ended.result, &counted, since);
    tracing::debug!(
        delivery = %Hex(ended.delivery.0),
        attempt = %Hex(ended.attempt.0),
        site = site.map(|site| &site.name()[..]),
        egress = ended.egress.map(|egress| tracing::field::display(Hex(egress.0))),
        tenant = ended.tenant.map(|tenant| tracing::field::display(Hex(tenant.0))),
        result = Operations::label(ended.result),
        code = ended.code,
        rules = ended.rules.as_deref(),
        "an attempt ended"
    );
}

/// Runs the scheduler on its inputs from `inbox`.
pub fn spawn(mut scheduler: Scheduler, mut inbox: UnboundedReceiver<Input>, wiring: Wiring) {
    let Wiring {
        store,
        transport,
        clock,
        drained,
        operations,
        inspections,
        dispatch,
        inbox: own_inbox,
    } = wiring;
    tokio::spawn(async move {
        let mut out = Vec::new();
        let mut questions = Vec::new();
        let mut wake = None;
        loop {
            let first = match wake {
                Some(at) => tokio::select! {
                    input = inbox.recv() => match input {
                        Some(input) => Some(input),
                        None => return,
                    },
                    () = tokio::time::sleep_until(clock.instant(at)) => None,
                },
                None => match inbox.recv().await {
                    Some(input) => Some(input),
                    None => return,
                },
            };
            let now = clock.now();
            for input in first
                .into_iter()
                .chain(std::iter::from_fn(|| inbox.try_recv().ok()))
            {
                scheduler.handle(now, input);
            }
            wake = scheduler.poll(now, &mut out);
            for output in out.drain(..) {
                match output {
                    Output::Store(request) => store.send_for_scheduler(request),
                    Output::Resolve(domain) => transport.resolve(domain),
                    Output::Dispatch(dispatch) => transport.dispatch(dispatch),
                    Output::Inspected { ticket, report } => inspections.answer(ticket, report),
                    Output::Consult { ticket, recipients } => questions.push((ticket, recipients)),
                    Output::Ended(ended) => count(&operations, &ended, now.wall),
                }
            }
            // The scheduler asks only when the build has a dispatch hook:
            // what one poll asks goes in one call.
            if let Some(hook) = &dispatch
                && !questions.is_empty()
            {
                hook.decide(std::mem::take(&mut questions), own_inbox.clone());
            }
            if scheduler.is_drained() {
                drained.send_replace(true);
            }
            let held = u64::try_from(scheduler.held()).unwrap_or(u64::MAX);
            let body_bytes = u64::try_from(scheduler.body_bytes()).unwrap_or(u64::MAX);
            operations.deliveries_held.store(held, Ordering::Relaxed);
            operations
                .body_bytes_held
                .store(body_bytes, Ordering::Relaxed);
            if scheduler.has_failed() {
                operations.scheduler_failed.store(true, Ordering::Relaxed);
                tracing::error!("the scheduler stopped, because the store failed under it");
                return;
            }
        }
    });
}
