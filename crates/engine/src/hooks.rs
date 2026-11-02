//! The hooks a build carries, and how the shell asks them:
//! each call on a task of its own, on threads of the hook point's own, so
//! a hook that blocks holds up none of the engine's, and outside the commit
//! owner. A call holds one of the hook point's places for calls under way
//! until it ends, and is cancelled when its caller goes. A call that fails,
//! panics, answers for the wrong number or does not decide within its time,
//! a wait for its place included, comes to what its failure policy says;
//! the time is kept on the engine's own threads. Failures are counted, and
//! logged as they begin and end rather than one by one. A build without a
//! hook asks nothing.
//!
//! A hook blocked inside a call keeps its thread until it returns, and the
//! engine's stop does not wait for it: the process's end ends it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use engine_core::component::Ticket;
use engine_core::hook::{self, Reason, admission, dispatch};
use engine_scheduler::Input;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::AbortHandle;

use crate::config::{self, OnFailure};
use crate::operator::Operations;

/// The hooks a build hands the engine, none in the engine's own binary: how
/// to make each, which the engine does once it has checked its privileges,
/// so whatever threads a hook starts are bound as the engine's are
/// (`privileges`).
#[derive(Default)]
pub struct Hooks {
    pub admission: Option<Make<dyn admission::Hook>>,
    pub dispatch: Option<Make<dyn dispatch::Hook>>,
}

/// How a hook is made.
pub type Make<H> = Box<dyn FnOnce() -> Arc<H>>;

/// How the threads hooks run on are named, which the engine's panic report
/// tells apart: a hook's panic is its runner's to report (`log`).
pub const THREAD_NAME: &str = "nitromta-hook";

/// One hook point's hook, and how it is asked.
pub struct Runner<H: ?Sized> {
    point: &'static str,
    hook: Arc<H>,
    pool: Pool,
    timeout: Duration,
    places: Arc<Semaphore>,
    on_failure: OnFailure,
    /// Whether its last call failed: a failure is logged as one begins,
    /// and an answer as they end.
    failing: AtomicBool,
    operations: Arc<Operations>,
}

/// The runner of the hook a build carries at `point`, with its settings, if
/// it carries one. Settings for a hook it does not carry are a mistake.
pub fn runner<H: ?Sized>(
    point: &'static str,
    hook: Option<Arc<H>>,
    settings: Option<&config::Hook>,
    operations: &Arc<Operations>,
) -> Result<Option<Arc<Runner<H>>>, String> {
    let Some(hook) = hook else {
        return match settings {
            Some(_) => Err(format!(
                "[hooks.{point}] is configured, and this build carries no {point} hook"
            )),
            None => Ok(None),
        };
    };
    let settings = settings.copied().unwrap_or_default();
    if settings.timeout_ms == 0 || settings.concurrency == 0 {
        return Err(format!(
            "[hooks.{point}]: timeout_ms and concurrency must be above 0"
        ));
    }
    // One thread a place, up to one a CPU: a hook that blocks holds its
    // thread, never the engine's.
    let threads = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(settings.concurrency);
    Ok(Some(Arc::new(Runner {
        point,
        hook,
        pool: Pool::new(threads)?,
        timeout: Duration::from_millis(settings.timeout_ms),
        places: Arc::new(Semaphore::new(settings.concurrency)),
        on_failure: settings.on_failure,
        failing: AtomicBool::new(false),
        operations: Arc::clone(operations),
    })))
}

impl<H: ?Sized + Send + Sync + 'static> Runner<H> {
    /// Asks the hook through `call` about `count` things: its verdicts, or
    /// none if the call failed, which is logged as failures begin.
    async fn ask<V: Send + 'static>(
        &self,
        count: usize,
        call: impl FnOnce(Arc<H>) -> hook::Answer<V> + Send + 'static,
    ) -> Option<Vec<V>> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let place = tokio::time::timeout_at(deadline, Arc::clone(&self.places).acquire_owned());
        let failure = match place.await {
            Ok(Ok(place)) => {
                let hook = Arc::clone(&self.hook);
                // The place is held until the call ends, even past its time:
                // a hook that ignores its cancellation still counts. The call
                // is cancelled once nothing waits for it, its caller gone.
                let task = self.pool.spawn(async move {
                    let _place = place;
                    call(hook).await
                });
                let _cancel = Cancel(task.abort_handle());
                match tokio::time::timeout_at(deadline, task).await {
                    Ok(Ok(Ok(verdicts))) if verdicts.len() == count => {
                        if self.failing.swap(false, Ordering::Relaxed) {
                            tracing::info!(hook = self.point, "a hook decides again");
                        }
                        return Some(verdicts);
                    }
                    Ok(Ok(Ok(verdicts))) => {
                        format!("it gave {} verdicts for {count}", verdicts.len())
                    }
                    Ok(Ok(Err(why))) => why,
                    Ok(Err(error)) => match error.try_into_panic() {
                        Ok(panic) => format!("it panicked: {}", panicked(panic.as_ref())),
                        Err(_) => "it was cancelled".to_owned(),
                    },
                    Err(_) => format!("it did not decide within {} ms", self.timeout.as_millis()),
                }
            }
            Ok(Err(_)) => "its places are closed".to_owned(),
            Err(_) => format!(
                "every place for its calls stayed taken for {} ms",
                self.timeout.as_millis()
            ),
        };
        if !self.failing.swap(true, Ordering::Relaxed) {
            let on_failure = match self.on_failure {
                OnFailure::Closed => "closed",
                OnFailure::Open => "open",
            };
            tracing::warn!(
                hook = self.point,
                why = %failure,
                on_failure,
                "a hook failed; until it decides again, its failure policy does"
            );
        }
        None
    }
}

/// A hook point's threads, a runtime of their own. It is shut down without
/// waiting, so it can be let go anywhere.
struct Pool(Option<Runtime>);

impl Pool {
    fn new(threads: usize) -> Result<Self, String> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads.max(1))
            .thread_name(THREAD_NAME)
            .enable_all()
            .build()
            .map(|runtime| Self(Some(runtime)))
            .map_err(|error| format!("a hook's threads: {error}"))
    }

    fn spawn<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        self.0.as_ref().expect("held until dropped").spawn(work)
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// Cancels a call when whoever waited for it stops waiting.
struct Cancel(AbortHandle);

impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What a panic said, as far as it says anything.
fn panicked(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("no message")
}

impl Runner<dyn admission::Hook> {
    /// The verdict on `message`, which is prepared and not yet accepted.
    pub async fn admit(&self, message: admission::Message) -> admission::Verdict {
        let asked = self.ask(1, move |hook| hook.admit(vec![message])).await;
        let verdict = match asked.and_then(|mut verdicts| verdicts.pop()) {
            Some(verdict) => verdict,
            None => {
                self.operations
                    .admission_failures
                    .fetch_add(1, Ordering::Relaxed);
                match self.on_failure {
                    OnFailure::Closed => {
                        admission::Verdict::Defer(Reason::new("the admission hook did not decide"))
                    }
                    OnFailure::Open => admission::Verdict::Accept,
                }
            }
        };
        self.operations.admitted(&verdict);
        verdict
    }
}

impl Runner<dyn dispatch::Hook> {
    /// Asks, in one call, about every recipient of the scheduler's
    /// `questions` from one of its polls, and answers each under its ticket.
    pub fn decide(
        self: &Arc<Self>,
        questions: Vec<(Ticket, Vec<dispatch::Recipient>)>,
        scheduler: UnboundedSender<Input>,
    ) {
        let runner = Arc::clone(self);
        tokio::spawn(async move {
            let counts: Vec<(Ticket, usize)> = questions
                .iter()
                .map(|(ticket, recipients)| (*ticket, recipients.len()))
                .collect();
            let recipients: Vec<dispatch::Recipient> = questions
                .into_iter()
                .flat_map(|(_, recipients)| recipients)
                .collect();
            let count = recipients.len();
            let verdicts = match runner.ask(count, move |hook| hook.decide(recipients)).await {
                Some(verdicts) => verdicts,
                None => {
                    runner
                        .operations
                        .dispatch_failures
                        .fetch_add(1, Ordering::Relaxed);
                    let verdict = match runner.on_failure {
                        OnFailure::Closed => {
                            dispatch::Verdict::Hold(Reason::new("the dispatch hook did not decide"))
                        }
                        OnFailure::Open => dispatch::Verdict::Proceed,
                    };
                    vec![verdict; count]
                }
            };
            let mut verdicts = verdicts.into_iter();
            for (ticket, count) in counts {
                let verdicts: Vec<dispatch::Verdict> = verdicts.by_ref().take(count).collect();
                for verdict in &verdicts {
                    runner.operations.decided(verdict);
                }
                let _ = scheduler.send(Input::Consulted { ticket, verdicts });
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use engine_core::address::Address;
    use engine_core::command::Authority;
    use engine_core::id::{AccountId, CredentialId, Id, IdentityId, MessageId};
    use engine_core::message::PolicyRevision;
    use engine_core::policy::Origin;

    use super::*;

    /// Never answers about a message that says WAIT, blocks its thread for
    /// two seconds over one that says BLOCK, and accepts the rest at once.
    struct Waiting;

    impl admission::Hook for Waiting {
        fn admit(
            self: Arc<Self>,
            messages: Vec<admission::Message>,
        ) -> hook::Answer<admission::Verdict> {
            Box::pin(async move {
                if messages
                    .iter()
                    .any(|message| &message.content[..] == b"WAIT")
                {
                    std::future::pending::<()>().await;
                }
                if messages
                    .iter()
                    .any(|message| &message.content[..] == b"BLOCK")
                {
                    std::thread::sleep(Duration::from_secs(2));
                }
                Ok(vec![admission::Verdict::Accept; messages.len()])
            })
        }
    }

    fn message(content: &'static [u8]) -> admission::Message {
        let id = |value| Id::from_u64(value).unwrap();
        admission::Message {
            id: MessageId(id(1)),
            authority: Authority {
                account: AccountId(id(2)),
                credential: CredentialId(id(3)),
                origin: Origin {
                    identity: IdentityId(id(4)),
                    tenant: None,
                    configuration: None,
                },
                revision: PolicyRevision(0),
                template: None,
            },
            recipients: vec![Address::parse("a@example.test").unwrap()],
            content: Bytes::from_static(content),
        }
    }

    fn waiting(concurrency: usize, timeout_ms: u64) -> Arc<Runner<dyn admission::Hook>> {
        let settings = config::Hook {
            timeout_ms,
            concurrency,
            on_failure: OnFailure::Closed,
        };
        let hook: Arc<dyn admission::Hook> = Arc::new(Waiting);
        let operations = Arc::new(Operations::default());
        runner("admission", Some(hook), Some(&settings), &operations)
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn a_call_whose_caller_goes_gives_its_place_back() {
        let runner = waiting(1, 10_000);
        let asking = Arc::clone(&runner);
        let abandoned = tokio::spawn(async move { asking.admit(message(b"WAIT")).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Its caller goes, as a client that disconnects does.
        abandoned.abort();
        let answered =
            tokio::time::timeout(Duration::from_secs(1), runner.admit(message(b"go"))).await;
        assert_eq!(answered, Ok(admission::Verdict::Accept));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_hook_that_blocks_its_thread_holds_up_none_of_the_engines() {
        let runner = waiting(1, 300);
        let started = std::time::Instant::now();
        // On the engine's one thread, the deadline still comes.
        let verdict = runner.admit(message(b"BLOCK")).await;
        assert!(
            matches!(verdict, admission::Verdict::Defer(_)),
            "{verdict:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }
}
