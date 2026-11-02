//! Acceptance, for every adapter: admission against its account's and
//! tenant's rates, preparation on the pool, the admission hook if the build
//! has one, then the commit through the store, and only then the
//! scheduler.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::sealing::Sealer;
use bytes::Bytes;
use engine_core::address::Address;
use engine_core::command::{
    Accept, AcceptMessage, AcceptRefusal, Answer, Authority, Command, Commit,
};
use engine_core::guard::Failures;
use engine_core::hook::admission;
use engine_core::id::{AccountId, DeliveryId, IdGenerator, MessageId, SubmissionId};
use engine_core::limit::Rates;
use engine_core::message::Mail;
use engine_core::policy::{Credential, Policy};
use engine_message::prepare::Limits;
use engine_scheduler::Accepted;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::UnboundedSender;

use crate::clock::SystemClock;
use crate::hooks::Runner;
use crate::log::Hex;
use crate::operator::{Operations, Pressure};
use crate::stop::Stop;
use crate::store::Store;

/// A message prepared for acceptance: its ID, its recipients, its content
/// as it is sent, and what SES-shaped events will say of it.
pub struct Prepared {
    pub id: MessageId,
    pub recipients: Vec<Address>,
    pub content: Bytes,
    pub mail: Option<Mail>,
}

/// A prepared message the admission hook took, for the commit.
struct Taken<'a> {
    id: MessageId,
    recipients: &'a [Address],
    content: Bytes,
    mail: Option<Mail>,
}

pub struct Acceptance {
    pub store: Store,
    pub scheduler: UnboundedSender<engine_scheduler::Input>,
    pub ids: Mutex<IdGenerator>,
    pub clock: Arc<SystemClock>,
    /// Bounds preparations under way to the pool's size.
    pub preparation: Arc<Semaphore>,
    pub limits: Limits,
    pub lifetime: Duration,
    pub rates: Mutex<Rates>,
    /// The engine's stop, which counts the client transactions under way.
    pub stop: Arc<Stop>,
    /// Failed authentications by source address, on every front end.
    pub failures: Mutex<Failures>,
    pub operations: Arc<Operations>,
    /// The build's admission hook, if it has one.
    pub admission: Option<Arc<Runner<dyn admission::Hook>>>,
    /// Seals bodies while encryption is on: here, on the thread
    /// that prepared them, never the store's.
    pub sealer: Arc<Sealer>,
}

/// Why a prepared message was not sent for its commit.
pub enum Refused {
    /// The admission hook refused it.
    Hook(admission::Refused),
    /// A drain began while it was prepared: it is refused for
    /// now, as a recipient is while the engine drains.
    Draining,
}

impl Acceptance {
    /// Whether `peer` may try to authenticate: not while it is past its
    /// failures.
    pub fn may_authenticate(&self, peer: IpAddr) -> bool {
        let now = self.clock.now().monotonic;
        self.failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allows(peer, now)
    }

    /// Counts a failed authentication from `peer`.
    pub fn authentication_failed(&self, peer: IpAddr) {
        self.operations
            .authentication_failures
            .fetch_add(1, Ordering::Relaxed);
        let now = self.clock.now().monotonic;
        self.failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failed(peer, now);
    }

    /// Whether `recipients` and `bytes` more fit the rates `policy` sets for
    /// `credential` and the tenant its request names, taken from them if so.
    /// It is asked before a message is prepared, so a request over its rate
    /// costs no signing.
    pub fn admit(
        &self,
        policy: &Policy,
        credential: &Credential,
        tenant: Option<&str>,
        recipients: u64,
        bytes: u64,
    ) -> bool {
        let now = self.clock.now().monotonic;
        self.rates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admit(policy, credential, tenant, recipients, bytes, now)
    }

    /// Why new mail is refused for now, if it is, counted
    /// as a refusal: one flag and one count, read for each recipient or
    /// request.
    pub fn pressure(&self) -> Option<Pressure> {
        let pressure = self.operations.pressure();
        if pressure.is_some() {
            self.operations
                .refused_for_storage
                .fetch_add(1, Ordering::Relaxed);
        }
        pressure
    }

    /// A new message's ID, drawn before it is prepared so composed content
    /// can carry it.
    pub fn message_id(&self) -> MessageId {
        let now = self.clock.now().wall;
        MessageId(self.ids().next(now))
    }

    /// Runs `work`, preparing message `id`, on the preparation pool, once a
    /// place is free. `None` if the pool is gone.
    pub async fn prepare<T: Send + 'static>(
        &self,
        id: MessageId,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let started = std::time::Instant::now();
        let permit = Arc::clone(&self.preparation).acquire_owned().await.ok()?;
        let done = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .ok();
        slow("preparing a message", started, id, None);
        done
    }

    /// Accepts prepared `content` as message `id` under `authority`, which
    /// policy decided as it was prepared, unless the admission hook refuses
    /// it or a drain has begun. Its deliveries reach the scheduler only once
    /// the acceptance has committed, and its latency counts from when its
    /// content was `received`.
    pub async fn accept(
        &self,
        authority: Authority,
        recipients: &[Address],
        id: MessageId,
        content: Bytes,
        mail: Option<Mail>,
        received: std::time::Instant,
    ) -> Result<Commit<(), AcceptRefusal>, Refused> {
        if let Some(refused) = self.hooked(authority, id, recipients, &content).await {
            return Err(Refused::Hook(refused));
        }
        let taken = Taken {
            id,
            recipients,
            content,
            mail,
        };
        self.commit(authority, vec![taken], received).await
    }

    /// Accepts several prepared messages under one `authority`, in one
    /// commit, as a bulk request's entries are: the admission hook asked of
    /// each, and those it refuses left out. Returns each message's refusal,
    /// in order, `None` for one put to the commit; and the commit, `None`
    /// if the hook left none for it.
    pub async fn accept_many(
        &self,
        authority: Authority,
        messages: Vec<Prepared>,
        received: std::time::Instant,
    ) -> (
        Vec<Option<admission::Refused>>,
        Option<Result<Commit<(), AcceptRefusal>, Refused>>,
    ) {
        let mut hooked = Vec::with_capacity(messages.len());
        let mut taken = Vec::with_capacity(messages.len());
        for prepared in &messages {
            let refused = self
                .hooked(
                    authority,
                    prepared.id,
                    &prepared.recipients,
                    &prepared.content,
                )
                .await;
            if refused.is_none() {
                taken.push(Taken {
                    id: prepared.id,
                    recipients: &prepared.recipients,
                    content: prepared.content.clone(),
                    mail: prepared.mail.clone(),
                });
            }
            hooked.push(refused);
        }
        if taken.is_empty() {
            return (hooked, None);
        }
        let commit = self.commit(authority, taken, received).await;
        (hooked, Some(commit))
    }

    /// What the build's admission hook says of a message: its refusal, if
    /// it refuses it.
    async fn hooked(
        &self,
        authority: Authority,
        id: MessageId,
        recipients: &[Address],
        content: &Bytes,
    ) -> Option<admission::Refused> {
        let hook = self.admission.as_ref()?;
        let message = admission::Message {
            id,
            authority,
            recipients: recipients.to_vec(),
            content: content.clone(),
        };
        let refused = hook.admit(message).await.refused();
        if refused.is_some() {
            tracing::debug!(message_id = %Hex(id.0), "the admission hook refused a message");
        }
        refused
    }

    /// Commits `messages` as one acceptance, unless a drain has begun.
    async fn commit(
        &self,
        authority: Authority,
        messages: Vec<Taken<'_>>,
        received: std::time::Instant,
    ) -> Result<Commit<(), AcceptRefusal>, Refused> {
        let first = messages.first().map(|taken| taken.id);
        let now = self.clock.now().wall;
        let mut accept = {
            let mut ids = self.ids();
            let messages = messages
                .into_iter()
                .map(|taken| {
                    AcceptMessage::new(
                        taken.id,
                        taken.content,
                        taken.recipients,
                        taken.mail,
                        &mut ids,
                        now,
                    )
                })
                .collect();
            Accept::new(authority, messages, &mut ids, now, self.lifetime)
        };
        let tenant = accept.authority.origin.tenant;
        for message in &mut accept.messages {
            if let Some(sealed) = self
                .sealer
                .seal_body(tenant, message.body, &message.content)
            {
                message.content = Bytes::from(sealed);
            }
        }
        let accepted: Vec<Accepted> = accept
            .messages
            .iter()
            .flat_map(|message| {
                message.recipients.iter().filter_map(|recipient| {
                    Some(Accepted {
                        delivery: accept.delivery(message, recipient)?,
                        content: message.content.clone(),
                    })
                })
            })
            .collect();
        let submission = accept.submission;
        let account = accept.authority.account;
        let count = accept.messages.len() as u64;
        // Each message, with each delivery and its recipient's domain, for
        // the debug lines.
        let lines: Vec<(MessageId, Vec<(DeliveryId, String)>)> =
            if tracing::enabled!(tracing::Level::DEBUG) {
                accept
                    .messages
                    .iter()
                    .map(|message| {
                        let deliveries = message
                            .recipients
                            .iter()
                            .map(|recipient| {
                                (recipient.delivery, recipient.address.domain().to_owned())
                            })
                            .collect();
                        (message.id, deliveries)
                    })
                    .collect()
            } else {
                Vec::new()
            };
        // Counted as waiting for its commit, which new mail is refused past,
        // until the commit owner answers, whether or not its caller is
        // still there.
        let bytes = content_bytes(&accept);
        let started = std::time::Instant::now();
        let commit = match self
            .store
            .ask_accepting(Command::Accept(accept), bytes)
            .await
        {
            Ok(Some(Answer::Accepted(commit))) => commit,
            Ok(_) => Commit::Unavailable,
            Err(crate::store::Draining) => {
                self.operations
                    .refused_for_storage
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(id) = first {
                    tracing::debug!(message_id = %Hex(id.0), "a message was refused as the engine drains");
                }
                return Err(Refused::Draining);
            }
        };
        if let Some(id) = first {
            slow("accepting a message", started, id, Some(submission));
        }
        for (id, deliveries) in &lines {
            accepted_lines(submission, account, *id, &commit, deliveries);
        }
        if commit == Commit::Committed(()) {
            for _ in 0..count {
                self.operations.accepted_in(received.elapsed());
            }
            self.operations
                .accepted_bytes
                .fetch_add(bytes, Ordering::Relaxed);
            self.operations
                .messages_accepted
                .fetch_add(count, Ordering::Relaxed);
            self.operations
                .recipients_accepted
                .fetch_add(accepted.len() as u64, Ordering::Relaxed);
            let _ = self
                .scheduler
                .send(engine_scheduler::Input::Accepted(accepted));
        }
        Ok(commit)
    }

    fn ids(&self) -> std::sync::MutexGuard<'_, IdGenerator> {
        self.ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The debug lines for an acceptance's commit: its message, and each of its
/// deliveries with its recipient's domain.
fn accepted_lines(
    submission: SubmissionId,
    account: AccountId,
    message: MessageId,
    commit: &Commit<(), AcceptRefusal>,
    deliveries: &[(DeliveryId, String)],
) {
    let (submission, message_id) = (Hex(submission.0), Hex(message.0));
    match commit {
        Commit::Committed(()) => {
            tracing::debug!(
                %submission,
                %message_id,
                account = %Hex(account.0),
                recipients = deliveries.len(),
                "a message was accepted"
            );
            for (delivery, domain) in deliveries {
                tracing::debug!(
                    %message_id,
                    delivery = %Hex(delivery.0),
                    domain = &domain[..],
                    "a delivery was accepted"
                );
            }
        }
        Commit::Refused(refusal) => {
            tracing::debug!(%submission, %message_id, ?refusal, "a message was refused");
        }
        Commit::Unknown => {
            tracing::debug!(%submission, %message_id, "a message's commit failed: it may or may not be accepted");
        }
        Commit::Unavailable => {
            tracing::debug!(%submission, %message_id, "a message was not accepted: the store did not answer");
        }
    }
}

/// Reports a step of acceptance that held its client up for long: every
/// such wait shows in the client's latency. Each is a line at `debug`, and
/// at the default level a line a minute at most counts them, so a store
/// that stays slow writes no line per message.
fn slow(
    what: &str,
    since: std::time::Instant,
    message: MessageId,
    submission: Option<SubmissionId>,
) {
    let took = since.elapsed();
    if took <= Duration::from_millis(500) {
        return;
    }
    let submission = submission.map(|submission| tracing::field::display(Hex(submission.0)));
    tracing::debug!(
        step = what,
        ms = took.as_millis(),
        message_id = %Hex(message.0),
        submission,
        "a step of acceptance held its client up"
    );
    SLOW_UNLOGGED.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let last = SLOW_LOGGED.load(Ordering::Relaxed);
    if now >= last.saturating_add(60)
        && SLOW_LOGGED
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::warn!(
            step = what,
            ms = took.as_millis(),
            message_id = %Hex(message.0),
            slow = SLOW_UNLOGGED.swap(0, Ordering::Relaxed),
            "steps of acceptance held their clients up: this one, and slow counts them since the last such line, a minute or more ago"
        );
    }
}

/// When a slow step was last logged at the default level, in seconds since
/// the epoch, and how many have been since.
static SLOW_LOGGED: AtomicU64 = AtomicU64::new(0);
static SLOW_UNLOGGED: AtomicU64 = AtomicU64::new(0);

/// The bytes of content an acceptance carries.
fn content_bytes(accept: &Accept) -> u64 {
    accept
        .messages
        .iter()
        .map(|message| message.content.len() as u64)
        .sum()
}
