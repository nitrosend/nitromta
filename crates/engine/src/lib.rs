//! The engine: the Tokio shell. It connects the components and
//! performs their I/O, carries messages between them, and supplies time and
//! randomness. The decisions are the components'.
//!
//! The engine's own binary runs [`main`] with no hooks. A build with hooks
//! of its own is a binary that depends on this crate and runs
//! [`main`] with them, as this one does with an admission hook:
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use engine::hook::{Answer, Reason, admission};
//!
//! struct Scanner;
//!
//! impl admission::Hook for Scanner {
//!     fn admit(self: Arc<Self>, messages: Vec<admission::Message>) -> Answer<admission::Verdict> {
//!         Box::pin(async move {
//!             let verdicts = messages.iter().map(|message| {
//!                 if message.content.windows(5).any(|window| window == b"EICAR") {
//!                     admission::Verdict::Reject(Reason::new("a test virus"))
//!                 } else {
//!                     admission::Verdict::Accept
//!                 }
//!             });
//!             Ok(verdicts.collect())
//!         })
//!     }
//! }
//!
//! fn main() -> std::process::ExitCode {
//!     engine::main(engine::Hooks {
//!         admission: Some(Box::new(|| Arc::new(Scanner))),
//!         dispatch: None,
//!     })
//! }
//! ```
//!
//! `run --config <file>` runs the engine in the foreground until it is
//! stopped. `admin --config <file>` sends native API requests, one to a
//! line of standard input, to that engine's admin socket. `check --config
//! <file>` checks a stopped engine's store. `key --to <file>` writes a new
//! key to the installation's keys.

mod acceptance;
mod admin;
mod backup;
mod capture;
mod cli;
mod clock;
mod config;
mod delivery;
mod doctor;
mod events;
mod feedback;
mod hooks;
mod keys;
mod listen;
mod log;
mod operator;
mod policy;
mod privileges;
mod scheduler;
mod sealing;
mod ses;
mod setup;
mod simulator;
mod sns;
mod stop;
mod store;
mod stream;
mod sts;
mod submission;
mod tls;
mod verify;
mod warmup;

use std::hash::{BuildHasher, RandomState};
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use engine_core::address::Address;
use engine_core::command::{Answer, Command, MAX_RECIPIENTS};
use engine_core::feedback::Trust;
use engine_core::id::{IdGenerator, Lane, Shard};
use engine_core::retry::RetrySchedule;
use engine_core::rng::Rng;
use engine_feedback::intake::Intake;
use engine_message::prepare::Limits;
use engine_rules::Rules;
use engine_scheduler::Scheduler;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::acceptance::Acceptance;
use crate::admin::Admin;
use crate::capture::{Capturer, Transport};
use crate::clock::SystemClock;
use crate::config::Config;
use crate::delivery::Deliverer;
use crate::feedback::Feedback;
pub use crate::hooks::{Hooks, Make};
use crate::operator::Operations;
use crate::scheduler::Inspections;
use crate::sealing::Sealer;
use crate::ses::Ses;
use crate::simulator::Simulator;
use crate::stop::Stop;
use crate::sts::Policies;
use crate::submission::Submission;

/// The hook interfaces a build's hooks implement.
pub use engine_core::hook;

/// Acceptance, attempts, administration, feedback, the simulator and SES's
/// managing operations issue IDs from lanes of their own, so none waits on
/// another.
const ACCEPTANCE_LANE: u8 = 0;
const ATTEMPT_LANE: u8 = 1;
const ADMIN_LANE: u8 = 2;
const FEEDBACK_LANE: u8 = 3;
const SIMULATOR_LANE: u8 = 4;
const MANAGING_LANE: u8 = 5;

/// Runs the command the process's arguments name, with `hooks`.
pub fn main(hooks: Hooks) -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // Every command may hold a key or a secret. The metrics' I/O counts are
    // opened first, as they cannot be after.
    operator::keep_io();
    let result = privileges::no_core_dumps()
        .and_then(|()| cli::Options::parse(&argv))
        .and_then(|options| match options.words().as_slice() {
            ["run"] => options
                .required("config")
                .and_then(|path| run(Path::new(path), hooks)),
            _ => cli::command(&options),
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // Once the logs have started, the reason the engine stops is one.
        Err(error) if tracing::dispatcher::has_been_set() => {
            tracing::error!(%error, "stopped");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("nitromta: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &Path, hooks: Hooks) -> Result<(), String> {
    privileges::check()?;
    let config = config::load(path)?;
    log::start(&config.log);
    // The keys are this engine's alone from before they are read until its
    // store is closed, so the one engine whose store a key can seal answers
    // `key retire`: the store's thread keeps the hold, whatever
    // ends the engine.
    let held = keys::hold(&config.store.keys)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the runtime: {error}"))?;
    let result = runtime.block_on(engine(config, hooks, held));
    // Blocking work left behind, such as a name lookup, does not hold the
    // stop past its bound.
    runtime.shutdown_timeout(Duration::from_secs(1));
    // With every handle on the store gone, the commit owner's thread closes
    // it, so the next start finds it closed.
    let store = result?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !store.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if store.is_finished() {
        let _ = store.join();
    } else {
        tracing::warn!("the store was not closed in time; the next start checks it");
    }
    Ok(())
}

/// Runs the engine until it stops, and returns the commit owner's thread,
/// which closes the store once nothing holds it.
async fn engine(
    config: Config,
    hooks: Hooks,
    held: std::fs::File,
) -> Result<std::thread::JoinHandle<()>, String> {
    // Stops and reloads are listened for before anything is served, so one
    // that comes as the engine starts is what it asks, never the signal's
    // default end.
    let mut signals = Signals::listen()?;
    // The receiver rules, as shipped and overridden, checked
    // before anything starts.
    let rules = Arc::new(Rules::new(&config.receivers)?);
    let clock = Arc::new(SystemClock::new());
    let (scheduler_inbox, scheduler_input) = tokio::sync::mpsc::unbounded_channel();
    let operations = Arc::new(Operations::default());
    // The build's hooks, with their settings.
    let admission = hooks::runner(
        "admission",
        hooks.admission.map(|make| make()),
        config.hooks.admission.as_ref(),
        &operations,
    )?;
    let dispatch = hooks::runner(
        "dispatch",
        hooks.dispatch.map(|make| make()),
        config.hooks.dispatch.as_ref(),
        &operations,
    )?;
    let options = config.store.options();
    let inspections = Arc::new(Inspections::default());
    operations.pending_limit.store(
        config.store.pending_mib << 20,
        std::sync::atomic::Ordering::Relaxed,
    );
    // Every secret is sealed under the newest key once the store opens.
    let keyring = Arc::new(keys::load(&config.store.keys)?);
    // Bodies are sealed by acceptance and opened by delivery, under the
    // installation's key or each tenant's.
    let sealer = Arc::new(Sealer::load(
        config.store.encryption,
        Arc::clone(&keyring),
        &config.store.keys,
    )?);
    let sealing = keyring.current();
    let full = |path: &std::path::Path| {
        std::fs::canonicalize(path)
            .map(|path| path.display().to_string())
            .map_err(|error| format!("{}: {error}", path.display()))
    };
    let keys_file = full(&config.store.keys)?;
    let store::Started {
        store,
        policy,
        after,
        thread: store_thread,
    } = store::start(
        &config.store.path,
        options,
        store::Keys {
            ring: keyring,
            held,
            sealer: Arc::clone(&sealer),
        },
        config.store.reserve_mib << 20,
        Arc::clone(&clock),
        scheduler_inbox.clone(),
        Arc::clone(&operations),
    )?;
    if let Some(fence) = policy.load().policy().fence() {
        tracing::warn!(
            discarding = fence.discarding,
            "the store was restored from a backup and is fenced: the deliveries the copy held wait for `nitromta fence release` or `nitromta fence discard`"
        );
    }
    let shard = Shard::new(config.store.shard);
    let lane = |lane| Lane::new(lane).ok_or_else(|| format!("lane {lane} does not exist"));
    // Bound before anything else is started, so a second engine on the
    // same store stops here.
    let admin_listener = match &config.admin {
        Some(settings) => {
            let listener = admin::bind(&settings.socket)?;
            tracing::info!(socket = %settings.socket.display(), "serving admin");
            Some(listener)
        }
        None => None,
    };

    let settings = &config.scheduler;
    let retry = RetrySchedule::new(
        Duration::from_secs(settings.retry_first_seconds),
        Duration::from_secs(settings.retry_max_seconds),
    )
    .ok_or("scheduler: retry_first_seconds must be above 0 and at most retry_max_seconds")?;
    let scheduler = Scheduler::new(
        engine_scheduler::Config {
            per_transaction: config.delivery.recipients_per_transaction.max(1),
            window: settings.window,
            window_bytes: settings.window_mib * 1024 * 1024,
            scan_every: Duration::from_secs(settings.scan_seconds),
            scan_page: settings.scan_page,
            retry,
            route_ttl: Duration::from_secs(settings.route_ttl_seconds),
            dispatch_hook: dispatch.is_some(),
            // The logs started before the scheduler, at their level.
            ended_rules: tracing::enabled!(tracing::Level::DEBUG),
        },
        Arc::clone(&rules),
        IdGenerator::new(shard, lane(ATTEMPT_LANE)?, after),
        Rng::from_seed(RandomState::new().hash_one(clock.now().wall)),
    );
    let outbound = config.outbound.policy();
    // Verified TLS's authorities: MTA-STS cannot be honoured
    // without them, so the engine does not start; event subscribers over
    // https cannot be reached.
    let verified = match tls::authorities(config.tls.authorities.as_deref()) {
        Ok(roots) => Some(tls::verified(roots)?),
        Err(error) if config.delivery.mta_sts && config.capture.is_none() => {
            return Err(format!(
                "MTA-STS needs certificate authorities: {error}; or set [delivery] mta_sts = false"
            ));
        }
        Err(error) => {
            tracing::warn!(%error, "subscribers over https cannot be reached");
            None
        }
    };
    // The transport, chosen once: in capture mode, mail is
    // captured into a directory, and nothing is looked up or sent.
    let transport = match &config.capture {
        Some(capture) => {
            tracing::warn!(
                directory = %capture.directory.display(),
                "capture mode: every delivery is captured, and none is sent"
            );
            Transport::Capture(Capturer::new(
                capture,
                &config.delivery,
                scheduler_inbox.clone(),
                Arc::clone(&clock),
                Arc::clone(&sealer),
            )?)
        }
        None => {
            let resolver = delivery::resolver(&config.delivery)?;
            if config.delivery.dane && config.delivery.trust_anchor.is_none() {
                delivery::check_dnssec(resolver.clone(), Arc::clone(&operations));
            }
            let policies = match (&verified, config.delivery.mta_sts) {
                (Some(verified), true) => {
                    let now = clock.now().wall;
                    let Some(Answer::StsPolicies(Ok(kept))) = store
                        .ask(Command::StsPolicies {
                            now,
                            domain: None,
                            limit: sts::MOST_KEPT + 1,
                        })
                        .await
                    else {
                        return Err("the store could not read its MTA-STS policies".to_owned());
                    };
                    Some(Arc::new(Policies::new(
                        resolver.clone(),
                        Arc::clone(verified),
                        config.delivery.mta_sts_port,
                        outbound,
                        Arc::clone(&clock),
                        store.clone(),
                        kept,
                    )))
                }
                _ => None,
            };
            Transport::Smtp {
                deliverer: Deliverer::new(
                    &config.delivery,
                    resolver,
                    policies,
                    verified.clone(),
                    outbound,
                    scheduler_inbox.clone(),
                    Arc::clone(&clock),
                    Arc::clone(&sealer),
                )?,
                simulator: Arc::new(Simulator {
                    scheduler: scheduler_inbox.clone(),
                    ids: Mutex::new(IdGenerator::new(shard, lane(SIMULATOR_LANE)?, after)),
                    clock: Arc::clone(&clock),
                }),
            }
        }
    };
    // In capture mode, the operator endpoint shows what was captured.
    let inspector = config.capture.as_ref().map(|capture| {
        Arc::new(capture::Inspector {
            directory: capture.directory.clone(),
            store: store.clone(),
            sealer: Arc::clone(&sealer),
        })
    });
    let (drained_sender, mut drained) = tokio::sync::watch::channel(false);
    scheduler::spawn(
        scheduler,
        scheduler_input,
        scheduler::Wiring {
            store: store.clone(),
            transport,
            clock: Arc::clone(&clock),
            drained: drained_sender,
            operations: Arc::clone(&operations),
            inspections: Arc::clone(&inspections),
            dispatch,
            inbox: scheduler_inbox.clone(),
        },
    );
    let drain_inbox = scheduler_inbox.clone();
    let drain_for = Duration::from_secs(config.scheduler.drain_seconds);
    let stop = Arc::new(Stop::default());
    // The SNS subset, served on the SES API's listener.
    let sns = match (&config.sns, &config.ses) {
        (Some(settings), Some(_)) => Some(Arc::new(sns::Sns::load(settings)?)),
        (Some(_), None) => {
            return Err(
                "[sns] is served on the SES API's listener: configure [ses] too".to_owned(),
            );
        }
        (None, _) => None,
    };
    let verified_for_sns = verified.clone();
    let replays = events::spawn(
        store.clone(),
        Arc::clone(&policy),
        &config.events,
        events::Delivery {
            clock: Arc::clone(&clock),
            outbound,
            tls: verified,
            rng: Rng::from_seed(RandomState::new().hash_one(clock.now().wall)),
            operations: Arc::clone(&operations),
        },
        sns.clone()
            .zip(config.ses.as_ref().map(|ses| ses.region.clone())),
    );
    let admin = match admin_listener {
        Some(listener) => {
            let admin = Arc::new(Admin {
                store: store.clone(),
                clock: Arc::clone(&clock),
                ids: Mutex::new(IdGenerator::new(shard, lane(ADMIN_LANE)?, after)),
                scheduler: scheduler_inbox.clone(),
                inspections: Arc::clone(&inspections),
                replays,
                policy: Arc::clone(&policy),
                operations: Arc::clone(&operations),
                sealing,
                keys_file,
                store_file: full(&config.store.path)?,
                sealer: Arc::clone(&sealer),
            });
            Some(admin.serve(listener))
        }
        None => None,
    };

    // Each listener's certificate, which SIGHUP reads again.
    let mut certificates: Vec<(&'static str, Arc<tls::Certified>)> = Vec::new();
    let mut certified = |listener: &'static str, certificate: &Path, key: &Path| {
        let loaded = tls::Certified::load(certificate, key)?;
        certificates.push((listener, Arc::clone(&loaded)));
        Ok::<_, String>(loaded)
    };
    let feedback = match &config.feedback {
        Some(settings) => {
            let loops = settings
                .loops
                .iter()
                .map(|address| {
                    Address::parse(address)
                        .map_err(|_| format!("feedback: {address} is not an address"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let feedback = Arc::new(Feedback {
                session: Arc::new(engine_smtp::server::Config {
                    role: engine_smtp::server::Role::Receiver,
                    hostname: settings.hostname.clone(),
                    max_message_bytes: settings.max_report_bytes,
                    max_recipients: 16,
                    idle: Duration::from_secs(settings.idle_seconds),
                }),
                tls: certified("feedback", &settings.certificate, &settings.key)?,
                intake: {
                    let policy = Arc::clone(&policy);
                    Intake::new(
                        delivery::return_path_keys(&config.delivery)?,
                        &config.delivery.return_path_domain,
                        &loops,
                        Arc::clone(&rules),
                    )
                    .also_at(move |domain| policy.load().returns_to(domain))
                    .trusting(match settings.trusted {
                        config::Trusted::Correlated => Trust::Correlated,
                        config::Trusted::Authenticated => Trust::Authenticated,
                    })
                },
                reporters: feedback::Reporters::new(&settings.reporters, &config.delivery)?,
                store: store.clone(),
                ids: Mutex::new(IdGenerator::new(shard, lane(FEEDBACK_LANE)?, after)),
                clock: Arc::clone(&clock),
                stop: Arc::clone(&stop),
                operations: Arc::clone(&operations),
            });
            let listener = TcpListener::bind(&settings.listen)
                .await
                .map_err(|error| format!("{}: {error}", settings.listen))?;
            tracing::info!(listen = %bound(&listener, &settings.listen), "taking bounce and complaint reports");
            Some(feedback.serve(listener))
        }
        None => None,
    };

    let settings = &config.submission;
    // The store refuses a message with more recipients than it can find
    // the deliveries of, so submission never takes more.
    if settings.max_recipients > MAX_RECIPIENTS {
        return Err(format!(
            "submission: max_recipients must be at most {MAX_RECIPIENTS}"
        ));
    }
    let threads = settings
        .preparation_threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
    let acceptance = Arc::new(Acceptance {
        store,
        scheduler: scheduler_inbox,
        ids: Mutex::new(IdGenerator::new(shard, lane(ACCEPTANCE_LANE)?, after)),
        clock: Arc::clone(&clock),
        preparation: Arc::new(Semaphore::new(threads.max(1))),
        limits: Limits {
            max_bytes: settings.max_message_bytes,
        },
        lifetime: Duration::from_secs(settings.lifetime_seconds),
        rates: Mutex::default(),
        stop: Arc::clone(&stop),
        failures: Mutex::default(),
        operations: Arc::clone(&operations),
        admission,
        sealer: Arc::clone(&sealer),
    });
    // Tenants' keys, settled as the store opened, kept in step with policy:
    // a removed tenant's erased.
    tokio::spawn(Arc::clone(&sealer).watch(acceptance.store.clone(), Arc::clone(&policy)));
    // Identities created through SES's API, each checked on its schedule:
    // nothing to do while there are none.
    tokio::spawn(
        Arc::new(verify::Verifier {
            policy: Arc::clone(&policy),
            store: acceptance.store.clone(),
            resolver: delivery::public_resolver(&config.delivery)?,
            clock: Arc::clone(&clock),
            bounce_host: config
                .feedback
                .as_ref()
                .map(|feedback| feedback.hostname.clone()),
            capture: config.capture.is_some(),
        })
        .run(),
    );
    // Each capped egress judged once a day on its evidence,
    // unless the operator sets caps alone.
    if config.warmup.automatic {
        tokio::spawn(
            warmup::Warmup {
                policy: Arc::clone(&policy),
                store: acceptance.store.clone(),
                rules: Arc::clone(&rules),
                clock: Arc::clone(&clock),
            }
            .run(),
        );
    }
    let submission = Arc::new(Submission {
        session: Arc::new(engine_smtp::server::Config {
            role: engine_smtp::server::Role::Submission,
            hostname: settings.hostname.clone(),
            max_message_bytes: settings.max_message_bytes,
            max_recipients: settings.max_recipients,
            idle: Duration::from_secs(settings.idle_seconds),
        }),
        tls: certified("submission", &settings.certificate, &settings.key)?,
        policy: Arc::clone(&policy),
        acceptance: Arc::clone(&acceptance),
        clock: Arc::clone(&clock),
    });
    let listener = TcpListener::bind(&settings.listen)
        .await
        .map_err(|error| format!("{}: {error}", settings.listen))?;
    tracing::info!(listen = %bound(&listener, &settings.listen), "accepting submission");
    let api = match &config.ses {
        Some(api) => {
            let ses = Arc::new(Ses {
                tls: certified("SES API", &api.certificate, &api.key)?,
                policy: Arc::clone(&policy),
                region: api.region.clone(),
                acceptance,
                ids: Mutex::new(IdGenerator::new(shard, lane(MANAGING_LANE)?, after)),
                bounce_host: config
                    .feedback
                    .as_ref()
                    .map(|feedback| feedback.hostname.clone()),
                sns: sns.clone(),
                network: events::Network::new(outbound, verified_for_sns),
                clock,
                max_recipients: settings.max_recipients,
                ladder: Arc::clone(&rules.default_warmup().ladder),
                unverified: Arc::new(tokio::sync::Semaphore::new(ses::UNVERIFIED_KIB)),
            });
            let listener = TcpListener::bind(&api.listen)
                .await
                .map_err(|error| format!("{}: {error}", api.listen))?;
            tracing::info!(listen = %bound(&listener, &api.listen), "serving the SES v2 API");
            Some(ses.serve(listener))
        }
        None => None,
    };
    tokio::spawn(reloads(signals.hangup.take(), certificates, sns));
    let operator = match &config.operator {
        Some(settings) => {
            let listener = TcpListener::bind(&settings.listen)
                .await
                .map_err(|error| format!("{}: {error}", settings.listen))?;
            tracing::info!(listen = %bound(&listener, &settings.listen), "serving health and metrics");
            Some(operator::serve(
                listener,
                Arc::clone(&operations),
                Arc::clone(&stop),
                Arc::clone(&policy),
                inspector,
            ))
        }
        None => None,
    };
    tokio::select! {
        result = submission.serve(listener) => return result.map(|()| store_thread),
        result = optional(api) => return result.map(|()| store_thread),
        result = optional(admin) => return result.map(|()| store_thread),
        result = optional(feedback) => return result.map(|()| store_thread),
        result = optional(operator) => return result.map(|()| store_thread),
        () = signals.stopped() => {}
    }
    // A graceful stop: the listeners are closed, what arrives on
    // connections already open is refused for now, nothing new is
    // dispatched, and the attempts and client transactions under way finish
    // within the bound.
    stop.start();
    let _ = drain_inbox.send(engine_scheduler::Input::Drain);
    tracing::info!("stopping, once what is under way finishes");
    let finished = tokio::time::timeout(drain_for, async {
        let _ = drained.wait_for(|drained| *drained).await;
        stop.finished().await;
    })
    .await;
    if finished.is_err() {
        tracing::warn!(
            seconds = drain_for.as_secs(),
            "stopped with work under way; the next start recovers its attempts"
        );
    } else {
        tracing::info!("stopped, with nothing under way");
    }
    Ok(store_thread)
}

/// The address a listener holds, for its log line: with port 0 configured,
/// the port the system gave it.
fn bound(listener: &TcpListener, configured: &str) -> String {
    listener
        .local_addr()
        .map_or_else(|_| configured.to_owned(), |address| address.to_string())
}

/// Serves a listener the configuration may leave out: a missing one never
/// finishes.
async fn optional(serving: Option<impl Future<Output = Result<(), String>>>) -> Result<(), String> {
    match serving {
        Some(serving) => serving.await,
        None => std::future::pending().await,
    }
}

/// Reads each listener's certificate and key again on SIGHUP, as a
/// renewal's hook asks (`systemctl reload nitromta`), and the SNS key and
/// certificates: one that cannot be read leaves what it had in place.
async fn reloads(
    hangup: Option<tokio::signal::unix::Signal>,
    certificates: Vec<(&'static str, Arc<tls::Certified>)>,
    sns: Option<Arc<sns::Sns>>,
) {
    let Some(mut hangup) = hangup else {
        return;
    };
    while hangup.recv().await.is_some() {
        if let Some(sns) = &sns {
            let key = sns.key().display();
            match sns.reload() {
                Ok(()) => tracing::info!(%key, "read the SNS key and certificates again"),
                Err(why) => tracing::error!(
                    %key,
                    why = %why,
                    "kept the SNS key it had: the one there now cannot sign"
                ),
            }
        }
        for (listener, certified) in &certificates {
            let certificate = certified.certificate().display();
            match certified.reload() {
                Ok(()) => tracing::info!(listener, %certificate, "read its certificate again"),
                Err(why) => tracing::error!(
                    listener,
                    %certificate,
                    why = %why,
                    "kept the certificate it had: the one there now cannot be served"
                ),
            }
        }
    }
}

/// The signals the engine takes: SIGTERM and SIGINT, which start the
/// graceful stop, and SIGHUP, which reloads.
struct Signals {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
    hangup: Option<tokio::signal::unix::Signal>,
}

impl Signals {
    fn listen() -> Result<Self, String> {
        use tokio::signal::unix::{SignalKind, signal};
        let listen = |kind| signal(kind).map_err(|error| format!("listening for signals: {error}"));
        Ok(Self {
            terminate: listen(SignalKind::terminate())?,
            interrupt: listen(SignalKind::interrupt())?,
            hangup: Some(listen(SignalKind::hangup())?),
        })
    }

    /// Resolves on SIGTERM or SIGINT.
    async fn stopped(&mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {},
            _ = self.interrupt.recv() => {},
        }
    }
}
