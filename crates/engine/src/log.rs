//! The engine's logs: one JSON object a line on standard error, or
//! plain text, at the configured level. Each names what it is about by its
//! IDs, never by a body, a credential or an address. Nothing is logged for
//! each message or recipient at the default level: the journal is the
//! per-delivery record, and `explain` reads it. At `debug`, each
//! message accepted, each of its deliveries and each attempt has a line,
//! correlated by their IDs, which cost a level check otherwise. A message's
//! ID is `message_id`, since `message` is the line's own text. A panic is
//! reported in the same format.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use engine_core::id::Id;

use tracing::Level;

use crate::config::{Log, LogFormat, LogLevel};
use crate::hooks;

/// Starts the logs. Called once, before anything logs.
pub fn start(settings: &Log) {
    let level = match settings.level {
        LogLevel::Error => Level::ERROR,
        LogLevel::Warn => Level::WARN,
        LogLevel::Info => Level::INFO,
        LogLevel::Debug => Level::DEBUG,
    };
    let logs = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false);
    match settings.format {
        LogFormat::Json => logs.json().flatten_event(true).init(),
        LogFormat::Text => logs.init(),
    }
    // A panic on a hook's threads is reported at most once a minute, so a
    // hook that panics at every call is not a line each time; its runner
    // reports the calls that fail as their failures begin.
    std::panic::set_hook(Box::new(|panic| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("unnamed");
        if !name.starts_with(hooks::THREAD_NAME) {
            return tracing::error!(thread = name, %panic, "a thread panicked");
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let last = HOOK_PANIC_LOGGED.load(Ordering::Relaxed);
        if now >= last.saturating_add(60)
            && HOOK_PANIC_LOGGED
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::error!(
                thread = name,
                %panic,
                "a hook panicked; a hook's panics are logged at most once a minute"
            );
        }
    }));
}

/// An ID as the admin socket and the API give it, sixteen hex digits,
/// written only if its line is.
pub struct Hex(pub Id);

impl fmt::Display for Hex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:016x}", self.0.as_u64())
    }
}

/// When a hook's panic was last logged, in seconds since the epoch.
static HOOK_PANIC_LOGGED: AtomicU64 = AtomicU64::new(0);
