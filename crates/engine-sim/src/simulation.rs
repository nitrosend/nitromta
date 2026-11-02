//! The event loop: a seeded event queue over simulated clocks.
//!
//! A run is a pure function of its seed and its world. Events fire in time
//! order. Events due at the same instant fire in an order the seed chooses,
//! so different seeds explore different interleavings and one seed always
//! repeats the same one; a world that needs two events in a fixed order
//! (messages on one connection) keeps that order itself. The wall clock can
//! step forwards and backwards, and the world reads it through the same
//! [`Clock`] the production shell uses. After every event the world's
//! invariants are checked, and a digest of everything that happened lets a
//! test prove that a seed replays exactly.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Duration;

use engine_core::rng::Rng;
use engine_core::time::{Clock, Monotonic, Now, Timestamp};

/// The largest wall-clock step, in either direction.
const MAX_CLOCK_STEP_MICROS: u64 = 3_600_000_000;

/// A system under simulation: its state, how it reacts to each event, and
/// the invariants it must keep.
pub trait World {
    type Event: fmt::Debug + Hash;

    /// Schedules the run's first events.
    fn start(&mut self, context: &mut Context<'_, Self::Event>);

    /// Reacts to one event, scheduling whatever follows from it.
    fn apply(&mut self, event: Self::Event, context: &mut Context<'_, Self::Event>);

    /// Every invariant the world must keep, checked after every event.
    fn check(&self) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub seed: u64,
    /// How much simulated time the run covers.
    pub duration: Duration,
    /// More events than this means the world never settles.
    pub max_steps: u64,
    /// The wall clock's reading when the run starts.
    pub wall_start: Timestamp,
    /// The average time between wall-clock steps of up to an hour in either
    /// direction, or `None` for a wall clock that never steps.
    pub clock_steps: Option<Duration>,
    /// Whether to record every event, to read the history of a failing seed.
    pub trace: bool,
}

/// What a world can do while it reacts to an event.
pub struct Context<'a, E> {
    now: Now,
    rng: &'a mut Rng,
    queue: &'a mut Queue<E>,
}

impl<E> Context<'_, E> {
    pub fn now(&self) -> Now {
        self.now
    }

    /// The world's randomness, seeded from the run's seed.
    pub fn rng(&mut self) -> &mut Rng {
        self.rng
    }

    /// Schedules `event` after `delay` of monotonic time.
    pub fn after(&mut self, delay: Duration, event: E) {
        self.at(self.now.monotonic.saturating_add(delay), event);
    }

    /// Schedules `event` at `time`, or now if `time` has passed.
    pub fn at(&mut self, time: Monotonic, event: E) {
        self.queue
            .push(time.max(self.now.monotonic), Entry::World(event));
    }
}

#[derive(Debug)]
pub struct Report {
    pub steps: u64,
    /// A digest of every event and clock step, in order.
    pub digest: u64,
    /// Every event, when tracing was enabled.
    pub trace: Vec<String>,
}

#[derive(Debug)]
pub struct Failure {
    pub seed: u64,
    pub step: u64,
    pub at: Monotonic,
    pub reason: String,
    /// Every event up to the failure, when tracing was enabled.
    pub trace: Vec<String>,
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "seed {} failed at step {}, {} µs into the run: {}",
            self.seed,
            self.step,
            self.at.as_micros(),
            self.reason
        )?;
        if self.trace.is_empty() {
            formatter.write_str("\n(run the seed again with tracing enabled for its history)")
        } else {
            write!(formatter, "\n{}", self.trace.join("\n"))
        }
    }
}

impl std::error::Error for Failure {}

/// Runs `world` from the seed and settings in `config`.
pub fn run<W: World>(world: &mut W, config: &Config) -> Result<Report, Failure> {
    let mut seeds = Rng::from_seed(config.seed);
    let mut world_rng = seeds.fork();
    let mut faults = seeds.fork();
    let mut queue = Queue {
        heap: BinaryHeap::new(),
        tiebreaks: seeds.fork(),
        sequence: 0,
    };
    let mut clock = Clock::default();
    let mut digest = DefaultHasher::new();
    let mut trace = Vec::new();
    let start = Monotonic::from_micros(0);
    let end = start.saturating_add(config.duration);
    let mut wall_offset: i64 = 0;
    let fail = |step, at, reason, trace| Failure {
        seed: config.seed,
        step,
        at,
        reason,
        trace,
    };

    if let Some(mean) = config.clock_steps {
        queue.push(
            start.saturating_add(gap(&mut faults, mean)),
            Entry::ClockStep,
        );
    }
    let now = clock.observe(wall(config.wall_start, start, wall_offset), start);
    let mut context = Context {
        now,
        rng: &mut world_rng,
        queue: &mut queue,
    };
    world.start(&mut context);
    if let Err(reason) = world.check() {
        return Err(fail(0, start, reason, trace));
    }

    let mut steps = 0;
    while let Some(Scheduled { at, entry, .. }) = queue.pop() {
        if at > end {
            break;
        }
        steps += 1;
        if steps > config.max_steps {
            let reason = format!("the world never settled: over {} events", config.max_steps);
            return Err(fail(steps, at, reason, trace));
        }
        at.hash(&mut digest);
        match entry {
            Entry::ClockStep => {
                let step = faults.below(2 * MAX_CLOCK_STEP_MICROS + 1);
                wall_offset += i64::try_from(step).expect("within an hour")
                    - i64::try_from(MAX_CLOCK_STEP_MICROS).expect("an hour");
                wall_offset.hash(&mut digest);
                if config.trace {
                    trace.push(format!(
                        "{} the wall clock steps to {wall_offset} µs from steady",
                        at.as_micros()
                    ));
                }
                if let Some(mean) = config.clock_steps {
                    queue.push(at.saturating_add(gap(&mut faults, mean)), Entry::ClockStep);
                }
            }
            Entry::World(event) => {
                event.hash(&mut digest);
                if config.trace {
                    trace.push(format!("{} {event:?}", at.as_micros()));
                }
                let now = clock.observe(wall(config.wall_start, at, wall_offset), at);
                let mut context = Context {
                    now,
                    rng: &mut world_rng,
                    queue: &mut queue,
                };
                world.apply(event, &mut context);
                if let Err(reason) = world.check() {
                    return Err(fail(steps, at, reason, trace));
                }
            }
        }
    }
    Ok(Report {
        steps,
        digest: digest.finish(),
        trace,
    })
}

/// The raw wall clock: steady with monotonic time, plus the steps so far.
fn wall(start: Timestamp, monotonic: Monotonic, offset: i64) -> Timestamp {
    let micros =
        i128::from(start.as_micros()) + i128::from(monotonic.as_micros()) + i128::from(offset);
    Timestamp::from_micros(u64::try_from(micros.max(0)).unwrap_or(u64::MAX))
}

/// A random gap averaging `mean`.
fn gap(rng: &mut Rng, mean: Duration) -> Duration {
    let mean = u64::try_from(mean.as_micros()).unwrap_or(u64::MAX / 2);
    Duration::from_micros(rng.below(2 * mean + 1))
}

enum Entry<E> {
    World(E),
    ClockStep,
}

struct Scheduled<E> {
    at: Monotonic,
    tiebreak: u64,
    sequence: u64,
    entry: Entry<E>,
}

impl<E> Scheduled<E> {
    fn key(&self) -> (Monotonic, u64, u64) {
        (self.at, self.tiebreak, self.sequence)
    }
}

impl<E> PartialEq for Scheduled<E> {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl<E> Eq for Scheduled<E> {}

impl<E> PartialOrd for Scheduled<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E> Ord for Scheduled<E> {
    /// Reversed, so the heap yields the earliest event first.
    fn cmp(&self, other: &Self) -> Ordering {
        other.key().cmp(&self.key())
    }
}

struct Queue<E> {
    heap: BinaryHeap<Scheduled<E>>,
    tiebreaks: Rng,
    sequence: u64,
}

impl<E> Queue<E> {
    fn push(&mut self, at: Monotonic, entry: Entry<E>) {
        self.sequence += 1;
        self.heap.push(Scheduled {
            at,
            tiebreak: self.tiebreaks.next_u64(),
            sequence: self.sequence,
            entry,
        });
    }

    fn pop(&mut self) -> Option<Scheduled<E>> {
        self.heap.pop()
    }
}
