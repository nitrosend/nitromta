//! The simulator's own guarantees: exact replay, interleavings chosen by
//! the seed, a wall clock that steps without ever running backwards for the
//! world, and failures that name their seed and step.

use std::collections::BTreeSet;
use std::time::Duration;

use engine_core::component::Component;
use engine_core::time::{Monotonic, Now, Timestamp};
use engine_sim::host::Host;
use engine_sim::simulation::{self, Config, Context, World};

/// Emits the numbers `0..total`, one per interval, on its own timer.
struct Producer {
    next: u32,
    total: u32,
    interval: Duration,
    due: Option<Monotonic>,
}

impl Component for Producer {
    type Input = ();
    type Output = u32;

    fn handle(&mut self, _now: Now, _input: ()) {}

    fn poll(&mut self, now: Now, out: &mut Vec<u32>) -> Option<Monotonic> {
        let due = *self.due.get_or_insert(now.monotonic);
        if now.monotonic >= due && self.next < self.total {
            out.push(self.next);
            self.next += 1;
            self.due = Some(due.saturating_add(self.interval));
        }
        (self.next < self.total).then_some(self.due).flatten()
    }
}

/// Collects numbers in batches, noting every wall time it is shown.
#[derive(Default)]
struct Consumer {
    pending: Vec<u32>,
    received: Vec<u32>,
    batches: Vec<usize>,
    last_wall: Option<Timestamp>,
    wall_went_back: bool,
    reordered: bool,
}

impl Consumer {
    fn observe(&mut self, now: Now) {
        if self.last_wall.is_some_and(|last| now.wall < last) {
            self.wall_went_back = true;
        }
        self.last_wall = Some(now.wall);
    }
}

impl Component for Consumer {
    type Input = u32;
    type Output = ();

    fn handle(&mut self, now: Now, number: u32) {
        self.observe(now);
        self.pending.push(number);
    }

    fn poll(&mut self, now: Now, _out: &mut Vec<()>) -> Option<Monotonic> {
        self.observe(now);
        if !self.pending.is_empty() {
            self.batches.push(self.pending.len());
            for number in self.pending.drain(..) {
                self.reordered |= self.received.last().is_some_and(|&last| number < last);
                self.received.push(number);
            }
        }
        None
    }
}

#[derive(Clone, Copy, Debug, Hash)]
enum Who {
    Producer,
    Consumer,
}

#[derive(Debug, Hash)]
enum Event {
    Poll(Who),
    Wake(Who, Monotonic),
    Arrive(u32),
}

/// A producer sending to a consumer over a network that delays each
/// number independently, so numbers can overtake each other.
struct Relay {
    producer: Host<Producer>,
    consumer: Host<Consumer>,
    numbers: Vec<u32>,
    acknowledgements: Vec<()>,
    /// Breaks the invariants once this many numbers have arrived.
    broken_after: Option<usize>,
}

const TOTAL: u32 = 200;

impl Relay {
    fn new() -> Self {
        Self {
            producer: Host::new(Producer {
                next: 0,
                total: TOTAL,
                interval: Duration::from_millis(10),
                due: None,
            }),
            consumer: Host::new(Consumer::default()),
            numbers: Vec::new(),
            acknowledgements: Vec::new(),
            broken_after: None,
        }
    }

    fn poll(&mut self, who: Who, context: &mut Context<'_, Event>) {
        let now = context.now();
        let wake = match who {
            Who::Producer => self.producer.poll(now, &mut self.numbers),
            Who::Consumer => self.consumer.poll(now, &mut self.acknowledgements),
        };
        if let Some(at) = wake {
            context.at(at, Event::Wake(who, at));
        }
        for number in self.numbers.drain(..) {
            let delay = Duration::from_millis(context.rng().below(30));
            context.after(delay, Event::Arrive(number));
        }
        self.acknowledgements.clear();
    }
}

impl World for Relay {
    type Event = Event;

    fn start(&mut self, context: &mut Context<'_, Event>) {
        context.after(Duration::ZERO, Event::Poll(Who::Producer));
    }

    fn apply(&mut self, event: Event, context: &mut Context<'_, Event>) {
        match event {
            Event::Poll(who) => self.poll(who, context),
            Event::Wake(who, at) => {
                let current = match who {
                    Who::Producer => self.producer.take_wake(at),
                    Who::Consumer => self.consumer.take_wake(at),
                };
                if current {
                    self.poll(who, context);
                }
            }
            Event::Arrive(number) => {
                if self.consumer.deliver(context.now(), number) {
                    context.after(Duration::ZERO, Event::Poll(Who::Consumer));
                }
            }
        }
    }

    fn check(&self) -> Result<(), String> {
        let consumer = self.consumer.component();
        if consumer.wall_went_back {
            return Err("the wall clock went backwards".to_owned());
        }
        let distinct: BTreeSet<u32> = consumer.received.iter().copied().collect();
        if distinct.len() != consumer.received.len() {
            return Err("a number arrived twice".to_owned());
        }
        if let Some(limit) = self.broken_after
            && consumer.received.len() > limit
        {
            return Err(format!("more than {limit} numbers arrived"));
        }
        Ok(())
    }
}

fn config(seed: u64) -> Config {
    Config {
        seed,
        duration: Duration::from_secs(10),
        max_steps: 100_000,
        wall_start: Timestamp::from_micros(1_800_000_000_000_000),
        clock_steps: None,
        trace: false,
    }
}

#[test]
fn a_seed_replays_exactly() {
    let first = simulation::run(&mut Relay::new(), &config(5)).expect("the run passes");
    let second = simulation::run(&mut Relay::new(), &config(5)).expect("the run passes");
    assert_eq!((first.steps, first.digest), (second.steps, second.digest));
}

#[test]
fn seeds_explore_different_interleavings() {
    let mut digests = BTreeSet::new();
    let (mut batched, mut reordered) = (false, false);
    for seed in 0..32 {
        let mut relay = Relay::new();
        let report = simulation::run(&mut relay, &config(seed)).expect("the run passes");
        digests.insert(report.digest);
        let consumer = relay.consumer.component();
        assert_eq!(consumer.received.len(), TOTAL as usize, "seed {seed}");
        batched |= consumer.batches.iter().any(|&batch| batch > 1);
        reordered |= consumer.reordered;
    }
    assert_eq!(digests.len(), 32, "every seed takes its own path");
    assert!(
        batched,
        "some inputs arrived together and were handled as one batch"
    );
    assert!(reordered, "some numbers overtook others on the network");
}

#[test]
fn the_wall_clock_steps_both_ways_but_never_runs_backwards_for_the_world() {
    let mut stepped_back = false;
    for seed in 0..16 {
        let mut config = config(seed);
        config.clock_steps = Some(Duration::from_millis(200));
        config.trace = true;
        // The world's check fails if it ever sees the wall clock go back.
        let report = simulation::run(&mut Relay::new(), &config).expect("the run passes");
        stepped_back |= report
            .trace
            .iter()
            .any(|line| line.contains("the wall clock steps to -"));
    }
    assert!(stepped_back, "the wall clock stepped back during some run");
}

#[test]
fn a_broken_invariant_stops_the_run_at_the_event_that_broke_it() {
    let mut config = config(9);
    config.trace = true;
    let run = || {
        let mut relay = Relay::new();
        relay.broken_after = Some(50);
        let failure = simulation::run(&mut relay, &config).expect_err("the invariant breaks");
        (relay, failure)
    };
    let (relay, failure) = run();
    assert_eq!(failure.seed, 9);
    assert!(failure.reason.contains("more than 50 numbers arrived"));
    assert_eq!(failure.trace.len() as u64, failure.step);
    assert!(failure.to_string().starts_with("seed 9 failed at step"));

    // The run stopped at the consumer's first batch to cross the limit,
    // not later: invariants are checked after every event.
    let consumer = relay.consumer.component();
    let last_batch = consumer.batches.last().copied().expect("a batch arrived");
    assert!(consumer.received.len() - last_batch <= 50);
    assert_eq!(
        run().1.step,
        failure.step,
        "the failure replays at the same step"
    );
}

/// Schedules two events for the same instant, always in the same order,
/// and records the order they fire in.
struct Pair {
    labels: [char; 2],
    fired: Vec<char>,
}

impl Default for Pair {
    fn default() -> Self {
        Self {
            labels: ['a', 'b'],
            fired: Vec::new(),
        }
    }
}

impl World for Pair {
    type Event = char;

    fn start(&mut self, context: &mut Context<'_, char>) {
        for label in self.labels {
            context.after(Duration::from_millis(1), label);
        }
    }

    fn apply(&mut self, event: char, _context: &mut Context<'_, char>) {
        self.fired.push(event);
    }

    fn check(&self) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn the_digest_covers_what_happened_not_only_when() {
    let mut first = Pair::default();
    let mut second = Pair {
        labels: ['x', 'y'],
        ..Pair::default()
    };
    let first = simulation::run(&mut first, &config(3)).expect("the run passes");
    let second = simulation::run(&mut second, &config(3)).expect("the run passes");
    assert_eq!(
        first.steps, second.steps,
        "the same events at the same times"
    );
    assert_ne!(first.digest, second.digest, "but different events");
}

#[test]
fn simultaneous_events_fire_in_an_order_the_seed_chooses() {
    let mut orders = BTreeSet::new();
    for seed in 0..32 {
        let mut pair = Pair::default();
        simulation::run(&mut pair, &config(seed)).expect("the run passes");
        let mut again = Pair::default();
        simulation::run(&mut again, &config(seed)).expect("the run passes");
        assert_eq!(pair.fired, again.fired, "seed {seed} repeats its order");
        orders.insert(pair.fired);
    }
    assert_eq!(orders.len(), 2, "both orders occur across seeds");
}

/// Reschedules itself at the same instant forever.
struct Spinner;

impl World for Spinner {
    type Event = ();

    fn start(&mut self, context: &mut Context<'_, ()>) {
        context.after(Duration::ZERO, ());
    }

    fn apply(&mut self, _event: (), context: &mut Context<'_, ()>) {
        context.after(Duration::ZERO, ());
    }

    fn check(&self) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn a_world_that_never_settles_is_reported() {
    let mut config = config(1);
    config.max_steps = 1_000;
    let failure = simulation::run(&mut Spinner, &config).expect_err("it never settles");
    assert!(failure.reason.contains("never settled"));
    assert_eq!(failure.step, 1_001);
}
