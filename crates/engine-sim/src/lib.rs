//! The deterministic simulator. It runs the engine's components on one
//! thread from a seeded event queue, over simulated clocks with injected
//! faults, checks every invariant after every event, and replays any run
//! exactly from its seed.
//!
//! [`simulation`] is the event loop. [`host`] runs one component as the
//! component contract describes, as the production shell does. [`disk`] is
//! a disk that power failures can tear, and [`vfs`] puts the real SQLite on
//! it. [`sender`] is the account and identity simulations send as, with
//! the installation's keys they run under, and [`receiver`] what simulated
//! receivers reply.

pub mod disk;
pub mod host;
pub mod receiver;
pub mod sender;
pub mod simulation;
pub mod vfs;
