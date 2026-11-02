//! The engine's native vocabulary and rules: identifiers, time and
//! randomness as inputs, envelope addresses, the native records (messages,
//! deliveries and attempts), the transitions that change them and the
//! journal that records them, policy and the authority it grants,
//! admission rates and the acceptance quota, retry timing, MTA-STS policies as
//! delivery keeps them, the commands to the commit owner, the component contract
//! that both drivers run, and the hook interfaces.
//!
//! Everything here is deterministic. Nothing reads a clock, asks the
//! operating system for randomness or performs I/O. Those arrive as inputs
//! from a driver, so the simulator can replay any run exactly from its seed.

pub mod address;
pub mod attempt;
pub mod budget;
pub mod command;
pub mod component;
pub mod delivery;
pub mod event;
pub mod feedback;
pub mod guard;
pub mod hook;
pub mod id;
pub mod journal;
pub mod limit;
pub mod message;
pub mod outbound;
pub mod policy;
pub mod quota;
pub mod retry;
pub mod rng;
pub mod status;
pub mod sts;
pub mod suppression;
pub mod time;
