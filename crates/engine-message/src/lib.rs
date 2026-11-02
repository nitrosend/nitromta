//! Messages as the engine sends them: the checks a submitted message passes
//! before acceptance, and its DKIM signature, made once.
//!
//! Everything here is a pure function of its inputs, so preparation can run
//! on any thread, and in the simulator.

pub mod compose;
pub mod dkim;
pub mod header;
pub mod prepare;
