//! SMTP's protocol state machines, the submission server and the delivery
//! client, its route decisions, and what MTA-STS and DANE decide, all sans
//! I/O. Each session is a
//! component: its driver feeds it the bytes that arrive and carries out what
//! it asks, so the same code runs over real sockets and in the simulator.

pub mod client;
pub mod dane;
mod data;
pub mod reply;
pub mod route;
pub mod server;
pub mod sts;
