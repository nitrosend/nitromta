//! The store: every authoritative record in one SQLite database, and the
//! commit owner, its one writer.
//!
//! [`store`] reads and writes records. [`commit_owner`] is the component
//! that groups commands into synchronous commits. [`keys`] seals the
//! secrets in policy under the installation's keys.

mod codec;
pub mod commit_owner;
#[cfg(test)]
mod golden;
pub mod keys;
#[cfg(feature = "fuzz")]
pub mod records;
#[cfg(not(feature = "fuzz"))]
mod records;
mod schema;
pub mod store;
