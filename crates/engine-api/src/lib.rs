//! Wire formats mapped to native commands, and native answers back to wire
//! replies. Adapters never touch storage or call a provider: they decide
//! what a request means, and the shell carries it out.

pub mod backup;
pub mod drain;
pub mod inspect;
pub mod list;
pub mod native;
pub mod parked;
pub mod sealing;
pub mod ses;
pub mod ses_manage;
pub mod sigv4;
pub mod snapshot;
pub mod sns;
pub mod space;
pub mod submission;
pub mod template;
