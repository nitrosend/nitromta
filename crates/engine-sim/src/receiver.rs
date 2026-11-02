//! What simulated receivers say: each attempt's reply as a real receiver
//! words it, so the journal holds evidence of its real size.

use engine_core::attempt::Evidence;
use engine_scheduler::Attempted;

/// The receiver's reply to an attempt that ended as `result`, if it
/// replied at all.
pub fn reply(result: Attempted) -> Option<Evidence> {
    let (code, text) = match result {
        Attempted::Delivered => (250, "2.0.0 Ok: queued as 4ZzPqB0vXcz9"),
        Attempted::Rejected => (
            550,
            "5.1.1 <rcpt@example.com>: Recipient address rejected: User unknown in virtual mailbox table",
        ),
        Attempted::Deferred => (451, "4.7.1 Try again later"),
        Attempted::Throttled => (421, "4.7.0 Too many connections, try again later"),
        // No receiver was asked in capture mode.
        Attempted::NotSent | Attempted::Uncertain | Attempted::Captured => return None,
    };
    Some(Evidence::new(code, text))
}
