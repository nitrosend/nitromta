//! The component contract.
//!
//! Every long-lived component (the commit owner, the scheduler, an SMTP
//! session, event delivery, feedback intake) is a deterministic state
//! machine behind [`Component`], and both drivers run it: the production
//! shell on real threads, sockets and clocks, and the simulator on one
//! thread from a seeded event queue. A driver carries inputs and outputs,
//! performs the I/O that outputs ask for, and supplies the time. It makes no
//! decision of its own, so the simulator exercises the production wiring
//! rather than a copy of it.
//!
//! A component owns the [`Rng`](crate::rng::Rng) its driver seeds for it at
//! construction, and never reads time except from the [`Now`] it is given.

use crate::time::{Monotonic, Now};

/// Identifies a request, so its answer reaches whoever asked. The driver
/// assigns tickets, unique among the requests in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticket(pub u64);

pub trait Component {
    /// Everything the component can be told: messages from other
    /// components, and the results of I/O it asked for.
    type Input;

    /// Everything it can ask for. Each output is addressed by its type: to
    /// another component, to I/O, or to a caller waiting for a reply.
    type Output;

    /// Takes one input. A driver may deliver several before it calls
    /// [`poll`](Self::poll), so a component that batches (the commit owner's
    /// group commit) collects the work here and does it once.
    fn handle(&mut self, now: Now, input: Self::Input);

    /// Does the work that its inputs and the passage of time call for,
    /// appends its outputs to `out`, and returns when it next needs polling
    /// without new input.
    ///
    /// The driver calls it after every batch of inputs, and again once the
    /// returned time has passed. It may also call it when nothing is due, so
    /// a component does only the work that is due and returns its next time
    /// again. `out` belongs to the driver and is reused from call to call,
    /// so producing outputs allocates nothing in the steady state.
    fn poll(&mut self, now: Now, out: &mut Vec<Self::Output>) -> Option<Monotonic>;
}
