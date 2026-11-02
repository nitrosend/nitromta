//! The engine's stop: whether it is stopping, and the client
//! transactions under way, which it lets finish before it exits, so none
//! loses its acknowledgement.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Stop {
    stopping: AtomicBool,
    under_way: AtomicUsize,
    idle: Notify,
    /// Cancelled as the stop starts, for the connections that close then.
    closing: CancellationToken,
}

impl Stop {
    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Starts a client transaction: `None` once the engine is stopping,
    /// when the client is told to try again. It counts itself before it
    /// looks, so a stop never misses it.
    pub fn begin(&self) -> Option<UnderWay<'_>> {
        self.under_way.fetch_add(1, Ordering::SeqCst);
        let under_way = UnderWay(self);
        (!self.stopping()).then_some(under_way)
    }

    /// Refuses new transactions from now on, and closes the connections
    /// that wait on [`Stop::closing`].
    pub fn start(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.closing.cancel();
    }

    /// Cancelled once the stop starts. Each connection takes its own, so
    /// waiting on it shares no lock with the others.
    pub fn closing(&self) -> CancellationToken {
        self.closing.child_token()
    }

    /// Waits until no client transaction is under way.
    pub async fn finished(&self) {
        loop {
            let idle = self.idle.notified();
            if self.under_way.load(Ordering::SeqCst) == 0 {
                return;
            }
            idle.await;
        }
    }
}

/// A client transaction under way, or a connection counted while it is
/// open, until it is dropped: once its reply is written.
pub struct UnderWay<'a>(&'a Stop);

impl Drop for UnderWay<'_> {
    fn drop(&mut self) {
        if self.0.under_way.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_stop_waits_for_the_transactions_under_way_and_refuses_new_ones() {
        let stop = Stop::default();
        let under_way = stop.begin().expect("not stopping");
        stop.start();
        assert!(stop.begin().is_none(), "refused once stopping");
        let finished = stop.finished();
        tokio::pin!(finished);
        assert!(
            futures_poll(&mut finished).await.is_none(),
            "one is under way"
        );
        drop(under_way);
        finished.await;
    }

    #[test]
    fn the_stop_closes_connections_open_before_it_and_after() {
        let stop = Stop::default();
        let before = stop.closing();
        assert!(!before.is_cancelled());
        stop.start();
        assert!(before.is_cancelled());
        assert!(stop.closing().is_cancelled());
    }

    /// Polls a future once.
    async fn futures_poll<F: std::future::Future + Unpin>(future: &mut F) -> Option<F::Output> {
        tokio::time::timeout(std::time::Duration::from_millis(10), future)
            .await
            .ok()
    }
}
