//! Runs one component as the component contract describes, as the
//! production shell does: inputs are handed over as they arrive, the
//! component is polled once for each batch, and polled again when the time
//! it asked for comes. A world keeps one [`Host`] per component and
//! schedules the polls and wakes it asks for.

use engine_core::component::Component;
use engine_core::time::{Monotonic, Now};

pub struct Host<C: Component> {
    component: C,
    poll_scheduled: bool,
    wake_scheduled: Option<Monotonic>,
}

impl<C: Component> Host<C> {
    pub fn new(component: C) -> Self {
        Self {
            component,
            poll_scheduled: false,
            wake_scheduled: None,
        }
    }

    /// Hands over one input. Returns `true` when the world must schedule a
    /// poll: inputs that arrive before it runs join the same batch.
    #[must_use = "a delivered input is only acted on when the component is polled"]
    pub fn deliver(&mut self, now: Now, input: C::Input) -> bool {
        self.component.handle(now, input);
        !std::mem::replace(&mut self.poll_scheduled, true)
    }

    /// Polls the component, appending its outputs to `out`. Returns a wake
    /// the world must schedule, when the component asks for one that is not
    /// already scheduled.
    #[must_use = "a requested wake must be scheduled"]
    pub fn poll(&mut self, now: Now, out: &mut Vec<C::Output>) -> Option<Monotonic> {
        self.poll_scheduled = false;
        let wake = self.component.poll(now, out)?;
        (self.wake_scheduled != Some(wake)).then(|| {
            self.wake_scheduled = Some(wake);
            wake
        })
    }

    /// Whether a wake that fires at `at` is still the one the component
    /// asked for; the world polls only if it is. A wake the component has
    /// since replaced is ignored.
    #[must_use]
    pub fn take_wake(&mut self, at: Monotonic) -> bool {
        let current = self.wake_scheduled == Some(at);
        if current {
            self.wake_scheduled = None;
        }
        current
    }

    pub fn component(&self) -> &C {
        &self.component
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::time::Timestamp;

    /// Returns the wakes it is given, one per poll.
    struct Scripted {
        wakes: Vec<Option<Monotonic>>,
    }

    impl Component for Scripted {
        type Input = ();
        type Output = ();

        fn handle(&mut self, _now: Now, _input: ()) {}

        fn poll(&mut self, _now: Now, _out: &mut Vec<()>) -> Option<Monotonic> {
            self.wakes.remove(0)
        }
    }

    const NOW: Now = Now {
        wall: Timestamp::from_micros(1_000),
        monotonic: Monotonic::from_micros(0),
    };

    fn at(micros: u64) -> Monotonic {
        Monotonic::from_micros(micros)
    }

    fn host(wakes: &[Option<Monotonic>]) -> Host<Scripted> {
        Host::new(Scripted {
            wakes: wakes.to_vec(),
        })
    }

    #[test]
    fn inputs_join_one_batch_until_the_poll() {
        let mut host = host(&[None]);
        assert!(host.deliver(NOW, ()));
        assert!(!host.deliver(NOW, ()));
        assert_eq!(host.poll(NOW, &mut Vec::new()), None);
        assert!(host.deliver(NOW, ()));
    }

    #[test]
    fn a_replaced_wake_is_ignored() {
        let mut host = host(&[Some(at(50)), Some(at(20))]);
        assert_eq!(host.poll(NOW, &mut Vec::new()), Some(at(50)));
        assert_eq!(host.poll(NOW, &mut Vec::new()), Some(at(20)));
        assert!(!host.take_wake(at(50)));
        assert!(host.take_wake(at(20)));
        assert!(!host.take_wake(at(20)));
    }

    #[test]
    fn an_unchanged_wake_is_scheduled_once() {
        let mut host = host(&[Some(at(50)), Some(at(50))]);
        assert_eq!(host.poll(NOW, &mut Vec::new()), Some(at(50)));
        assert_eq!(host.poll(NOW, &mut Vec::new()), None);
    }
}
