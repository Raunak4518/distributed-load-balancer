use lb_core::Clock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker<C: Clock> {
    clock: C,
    failure_threshold: u32,
    cooldown: Duration,
    consecutive_failures: AtomicU32,
    state: Mutex<CircuitState>,
    opened_at: Mutex<Option<Instant>>,
}

impl<C: Clock> CircuitBreaker<C> {
    pub fn new(failure_threshold: u32, cooldown: Duration, clock: C) -> Self {
        CircuitBreaker {
            clock,
            failure_threshold,
            cooldown,
            consecutive_failures: AtomicU32::new(0),
            state: Mutex::new(CircuitState::Closed),
            opened_at: Mutex::new(None),
        }
    }

    pub fn state(&self) -> CircuitState {
        self.maybe_transition_to_half_open();
        *self.state.lock().expect("circuit breaker mutex poisoned")
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state(), CircuitState::Open)
    }

    fn maybe_transition_to_half_open(&self) {
        let mut state = self.state.lock().expect("circuit breaker mutex poisoned");
        if *state == CircuitState::Open {
            let opened_at = *self
                .opened_at
                .lock()
                .expect("circuit breaker mutex poisoned");
            if let Some(t) = opened_at {
                if self.clock.now().duration_since(t) >= self.cooldown {
                    *state = CircuitState::HalfOpen;
                }
            }
        }
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        *self.state.lock().expect("circuit breaker mutex poisoned") = CircuitState::Closed;
    }

    pub fn record_failure(&self) {
        let mut state = self.state.lock().expect("circuit breaker mutex poisoned");
        match *state {
            CircuitState::HalfOpen => self.trip(&mut state),
            CircuitState::Closed => {
                let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
                if failures >= self.failure_threshold {
                    self.trip(&mut state);
                }
            }
            CircuitState::Open => {}
        }
    }

    fn trip(&self, state: &mut CircuitState) {
        *state = CircuitState::Open;
        *self
            .opened_at
            .lock()
            .expect("circuit breaker mutex poisoned") = Some(self.clock.now());
        self.consecutive_failures.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;

    fn breaker(threshold: u32, cooldown: Duration) -> (CircuitBreaker<FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        (
            CircuitBreaker::new(threshold, cooldown, clock.clone()),
            clock,
        )
    }

    #[test]
    fn stays_closed_below_threshold() {
        let (cb, _clock) = breaker(3, Duration::from_secs(5));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn opens_at_threshold() {
        let (cb, _clock) = breaker(3, Duration::from_secs(5));
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn stays_open_before_cooldown_elapses() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        clock.advance(Duration::from_secs(4));
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn transitions_to_half_open_after_cooldown() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_success_closes_circuit() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn half_open_failure_reopens_and_resets_timer() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // cooldown timer restarted: not enough time has passed yet from this re-open
        clock.advance(Duration::from_secs(1));
        assert_eq!(cb.state(), CircuitState::Open);
    }
}
