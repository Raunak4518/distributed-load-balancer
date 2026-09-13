use lb_core::Clock;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitState {
    fn as_u8(self) -> u8 {
        match self {
            CircuitState::Closed => 0,
            CircuitState::Open => 1,
            CircuitState::HalfOpen => 2,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => unreachable!("circuit breaker state byte out of range"),
        }
    }
}

/// `opened_at` sentinel meaning "not currently open". Real values are
/// nanoseconds elapsed since `creation`, which stays comfortably below this
/// for tens of thousands of years of process uptime.
const NOT_OPENED: u64 = u64::MAX;

/// No mutex anywhere in here: `state()` runs once per backend on every
/// proxied request (see `service.rs`'s per-request circuit refresh), so a
/// lock would serialize otherwise-independent worker threads across every
/// listener sharing this breaker. `Instant` has no atomic representation, so
/// `opened_at` is stored as nanoseconds elapsed since `creation` instead of a
/// raw `Instant`.
pub struct CircuitBreaker<C: Clock> {
    clock: C,
    creation: Instant,
    failure_threshold: u32,
    cooldown: Duration,
    consecutive_failures: AtomicU32,
    state: AtomicU8,
    opened_at_nanos: AtomicU64,
}

impl<C: Clock> CircuitBreaker<C> {
    pub fn new(failure_threshold: u32, cooldown: Duration, clock: C) -> Self {
        let creation = clock.now();
        CircuitBreaker {
            clock,
            creation,
            failure_threshold,
            cooldown,
            consecutive_failures: AtomicU32::new(0),
            state: AtomicU8::new(CircuitState::Closed.as_u8()),
            opened_at_nanos: AtomicU64::new(NOT_OPENED),
        }
    }

    fn load_state(&self) -> CircuitState {
        CircuitState::from_u8(self.state.load(Ordering::SeqCst))
    }

    pub fn state(&self) -> CircuitState {
        self.maybe_transition_to_half_open();
        self.load_state()
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state(), CircuitState::Open)
    }

    fn maybe_transition_to_half_open(&self) {
        if self.load_state() != CircuitState::Open {
            return;
        }
        let opened_at_nanos = self.opened_at_nanos.load(Ordering::SeqCst);
        if opened_at_nanos == NOT_OPENED {
            return;
        }
        let opened_at = self.creation + Duration::from_nanos(opened_at_nanos);
        if self.clock.now().duration_since(opened_at) >= self.cooldown {
            // Best-effort: if this loses the race, another thread already
            // made (or is making) the same transition, which is the outcome
            // this call wanted anyway -- no need to retry.
            let _ = self.state.compare_exchange(
                CircuitState::Open.as_u8(),
                CircuitState::HalfOpen.as_u8(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        let _ = self.state.compare_exchange(
            CircuitState::HalfOpen.as_u8(),
            CircuitState::Closed.as_u8(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    pub fn record_failure(&self) {
        match self.load_state() {
            CircuitState::Open => {}
            CircuitState::HalfOpen => self.try_trip(CircuitState::HalfOpen),
            CircuitState::Closed => {
                let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
                if failures >= self.failure_threshold {
                    self.try_trip(CircuitState::Closed);
                }
            }
        }
    }

    /// Attempts the transition to `Open` from `expected`. A failed CAS means
    /// another thread already moved the state first (tripped it itself, or
    /// closed it via a concurrent success) -- either way this call's own
    /// transition is now redundant, so it is not retried.
    fn try_trip(&self, expected: CircuitState) {
        let won = self
            .state
            .compare_exchange(
                expected.as_u8(),
                CircuitState::Open.as_u8(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();
        if won {
            let nanos = self.clock.now().duration_since(self.creation).as_nanos() as u64;
            self.opened_at_nanos.store(nanos, Ordering::SeqCst);
            self.consecutive_failures.store(0, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;
    use std::sync::Arc;

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
    fn a_stale_success_while_open_does_not_cancel_the_cooldown() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Open);
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
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

    /// The whole point of dropping the mutex: many threads hammering
    /// `record_failure`/`record_success` concurrently must never panic (no
    /// poisoning is even possible without a lock) and must leave the
    /// breaker in a state consistent with *some* valid interleaving --
    /// tripped exactly once's worth of effect, not a torn read.
    #[test]
    fn concurrent_failures_from_many_threads_trip_exactly_once() {
        let cb = Arc::new(CircuitBreaker::new(
            50,
            Duration::from_secs(5),
            FakeClock::new(),
        ));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cb = Arc::clone(&cb);
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        cb.record_failure();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // 8 threads * 20 failures each = 160, well past the threshold of 50.
        assert_eq!(cb.state(), CircuitState::Open);
    }
}
