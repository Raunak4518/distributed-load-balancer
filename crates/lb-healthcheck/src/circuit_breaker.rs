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

/// See `CircuitBreaker::snapshot`/`from_snapshot`.
#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerSnapshot {
    creation: Instant,
    consecutive_failures: u32,
    consecutive_successes: u32,
    state: u8,
    opened_at_nanos: u64,
    trip_streak: u32,
    closed_since_nanos: u64,
}

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
    half_open_successes_required: u32,
    flap_backoff_multiplier: f64,
    max_cooldown: Duration,
    flap_streak_reset: Duration,
    consecutive_failures: AtomicU32,
    consecutive_successes: AtomicU32,
    state: AtomicU8,
    opened_at_nanos: AtomicU64,
    /// How many times this breaker has re-tripped `Open` since it last
    /// stayed `Closed` for at least `flap_streak_reset` -- see
    /// `effective_cooldown`/`try_trip`.
    trip_streak: AtomicU32,
    /// Nanoseconds since `creation` at which this breaker most recently
    /// became `Closed` (or `0`, meaning "closed since creation").
    closed_since_nanos: AtomicU64,
}

impl<C: Clock> CircuitBreaker<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        failure_threshold: u32,
        cooldown: Duration,
        half_open_successes_required: u32,
        flap_backoff_multiplier: f64,
        max_cooldown: Duration,
        flap_streak_reset: Duration,
        clock: C,
    ) -> Self {
        let creation = clock.now();
        CircuitBreaker {
            clock,
            creation,
            failure_threshold,
            cooldown,
            half_open_successes_required,
            flap_backoff_multiplier,
            max_cooldown,
            flap_streak_reset,
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            state: AtomicU8::new(CircuitState::Closed.as_u8()),
            opened_at_nanos: AtomicU64::new(NOT_OPENED),
            trip_streak: AtomicU32::new(0),
            closed_since_nanos: AtomicU64::new(0),
        }
    }

    /// Rebuilds a breaker for the same backend with `failure_threshold`/
    /// `cooldown`/`half_open_successes_required`/the flap-backoff settings
    /// taken fresh (an operator may have just changed any of these in the
    /// same config edit that's carrying this state forward) but its live
    /// state -- Open/HalfOpen/Closed, the failure/success counts, the flap
    /// streak, and the cooldown clock -- taken from `snapshot`. Used by
    /// config reload, so a backend mid-cooldown or mid-recovery when an
    /// unrelated field on its listener changes does not get a clean slate
    /// and go straight back into rotation.
    #[allow(clippy::too_many_arguments)]
    pub fn from_snapshot(
        failure_threshold: u32,
        cooldown: Duration,
        half_open_successes_required: u32,
        flap_backoff_multiplier: f64,
        max_cooldown: Duration,
        flap_streak_reset: Duration,
        clock: C,
        snapshot: CircuitBreakerSnapshot,
    ) -> Self {
        CircuitBreaker {
            clock,
            creation: snapshot.creation,
            failure_threshold,
            cooldown,
            half_open_successes_required,
            flap_backoff_multiplier,
            max_cooldown,
            flap_streak_reset,
            consecutive_failures: AtomicU32::new(snapshot.consecutive_failures),
            consecutive_successes: AtomicU32::new(snapshot.consecutive_successes),
            state: AtomicU8::new(snapshot.state),
            opened_at_nanos: AtomicU64::new(snapshot.opened_at_nanos),
            trip_streak: AtomicU32::new(snapshot.trip_streak),
            closed_since_nanos: AtomicU64::new(snapshot.closed_since_nanos),
        }
    }

    /// A `Copy`able capture of this breaker's live state, for `from_snapshot`
    /// to rebuild an equivalent breaker elsewhere -- see its own docs.
    pub fn snapshot(&self) -> CircuitBreakerSnapshot {
        CircuitBreakerSnapshot {
            creation: self.creation,
            consecutive_failures: self.consecutive_failures.load(Ordering::SeqCst),
            consecutive_successes: self.consecutive_successes.load(Ordering::SeqCst),
            state: self.state.load(Ordering::SeqCst),
            opened_at_nanos: self.opened_at_nanos.load(Ordering::SeqCst),
            trip_streak: self.trip_streak.load(Ordering::SeqCst),
            closed_since_nanos: self.closed_since_nanos.load(Ordering::SeqCst),
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

    /// The cooldown this breaker's *current* Open episode actually uses:
    /// `cooldown` scaled by `flap_backoff_multiplier` raised to one less
    /// than the current flap streak (so an isolated trip, streak 1, always
    /// gets the plain configured cooldown), capped at `max_cooldown`.
    fn effective_cooldown(&self) -> Duration {
        let streak = self.trip_streak.load(Ordering::SeqCst).max(1);
        let scaled =
            self.cooldown.as_secs_f64() * self.flap_backoff_multiplier.powi(streak as i32 - 1);
        Duration::from_secs_f64(scaled.min(self.max_cooldown.as_secs_f64()))
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
        if self.clock.now().duration_since(opened_at) >= self.effective_cooldown() {
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
        if self.load_state() != CircuitState::HalfOpen {
            // A success while Closed (nothing to recover from) or Open (see
            // `a_stale_success_while_open_does_not_cancel_the_cooldown`) has
            // no further effect.
            return;
        }
        let successes = self.consecutive_successes.fetch_add(1, Ordering::SeqCst) + 1;
        if successes >= self.half_open_successes_required {
            let closed = self
                .state
                .compare_exchange(
                    CircuitState::HalfOpen.as_u8(),
                    CircuitState::Closed.as_u8(),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok();
            self.consecutive_successes.store(0, Ordering::SeqCst);
            if closed {
                let nanos = self.clock.now().duration_since(self.creation).as_nanos() as u64;
                self.closed_since_nanos.store(nanos, Ordering::SeqCst);
            }
        }
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
            self.consecutive_successes.store(0, Ordering::SeqCst);

            let closed_since = self.closed_since_nanos.load(Ordering::SeqCst);
            let closed_duration = Duration::from_nanos(nanos.saturating_sub(closed_since));
            if closed_duration >= self.flap_streak_reset {
                // Long enough healthy stretch since the last trip: this one
                // starts a fresh flap streak rather than continuing the old
                // one.
                self.trip_streak.store(0, Ordering::SeqCst);
            }
            self.trip_streak.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;
    use std::sync::Arc;

    fn breaker(threshold: u32, cooldown: Duration) -> (CircuitBreaker<FakeClock>, FakeClock) {
        breaker_with_recovery(threshold, cooldown, 1)
    }

    fn breaker_with_recovery(
        threshold: u32,
        cooldown: Duration,
        half_open_successes_required: u32,
    ) -> (CircuitBreaker<FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        (
            CircuitBreaker::new(
                threshold,
                cooldown,
                half_open_successes_required,
                1.0,
                Duration::from_secs(1_000_000_000),
                Duration::from_secs(60),
                clock.clone(),
            ),
            clock,
        )
    }

    fn breaker_with_flap_backoff(
        threshold: u32,
        cooldown: Duration,
        flap_backoff_multiplier: f64,
        max_cooldown: Duration,
        flap_streak_reset: Duration,
    ) -> (CircuitBreaker<FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        (
            CircuitBreaker::new(
                threshold,
                cooldown,
                1,
                flap_backoff_multiplier,
                max_cooldown,
                flap_streak_reset,
                clock.clone(),
            ),
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
    fn stays_half_open_below_the_required_consecutive_successes() {
        let (cb, clock) = breaker_with_recovery(1, Duration::from_secs(5), 3);
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "only 2 of the 3 required consecutive successes landed"
        );
    }

    #[test]
    fn closes_after_exactly_n_consecutive_half_open_successes() {
        let (cb, clock) = breaker_with_recovery(1, Duration::from_secs(5), 3);
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn an_intervening_failure_resets_the_half_open_success_streak() {
        let (cb, clock) = breaker_with_recovery(1, Duration::from_secs(5), 3);
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        cb.record_success();
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "a failure mid-recovery re-trips the breaker"
        );
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "the earlier 2 successes before the failure must not count toward this recovery"
        );
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

    #[test]
    fn a_lone_trip_uses_the_plain_cooldown() {
        let (cb, clock) = breaker_with_flap_backoff(
            1,
            Duration::from_secs(5),
            2.0,
            Duration::from_secs(100),
            Duration::from_secs(60),
        );
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "a first-ever trip must not be scaled by the flap-backoff multiplier"
        );
    }

    #[test]
    fn repeated_flapping_doubles_the_cooldown_each_time() {
        let (cb, clock) = breaker_with_flap_backoff(
            1,
            Duration::from_secs(5),
            2.0,
            Duration::from_secs(1000),
            Duration::from_secs(60),
        );
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "a second re-trip within the flap-streak-reset window"
        );
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "cooldown should now be 5s * 2^1 = 10s, only 5s have passed"
        );
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn the_scaled_cooldown_is_capped_at_the_configured_ceiling() {
        let (cb, clock) = breaker_with_flap_backoff(
            1,
            Duration::from_secs(5),
            2.0,
            Duration::from_secs(8),
            Duration::from_secs(60),
        );
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // uncapped this would be 10s; the 8s ceiling applies instead
        clock.advance(Duration::from_secs(7));
        assert_eq!(cb.state(), CircuitState::Open);
        clock.advance(Duration::from_secs(1));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn a_sustained_healthy_period_resets_the_flap_streak() {
        let (cb, clock) = breaker_with_flap_backoff(
            1,
            Duration::from_secs(5),
            2.0,
            Duration::from_secs(1000),
            Duration::from_secs(30),
        );
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        clock.advance(Duration::from_secs(31));
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "a long enough healthy stretch means this trip starts a fresh streak"
        );
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "cooldown should be the plain 5s again, not doubled"
        );
    }

    #[test]
    fn from_snapshot_preserves_the_flap_streak() {
        let (cb, clock) = breaker_with_flap_backoff(
            1,
            Duration::from_secs(5),
            2.0,
            Duration::from_secs(1000),
            Duration::from_secs(60),
        );
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        let migrated = CircuitBreaker::from_snapshot(
            1,
            Duration::from_secs(5),
            1,
            2.0,
            Duration::from_secs(1000),
            Duration::from_secs(60),
            clock.clone(),
            cb.snapshot(),
        );
        assert_eq!(migrated.state(), CircuitState::Open);
        clock.advance(Duration::from_secs(9));
        assert_eq!(
            migrated.state(),
            CircuitState::Open,
            "the flap streak of 2 (10s cooldown) must survive the migration"
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(migrated.state(), CircuitState::HalfOpen);
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
            1,
            1.0,
            Duration::from_secs(1_000_000_000),
            Duration::from_secs(60),
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

    #[test]
    fn from_snapshot_preserves_open_state_and_cooldown_progress() {
        let (cb, clock) = breaker(1, Duration::from_secs(10));
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        clock.advance(Duration::from_secs(4));

        let migrated = CircuitBreaker::from_snapshot(
            1,
            Duration::from_secs(10),
            1,
            1.0,
            Duration::from_secs(1_000_000_000),
            Duration::from_secs(60),
            clock.clone(),
            cb.snapshot(),
        );
        assert_eq!(migrated.state(), CircuitState::Open);
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            migrated.state(),
            CircuitState::Open,
            "only 9 of the original 10s cooldown have elapsed"
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(migrated.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn from_snapshot_preserves_a_closed_breakers_failure_count() {
        let (cb, clock) = breaker(3, Duration::from_secs(5));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        let migrated = CircuitBreaker::from_snapshot(
            3,
            Duration::from_secs(5),
            1,
            1.0,
            Duration::from_secs(1_000_000_000),
            Duration::from_secs(60),
            clock,
            cb.snapshot(),
        );
        migrated.record_failure();
        assert_eq!(
            migrated.state(),
            CircuitState::Open,
            "the third failure should trip it, since 2 were already carried over"
        );
    }

    #[test]
    fn from_snapshot_preserves_a_half_open_breakers_success_count() {
        let (cb, clock) = breaker_with_recovery(1, Duration::from_secs(5), 3);
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        cb.record_success();

        let migrated = CircuitBreaker::from_snapshot(
            1,
            Duration::from_secs(5),
            3,
            1.0,
            Duration::from_secs(1_000_000_000),
            Duration::from_secs(60),
            clock,
            cb.snapshot(),
        );
        migrated.record_success();
        assert_eq!(
            migrated.state(),
            CircuitState::Closed,
            "the third success should close it, since 2 were already carried over"
        );
    }
}
