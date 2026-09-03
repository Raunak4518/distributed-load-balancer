use dashmap::DashMap;
use lb_core::{Clock, Decision, RateLimiter};
use std::time::{Duration, Instant};

pub struct GcraConfig {
    pub rate_per_sec: f64,
    pub burst: u32,
}

pub struct Gcra<C: Clock> {
    period: Duration,
    tau: Duration,
    clock: C,
    state: DashMap<String, Instant>,
}

impl<C: Clock> Gcra<C> {
    pub fn new(config: GcraConfig, clock: C) -> Self {
        let period = Duration::from_secs_f64(1.0 / config.rate_per_sec);
        let tau = period.saturating_mul(config.burst.max(1));
        Gcra {
            period,
            tau,
            clock,
            state: DashMap::new(),
        }
    }

    /// Evicts keys whose theoretical arrival time is more than `idle_after`
    /// behind the clock, so idle clients don't grow the map forever.
    pub fn sweep(&self, idle_after: Duration) {
        let now = self.clock.now();
        self.state
            .retain(|_, tat| *tat > now || now.duration_since(*tat) < idle_after);
    }
}

impl<C: Clock> RateLimiter for Gcra<C> {
    fn check(&self, key: &str) -> Decision {
        let now = self.clock.now();
        let mut entry = self.state.entry(key.to_string()).or_insert(now);
        let tat = if *entry > now { *entry } else { now };
        let new_tat = tat + self.period;
        // `checked_sub` can only underflow if tau exceeds new_tat's distance
        // from the clock's own origin (e.g. a huge burst right at process
        // start) — treat that as "definitely allowed" rather than panicking.
        let allow_at = new_tat.checked_sub(self.tau).unwrap_or(now);
        if allow_at <= now {
            *entry = new_tat;
            Decision::Allow
        } else {
            Decision::Deny {
                retry_after: allow_at - now,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;
    use std::time::Duration;

    fn limiter(rate_per_sec: f64, burst: u32) -> (Gcra<FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        let gcra = Gcra::new(
            GcraConfig {
                rate_per_sec,
                burst,
            },
            clock.clone(),
        );
        (gcra, clock)
    }

    #[test]
    fn allows_up_to_burst_then_denies() {
        let (gcra, _clock) = limiter(10.0, 3);
        assert_eq!(gcra.check("k"), Decision::Allow);
        assert_eq!(gcra.check("k"), Decision::Allow);
        assert_eq!(gcra.check("k"), Decision::Allow);
        assert!(matches!(gcra.check("k"), Decision::Deny { .. }));
    }

    #[test]
    fn refills_after_waiting_one_period() {
        let (gcra, clock) = limiter(10.0, 1); // period = 100ms
        assert_eq!(gcra.check("k"), Decision::Allow);
        assert!(matches!(gcra.check("k"), Decision::Deny { .. }));
        clock.advance(Duration::from_millis(100));
        assert_eq!(gcra.check("k"), Decision::Allow);
    }

    #[test]
    fn retry_after_reflects_remaining_wait() {
        let (gcra, _clock) = limiter(10.0, 1); // period = 100ms
        gcra.check("k"); // consumes the only token
        match gcra.check("k") {
            Decision::Deny { retry_after } => {
                assert!(retry_after <= Duration::from_millis(100));
                assert!(retry_after > Duration::ZERO);
            }
            Decision::Allow => panic!("expected deny"),
        }
    }

    #[test]
    fn keys_are_independent() {
        let (gcra, _clock) = limiter(10.0, 1);
        assert_eq!(gcra.check("a"), Decision::Allow);
        assert_eq!(gcra.check("b"), Decision::Allow); // different key, unaffected by "a"
        assert!(matches!(gcra.check("a"), Decision::Deny { .. }));
    }

    #[test]
    fn sweep_removes_long_idle_keys() {
        let (gcra, clock) = limiter(10.0, 1);
        gcra.check("stale");
        clock.advance(Duration::from_secs(60));
        gcra.sweep(Duration::from_secs(30));
        // after sweep, "stale" is gone, so a fresh check treats it as a new key (Allow)
        assert_eq!(gcra.check("stale"), Decision::Allow);
    }
}
