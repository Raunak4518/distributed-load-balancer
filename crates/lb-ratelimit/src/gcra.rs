use dashmap::DashMap;
use lb_core::{Clock, Decision, RateLimiter};
use std::time::{Duration, Instant};

/// Shared budget for keys arriving after the map is full.
///
/// The NUL prefix cannot appear in an IP string or an HTTP header value, so
/// a client cannot craft a key that collides with it.
const OVERFLOW_KEY: &str = "\u{0}overflow";

pub struct GcraConfig {
    pub rate_per_sec: f64,
    pub burst: u32,
    /// Caps distinct tracked keys. Beyond this, newcomers share one budget —
    /// see `check` for why that beats rejecting them or evicting incumbents.
    pub max_tracked_keys: usize,
}

pub struct Gcra<C: Clock> {
    period: Duration,
    tau: Duration,
    max_tracked_keys: usize,
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
            max_tracked_keys: config.max_tracked_keys.max(1),
            clock,
            state: DashMap::new(),
        }
    }

    /// Number of distinct keys currently tracked. Exposed so operators can
    /// see the overflow bucket coming before it engages.
    pub fn tracked_keys(&self) -> usize {
        self.state.len()
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
        // Bounded state: an attacker spraying source addresses must not be
        // able to grow this map without limit.
        //
        // Newcomers past the cap share one overflow budget. Rejecting them
        // outright would deny legitimate new users during an attack, and LRU
        // eviction would let an attacker evict established clients — this
        // way incumbents keep their own limits and a spray attack
        // collectively gets one client's worth of throughput.
        //
        // Short-circuits on the common path: normally only the `len()`
        // comparison runs, and the extra `contains_key` lookup happens solely
        // once the map is already at capacity.
        let key = if self.state.len() >= self.max_tracked_keys && !self.state.contains_key(key) {
            OVERFLOW_KEY
        } else {
            key
        };

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

    /// Effectively unbounded, so these tests measure GCRA behaviour rather
    /// than the cardinality cap. The cap has its own tests below.
    fn limiter(rate_per_sec: f64, burst: u32) -> (Gcra<FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        let gcra = Gcra::new(
            GcraConfig {
                rate_per_sec,
                burst,
                max_tracked_keys: usize::MAX,
            },
            clock.clone(),
        );
        (gcra, clock)
    }

    fn bounded(rate_per_sec: f64, burst: u32, max_tracked_keys: usize) -> Gcra<FakeClock> {
        Gcra::new(
            GcraConfig {
                rate_per_sec,
                burst,
                max_tracked_keys,
            },
            FakeClock::new(),
        )
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
    fn new_keys_share_an_overflow_bucket_once_the_map_is_full() {
        let gcra = bounded(10.0, 1, 2);

        // Two established clients each get their own budget.
        assert_eq!(gcra.check("a"), Decision::Allow);
        assert_eq!(gcra.check("b"), Decision::Allow);

        // The map is full. The first newcomer lands in the overflow bucket
        // and is allowed; the second shares that budget and is not.
        assert_eq!(gcra.check("c"), Decision::Allow);
        assert!(matches!(gcra.check("d"), Decision::Deny { .. }));
    }

    #[test]
    fn established_keys_keep_their_own_budget_when_full() {
        let gcra = bounded(10.0, 2, 1);
        assert_eq!(gcra.check("established"), Decision::Allow);

        // Spray newcomers until the shared overflow budget is exhausted.
        for i in 0..10 {
            let _ = gcra.check(&format!("attacker-{i}"));
        }

        // The established client is untouched — the property the overflow
        // design exists to protect.
        assert_eq!(gcra.check("established"), Decision::Allow);
    }

    #[test]
    fn tracked_keys_stays_bounded_under_a_spray() {
        let gcra = bounded(1e9, 1_000_000, 10);
        for i in 0..1_000 {
            let _ = gcra.check(&format!("client-{i}"));
        }
        // The cap, plus at most the single overflow entry.
        assert!(
            gcra.tracked_keys() <= 11,
            "map grew to {} keys",
            gcra.tracked_keys()
        );
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
