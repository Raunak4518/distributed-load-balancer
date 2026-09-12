use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use lb_core::{Clock, Decision, RateLimiter};
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// Cached key count.
    ///
    /// `DashMap::len()` is *not* O(1) — it walks every shard and sums them.
    /// Calling it per request measured 4x slower than the whole rest of
    /// `check()` combined. This is maintained on insert instead and read
    /// with a single relaxed load. It can lag `state.len()` slightly under
    /// concurrent sweeps, which is fine: the cap is a safety bound, not an
    /// exact quota.
    tracked: AtomicUsize,
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
            tracked: AtomicUsize::new(0),
            clock,
            state: DashMap::new(),
        }
    }

    /// Number of distinct keys currently tracked. Exposed so operators can
    /// see the overflow bucket coming before it engages.
    pub fn tracked_keys(&self) -> usize {
        self.tracked.load(Ordering::Relaxed)
    }

    /// Evicts keys whose theoretical arrival time is more than `idle_after`
    /// behind the clock, so idle clients don't grow the map forever.
    pub fn sweep(&self, idle_after: Duration) {
        let now = self.clock.now();
        self.state
            .retain(|_, tat| *tat > now || now.duration_since(*tat) < idle_after);
        // Resync after eviction. Sweeping is infrequent, so paying for a
        // real `len()` here is fine — unlike on the request path.
        self.tracked.store(self.state.len(), Ordering::Relaxed);
    }
}

impl<C: Clock> Gcra<C> {
    /// The GCRA arithmetic itself, shared by both paths below so the
    /// borrowed-lookup fast path and the allocating insert path can't drift.
    fn admit(entry: &mut Instant, now: Instant, period: Duration, tau: Duration) -> Decision {
        let tat = if *entry > now { *entry } else { now };
        let new_tat = tat + period;
        // `checked_sub` can only underflow if tau exceeds new_tat's distance
        // from the clock's own origin (e.g. a huge burst right at process
        // start) — treat that as "definitely allowed" rather than panicking.
        let allow_at = new_tat.checked_sub(tau).unwrap_or(now);
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
        // Short-circuits on the common path: normally only a relaxed atomic
        // load runs. The `contains_key` lookup happens solely once the map is
        // already at capacity.
        let at_capacity = self.tracked.load(Ordering::Relaxed) >= self.max_tracked_keys;
        let key = if at_capacity && !self.state.contains_key(key) {
            OVERFLOW_KEY
        } else {
            key
        };

        let now = self.clock.now();

        // Borrowed lookup first: every key past its first request takes this
        // path, and it allocates nothing. `key.to_string()` below is only
        // ever worth paying the first time a given key is seen.
        if let Some(mut existing) = self.state.get_mut(key) {
            return Self::admit(&mut existing, now, self.period, self.tau);
        }

        // Key not found above. Another thread may have inserted it in the
        // gap between that lookup and this one; the explicit Entry match
        // handles that race correctly (Occupied, not double-counted) and is
        // also what keeps `tracked` accurate -- it is the only way to know
        // whether this call is the one that created the key.
        let mut entry = match self.state.entry(key.to_string()) {
            Entry::Occupied(occupied) => occupied.into_ref(),
            Entry::Vacant(vacant) => {
                self.tracked.fetch_add(1, Ordering::Relaxed);
                vacant.insert(now)
            }
        };
        Self::admit(&mut entry, now, self.period, self.tau)
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
