use lb_core::{BackendId, BackendPool, Clock, LoadBalancer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

const DEFAULT_DECAY: Duration = Duration::from_secs(10);
const DEFAULT_ESTIMATE_NANOS: u64 = 1_000_000_000;
const NO_SAMPLE: u64 = u64::MAX;

struct EwmaEntry {
    estimate_nanos: AtomicU64,
    last_update_nanos: AtomicU64,
}

/// Power-of-two-choices load balancing weighted by a decaying latency
/// estimate: samples two eligible backends at random and picks whichever has
/// the lower `estimate * (pending + 1)` -- the same cost function Finagle's
/// (and, downstream of it, Linkerd's) Peak EWMA balancer uses, chosen so a
/// backend with several slow requests already outstanding looks expensive
/// immediately, via the pending-count multiplier, even before its own
/// decaying estimate has caught up.
///
/// A backend with no recorded latency yet is treated as `DEFAULT_ESTIMATE_NANOS`
/// (1s) rather than 0 -- a fresh or just-recovered backend competes on equal
/// footing with the field instead of being flooded because it looks free.
pub struct PeakEwmaP2c<C: Clock> {
    clock: C,
    creation: Instant,
    decay: Duration,
    entries: RwLock<HashMap<BackendId, EwmaEntry>>,
    rng_state: AtomicU64,
}

impl<C: Clock> PeakEwmaP2c<C> {
    pub fn new(clock: C) -> Self {
        Self::with_decay(clock, DEFAULT_DECAY)
    }

    pub fn with_decay(clock: C, decay: Duration) -> Self {
        let creation = clock.now();
        let seed = (creation.elapsed().as_nanos() as u64) ^ 0x9E3779B97F4A7C15;
        PeakEwmaP2c {
            clock,
            creation,
            decay,
            entries: RwLock::new(HashMap::new()),
            rng_state: AtomicU64::new(seed | 1),
        }
    }

    fn next_index(&self, n: usize) -> usize {
        let mut x = self.rng_state.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state.store(x, Ordering::Relaxed);
        (x % n as u64) as usize
    }

    fn estimate_nanos(&self, id: &BackendId) -> u64 {
        match self.entries.read().unwrap().get(id) {
            Some(entry) => match entry.estimate_nanos.load(Ordering::Relaxed) {
                NO_SAMPLE => DEFAULT_ESTIMATE_NANOS,
                nanos => nanos,
            },
            None => DEFAULT_ESTIMATE_NANOS,
        }
    }

    /// `false` until at least one `record_latency` call has landed for `id`.
    /// `pick` uses this, not `estimate_nanos`'s numeric default, to decide
    /// whether to compare two candidates on cost -- see `pick`'s own docs
    /// for why a numeric default alone is not enough.
    fn has_sample(&self, id: &BackendId) -> bool {
        self.entries
            .read()
            .unwrap()
            .get(id)
            .is_some_and(|entry| entry.estimate_nanos.load(Ordering::Relaxed) != NO_SAMPLE)
    }

    fn cost(&self, pool: &BackendPool, id: &BackendId) -> u128 {
        let estimate = self.estimate_nanos(id) as u128;
        let pending = pool.active_count(id) as u128;
        estimate * (pending + 1)
    }
}

impl<C: Clock> LoadBalancer for PeakEwmaP2c<C> {
    /// Samples two eligible backends and picks the cheaper one -- except
    /// when exactly one of the two has never had a `record_latency` call
    /// land for it, in which case that one wins outright, regardless of
    /// what the other's real cost is.
    ///
    /// This isn't an optimization, it's what keeps the whole scheme from
    /// getting stuck: `estimate_nanos`'s numeric default exists so a cold
    /// backend doesn't look artificially *free* (0 cost) and get flooded,
    /// but comparing that default as a plain number creates the opposite
    /// trap -- the moment any backend gets even one real, unremarkable
    /// sample (say 120ms), it will beat every other backend's still-default
    /// estimate (1s) on every future comparison, so nothing else is ever
    /// sampled again and the pool converges on a single backend regardless
    /// of its real relative speed. Treating "no sample yet" as a distinct
    /// explore-me signal, checked before any numeric comparison, is what
    /// guarantees every backend gets tried at least once.
    fn pick(&self, pool: &BackendPool, _key: &str) -> Option<BackendId> {
        let eligible = pool.eligible_backends();
        match eligible.len() {
            0 => None,
            1 => Some(eligible[0].clone()),
            n => {
                let i = self.next_index(n);
                let mut j = self.next_index(n);
                if j == i {
                    j = (j + 1) % n;
                }
                let a = &eligible[i];
                let b = &eligible[j];
                let winner = match (self.has_sample(a), self.has_sample(b)) {
                    (false, true) => a,
                    (true, false) => b,
                    _ => {
                        if self.cost(pool, a) <= self.cost(pool, b) {
                            a
                        } else {
                            b
                        }
                    }
                };
                Some(winner.clone())
            }
        }
    }

    fn record_latency(&self, id: &BackendId, latency: Duration) {
        let now_nanos = self
            .clock
            .now()
            .saturating_duration_since(self.creation)
            .as_nanos() as u64;
        let sample_nanos = latency.as_nanos() as u64;

        if let Some(entry) = self.entries.read().unwrap().get(id) {
            store_sample(entry, sample_nanos, now_nanos, self.decay);
            return;
        }
        let mut entries = self.entries.write().unwrap();
        let entry = entries.entry(id.clone()).or_insert_with(|| EwmaEntry {
            estimate_nanos: AtomicU64::new(NO_SAMPLE),
            last_update_nanos: AtomicU64::new(0),
        });
        store_sample(entry, sample_nanos, now_nanos, self.decay);
    }
}

fn store_sample(entry: &EwmaEntry, sample_nanos: u64, now_nanos: u64, decay: Duration) {
    let prev = entry.estimate_nanos.load(Ordering::Relaxed);
    let new_estimate = if prev == NO_SAMPLE {
        sample_nanos
    } else {
        let last = entry.last_update_nanos.load(Ordering::Relaxed);
        let dt_nanos = now_nanos.saturating_sub(last) as f64;
        let weight = (-dt_nanos / decay.as_nanos() as f64).exp();
        (prev as f64 * weight + sample_nanos as f64 * (1.0 - weight)) as u64
    };
    entry.estimate_nanos.store(new_estimate, Ordering::Relaxed);
    entry.last_update_nanos.store(now_nanos, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;
    use lb_core::Backend;
    use std::sync::Arc;

    fn pool_of(ids: &[&str]) -> Arc<BackendPool> {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1, None))
            .collect();
        Arc::new(BackendPool::new(backends))
    }

    #[test]
    fn a_single_eligible_backend_is_returned_without_sampling() {
        let pool = pool_of(&["b1"]);
        let lb = PeakEwmaP2c::new(FakeClock::new());
        assert_eq!(lb.pick(&pool, ""), Some(BackendId::new("b1")));
    }

    #[test]
    fn returns_none_when_nothing_is_eligible() {
        let pool = pool_of(&["b1"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let lb = PeakEwmaP2c::new(FakeClock::new());
        assert_eq!(lb.pick(&pool, ""), None);
    }

    #[test]
    fn skips_ineligible_backends() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let lb = PeakEwmaP2c::new(FakeClock::new());
        for _ in 0..20 {
            assert_eq!(lb.pick(&pool, ""), Some(BackendId::new("b2")));
        }
    }

    /// Regression for a real starvation bug: with exactly two backends,
    /// P2C always compares that same pair. If the first-ever request landed
    /// on the slower one, its one real sample (still fast in absolute terms)
    /// would permanently beat the other backend's *never-sampled* numeric
    /// default on every later comparison -- so the genuinely faster backend
    /// would never get tried again, and the pool would converge on the
    /// slower one for good, for exactly the opposite of the reason the
    /// strategy exists. `pick` must give an unsampled backend priority over
    /// a sampled one regardless of the sampled one's actual number.
    #[test]
    fn a_backend_that_already_has_a_decent_sample_does_not_starve_an_unsampled_sibling() {
        let pool = pool_of(&["sampled", "cold"]);
        let lb = PeakEwmaP2c::new(FakeClock::new());
        // A perfectly reasonable, fast-looking real sample -- deliberately
        // far below DEFAULT_ESTIMATE_NANOS, so a plain numeric comparison
        // would have it win every time.
        lb.record_latency(&BackendId::new("sampled"), Duration::from_millis(50));

        assert_eq!(
            lb.pick(&pool, ""),
            Some(BackendId::new("cold")),
            "the never-sampled backend must be preferred so it gets a chance to be measured"
        );
    }

    #[test]
    fn a_backend_with_no_samples_uses_the_default_estimate_not_zero() {
        let lb = PeakEwmaP2c::new(FakeClock::new());
        assert_eq!(
            lb.estimate_nanos(&BackendId::new("ghost")),
            DEFAULT_ESTIMATE_NANOS
        );
    }

    #[test]
    fn a_faster_backend_is_picked_far_more_often_once_latency_is_known() {
        let pool = pool_of(&["fast", "slow"]);
        let lb = PeakEwmaP2c::new(FakeClock::new());
        lb.record_latency(&BackendId::new("fast"), Duration::from_millis(1));
        lb.record_latency(&BackendId::new("slow"), Duration::from_millis(500));

        let mut fast_picks = 0;
        for _ in 0..200 {
            if lb.pick(&pool, "") == Some(BackendId::new("fast")) {
                fast_picks += 1;
            }
        }
        assert!(
            fast_picks > 150,
            "expected the fast backend to dominate p2c sampling, got {fast_picks}/200"
        );
    }

    #[test]
    fn many_pending_requests_make_a_backend_look_expensive_even_with_good_latency() {
        let pool = pool_of(&["busy", "idle"]);
        let lb = PeakEwmaP2c::new(FakeClock::new());
        lb.record_latency(&BackendId::new("busy"), Duration::from_millis(1));
        lb.record_latency(&BackendId::new("idle"), Duration::from_millis(1));
        let _guards: Vec<_> = (0..50)
            .map(|_| pool.track_active(&BackendId::new("busy")))
            .collect();

        let mut idle_picks = 0;
        for _ in 0..200 {
            if lb.pick(&pool, "") == Some(BackendId::new("idle")) {
                idle_picks += 1;
            }
        }
        assert!(
            idle_picks > 150,
            "expected the idle backend to dominate once its sibling has 50 pending, got {idle_picks}/200"
        );
    }

    #[test]
    fn the_estimate_decays_back_down_after_a_slow_sample_once_time_passes() {
        let clock = FakeClock::new();
        let lb = PeakEwmaP2c::with_decay(clock.clone(), Duration::from_secs(10));
        let id = BackendId::new("b1");
        lb.record_latency(&id, Duration::from_millis(1));
        clock.advance(Duration::from_millis(100));
        lb.record_latency(&id, Duration::from_secs(1));
        let spiked = lb.estimate_nanos(&id);
        assert!(
            spiked > Duration::from_millis(1).as_nanos() as u64,
            "a slow sample after real elapsed time should move the estimate up: spiked={spiked}"
        );

        clock.advance(Duration::from_secs(60));
        lb.record_latency(&id, Duration::from_millis(1));
        let decayed = lb.estimate_nanos(&id);

        assert!(
            decayed < spiked,
            "estimate should have decayed back down after 60s at the 10s time constant: spiked={spiked} decayed={decayed}"
        );
    }

    #[test]
    fn record_latency_is_a_pure_side_effect_visible_to_the_next_pick() {
        let lb = PeakEwmaP2c::new(FakeClock::new());
        assert_eq!(
            lb.estimate_nanos(&BackendId::new("b1")),
            DEFAULT_ESTIMATE_NANOS
        );
        lb.record_latency(&BackendId::new("b1"), Duration::from_millis(42));
        assert_eq!(
            lb.estimate_nanos(&BackendId::new("b1")),
            Duration::from_millis(42).as_nanos() as u64
        );
    }
}
