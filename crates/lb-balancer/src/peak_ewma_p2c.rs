use lb_core::{BackendId, BackendPool, Clock, LoadBalancer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

const DEFAULT_DECAY: Duration = Duration::from_secs(10);
const DEFAULT_ESTIMATE_NANOS: u64 = 1_000_000_000;
const NO_SAMPLE: u64 = u64::MAX;

struct EwmaEntry {
    estimate_nanos: AtomicU64,
    last_update_nanos: AtomicU64,
    update_lock: Mutex<()>,
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
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        self.pick_excluding(pool, key, &[])
    }

    fn pick_excluding(
        &self,
        pool: &BackendPool,
        _key: &str,
        excluded: &[BackendId],
    ) -> Option<BackendId> {
        let mut eligible = pool.eligible_backends();
        eligible.retain(|id| !excluded.contains(id));
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
        let sample_nanos = latency.as_nanos().min((NO_SAMPLE - 1) as u128) as u64;

        if let Some(entry) = self.entries.read().unwrap().get(id) {
            store_sample(entry, sample_nanos, now_nanos, self.decay);
            return;
        }
        let mut entries = self.entries.write().unwrap();
        let entry = entries.entry(id.clone()).or_insert_with(|| EwmaEntry {
            estimate_nanos: AtomicU64::new(NO_SAMPLE),
            last_update_nanos: AtomicU64::new(0),
            update_lock: Mutex::new(()),
        });
        store_sample(entry, sample_nanos, now_nanos, self.decay);
    }
}

fn store_sample(entry: &EwmaEntry, sample_nanos: u64, now_nanos: u64, decay: Duration) {
    let _guard = entry.update_lock.lock().unwrap();
    let prev = entry.estimate_nanos.load(Ordering::Relaxed);
    let new_estimate = if prev == NO_SAMPLE {
        sample_nanos
    } else {
        let last = entry.last_update_nanos.load(Ordering::Relaxed);
        let dt_nanos = now_nanos.saturating_sub(last) as f64;
        let decay_nanos = decay.as_nanos() as f64;
        let weight = if decay_nanos > 0.0 {
            (-dt_nanos / decay_nanos).exp()
        } else {
            0.0
        };
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
    fn a_duration_max_latency_saturates_instead_of_wrapping_into_the_no_sample_sentinel() {
        let lb = PeakEwmaP2c::new(FakeClock::new());
        let id = BackendId::new("b1");
        lb.record_latency(&id, Duration::MAX);
        assert!(
            lb.has_sample(&id),
            "a recorded latency must never be mistaken for no sample at all"
        );
        assert_eq!(
            lb.estimate_nanos(&id),
            NO_SAMPLE - 1,
            "an as-u64 latency at or beyond u64::MAX must saturate to NO_SAMPLE - 1, not wrap"
        );
    }

    #[test]
    fn zero_decay_with_zero_elapsed_time_does_not_produce_a_nan_estimate() {
        let lb = PeakEwmaP2c::with_decay(FakeClock::new(), Duration::ZERO);
        let id = BackendId::new("b1");
        lb.record_latency(&id, Duration::from_millis(100));
        lb.record_latency(&id, Duration::from_millis(50));
        assert_eq!(
            lb.estimate_nanos(&id),
            Duration::from_millis(50).as_nanos() as u64,
            "zero decay must fully trust the newest sample, not divide 0.0/0.0 into NaN \
             (which an `as u64` cast would silently turn into 0)"
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

    #[test]
    fn nanosecond_scale_samples_decay_to_the_precisely_predicted_weighted_value() {
        let clock = FakeClock::new();
        let lb = PeakEwmaP2c::new(clock.clone());
        let id = BackendId::new("b1");
        lb.record_latency(&id, Duration::from_nanos(1));
        assert_eq!(lb.estimate_nanos(&id), 1);

        clock.advance(Duration::from_nanos(500));
        lb.record_latency(&id, Duration::from_nanos(700));
        assert_eq!(
            lb.estimate_nanos(&id),
            1,
            "at a 10s decay constant a 500ns gap barely moves the weight off 1.0, \
             so the estimate should still round down to the prior 1ns sample"
        );
    }

    #[test]
    fn multi_day_latencies_decay_to_the_precisely_predicted_weighted_value_without_overflow() {
        let clock = FakeClock::new();
        let lb = PeakEwmaP2c::new(clock.clone());
        let id = BackendId::new("b1");
        let slow = Duration::from_secs(3 * 24 * 3600);
        lb.record_latency(&id, slow);
        assert_eq!(lb.estimate_nanos(&id), slow.as_nanos() as u64);

        clock.advance(Duration::from_secs(3600));
        let fast = Duration::from_secs(24 * 3600);
        lb.record_latency(&id, fast);
        assert_eq!(
            lb.estimate_nanos(&id),
            fast.as_nanos() as u64,
            "one hour at a 10s decay constant is ~360 time constants, so the weight on \
             the stale 3-day estimate underflows to exactly 0.0 and the new sample wins outright"
        );
    }

    #[test]
    fn a_hundred_day_idle_gap_lets_the_new_sample_fully_dominate() {
        let clock = FakeClock::new();
        let lb = PeakEwmaP2c::with_decay(clock.clone(), Duration::from_secs(10));
        let id = BackendId::new("b1");
        lb.record_latency(&id, Duration::from_secs(1));

        clock.advance(Duration::from_secs(3600 * 24 * 100));
        lb.record_latency(&id, Duration::from_millis(1));
        assert_eq!(
            lb.estimate_nanos(&id),
            Duration::from_millis(1).as_nanos() as u64,
            "a 100-day idle gap must not produce a negative, zero, or nonsensical weight; \
             the decay weight on the stale estimate underflows cleanly to 0.0"
        );
    }

    #[test]
    fn thousands_of_repeated_decays_stay_bounded_by_the_span_of_the_samples_fed_in() {
        let clock = FakeClock::new();
        let lb = PeakEwmaP2c::with_decay(clock.clone(), Duration::from_secs(10));
        let id = BackendId::new("b1");
        let low = Duration::from_millis(1).as_nanos() as u64;
        let high = Duration::from_millis(100).as_nanos() as u64;

        for i in 0..10_000u32 {
            clock.advance(Duration::from_millis(50));
            let sample = if i % 2 == 0 { low } else { high };
            lb.record_latency(&id, Duration::from_nanos(sample));
            let estimate = lb.estimate_nanos(&id);
            assert!(
                (low..=high).contains(&estimate),
                "iteration {i}: estimate {estimate} left the [{low}, {high}] band \
                 every sample was drawn from -- repeated decay must not drift or saturate"
            );
        }
    }

    #[test]
    fn samples_near_u64_max_decay_to_the_precisely_predicted_weighted_value() {
        let clock = FakeClock::new();
        let lb = PeakEwmaP2c::with_decay(clock.clone(), Duration::from_secs(10));
        let id = BackendId::new("b1");
        let huge_a = u64::MAX - 2;
        let huge_b = (u64::MAX / 2) - 1;
        lb.record_latency(&id, Duration::from_nanos(huge_a));
        clock.advance(Duration::from_secs(5));
        lb.record_latency(&id, Duration::from_nanos(huge_b));

        let estimate = lb.estimate_nanos(&id);
        let expected: u64 = 14_817_629_963_143_358_464;
        assert!(
            estimate.abs_diff(expected) <= 4096,
            "expected an f64-precision-bounded estimate near {expected}, got {estimate}"
        );
        assert!(
            (huge_b..=huge_a).contains(&estimate),
            "estimate {estimate} must stay within [{huge_b}, {huge_a}] despite f64 \
             precision limits above 2^53, i.e. it must not overflow past huge_a or \
             underflow past huge_b"
        );
    }

    #[test]
    fn a_zero_latency_sample_decays_the_estimate_to_the_precisely_predicted_weighted_value() {
        let clock = FakeClock::new();
        let lb = PeakEwmaP2c::with_decay(clock.clone(), Duration::from_secs(10));
        let id = BackendId::new("b1");
        lb.record_latency(&id, Duration::from_millis(100));
        clock.advance(Duration::from_secs(5));
        lb.record_latency(&id, Duration::ZERO);

        let estimate = lb.estimate_nanos(&id);
        assert!(
            (60_000_000..=61_000_000).contains(&estimate),
            "at a 10s decay constant a 5s gap gives weight=exp(-0.5)=~0.6065, so 100ms of \
             prior estimate weighted against a 0ns sample should land around 60.65ms, got {estimate}"
        );
    }

    #[test]
    fn heavy_concurrent_record_latency_on_one_backend_never_panics_or_leaves_a_stale_pairing() {
        use lb_core::SystemClock;
        use std::thread;

        let lb = Arc::new(PeakEwmaP2c::new(SystemClock));
        let id = BackendId::new("b1");
        let low = Duration::from_millis(1).as_nanos() as u64;
        let high = Duration::from_millis(100).as_nanos() as u64;

        let handles: Vec<_> = (0..16)
            .map(|t| {
                let lb = Arc::clone(&lb);
                let id = id.clone();
                thread::spawn(move || {
                    for i in 0..500u64 {
                        let sample = if (t + i) % 2 == 0 { low } else { high };
                        lb.record_latency(&id, Duration::from_nanos(sample));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let estimate = lb.estimate_nanos(&id);
        assert!(
            (low..=high).contains(&estimate),
            "8000 concurrent updates from 16 real threads, every sample in [{low}, {high}], \
             produced an out-of-band estimate {estimate} -- a torn read/compute/write would \
             surface here as a corrupted value, not just a lost update"
        );
    }

    #[test]
    fn a_same_instant_second_sample_does_not_corrupt_the_estimate_with_nan() {
        let clock = FakeClock::new();
        let lb = PeakEwmaP2c::new(clock.clone());
        let id = BackendId::new("b1");
        lb.record_latency(&id, Duration::from_millis(100));
        lb.record_latency(&id, Duration::from_millis(50));
        assert_eq!(
            lb.estimate_nanos(&id),
            Duration::from_millis(100).as_nanos() as u64,
            "with zero elapsed time the decay weight on the prior estimate is exactly 1.0, \
             so the second sample must be fully discarded rather than corrupting the \
             estimate via a stray NaN"
        );
    }
}
