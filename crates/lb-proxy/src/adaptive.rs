use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AdaptiveConfig {
    pub initial_limit: usize,
    pub min_limit: usize,
    pub max_limit: usize,
    pub smoothing: f64,
    pub tolerance: f64,
}

const LONG_WINDOW: f64 = 600.0;
const FAILURE_BACKOFF: f64 = 0.9;

struct State {
    estimated: f64,
    long_rtt: Option<f64>,
}

pub struct AdaptiveLimit {
    cfg: AdaptiveConfig,
    state: Mutex<State>,
    limit: AtomicUsize,
    in_flight: AtomicUsize,
}

impl AdaptiveLimit {
    pub fn new(cfg: AdaptiveConfig) -> Self {
        let initial = cfg.initial_limit.clamp(cfg.min_limit, cfg.max_limit);
        AdaptiveLimit {
            cfg,
            state: Mutex::new(State {
                estimated: initial as f64,
                long_rtt: None,
            }),
            limit: AtomicUsize::new(initial),
            in_flight: AtomicUsize::new(0),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Relaxed)
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<AdaptiveGuard> {
        let limit = self.limit();
        let mut current = self.in_flight.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(AdaptiveGuard {
                        limit: Arc::clone(self),
                        in_flight_at_start: current + 1,
                    })
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn publish(&self, state: &State) {
        let rounded = state.estimated.round() as usize;
        self.limit.store(
            rounded.clamp(self.cfg.min_limit, self.cfg.max_limit),
            Ordering::Relaxed,
        );
    }

    fn on_sample(&self, rtt: Duration, in_flight_at_start: usize) {
        let rtt = rtt.as_secs_f64().max(1e-6);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let long = match state.long_rtt {
            None => rtt,
            Some(long) => {
                let mut long = long + (rtt - long) / LONG_WINDOW;
                if long / rtt > 2.0 {
                    long *= 0.95;
                }
                long
            }
        };
        state.long_rtt = Some(long);
        if (in_flight_at_start as f64) < state.estimated / 2.0 {
            return;
        }
        let gradient = (self.cfg.tolerance * long / rtt).clamp(0.5, 1.0);
        let queue = state.estimated.sqrt();
        let target = state.estimated * gradient + queue;
        state.estimated = (state.estimated * (1.0 - self.cfg.smoothing)
            + target * self.cfg.smoothing)
            .clamp(self.cfg.min_limit as f64, self.cfg.max_limit as f64);
        self.publish(&state);
    }

    fn on_failure(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.estimated = (state.estimated * FAILURE_BACKOFF).max(self.cfg.min_limit as f64);
        self.publish(&state);
    }
}

pub struct AdaptiveGuard {
    limit: Arc<AdaptiveLimit>,
    in_flight_at_start: usize,
}

impl AdaptiveGuard {
    pub fn record(&self, rtt: Duration) {
        self.limit.on_sample(rtt, self.in_flight_at_start);
    }

    pub fn record_failure(&self) {
        self.limit.on_failure();
    }

    pub fn current_limit(&self) -> usize {
        self.limit.limit()
    }
}

impl Drop for AdaptiveGuard {
    fn drop(&mut self) {
        self.limit.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AdaptiveConfig {
        AdaptiveConfig {
            initial_limit: 10,
            min_limit: 2,
            max_limit: 200,
            smoothing: 0.2,
            tolerance: 1.5,
        }
    }

    fn saturate(limit: &Arc<AdaptiveLimit>, rtt: Duration, rounds: usize) {
        for _ in 0..rounds {
            let guards: Vec<_> = std::iter::from_fn(|| limit.try_acquire()).collect();
            for guard in &guards {
                guard.record(rtt);
            }
        }
    }

    #[test]
    fn requests_past_the_limit_are_refused_and_slots_return_on_drop() {
        let limit = Arc::new(AdaptiveLimit::new(cfg()));
        let guards: Vec<_> = std::iter::from_fn(|| limit.try_acquire()).collect();
        assert_eq!(guards.len(), 10);
        assert!(limit.try_acquire().is_none());
        drop(guards);
        assert_eq!(limit.in_flight(), 0);
        assert!(limit.try_acquire().is_some());
    }

    #[test]
    fn a_fully_used_backend_at_steady_latency_earns_a_higher_limit() {
        let limit = Arc::new(AdaptiveLimit::new(cfg()));
        saturate(&limit, Duration::from_millis(20), 30);
        assert!(limit.limit() > 30, "limit only reached {}", limit.limit());
        assert!(limit.limit() <= 200);
    }

    #[test]
    fn rising_latency_shrinks_the_limit() {
        let limit = Arc::new(AdaptiveLimit::new(cfg()));
        saturate(&limit, Duration::from_millis(20), 30);
        let before = limit.limit();
        saturate(&limit, Duration::from_millis(200), 1);
        assert!(
            limit.limit() < before / 2,
            "limit went from {before} to {} despite 10x latency",
            limit.limit()
        );
        assert!(limit.limit() >= 2);
    }

    #[test]
    fn a_lightly_used_backend_keeps_its_limit() {
        let limit = Arc::new(AdaptiveLimit::new(cfg()));
        for _ in 0..200 {
            let guard = limit.try_acquire().unwrap();
            guard.record(Duration::from_millis(20));
        }
        assert_eq!(limit.limit(), 10);
    }

    #[test]
    fn failures_shrink_the_limit_down_to_the_floor() {
        let limit = Arc::new(AdaptiveLimit::new(cfg()));
        for _ in 0..100 {
            limit.try_acquire().unwrap().record_failure();
        }
        assert_eq!(limit.limit(), 2);
    }
}
