use lb_core::{BackendId, BackendMap, BackendPool};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

#[derive(Debug, Clone, Copy)]
pub struct OutlierConfig {
    pub min_volume: u32,
    pub min_hosts: usize,
    pub stddev_factor: f64,
    pub eject_ticks: u32,
}

struct BackendCounts {
    successes: AtomicU32,
    total: AtomicU32,
    flagged: AtomicBool,
    cooldown_ticks_remaining: AtomicU32,
}

pub struct OutlierDetector {
    config: OutlierConfig,
    counts: BackendMap<BackendCounts>,
}

impl BackendCounts {
    fn new() -> Self {
        BackendCounts {
            successes: AtomicU32::new(0),
            total: AtomicU32::new(0),
            flagged: AtomicBool::new(false),
            cooldown_ticks_remaining: AtomicU32::new(0),
        }
    }
}

impl OutlierDetector {
    pub fn new(ids: impl IntoIterator<Item = BackendId>, config: OutlierConfig) -> Self {
        let counts = ids
            .into_iter()
            .map(|id| (id, BackendCounts::new()))
            .collect();
        OutlierDetector { config, counts }
    }

    pub fn reconcile(&self, live: &[BackendId]) {
        self.counts.reconcile(live, |_| BackendCounts::new());
    }

    pub fn tracks(&self, id: &BackendId) -> bool {
        self.counts.contains(id)
    }

    pub fn record_outcome(&self, id: &BackendId, success: bool) {
        let Some(counts) = self.counts.get(id) else {
            return;
        };
        counts.total.fetch_add(1, Ordering::Relaxed);
        if success {
            counts.successes.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn is_outlier(&self, id: &BackendId) -> bool {
        self.counts
            .get(id)
            .is_some_and(|c| c.flagged.load(Ordering::SeqCst))
    }

    pub fn recompute(&self, pool: &BackendPool) {
        let counts = self.counts.snapshot();
        let snapshot: Vec<(&BackendId, u32, u32)> = counts
            .iter()
            .map(|(id, c)| {
                (
                    id,
                    c.successes.swap(0, Ordering::Relaxed),
                    c.total.swap(0, Ordering::Relaxed),
                )
            })
            .collect();

        let rates: Vec<(&BackendId, f64)> = snapshot
            .iter()
            .filter(|(_, _, total)| *total >= self.config.min_volume)
            .map(|(id, successes, total)| (*id, f64::from(*successes) / f64::from(*total)))
            .collect();

        let active = rates.len() >= self.config.min_hosts;
        let cutoff = if active {
            let mean = rates.iter().map(|(_, r)| r).sum::<f64>() / rates.len() as f64;
            let variance =
                rates.iter().map(|(_, r)| (r - mean).powi(2)).sum::<f64>() / rates.len() as f64;
            mean - self.config.stddev_factor * variance.sqrt()
        } else {
            f64::NEG_INFINITY
        };

        for (id, counts) in counts.iter() {
            match rates.iter().find(|(rid, _)| *rid == id) {
                Some((_, rate)) if active => {
                    let flagged = *rate < cutoff;
                    counts.flagged.store(flagged, Ordering::SeqCst);
                    counts.cooldown_ticks_remaining.store(
                        if flagged {
                            self.config.eject_ticks.max(1)
                        } else {
                            0
                        },
                        Ordering::SeqCst,
                    );
                    pool.set_outlier_ejected(id, flagged);
                }
                _ if counts.flagged.load(Ordering::SeqCst) => {
                    let before = counts
                        .cooldown_ticks_remaining
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |t| {
                            Some(t.saturating_sub(1))
                        })
                        .unwrap_or(0);
                    if before <= 1 {
                        counts.flagged.store(false, Ordering::SeqCst);
                        pool.set_outlier_ejected(id, false);
                    }
                }
                _ => {}
            }
        }
    }
}

pub fn spawn_outlier_detector(
    pool: Arc<BackendPool>,
    detector: Arc<OutlierDetector>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            detector.recompute(&pool);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::Backend;

    fn detector(ids: &[&str], config: OutlierConfig) -> OutlierDetector {
        OutlierDetector::new(ids.iter().map(|s| BackendId::new(*s)), config)
    }

    fn pool_of(ids: &[&str]) -> BackendPool {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1, None))
            .collect();
        BackendPool::new(backends)
    }

    fn default_config() -> OutlierConfig {
        OutlierConfig {
            min_volume: 10,
            min_hosts: 2,
            stddev_factor: 0.5,
            eject_ticks: 1,
        }
    }

    #[test]
    fn a_fresh_detector_flags_nothing() {
        let d = detector(&["b1", "b2"], default_config());
        assert!(!d.is_outlier(&BackendId::new("b1")));
    }

    #[test]
    fn record_outcome_on_an_unknown_id_does_not_panic() {
        let d = detector(&["b1"], default_config());
        d.record_outcome(&BackendId::new("ghost"), true);
    }

    #[test]
    fn a_backend_added_by_reconcile_is_judged_and_ejected() {
        let d = OutlierDetector::new(Vec::new(), default_config());
        let pool = pool_of(&["b1", "b2", "b3"]);
        let ids: Vec<BackendId> = ["b1", "b2", "b3"]
            .iter()
            .map(|s| BackendId::new(*s))
            .collect();
        d.reconcile(&ids);
        for _ in 0..20 {
            d.record_outcome(&BackendId::new("b1"), false);
            d.record_outcome(&BackendId::new("b2"), true);
            d.record_outcome(&BackendId::new("b3"), true);
        }
        d.recompute(&pool);
        assert!(d.is_outlier(&BackendId::new("b1")));
        assert!(pool.is_outlier_ejected(&BackendId::new("b1")));
    }

    #[test]
    fn reconcile_stops_tracking_a_departed_backend() {
        let d = detector(&["b1", "b2"], default_config());
        d.reconcile(&[BackendId::new("b2")]);
        assert!(!d.tracks(&BackendId::new("b1")));
        assert!(d.tracks(&BackendId::new("b2")));
    }

    #[test]
    fn below_min_volume_no_backend_is_judged() {
        let d = detector(&["b1", "b2", "b3"], default_config());
        let pool = pool_of(&["b1", "b2", "b3"]);
        for _ in 0..5 {
            d.record_outcome(&BackendId::new("b1"), false);
        }
        for _ in 0..20 {
            d.record_outcome(&BackendId::new("b2"), true);
            d.record_outcome(&BackendId::new("b3"), true);
        }
        d.recompute(&pool);
        assert!(!d.is_outlier(&BackendId::new("b1")));
        assert!(pool.is_eligible(&BackendId::new("b1")));
    }

    #[test]
    fn below_min_hosts_nobody_is_flagged_even_with_a_clear_laggard() {
        let d = detector(
            &["b1", "b2", "b3"],
            OutlierConfig {
                min_volume: 10,
                min_hosts: 3,
                stddev_factor: 1.0,
                eject_ticks: 1,
            },
        );
        let pool = pool_of(&["b1", "b2", "b3"]);
        for _ in 0..20 {
            d.record_outcome(&BackendId::new("b1"), false);
            d.record_outcome(&BackendId::new("b2"), true);
        }
        d.recompute(&pool);
        assert!(!d.is_outlier(&BackendId::new("b1")));
        assert!(pool.is_eligible(&BackendId::new("b1")));
    }

    #[test]
    fn a_backend_far_below_its_peers_success_rate_is_flagged() {
        let d = detector(&["b1", "b2", "b3", "b4"], default_config());
        let pool = pool_of(&["b1", "b2", "b3", "b4"]);
        for _ in 0..100 {
            d.record_outcome(&BackendId::new("b1"), false);
            d.record_outcome(&BackendId::new("b2"), true);
            d.record_outcome(&BackendId::new("b3"), true);
            d.record_outcome(&BackendId::new("b4"), true);
        }
        d.recompute(&pool);
        assert!(d.is_outlier(&BackendId::new("b1")));
        assert!(!pool.is_eligible(&BackendId::new("b1")));
        assert!(!d.is_outlier(&BackendId::new("b2")));
        assert!(pool.is_eligible(&BackendId::new("b2")));
    }

    #[test]
    fn backends_performing_similarly_are_never_flagged() {
        let d = detector(&["b1", "b2", "b3"], default_config());
        let pool = pool_of(&["b1", "b2", "b3"]);
        for _ in 0..100 {
            d.record_outcome(&BackendId::new("b1"), true);
            d.record_outcome(&BackendId::new("b2"), true);
            d.record_outcome(&BackendId::new("b3"), true);
        }
        d.recompute(&pool);
        for id in ["b1", "b2", "b3"] {
            assert!(!d.is_outlier(&BackendId::new(id)));
        }
    }

    #[test]
    fn a_flag_clears_once_the_backend_recovers_the_following_round() {
        let d = detector(&["b1", "b2"], default_config());
        let pool = pool_of(&["b1", "b2"]);
        for _ in 0..100 {
            d.record_outcome(&BackendId::new("b1"), false);
            d.record_outcome(&BackendId::new("b2"), true);
        }
        d.recompute(&pool);
        assert!(d.is_outlier(&BackendId::new("b1")));

        for _ in 0..100 {
            d.record_outcome(&BackendId::new("b1"), true);
            d.record_outcome(&BackendId::new("b2"), true);
        }
        d.recompute(&pool);
        assert!(!d.is_outlier(&BackendId::new("b1")));
        assert!(pool.is_eligible(&BackendId::new("b1")));
    }

    #[test]
    fn recompute_resets_counts_for_the_next_window() {
        let d = detector(&["b1", "b2"], default_config());
        let pool = pool_of(&["b1", "b2"]);
        for _ in 0..100 {
            d.record_outcome(&BackendId::new("b1"), false);
            d.record_outcome(&BackendId::new("b2"), true);
        }
        d.recompute(&pool);
        assert!(d.is_outlier(&BackendId::new("b1")));

        d.record_outcome(&BackendId::new("b1"), false);
        d.recompute(&pool);
        assert!(!d.is_outlier(&BackendId::new("b1")));
    }

    #[test]
    fn an_ejected_backend_with_zero_traffic_stays_ejected_across_several_ticks() {
        let d = detector(
            &["b1", "b2"],
            OutlierConfig {
                min_volume: 10,
                min_hosts: 2,
                stddev_factor: 0.5,
                eject_ticks: 3,
            },
        );
        let pool = pool_of(&["b1", "b2"]);
        for _ in 0..100 {
            d.record_outcome(&BackendId::new("b1"), false);
            d.record_outcome(&BackendId::new("b2"), true);
        }
        d.recompute(&pool);
        assert!(d.is_outlier(&BackendId::new("b1")));

        for _ in 0..2 {
            d.record_outcome(&BackendId::new("b2"), true);
            d.recompute(&pool);
            assert!(d.is_outlier(&BackendId::new("b1")));
            assert!(!pool.is_eligible(&BackendId::new("b1")));
        }

        d.record_outcome(&BackendId::new("b2"), true);
        d.recompute(&pool);
        assert!(!d.is_outlier(&BackendId::new("b1")));
        assert!(pool.is_eligible(&BackendId::new("b1")));
    }

    #[test]
    fn a_backend_still_bad_on_probation_is_ejected_again_for_a_fresh_countdown() {
        let d = detector(
            &["b1", "b2"],
            OutlierConfig {
                min_volume: 10,
                min_hosts: 2,
                stddev_factor: 0.5,
                eject_ticks: 1,
            },
        );
        let pool = pool_of(&["b1", "b2"]);
        for _ in 0..100 {
            d.record_outcome(&BackendId::new("b1"), false);
            d.record_outcome(&BackendId::new("b2"), true);
        }
        d.recompute(&pool);
        assert!(d.is_outlier(&BackendId::new("b1")));

        d.record_outcome(&BackendId::new("b2"), true);
        d.recompute(&pool);
        assert!(!d.is_outlier(&BackendId::new("b1")));

        for _ in 0..100 {
            d.record_outcome(&BackendId::new("b1"), false);
            d.record_outcome(&BackendId::new("b2"), true);
        }
        d.recompute(&pool);
        assert!(d.is_outlier(&BackendId::new("b1")));
    }

    #[tokio::test(start_paused = true)]
    async fn spawn_outlier_detector_recomputes_on_the_configured_interval() {
        let ids = ["b1", "b2"];
        let config = default_config();
        let detector = Arc::new(OutlierDetector::new(
            ids.iter().map(|s| BackendId::new(*s)),
            config,
        ));
        let pool = Arc::new(pool_of(&ids));
        for _ in 0..100 {
            detector.record_outcome(&BackendId::new("b1"), false);
            detector.record_outcome(&BackendId::new("b2"), true);
        }

        let handle = spawn_outlier_detector(
            Arc::clone(&pool),
            Arc::clone(&detector),
            Duration::from_millis(50),
        );
        time::advance(Duration::from_millis(60)).await;
        time::sleep(Duration::from_millis(1)).await;
        assert!(!pool.is_eligible(&BackendId::new("b1")));
        handle.abort();
    }
}
