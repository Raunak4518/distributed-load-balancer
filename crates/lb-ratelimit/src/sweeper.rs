use crate::gcra::Gcra;
use lb_core::Clock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

pub fn spawn_sweeper<C: Clock + 'static>(
    limiter: Arc<Gcra<C>>,
    interval: Duration,
    idle_after: Duration,
    report_tracked_keys: impl Fn(usize) + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            limiter.sweep(idle_after);
            report_tracked_keys(limiter.tracked_keys());
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcra::GcraConfig;
    use lb_core::test_util::FakeClock;
    use lb_core::{Decision, RateLimiter};

    #[tokio::test(start_paused = true)]
    async fn periodically_sweeps_idle_keys() {
        let clock = FakeClock::new();
        let limiter = Arc::new(Gcra::new(
            GcraConfig {
                rate_per_sec: 10.0,
                burst: 1,
                max_tracked_keys: usize::MAX,
            },
            clock.clone(),
        ));
        limiter.check("stale");

        let _handle = spawn_sweeper(
            limiter.clone(),
            Duration::from_millis(50),
            Duration::from_millis(10),
            |_| {},
        );

        clock.advance(Duration::from_secs(1));
        // advance tokio's paused virtual time so the interval actually ticks
        time::advance(Duration::from_millis(60)).await;
        time::sleep(Duration::from_millis(1)).await; // yield so the spawned task runs

        assert_eq!(limiter.check("stale"), Decision::Allow);
    }

    #[tokio::test(start_paused = true)]
    async fn each_sweep_reports_the_tracked_key_count() {
        let clock = FakeClock::new();
        let limiter = Arc::new(Gcra::new(
            GcraConfig {
                rate_per_sec: 10.0,
                burst: 1,
                max_tracked_keys: usize::MAX,
            },
            clock.clone(),
        ));
        limiter.check("a");
        limiter.check("b");
        let reported = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
        let sink = Arc::clone(&reported);
        let _handle = spawn_sweeper(
            Arc::clone(&limiter),
            Duration::from_secs(30),
            Duration::from_secs(3600),
            move |n| sink.store(n, std::sync::atomic::Ordering::SeqCst),
        );
        time::sleep(Duration::from_millis(1)).await;
        assert_eq!(reported.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
