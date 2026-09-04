use crate::gcra::Gcra;
use lb_core::Clock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

pub fn spawn_sweeper<C: Clock + 'static>(
    limiter: Arc<Gcra<C>>,
    interval: Duration,
    idle_after: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            limiter.sweep(idle_after);
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
        );

        clock.advance(Duration::from_secs(1));
        // advance tokio's paused virtual time so the interval actually ticks
        time::advance(Duration::from_millis(60)).await;
        time::sleep(Duration::from_millis(1)).await; // yield so the spawned task runs

        assert_eq!(limiter.check("stale"), Decision::Allow);
    }
}
