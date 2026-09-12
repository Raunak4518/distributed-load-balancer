use lb_core::{Backend, BackendPool, HealthProbe};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

pub struct ActiveCheckConfig {
    pub interval: Duration,
    /// Optional gauge mirroring the health flag, so backend health is
    /// visible in metrics as well as in the pool. `None` in tests that don't
    /// care about metrics.
    pub healthy_gauge: Option<lb_metrics::IntGauge>,
}

/// Polls one backend on an interval and publishes the result into the pool's
/// "administratively healthy" flag. What counts as healthy is entirely the
/// probe's business — this loop only schedules it.
pub fn spawn_active_checker<P>(
    backend: Backend,
    pool: Arc<BackendPool>,
    config: ActiveCheckConfig,
    probe: P,
) -> tokio::task::JoinHandle<()>
where
    P: HealthProbe + 'static,
{
    tokio::spawn(async move {
        let mut ticker = time::interval(config.interval);
        let mut previous: Option<bool> = None;
        loop {
            ticker.tick().await;
            let healthy = probe.probe(&backend).await;
            if previous != Some(healthy) {
                if healthy {
                    tracing::info!(backend = %backend.id, "backend health check recovered");
                } else {
                    tracing::warn!(backend = %backend.id, "backend health check failed; removed from rotation");
                }
                previous = Some(healthy);
            }
            pool.set_active_healthy(&backend.id, healthy);
            if let Some(gauge) = &config.healthy_gauge {
                gauge.set(if healthy { 1 } else { 0 });
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{HttpProbe, TcpConnectProbe};
    use crate::test_support::{StubProbeClient, StubTransport};

    /// The checker's whole job: run the probe and publish its verdict into
    /// the pool. The probe's own transport is a seam (`ProbeClient`), so
    /// these tests drive it directly instead of standing up an HTTP server --
    /// the proof that the *real* client agrees with the data plane is
    /// `lb-server`'s integration suite, where an untrusted certificate is
    /// genuinely refused.
    fn checker_config() -> ActiveCheckConfig {
        ActiveCheckConfig {
            interval: Duration::from_millis(20),
            healthy_gauge: None,
        }
    }

    #[tokio::test]
    async fn marks_backend_healthy_on_2xx() {
        let backend = Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        pool.set_active_healthy(&backend.id, false); // start unhealthy to prove the checker flips it

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            checker_config(),
            HttpProbe::new(
                Arc::new(StubProbeClient::new(Some(200))),
                "/health",
                Duration::from_millis(200),
                false,
            ),
        );

        time::sleep(Duration::from_millis(60)).await;
        assert!(pool.is_eligible(&backend.id));
        handle.abort();
    }

    #[tokio::test]
    async fn marks_backend_unhealthy_on_non_2xx() {
        let backend = Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            checker_config(),
            HttpProbe::new(
                Arc::new(StubProbeClient::new(Some(500))),
                "/health",
                Duration::from_millis(200),
                false,
            ),
        );

        time::sleep(Duration::from_millis(60)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }

    /// A backend the probe client could not reach at all -- which is how a
    /// refused backend certificate arrives -- must leave rotation, not stay
    /// in it because there was no status to judge.
    #[tokio::test]
    async fn marks_backend_unhealthy_when_the_probe_cannot_reach_it() {
        let backend = Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            checker_config(),
            HttpProbe::new(
                Arc::new(StubProbeClient::new(None)),
                "/health",
                Duration::from_millis(200),
                false,
            ),
        );

        time::sleep(Duration::from_millis(60)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }

    #[tokio::test]
    async fn marks_backend_unhealthy_when_tcp_port_is_closed() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let backend = Backend::new("b1", addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            checker_config(),
            TcpConnectProbe::new(Duration::from_millis(100), None),
        );

        // Wait comfortably longer than the probe's own timeout: on Windows a
        // connect to a closed port hangs until it times out rather than being
        // refused immediately, so the first probe only resolves at ~100ms.
        time::sleep(Duration::from_millis(300)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }

    /// The L4 half of the same invariant, through the checker: a backend
    /// whose port accepts but whose outbound wrap fails leaves rotation.
    /// Before Task 9 this backend stayed in rotation indefinitely.
    #[tokio::test]
    async fn marks_backend_unhealthy_when_the_outbound_wrap_fails() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    return;
                }
            }
        });

        let backend = Backend::new("b1", addr, 1, Some("backend.internal".into()));
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            checker_config(),
            TcpConnectProbe::new(
                Duration::from_millis(200),
                Some(Arc::new(StubTransport::new(false))),
            ),
        );

        time::sleep(Duration::from_millis(120)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }
}
