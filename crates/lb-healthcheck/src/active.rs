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
        loop {
            ticker.tick().await;
            let healthy = probe.probe(&backend).await;
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
    use crate::probe::HttpProbe;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn marks_backend_healthy_on_2xx() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let backend = Backend::new("b1", *mock.address(), 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        pool.set_active_healthy(&backend.id, false); // start unhealthy to prove the checker flips it

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig {
                interval: Duration::from_millis(20),
                healthy_gauge: None,
            },
            HttpProbe::new("/health", Duration::from_millis(200)),
        );

        time::sleep(Duration::from_millis(60)).await;
        assert!(pool.is_eligible(&backend.id));
        handle.abort();
    }

    #[tokio::test]
    async fn marks_backend_unhealthy_on_non_2xx() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let backend = Backend::new("b1", *mock.address(), 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig {
                interval: Duration::from_millis(20),
                healthy_gauge: None,
            },
            HttpProbe::new("/health", Duration::from_millis(200)),
        );

        time::sleep(Duration::from_millis(60)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }

    #[tokio::test]
    async fn marks_backend_unhealthy_when_tcp_port_is_closed() {
        use crate::probe::TcpConnectProbe;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let backend = Backend::new("b1", addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig {
                interval: Duration::from_millis(20),
                healthy_gauge: None,
            },
            TcpConnectProbe::new(Duration::from_millis(100)),
        );

        // Wait comfortably longer than the probe's own timeout: on Windows a
        // connect to a closed port hangs until it times out rather than being
        // refused immediately, so the first probe only resolves at ~100ms.
        time::sleep(Duration::from_millis(300)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }
}
