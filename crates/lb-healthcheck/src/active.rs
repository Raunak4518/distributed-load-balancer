use lb_core::{Backend, BackendPool};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

pub struct ActiveCheckConfig {
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
}

pub fn spawn_active_checker(
    backend: Backend,
    pool: Arc<BackendPool>,
    config: ActiveCheckConfig,
    client: reqwest::Client,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let url = format!("http://{}{}", backend.address, config.path);
        let mut ticker = time::interval(config.interval);
        loop {
            ticker.tick().await;
            let healthy = match time::timeout(config.timeout, client.get(&url).send()).await {
                Ok(Ok(resp)) => resp.status().is_success(),
                _ => false,
            };
            pool.set_active_healthy(&backend.id, healthy);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let backend = Backend::new("b1", *mock.address(), 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        pool.set_active_healthy(&backend.id, false); // start unhealthy to prove the checker flips it

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig {
                path: "/health".into(),
                interval: Duration::from_millis(20),
                timeout: Duration::from_millis(200),
            },
            reqwest::Client::new(),
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

        let backend = Backend::new("b1", *mock.address(), 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()])); // starts healthy by default

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig {
                path: "/health".into(),
                interval: Duration::from_millis(20),
                timeout: Duration::from_millis(200),
            },
            reqwest::Client::new(),
        );

        time::sleep(Duration::from_millis(60)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }
}
