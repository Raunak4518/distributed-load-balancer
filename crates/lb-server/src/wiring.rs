use lb_balancer::RoundRobin;
use lb_core::{Backend, Config, SystemClock};
use lb_core::BackendPool;
use lb_healthcheck::{spawn_active_checker, ActiveCheckConfig, CircuitBreaker};
use lb_proxy::ProxyContext;
use lb_ratelimit::{spawn_sweeper, Gcra, GcraConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub type AppContext = ProxyContext<Gcra<SystemClock>, RoundRobin, SystemClock>;

pub struct WiredApp {
    pub context: Arc<AppContext>,
    pub background_tasks: Vec<tokio::task::JoinHandle<()>>,
}

pub fn build_context(config: &Config) -> WiredApp {
    let backends: Vec<Backend> = config
        .backends
        .iter()
        .map(|b| Backend::new(b.id.clone(), b.address, b.weight))
        .collect();
    let pool = Arc::new(BackendPool::new(backends.clone()));

    let mut circuit_breakers = HashMap::new();
    for b in &backends {
        circuit_breakers.insert(
            b.id.clone(),
            CircuitBreaker::new(
                config.health_check.failure_threshold,
                Duration::from_millis(config.health_check.cooldown_ms),
                SystemClock,
            ),
        );
    }

    let rate_limiter = Arc::new(Gcra::new(
        GcraConfig { rate_per_sec: config.rate_limit.rate_per_sec, burst: config.rate_limit.burst },
        SystemClock,
    ));

    let context = Arc::new(ProxyContext {
        rate_limiter: rate_limiter.clone(),
        balancer: Arc::new(RoundRobin::new()),
        pool: pool.clone(),
        circuit_breakers,
        client: lb_proxy::build_client(),
        rate_limit_key: config.rate_limit.key.clone(),
        forward_timeout: Duration::from_millis(config.server.forward_timeout_ms),
        max_request_body_bytes: config.server.max_request_body_bytes,
    });

    let mut background_tasks = vec![spawn_sweeper(rate_limiter, Duration::from_secs(30), Duration::from_secs(60))];

    let http_client = reqwest::Client::new();
    for b in &backends {
        background_tasks.push(spawn_active_checker(
            b.clone(),
            pool.clone(),
            ActiveCheckConfig {
                path: config.health_check.path.clone(),
                interval: Duration::from_millis(config.health_check.interval_ms),
                timeout: Duration::from_millis(config.health_check.timeout_ms),
            },
            http_client.clone(),
        ));
    }

    WiredApp { context, background_tasks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::BackendId;

    const CONFIG: &str = r#"
        [server]
        listen = "127.0.0.1:0"

        [[backends]]
        id = "b1"
        address = "127.0.0.1:9001"

        [[backends]]
        id = "b2"
        address = "127.0.0.1:9002"

        [health_check]
        path = "/health"
        interval_ms = 2000
        timeout_ms = 500
        failure_threshold = 3
        cooldown_ms = 5000

        [rate_limit]
        key = "source_ip"
        rate_per_sec = 50
        burst = 100

        [load_balancing]
        strategy = "round_robin"
    "#;

    #[tokio::test]
    async fn wires_one_circuit_breaker_and_backend_per_configured_backend() {
        // build_context spawns background tasks (sweeper, active checkers)
        // via tokio::spawn, which panics outside a running Tokio runtime —
        // hence #[tokio::test] rather than a plain #[test] here.
        let config = Config::parse(CONFIG).unwrap();
        let app = build_context(&config);
        assert_eq!(app.context.pool.all_backend_ids().len(), 2);
        assert_eq!(app.context.circuit_breakers.len(), 2);
        assert!(app.context.pool.is_eligible(&BackendId::new("b1")));
        // sweeper + one active checker per backend
        assert_eq!(app.background_tasks.len(), 3);
        for task in app.background_tasks {
            task.abort();
        }
    }
}
