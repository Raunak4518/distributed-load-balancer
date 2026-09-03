use lb_balancer::RoundRobin;
use lb_core::{Backend, BackendPool, Config, ListenerConfig, Protocol, SystemClock};
use lb_healthcheck::{
    spawn_active_checker, ActiveCheckConfig, CircuitBreaker, HttpProbe, TcpConnectProbe,
};
use lb_proxy::ProxyContext;
use lb_ratelimit::{spawn_sweeper, Gcra, GcraConfig};
use lb_tcp::TcpContext;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub type HttpContext = ProxyContext<Gcra<SystemClock>, RoundRobin, SystemClock>;
pub type TcpAppContext = TcpContext<Gcra<SystemClock>, RoundRobin, SystemClock>;

/// One configured listener, ready to accept. An enum rather than a trait:
/// this is a genuinely closed set, and `serve_listener` must match on it
/// exhaustively to know which protocol driver to run.
pub enum ListenerRuntime {
    Http {
        name: String,
        listen: SocketAddr,
        ctx: Arc<HttpContext>,
    },
    Tcp {
        name: String,
        listen: SocketAddr,
        ctx: Arc<TcpAppContext>,
    },
}

impl ListenerRuntime {
    pub fn name(&self) -> &str {
        match self {
            ListenerRuntime::Http { name, .. } | ListenerRuntime::Tcp { name, .. } => name,
        }
    }

    pub fn listen(&self) -> SocketAddr {
        match self {
            ListenerRuntime::Http { listen, .. } | ListenerRuntime::Tcp { listen, .. } => *listen,
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match self {
            ListenerRuntime::Http { .. } => "http",
            ListenerRuntime::Tcp { .. } => "tcp",
        }
    }
}

pub struct WiredApp {
    pub listeners: Vec<ListenerRuntime>,
    pub background_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub drain_timeout: Duration,
}

pub fn build_app(config: &Config) -> WiredApp {
    let mut listeners = Vec::with_capacity(config.listeners.len());
    let mut background_tasks = Vec::new();

    for lc in &config.listeners {
        let backends: Vec<Backend> = lc
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
                    lc.health_check.failure_threshold,
                    Duration::from_millis(lc.health_check.cooldown_ms),
                    SystemClock,
                ),
            );
        }

        let rate_limiter = Arc::new(Gcra::new(
            GcraConfig {
                rate_per_sec: lc.rate_limit.rate_per_sec,
                burst: lc.rate_limit.burst,
            },
            SystemClock,
        ));
        background_tasks.push(spawn_sweeper(
            rate_limiter.clone(),
            Duration::from_secs(30),
            Duration::from_secs(60),
        ));

        spawn_health_checkers(lc, &backends, &pool, &mut background_tasks);

        listeners.push(match lc.protocol {
            Protocol::Http => ListenerRuntime::Http {
                name: lc.name.clone(),
                listen: lc.listen,
                ctx: Arc::new(ProxyContext {
                    rate_limiter,
                    balancer: Arc::new(RoundRobin::new()),
                    pool,
                    circuit_breakers,
                    client: lb_proxy::build_client(),
                    rate_limit_key: lc.rate_limit.key.clone(),
                    forward_timeout: lc.forward_timeout(),
                    max_request_body_bytes: lc.max_request_body_bytes(),
                }),
            },
            Protocol::Tcp => ListenerRuntime::Tcp {
                name: lc.name.clone(),
                listen: lc.listen,
                ctx: Arc::new(TcpContext {
                    rate_limiter,
                    balancer: Arc::new(RoundRobin::new()),
                    pool,
                    circuit_breakers,
                    connect_timeout: lc.connect_timeout(),
                    idle_timeout: lc.idle_timeout(),
                }),
            },
        });
    }

    WiredApp {
        listeners,
        background_tasks,
        drain_timeout: Duration::from_millis(config.server.drain_timeout_ms),
    }
}

/// The listener's protocol picks the probe — an HTTP listener always wants an
/// HTTP probe, so there is no config knob here to get wrong.
fn spawn_health_checkers(
    lc: &ListenerConfig,
    backends: &[Backend],
    pool: &Arc<BackendPool>,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    let interval = Duration::from_millis(lc.health_check.interval_ms);
    let timeout = Duration::from_millis(lc.health_check.timeout_ms);

    for b in backends {
        let config = ActiveCheckConfig { interval };
        match lc.protocol {
            Protocol::Http => {
                let path = lc
                    .health_check
                    .path
                    .clone()
                    .expect("config validation guarantees http listeners have a health_check.path");
                tasks.push(spawn_active_checker(
                    b.clone(),
                    pool.clone(),
                    config,
                    HttpProbe::new(path, timeout),
                ));
            }
            Protocol::Tcp => {
                tasks.push(spawn_active_checker(
                    b.clone(),
                    pool.clone(),
                    config,
                    TcpConnectProbe::new(timeout),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::BackendId;

    const CONFIG: &str = r#"
        [[listeners]]
        name = "web"
        protocol = "http"
        listen = "127.0.0.1:0"

          [[listeners.backends]]
          id = "w1"
          address = "127.0.0.1:9001"

          [[listeners.backends]]
          id = "w2"
          address = "127.0.0.1:9002"

          [listeners.health_check]
          path = "/health"
          interval_ms = 2000
          timeout_ms = 500
          failure_threshold = 3
          cooldown_ms = 5000

          [listeners.rate_limit]
          key = "source_ip"
          rate_per_sec = 50
          burst = 100

          [listeners.load_balancing]
          strategy = "round_robin"

        [[listeners]]
        name = "db"
        protocol = "tcp"
        listen = "127.0.0.1:1"

          [[listeners.backends]]
          id = "pg1"
          address = "127.0.0.1:9003"

          [listeners.health_check]
          interval_ms = 2000
          timeout_ms = 500
          failure_threshold = 3
          cooldown_ms = 5000

          [listeners.rate_limit]
          key = "source_ip"
          rate_per_sec = 10
          burst = 20

          [listeners.load_balancing]
          strategy = "round_robin"
    "#;

    #[tokio::test]
    async fn builds_one_runtime_per_listener_with_the_right_protocol() {
        // build_app spawns background tasks, so this needs a Tokio runtime.
        let config = Config::parse(CONFIG).unwrap();
        let app = build_app(&config);

        assert_eq!(app.listeners.len(), 2);
        assert!(matches!(app.listeners[0], ListenerRuntime::Http { .. }));
        assert!(matches!(app.listeners[1], ListenerRuntime::Tcp { .. }));
        assert_eq!(app.listeners[0].name(), "web");
        assert_eq!(app.listeners[1].protocol_name(), "tcp");

        // 2 sweepers (one per listener) + 3 health checkers (2 http + 1 tcp)
        assert_eq!(app.background_tasks.len(), 5);

        match &app.listeners[0] {
            ListenerRuntime::Http { ctx, .. } => {
                assert_eq!(ctx.pool.all_backend_ids().len(), 2);
                assert!(ctx.pool.is_eligible(&BackendId::new("w1")));
            }
            _ => panic!("expected an http listener"),
        }

        for task in app.background_tasks {
            task.abort();
        }
    }

    #[tokio::test]
    async fn applies_drain_timeout_default() {
        let config = Config::parse(CONFIG).unwrap();
        let app = build_app(&config);
        assert_eq!(app.drain_timeout, Duration::from_millis(10_000));
        for task in app.background_tasks {
            task.abort();
        }
    }
}
