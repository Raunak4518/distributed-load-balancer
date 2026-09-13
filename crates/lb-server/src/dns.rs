use lb_core::{Backend, BackendId, BackendPool, DnsDiscoveryConfig, Resolve};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time;

pub struct TokioResolver;

impl Resolve for TokioResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let addrs = tokio::net::lookup_host((host, port)).await?;
        Ok(addrs.collect())
    }
}

pub fn spawn_dns_poller<R: Resolve + 'static>(
    resolver: R,
    cfg: DnsDiscoveryConfig,
    pool: Arc<BackendPool>,
    listener_name: String,
    per_backend_client: Option<Arc<lb_proxy::PerBackendClients>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(cfg.poll_interval());
        loop {
            ticker.tick().await;
            match resolver.resolve(&cfg.name, cfg.port).await {
                Ok(addrs) => {
                    let backends: Vec<Backend> = addrs
                        .into_iter()
                        .map(|addr| {
                            Backend::new(format!("dns:{addr}"), addr, 1, cfg.server_name.clone())
                        })
                        .collect();
                    let ids: Vec<BackendId> = backends.iter().map(|b| b.id.clone()).collect();
                    pool.apply_resolved(backends);
                    if let Some(per_backend) = &per_backend_client {
                        per_backend.evict_missing(&ids);
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        listener = %listener_name,
                        dns_name = %cfg.name,
                        error = %err,
                        "dns discovery lookup failed; keeping the previous backend set"
                    );
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::BackendId;
    use std::time::Duration;

    struct FakeResolver {
        addrs: Vec<SocketAddr>,
    }

    impl Resolve for FakeResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(self.addrs.clone())
        }
    }

    struct FailingResolver;

    impl Resolve for FailingResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            Err(io::Error::other("lookup failed"))
        }
    }

    fn cfg() -> DnsDiscoveryConfig {
        DnsDiscoveryConfig {
            name: "svc.internal".to_string(),
            port: 9001,
            poll_interval_secs: Some(10),
            server_name: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_successful_poll_populates_the_pool() {
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let pool = Arc::new(BackendPool::new(Vec::new()));

        let _handle = spawn_dns_poller(
            FakeResolver { addrs: vec![addr] },
            cfg(),
            Arc::clone(&pool),
            "web".to_string(),
            None,
        );
        time::sleep(Duration::from_millis(1)).await; // yield so the spawned task runs

        let ids = pool.all_backend_ids();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], BackendId::new("dns:127.0.0.1:9001"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_poll_keeps_the_previous_backend_set() {
        let existing = Backend::new(
            "dns:127.0.0.1:9001",
            "127.0.0.1:9001".parse().unwrap(),
            1,
            None,
        );
        let pool = Arc::new(BackendPool::new(vec![existing]));

        let _handle = spawn_dns_poller(
            FailingResolver,
            cfg(),
            Arc::clone(&pool),
            "web".to_string(),
            None,
        );
        time::sleep(Duration::from_millis(1)).await; // yield so the spawned task runs

        assert_eq!(pool.all_backend_ids().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_backend_that_leaves_dns_is_evicted_from_the_per_backend_client_cache() {
        let gone: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let staying: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let pool = Arc::new(BackendPool::new(Vec::new()));
        let connector = Arc::new(
            lb_tls::BackendConnector::new(&lb_core::BackendTlsConfig {
                ca_file: None,
                danger_accept_invalid_certs: true,
            })
            .unwrap(),
        );
        let per_backend = Arc::new(lb_proxy::PerBackendClients::new(
            "svc.internal".into(),
            connector,
            false,
            None,
        ));
        per_backend.get_or_build(&Backend::new("dns:127.0.0.1:9001", gone, 1, None));
        per_backend.get_or_build(&Backend::new("dns:127.0.0.1:9002", staying, 1, None));

        let _handle = spawn_dns_poller(
            FakeResolver {
                addrs: vec![staying],
            },
            cfg(),
            Arc::clone(&pool),
            "web".to_string(),
            Some(Arc::clone(&per_backend)),
        );
        time::sleep(Duration::from_millis(1)).await;

        let tracked = per_backend.tracked_ids();
        assert!(!tracked.contains(&BackendId::new("dns:127.0.0.1:9001")));
        assert!(tracked.contains(&BackendId::new("dns:127.0.0.1:9002")));
    }
}
