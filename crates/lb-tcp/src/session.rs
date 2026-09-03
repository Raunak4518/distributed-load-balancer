use crate::pump::pump;
use lb_core::{BackendId, BackendPool, Clock, Decision, LoadBalancer, RateLimiter};
use lb_healthcheck::CircuitBreaker;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

pub struct TcpContext<R: RateLimiter, L: LoadBalancer, C: Clock> {
    pub rate_limiter: Arc<R>,
    pub balancer: Arc<L>,
    pub pool: Arc<BackendPool>,
    pub circuit_breakers: HashMap<BackendId, CircuitBreaker<C>>,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Present only when `[cluster]` is configured; `None` means single-node.
    pub cluster: Option<Arc<dyn lb_core::ClusterCoordinator>>,
}

impl<R: RateLimiter, L: LoadBalancer, C: Clock> TcpContext<R, L, C> {
    fn circuit_breaker(&self, id: &BackendId) -> &CircuitBreaker<C> {
        self.circuit_breakers
            .get(id)
            .expect("a circuit breaker is constructed for every configured backend")
    }

    /// Same pattern as the HTTP path: the breaker's Open -> HalfOpen
    /// transition is evaluated lazily inside `is_open()`, so the pool's
    /// cached flag has to be refreshed from it or a tripped backend would
    /// stay excluded forever.
    fn refresh_circuit_state(&self) {
        for id in self.pool.all_backend_ids() {
            if let Some(breaker) = self.circuit_breakers.get(id) {
                self.pool.set_circuit_open(id, breaker.is_open());
            }
        }
    }
}

/// What happened to one proxied connection. Returned rather than logged so
/// tests can assert on the outcome directly; `lb-server` decides what (if
/// anything) to report.
#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionOutcome {
    /// Over the rate limit — connection closed without contacting a backend.
    /// There is no L4 way to explain the rejection, so closing is the signal.
    RateLimited,
    /// No eligible backend to send this to.
    NoBackend,
    /// Both connect attempts failed.
    ConnectFailed,
    /// Bytes were proxied until both directions finished cleanly.
    Completed {
        bytes_to_backend: u64,
        bytes_to_client: u64,
    },
    /// The connection was established but a direction failed or went idle.
    Aborted,
}

pub async fn handle_connection<R, L, C>(
    inbound: TcpStream,
    peer: SocketAddr,
    ctx: Arc<TcpContext<R, L, C>>,
) -> ConnectionOutcome
where
    R: RateLimiter,
    L: LoadBalancer,
    C: Clock,
{
    // At L4 the peer's IP is the only identity available — there are no
    // headers to key on, and nothing the client sends can be trusted as one.
    let key = peer.ip().to_string();
    if let Decision::Deny { .. } = ctx.rate_limiter.check(&key) {
        return ConnectionOutcome::RateLimited;
    }

    // The cluster budget is consulted only after the local limiter allowed
    // the connection: local is free, this is shared state.
    if let Some(cluster) = &ctx.cluster {
        if !cluster.try_admit(&key) {
            return ConnectionOutcome::RateLimited;
        }
    }

    ctx.refresh_circuit_state();

    let mut outbound: Option<TcpStream> = None;
    for attempt in 0..2u8 {
        let Some(backend_id) = ctx.balancer.pick(&ctx.pool) else {
            return ConnectionOutcome::NoBackend;
        };
        let backend = ctx
            .pool
            .backend(&backend_id)
            .expect("picked id exists in the pool it was picked from")
            .clone();

        match tokio::time::timeout(ctx.connect_timeout, TcpStream::connect(backend.address)).await {
            Ok(Ok(stream)) => {
                ctx.circuit_breaker(&backend_id).record_success();
                ctx.pool.set_circuit_open(&backend_id, false);
                outbound = Some(stream);
                break;
            }
            // Either the connect failed or it timed out; both mean this
            // backend did not answer. Retrying is safe here in a way it
            // never is at L7: not one client byte has been read yet.
            _ => {
                let breaker = ctx.circuit_breaker(&backend_id);
                breaker.record_failure();
                ctx.pool.set_circuit_open(&backend_id, breaker.is_open());
                if attempt == 1 {
                    return ConnectionOutcome::ConnectFailed;
                }
            }
        }
    }

    let Some(outbound) = outbound else {
        return ConnectionOutcome::ConnectFailed;
    };

    let (client_read, client_write) = inbound.into_split();
    let (backend_read, backend_write) = outbound.into_split();

    // try_join! (not select!): each direction must finish on its own. With
    // select!, the first EOF would tear down the whole connection and break
    // every protocol that half-closes one direction while still reading the
    // other.
    let to_backend = pump(client_read, backend_write, ctx.idle_timeout);
    let to_client = pump(backend_read, client_write, ctx.idle_timeout);

    match tokio::try_join!(to_backend, to_client) {
        Ok((bytes_to_backend, bytes_to_client)) => ConnectionOutcome::Completed {
            bytes_to_backend,
            bytes_to_client,
        },
        Err(_) => ConnectionOutcome::Aborted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;
    use lb_core::Backend;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct AllowAll;
    impl RateLimiter for AllowAll {
        fn check(&self, _key: &str) -> Decision {
            Decision::Allow
        }
    }

    struct DenyAll;
    impl RateLimiter for DenyAll {
        fn check(&self, _key: &str) -> Decision {
            Decision::Deny {
                retry_after: Duration::from_secs(1),
            }
        }
    }

    struct FirstEligible;
    impl LoadBalancer for FirstEligible {
        fn pick(&self, pool: &BackendPool) -> Option<BackendId> {
            pool.eligible_backends().into_iter().next()
        }
    }

    struct NoBackendPicker;
    impl LoadBalancer for NoBackendPicker {
        fn pick(&self, _pool: &BackendPool) -> Option<BackendId> {
            None
        }
    }

    /// A backend that echoes everything sent to it back to the sender.
    async fn spawn_echo_backend() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    fn context<R: RateLimiter, L: LoadBalancer>(
        rate_limiter: R,
        balancer: L,
        backends: Vec<Backend>,
    ) -> Arc<TcpContext<R, L, FakeClock>> {
        let pool = Arc::new(BackendPool::new(backends.clone()));
        let mut circuit_breakers = HashMap::new();
        for b in &backends {
            circuit_breakers.insert(
                b.id.clone(),
                CircuitBreaker::new(1, Duration::from_secs(60), FakeClock::new()),
            );
        }
        Arc::new(TcpContext {
            rate_limiter: Arc::new(rate_limiter),
            balancer: Arc::new(balancer),
            pool,
            circuit_breakers,
            connect_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(5),
            cluster: None,
        })
    }

    /// Runs one client connection through `handle_connection`, returning the
    /// outcome plus whatever the client read back.
    async fn run_session<R, L>(
        ctx: Arc<TcpContext<R, L, FakeClock>>,
        payload: &'static [u8],
    ) -> (ConnectionOutcome, Vec<u8>)
    where
        R: RateLimiter + 'static,
        L: LoadBalancer + 'static,
    {
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, peer) = front.accept().await.unwrap();
            handle_connection(stream, peer, ctx).await
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        // These are deliberately fallible-tolerant: on the rate-limited path
        // the server closes the connection immediately, so the write or
        // shutdown may legitimately fail with a reset. The assertions that
        // matter are the returned outcome and the bytes read back.
        let _ = client.write_all(payload).await;
        let _ = client.shutdown().await;

        let mut echoed = Vec::new();
        let _ = client.read_to_end(&mut echoed).await;

        (server.await.unwrap(), echoed)
    }

    #[tokio::test]
    async fn proxies_bytes_to_backend_and_back() {
        let backend_addr = spawn_echo_backend().await;
        let ctx = context(
            AllowAll,
            FirstEligible,
            vec![Backend::new("b1", backend_addr, 1)],
        );

        let (outcome, echoed) = run_session(ctx, b"ping").await;

        assert_eq!(echoed, b"ping");
        assert_eq!(
            outcome,
            ConnectionOutcome::Completed {
                bytes_to_backend: 4,
                bytes_to_client: 4
            }
        );
    }

    #[tokio::test]
    async fn rate_limited_connection_is_closed_without_reaching_a_backend() {
        let backend_addr = spawn_echo_backend().await;
        let ctx = context(
            DenyAll,
            FirstEligible,
            vec![Backend::new("b1", backend_addr, 1)],
        );

        let (outcome, echoed) = run_session(ctx, b"ping").await;

        assert_eq!(outcome, ConnectionOutcome::RateLimited);
        assert!(echoed.is_empty(), "nothing should be echoed back");
    }

    #[tokio::test]
    async fn no_eligible_backend_closes_the_connection() {
        let ctx = context(AllowAll, NoBackendPicker, vec![]);
        let (outcome, _) = run_session(ctx, b"ping").await;
        assert_eq!(outcome, ConnectionOutcome::NoBackend);
    }

    #[tokio::test]
    async fn retries_onto_a_healthy_backend_when_the_first_connect_fails() {
        // A closed port first, a working echo server second. FirstEligible
        // picks the dead one, its connect fails and trips the breaker
        // (threshold 1), and the retry lands on the healthy backend.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = closed.local_addr().unwrap();
        drop(closed);

        let healthy_addr = spawn_echo_backend().await;
        let ctx = context(
            AllowAll,
            FirstEligible,
            vec![
                Backend::new("dead", dead_addr, 1),
                Backend::new("alive", healthy_addr, 1),
            ],
        );

        let (outcome, echoed) = run_session(ctx.clone(), b"retry").await;

        assert_eq!(echoed, b"retry");
        assert_eq!(
            outcome,
            ConnectionOutcome::Completed {
                bytes_to_backend: 5,
                bytes_to_client: 5
            }
        );
        assert!(ctx.circuit_breaker(&BackendId::new("dead")).is_open());
    }
}
