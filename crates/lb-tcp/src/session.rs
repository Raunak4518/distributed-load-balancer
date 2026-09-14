use crate::pump::pump;
use lb_core::{
    Backend, BackendId, BackendPool, Clock, Decision, LoadBalancer, OutboundTransport, ProxyStream,
    RateLimiter,
};
use lb_healthcheck::CircuitBreaker;
use lb_metrics::{BackendMetrics, IntGauge, ListenerMetrics};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

pub struct TcpContext<R: RateLimiter, C: Clock> {
    pub rate_limiter: Arc<R>,
    pub balancer: Arc<dyn LoadBalancer>,
    pub pool: Arc<BackendPool>,
    pub circuit_breakers: HashMap<BackendId, CircuitBreaker<C>>,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Present only when this listener re-encrypts to its backends; `None`
    /// means the outbound leg is plaintext.
    ///
    /// A trait object rather than a concrete TLS type on purpose: it is what
    /// keeps `lb-tcp` free of any TLS dependency at all. The L4 data plane
    /// asks for a connection to be wrapped and pumps whatever it gets back,
    /// exactly as it is already generic over the inbound stream.
    pub backend_tls: Option<Arc<dyn OutboundTransport>>,
    /// See `lb_core::TcpKeepaliveConfig`. Applied to the raw `TcpStream` in
    /// `establish`, before it's wrapped for TLS or boxed into
    /// `Box<dyn ProxyStream>` (boxing erases the OS-handle traits `socket2`
    /// needs).
    pub backend_tcp_keepalive: Option<lb_core::TcpKeepaliveConfig>,
    /// Present only when `[cluster]` is configured; `None` means single-node.
    pub cluster: Option<Arc<dyn lb_core::ClusterCoordinator>>,
    /// Always present — see the note on `ProxyContext::metrics`.
    pub metrics: Arc<ListenerMetrics>,
    pub backend_metrics: HashMap<BackendId, BackendMetrics>,
}

/// Decrements the active-connection gauge on drop.
///
/// `handle_connection` has five early-return paths; a manual decrement at
/// each would eventually be forgotten and the gauge would drift upward
/// forever, which is worse than no gauge at all.
struct ConnectionGuard(IntGauge);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

impl<R: RateLimiter, C: Clock> TcpContext<R, C> {
    fn circuit_breaker(&self, id: &BackendId) -> Option<&CircuitBreaker<C>> {
        self.circuit_breakers.get(id)
    }

    /// Same pattern as the HTTP path: the breaker's Open -> HalfOpen
    /// transition is evaluated lazily inside `is_open()`, so the pool's
    /// cached flag has to be refreshed from it or a tripped backend would
    /// stay excluded forever.
    fn refresh_circuit_state(&self) {
        for id in &self.pool.all_backend_ids() {
            if let Some(breaker) = self.circuit_breakers.get(id) {
                self.pool.set_circuit_open(id, breaker.is_open());
            }
        }
    }
}

/// Completes the outbound leg: the TCP connection, and the TLS handshake on
/// top of it when this listener re-encrypts.
///
/// `None` means the backend did not give us a usable connection, and it is
/// deliberately the same answer for a refused connect, a connect timeout and
/// a failed handshake. A backend we cannot hand bytes to is a backend that
/// did not answer, whichever step failed, so the caller records one outcome
/// and retries once.
async fn establish<R, C>(ctx: &TcpContext<R, C>, backend: &Backend) -> Option<Box<dyn ProxyStream>>
where
    R: RateLimiter,
    C: Clock,
{
    let stream = match tokio::time::timeout(
        ctx.connect_timeout,
        TcpStream::connect(backend.address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        // Either the connect failed or it timed out; both mean this backend
        // did not answer.
        _ => return None,
    };
    if let Some(keepalive) = &ctx.backend_tcp_keepalive {
        apply_tcp_keepalive(&stream, keepalive);
    }
    let stream: Box<dyn ProxyStream> = Box::new(stream);

    match (&ctx.backend_tls, &backend.server_name) {
        // L4 does not pool, and should not: a TCP session is 1:1 with a
        // client connection. So every proxied connection pays one backend
        // handshake -- inherent to L4, not a defect.
        (Some(transport), Some(server_name)) => transport
            .wrap(stream, server_name.clone(), ctx.connect_timeout)
            .await
            .ok(),
        // Config validation requires a `server_name` on every backend of a
        // listener that sets `backend_tls`, so this is unreachable through
        // the config. It is spelled out rather than folded into the
        // plaintext arm because falling back to plaintext would silently
        // defeat the encryption that was asked for.
        (Some(_), None) => None,
        (None, _) => Some(stream),
    }
}

/// Fire-and-log, never fatal: a keepalive that fails to apply (an unusual
/// platform/socket state) must not take a connection down over a purely
/// advisory setting. `set_tcp_keepalive` also turns on `SO_KEEPALIVE`
/// itself, so no separate call is needed.
fn apply_tcp_keepalive(stream: &TcpStream, cfg: &lb_core::TcpKeepaliveConfig) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(cfg.time_secs))
        .with_interval(Duration::from_secs(cfg.interval_secs))
        .with_retries(cfg.retries);
    if let Err(err) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        tracing::warn!(error = %err, "failed to set backend tcp keepalive");
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

/// Proxies one client connection to a backend.
///
/// Generic over the inbound stream so the same code serves a plain
/// `TcpStream` and a TLS stream: `pump` is already written against
/// `AsyncRead`/`AsyncWrite`, so the L4 data plane never learns which it got.
///
/// `#[instrument]` gives this whole session one span -- the TCP counterpart
/// of `lb_proxy::service::handle`'s per-request span (L4 has no per-request
/// boundary, so the session is the natural unit). Unconditional and cheap
/// when nothing is exporting, same as there: this code does not need to
/// know whether OpenTelemetry export is turned on.
#[tracing::instrument(name = "tcp_session", skip(inbound, ctx), fields(peer = %peer))]
pub async fn handle_connection<S, R, C>(
    inbound: S,
    peer: SocketAddr,
    ctx: Arc<TcpContext<R, C>>,
) -> ConnectionOutcome
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    R: RateLimiter,
    C: Clock,
{
    ctx.metrics.connections_total.inc();
    ctx.metrics.active_connections.inc();
    let _guard = ConnectionGuard(ctx.metrics.active_connections.clone());

    // At L4 the peer's IP is the only identity available — there are no
    // headers to key on, and nothing the client sends can be trusted as one.
    let key = peer.ip().to_string();
    if let Decision::Deny { .. } = ctx.rate_limiter.check(&key) {
        ctx.metrics.ratelimit_rejected_local.inc();
        return ConnectionOutcome::RateLimited;
    }

    // The cluster budget is consulted only after the local limiter allowed
    // the connection: local is free, this is shared state.
    if let Some(cluster) = &ctx.cluster {
        if !cluster.try_admit(&key) {
            ctx.metrics.ratelimit_rejected_cluster.inc();
            return ConnectionOutcome::RateLimited;
        }
    }

    ctx.refresh_circuit_state();

    let mut outbound: Option<Box<dyn ProxyStream>> = None;
    for attempt in 0..2u8 {
        let Some(backend_id) = ctx.balancer.pick(&ctx.pool, &key) else {
            return ConnectionOutcome::NoBackend;
        };
        let Some(backend) = ctx.pool.backend(&backend_id) else {
            continue;
        };
        // Held across the connect attempt and dropped at the end of this
        // iteration regardless of outcome -- same reasoning as the HTTP
        // path's guard.
        let _active_guard = ctx.pool.track_active(&backend_id);

        let attempt_started = std::time::Instant::now();
        match establish(&ctx, &backend).await {
            Some(stream) => {
                if let Some(bm) = ctx.backend_metrics.get(&backend_id) {
                    bm.requests_success.inc();
                }
                ctx.balancer
                    .record_latency(&backend_id, attempt_started.elapsed());
                if let Some(breaker) = ctx.circuit_breaker(&backend_id) {
                    breaker.record_success();
                }
                ctx.pool.set_circuit_open(&backend_id, false);
                outbound = Some(stream);
                break;
            }
            // The connect failed, timed out, or the handshake did not
            // complete; all three mean this backend did not answer.
            // Retrying is safe here in a way it never is at L7: not one
            // client byte has been read yet.
            None => {
                if let Some(bm) = ctx.backend_metrics.get(&backend_id) {
                    bm.requests_failure.inc();
                }
                ctx.balancer
                    .record_latency(&backend_id, attempt_started.elapsed());
                if let Some(breaker) = ctx.circuit_breaker(&backend_id) {
                    breaker.record_failure();
                    ctx.pool.set_circuit_open(&backend_id, breaker.is_open());
                }
                if attempt == 1 {
                    return ConnectionOutcome::ConnectFailed;
                }
            }
        }
    }

    let Some(outbound) = outbound else {
        return ConnectionOutcome::ConnectFailed;
    };

    // `tokio::io::split` rather than `TcpStream::into_split`, because the
    // inbound stream is no longer necessarily a socket. A TLS stream cannot
    // be split without a lock anyway — one rustls connection drives both
    // directions — and the lock is held only for the duration of a single
    // non-blocking poll, so the two directions never wait on each other for
    // longer than one syscall.
    let (client_read, client_write) = tokio::io::split(inbound);
    // The backend side is split the same way, and for the same reason: it is
    // a plain socket only when the listener does not re-encrypt.
    let (backend_read, backend_write) = tokio::io::split(outbound);

    // try_join! (not select!): each direction must finish on its own. With
    // select!, the first EOF would tear down the whole connection and break
    // every protocol that half-closes one direction while still reading the
    // other.
    let activity = crate::pump::IdleTracker::new();
    let to_backend = pump(client_read, backend_write, ctx.idle_timeout, &activity);
    let to_client = pump(backend_read, client_write, ctx.idle_timeout, &activity);

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
        fn pick(&self, pool: &BackendPool, _key: &str) -> Option<BackendId> {
            pool.eligible_backends().into_iter().next()
        }
    }

    struct NoBackendPicker;
    impl LoadBalancer for NoBackendPicker {
        fn pick(&self, _pool: &BackendPool, _key: &str) -> Option<BackendId> {
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

    fn context<R: RateLimiter, L: LoadBalancer + 'static>(
        rate_limiter: R,
        balancer: L,
        backends: Vec<Backend>,
    ) -> Arc<TcpContext<R, FakeClock>> {
        let pool = Arc::new(BackendPool::new(backends.clone()));
        let mut circuit_breakers = HashMap::new();
        for b in &backends {
            circuit_breakers.insert(
                b.id.clone(),
                CircuitBreaker::new(1, Duration::from_secs(60), 1, FakeClock::new()),
            );
        }
        Arc::new(TcpContext {
            rate_limiter: Arc::new(rate_limiter),
            balancer: Arc::new(balancer),
            pool,
            circuit_breakers,
            connect_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(5),
            backend_tls: None,
            backend_tcp_keepalive: None,
            cluster: None,
            metrics: {
                let registry = lb_metrics::Metrics::new().expect("metrics registry");
                Arc::new(registry.listener("test"))
            },
            backend_metrics: HashMap::new(),
        })
    }

    /// Runs one client connection through `handle_connection`, returning the
    /// outcome plus whatever the client read back.
    async fn run_session<R>(
        ctx: Arc<TcpContext<R, FakeClock>>,
        payload: &'static [u8],
    ) -> (ConnectionOutcome, Vec<u8>)
    where
        R: RateLimiter + 'static,
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
            vec![Backend::new("b1", backend_addr, 1, None)],
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

    /// The balancer is consulted once, at connect time -- never again for the
    /// life of this session. Proven here by mutating the pool out from under
    /// an already-established connection (removing its backend entirely) and
    /// showing the session keeps proxying bytes over the same socket anyway,
    /// since `pump` only ever holds the already-connected stream, never a
    /// reference back into the pool.
    #[tokio::test]
    async fn an_established_connection_survives_its_backend_leaving_the_pool() {
        let backend_addr = spawn_echo_backend().await;
        let ctx = context(
            AllowAll,
            FirstEligible,
            vec![Backend::new("b1", backend_addr, 1, None)],
        );
        let pool = Arc::clone(&ctx.pool);

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let ctx_for_session = Arc::clone(&ctx);
        let server = tokio::spawn(async move {
            let (stream, peer) = front.accept().await.unwrap();
            handle_connection(stream, peer, ctx_for_session).await
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(b"first").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"first");

        pool.apply_resolved(vec![]);
        assert!(
            pool.all_backend_ids().is_empty(),
            "the pool must genuinely no longer list this backend"
        );

        client.write_all(b"second").await.unwrap();
        let mut buf2 = [0u8; 6];
        client.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"second");

        client.shutdown().await.unwrap();
        let outcome = server.await.unwrap();
        assert_eq!(
            outcome,
            ConnectionOutcome::Completed {
                bytes_to_backend: 11,
                bytes_to_client: 11
            }
        );
    }

    #[tokio::test]
    async fn rate_limited_connection_is_closed_without_reaching_a_backend() {
        let backend_addr = spawn_echo_backend().await;
        let ctx = context(
            DenyAll,
            FirstEligible,
            vec![Backend::new("b1", backend_addr, 1, None)],
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

    /// A stand-in for the real transport `lb-tls` provides. It upper-cases
    /// everything written towards the backend, which is a visible,
    /// byte-level proof that the *wrapped* stream is the one the data plane
    /// pumps through -- not merely that `wrap` was called and its result
    /// dropped on the floor.
    ///
    /// `fail_first` makes the first wrap fail, so a handshake failure can be
    /// exercised separately from a connect failure.
    struct ShoutingTransport {
        calls: Arc<std::sync::Mutex<Vec<String>>>,
        fail_first: bool,
    }

    impl ShoutingTransport {
        fn new(fail_first: bool) -> Self {
            ShoutingTransport {
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
                fail_first,
            }
        }
    }

    impl lb_core::OutboundTransport for ShoutingTransport {
        fn wrap(
            &self,
            stream: Box<dyn lb_core::ProxyStream>,
            server_name: String,
            _timeout: Duration,
        ) -> lb_core::WrapFuture<'_> {
            let first = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(server_name);
                calls.len() == 1
            };
            let fail = self.fail_first && first;
            Box::pin(async move {
                if fail {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "handshake refused",
                    ));
                }
                Ok(Box::new(Shouting(stream)) as Box<dyn lb_core::ProxyStream>)
            })
        }
    }

    /// `context`, plus an outbound transport. Set after construction rather
    /// than threaded through `context`'s signature, so the four plaintext
    /// tests above stay unchanged.
    fn context_with_transport<R: RateLimiter, L: LoadBalancer + 'static>(
        rate_limiter: R,
        balancer: L,
        backends: Vec<Backend>,
        transport: Arc<dyn lb_core::OutboundTransport>,
    ) -> Arc<TcpContext<R, FakeClock>> {
        let mut ctx = context(rate_limiter, balancer, backends);
        Arc::get_mut(&mut ctx).expect("sole owner").backend_tls = Some(transport);
        ctx
    }

    /// Upper-cases bytes on their way to the backend; reads pass through.
    struct Shouting(Box<dyn lb_core::ProxyStream>);

    impl tokio::io::AsyncRead for Shouting {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for Shouting {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let shouted = buf.to_ascii_uppercase();
            std::pin::Pin::new(&mut self.0).poll_write(cx, &shouted)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
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
                Backend::new("dead", dead_addr, 1, None),
                Backend::new("alive", healthy_addr, 1, None),
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
        assert!(ctx
            .circuit_breaker(&BackendId::new("dead"))
            .unwrap()
            .is_open());
    }

    /// The point of the seam: `lb-tcp` never names a TLS crate, it asks
    /// whatever `OutboundTransport` it was handed to wrap the connection and
    /// pumps whatever comes back.
    #[tokio::test]
    async fn a_configured_transport_wraps_the_outbound_connection() {
        let backend_addr = spawn_echo_backend().await;
        let transport = Arc::new(ShoutingTransport::new(false));
        let calls = Arc::clone(&transport.calls);
        let ctx = context_with_transport(
            AllowAll,
            FirstEligible,
            vec![Backend::new(
                "b1",
                backend_addr,
                1,
                Some("b1.internal".to_string()),
            )],
            transport,
        );

        let (outcome, echoed) = run_session(ctx, b"ping").await;

        // The echo backend saw upper case, so the wrapped stream -- not the
        // raw socket -- is what the two pumps were joined on.
        assert_eq!(echoed, b"PING");
        assert_eq!(
            outcome,
            ConnectionOutcome::Completed {
                bytes_to_backend: 4,
                bytes_to_client: 4
            }
        );
        // The name on the certificate, not the address that was dialled.
        assert_eq!(calls.lock().unwrap().as_slice(), ["b1.internal"]);
    }

    /// A handshake that fails is a backend that did not answer: same metrics,
    /// same breaker, same retry. The retry stays safe for the reason it
    /// always has been -- not one client byte has been read yet.
    #[tokio::test]
    async fn a_failed_wrap_is_recorded_and_retried_like_a_connect_failure() {
        let first_addr = spawn_echo_backend().await;
        let second_addr = spawn_echo_backend().await;
        let transport = Arc::new(ShoutingTransport::new(true));
        let ctx = context_with_transport(
            AllowAll,
            FirstEligible,
            vec![
                Backend::new("first", first_addr, 1, Some("first.internal".to_string())),
                Backend::new(
                    "second",
                    second_addr,
                    1,
                    Some("second.internal".to_string()),
                ),
            ],
            transport,
        );

        let (outcome, echoed) = run_session(ctx.clone(), b"retry").await;

        assert_eq!(echoed, b"RETRY");
        assert_eq!(
            outcome,
            ConnectionOutcome::Completed {
                bytes_to_backend: 5,
                bytes_to_client: 5
            }
        );
        // Recorded against the backend whose handshake failed, exactly as a
        // refused connect would have been.
        assert!(ctx
            .circuit_breaker(&BackendId::new("first"))
            .unwrap()
            .is_open());
    }

    /// Config validation requires a `server_name` on every backend of a
    /// re-encrypting listener. If that guard were ever bypassed, falling back
    /// to plaintext would silently defeat the encryption that was asked for,
    /// so the connection fails instead.
    #[tokio::test]
    async fn a_backend_with_no_server_name_is_never_proxied_to_in_plaintext() {
        let backend_addr = spawn_echo_backend().await;
        let transport = Arc::new(ShoutingTransport::new(false));
        let calls = Arc::clone(&transport.calls);
        let ctx = context_with_transport(
            AllowAll,
            FirstEligible,
            vec![Backend::new("b1", backend_addr, 1, None)],
            transport,
        );

        let (outcome, echoed) = run_session(ctx, b"ping").await;

        // The refusal is recorded like any other backend failure, which
        // trips this fixture's threshold-of-one breaker and leaves nothing
        // eligible for the retry -- the same path a single backend with a
        // refused connect takes.
        assert_eq!(outcome, ConnectionOutcome::NoBackend);
        assert!(echoed.is_empty(), "bytes reached a backend in plaintext");
        assert!(
            calls.lock().unwrap().is_empty(),
            "a nameless backend must not reach the transport at all"
        );
    }

    /// There's no meaningful way to assert on `SO_KEEPALIVE`'s actual
    /// *timing* behavior within a test's timescale -- this calls the real
    /// `apply_tcp_keepalive` against a real connected socket and checks the
    /// one directly observable effect: `SO_KEEPALIVE` itself gets turned on
    /// (a side effect of `set_tcp_keepalive`), which it was not before.
    #[tokio::test]
    async fn applying_tcp_keepalive_turns_on_so_keepalive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        assert!(
            !socket2::SockRef::from(&stream).keepalive().unwrap(),
            "keepalive should be off by default"
        );

        apply_tcp_keepalive(
            &stream,
            &lb_core::TcpKeepaliveConfig {
                time_secs: 60,
                interval_secs: 10,
                retries: 6,
            },
        );

        assert!(
            socket2::SockRef::from(&stream).keepalive().unwrap(),
            "apply_tcp_keepalive should have turned SO_KEEPALIVE on"
        );
    }
}
