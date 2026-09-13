use crate::forward::{backend_scheme_and_authority, forward, ForwardError, ProxyClient};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use lb_core::{
    BackendId, BackendPool, Clock, Decision, LoadBalancer, RateLimitKeySource, RateLimiter,
};
use lb_healthcheck::CircuitBreaker;
use lb_metrics::{BackendMetrics, ListenerMetrics, StatusClass};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub struct ProxyContext<R: RateLimiter, C: Clock> {
    pub rate_limiter: Arc<R>,
    /// The default route: used for any request that matches no rule in
    /// `routes` below, and for every request when `routes` is empty (the
    /// common case, and the entire config surface before routing rules
    /// existed) -- this is what makes routing rules fully backward
    /// compatible with every config that predates them.
    pub balancer: Arc<dyn LoadBalancer>,
    pub pool: Arc<BackendPool>,
    /// Path/Host-based backend selection (nginx's `location` blocks,
    /// HAProxy's ACL-based backend selection). Evaluated in order, first
    /// match wins, checked before `pool`/`balancer` above. Empty for a
    /// listener with no `[[listeners.routes]]`, which costs nothing extra
    /// on that path -- resolving "no match" against an empty `Vec` is one
    /// `is_empty()` check.
    pub routes: Vec<CompiledRoute>,
    /// Flat, not scoped per pool: correct because `Config::validate()`
    /// requires every backend id to be unique across the default backends
    /// *and every route's* within one listener, so a `BackendId` here
    /// unambiguously names one backend in one pool (`pool` or exactly one
    /// `routes[i].pool`) regardless of how many pools this context holds.
    pub circuit_breakers: HashMap<BackendId, CircuitBreaker<C>>,
    pub client: ProxyClient,
    /// Set only for a `dns_discovery` + `backend_tls` HTTP listener, where
    /// several backends share one `server_name` and so cannot safely share
    /// `client`'s connection pool -- see `lb_proxy::per_backend`. Checked
    /// ahead of `client` in the forwarding loop; `client` itself stays
    /// harmless (an empty dial-pinning table, never consulted) in that case.
    pub per_backend_client: Option<Arc<crate::per_backend::PerBackendClients>>,
    /// Whether this listener has a `[listeners.backend_tls]` section.
    ///
    /// A listener-level fact, not a per-backend one: it decides the
    /// forwarding scheme, and reading it off the backend instead would let a
    /// `server_name` set on a plaintext listener silently upgrade its
    /// traffic to a scheme nobody asked for.
    pub backend_tls: bool,
    pub rate_limit_key: RateLimitKeySource,
    pub forward_timeout: Duration,
    pub max_request_body_bytes: usize,
    /// Present only when `[cluster]` is configured; `None` means single-node.
    pub cluster: Option<Arc<dyn lb_core::ClusterCoordinator>>,
    /// Always present, never optional: recording is a few atomic increments,
    /// so keeping it unconditional avoids a branch on the hot path. The
    /// `[admin]` section controls *exposure*, not collection.
    pub metrics: Arc<ListenerMetrics>,
    pub backend_metrics: HashMap<BackendId, BackendMetrics>,
    /// Access-log settings. Logging every request at 50k req/s is ~50,000
    /// lines a second, so it is off unless explicitly enabled and sampled.
    pub access_log: AccessLog,
    /// Caps how long a client may take to send the body. A size limit alone
    /// is not a bound: 1 MiB at one byte per second is eleven days.
    pub body_read_timeout: Duration,
    /// `Some(seconds)` adds `Strict-Transport-Security: max-age=<seconds>` to
    /// every response; `None` adds nothing.
    ///
    /// Both gating conditions -- "only on a listener that terminates TLS"
    /// and "only when `hsts_max_age_secs` is above its default of 0" -- are
    /// folded into this one `Option` at wiring time
    /// (`lb_server::wiring::build_app`), not checked here. `handle` has no
    /// way to learn whether the connection it is serving arrived over TLS or
    /// plaintext: that fact was already consumed, and discarded, before this
    /// context was ever built. Emitting the header whenever this is `Some`
    /// is therefore correct by construction, not by a runtime check against
    /// something this layer cannot see. Zero is deliberately never
    /// represented as `Some(0)`: sending `max-age=0` is a materially
    /// different instruction to a browser than sending nothing at all -- it
    /// actively tells the browser to forget the policy, rather than simply
    /// never having asserted one.
    pub hsts_max_age_secs: Option<u64>,
}

/// One compiled routing rule -- see `ProxyContext::routes`.
pub struct CompiledRoute {
    /// Matched as a path *segment* prefix: `"/api"` matches `/api` and
    /// `/api/anything`, but not `/apiary` -- nginx's own `location /api`
    /// has exactly this gotcha (`route_matches` below is what avoids it).
    /// `None` matches every path.
    pub path_prefix: Option<String>,
    /// Case-insensitive exact match against the request's `Host` header.
    /// `None` matches every host.
    pub host: Option<String>,
    pub pool: Arc<BackendPool>,
    pub balancer: Arc<dyn LoadBalancer>,
}

/// `path` must be the path component alone (no query string) -- a route's
/// `path_prefix` is about where a request is going, not what it carries in
/// its query, and query strings can otherwise produce surprising matches
/// (`/api?path_prefix=/other`).
fn route_matches(route: &CompiledRoute, path: &str, host: Option<&str>) -> bool {
    let path_ok = match &route.path_prefix {
        None => true,
        Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")),
    };
    let host_ok = match &route.host {
        None => true,
        Some(expected) => host.is_some_and(|h| h.eq_ignore_ascii_case(expected)),
    };
    path_ok && host_ok
}

/// The first rule (in declaration order) whose `path_prefix`/`host` both
/// match, or `None` if `routes` is empty or nothing matches -- the caller's
/// existing `pool`/`balancer` fields are the correct fallback for `None`,
/// which is what makes an empty `routes` list behave exactly as it did
/// before routing rules existed.
fn resolve_route<'a, R: RateLimiter, C: Clock>(
    ctx: &'a ProxyContext<R, C>,
    path: &str,
    headers: &hyper::HeaderMap,
) -> Option<&'a CompiledRoute> {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    ctx.routes.iter().find(|r| route_matches(r, path, host))
}

/// Sampled per-request access logging.
pub struct AccessLog {
    pub enabled: bool,
    /// Log one request in every `sample_every`. Derived from `sample_rate`
    /// at wiring time so the hot path does no floating-point work.
    pub sample_every: u64,
    counter: std::sync::atomic::AtomicU64,
}

impl AccessLog {
    pub fn new(enabled: bool, sample_rate: f64) -> Self {
        let sample_every = if sample_rate <= 0.0 {
            u64::MAX
        } else {
            (1.0 / sample_rate).round().max(1.0) as u64
        };
        AccessLog {
            enabled,
            sample_every,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn disabled() -> Self {
        Self::new(false, 0.0)
    }

    /// Deterministic 1-in-N sampling off a counter rather than drawing a
    /// random number per request — cheaper, and gives an exact rate.
    fn should_log(&self) -> bool {
        if !self.enabled {
            return false;
        }
        self.counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .is_multiple_of(self.sample_every)
    }
}

impl<R: RateLimiter, C: Clock> ProxyContext<R, C> {
    fn circuit_breaker(&self, id: &BackendId) -> Option<&CircuitBreaker<C>> {
        self.circuit_breakers.get(id)
    }
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn text_body(text: &'static str) -> ProxyBody {
    Full::new(Bytes::from_static(text.as_bytes()))
        .map_err(|never| match never {})
        .boxed()
}

fn simple_response(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
    let mut resp = Response::new(if body.is_empty() {
        empty_body()
    } else {
        text_body(body)
    });
    *resp.status_mut() = status;
    resp
}

fn extract_key(req: &Request<Incoming>, source: &RateLimitKeySource, peer_ip: IpAddr) -> String {
    match source {
        // The connection's real peer address, not a client-supplied header.
        // Trusting X-Forwarded-For here would let any client mint itself a
        // fresh rate-limit bucket just by changing the header.
        RateLimitKeySource::SourceIp => peer_ip.to_string(),
        RateLimitKeySource::Header(name) => req
            .headers()
            .get(name.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string(),
    }
}

async fn read_bounded(body: Incoming, max_bytes: usize) -> Result<Bytes, ()> {
    let collected = body.collect().await.map_err(|_| ())?;
    let bytes = collected.to_bytes();
    if bytes.len() > max_bytes {
        Err(())
    } else {
        Ok(bytes)
    }
}

/// Removes hop-by-hop headers, which describe a single connection rather than
/// the message.
///
/// HTTP/2 forbids them outright and a client may reject a response carrying
/// one. Before this phase the question never arose — an HTTP/1.1 backend's
/// response went to an HTTP/1.1 client and both ends tolerated it — but an
/// HTTP/1.1 backend's response can now land on an HTTP/2 stream.
///
/// Applied unconditionally rather than only for HTTP/2 clients: these headers
/// were never correct to forward, HTTP/1.1 was simply tolerant of the
/// mistake, and one code path is one behaviour to test.
fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    const ALWAYS: [&str; 8] = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
    ];

    // `Connection` may *name* further headers that are hop-by-hop for this
    // hop only. Collect them before removing `Connection` itself.
    let named: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();

    for name in ALWAYS {
        headers.remove(name);
    }
    headers.remove("upgrade");
    for name in named {
        headers.remove(name.as_str());
    }
}

/// Rewrites the client's request as the one we send onward.
///
/// `None` means this backend cannot be forwarded to at all -- see the
/// nameless-backend arm below.
fn build_outbound_request(
    parts: &http::request::Parts,
    body: Bytes,
    backend: &lb_core::Backend,
    backend_tls: bool,
) -> Option<Request<Full<Bytes>>> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    // Shared with the health probe's own request building, deliberately: see
    // `backend_scheme_and_authority`. If the two ever decided this
    // separately, a probe could report a backend healthy over one transport
    // while traffic failed against it over another.
    let (scheme, authority) = backend_scheme_and_authority(backend, backend_tls)?;
    let uri = hyper::Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .expect("backend authority + original path form a valid URI");
    let mut builder = Request::builder().method(parts.method.clone()).uri(uri);
    // Direction: client -> backend. Strip before forwarding so a hop-by-hop
    // header the client sent us (describing its hop to us) is never carried
    // onto our hop to the backend.
    let mut headers = parts.headers.clone();
    strip_hop_by_hop(&mut headers);
    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }
    Some(
        builder
            .body(Full::new(body))
            .expect("forwarded request is well-formed"),
    )
}

pub async fn handle<R, C>(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext<R, C>>,
    peer_ip: IpAddr,
) -> Result<Response<ProxyBody>, Infallible>
where
    R: RateLimiter,
    C: Clock,
{
    let started = std::time::Instant::now();

    // Generated here, never taken from an inbound header: at the edge an
    // X-Request-Id is attacker-controlled and could be used to forge or
    // collide log entries.
    let request_id = uuid::Uuid::new_v4();
    let method = req.method().clone();
    // Read before `req` is moved into `handle_inner`. hyper sets this from
    // the connection that carried the request, so it is the negotiated
    // protocol rather than anything the client can assert in a header.
    let is_h2 = req.version() == hyper::Version::HTTP_2;
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // The root span for this request: everything `handle_inner` awaits
    // (rate limiting, backend selection, the forward itself) nests under
    // it, so an OpenTelemetry export (when configured -- see `lb-tracing`)
    // sees one trace per request rather than a flat pile of sibling spans.
    // Unconditional and cheap when nothing is exporting: that is the whole
    // design point of `tracing` spans, which is why this code does not
    // need to know whether OTel export is even turned on.
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        path = %path,
    );
    let mut result = handle_inner(req, Arc::clone(&ctx), peer_ip)
        .instrument(span)
        .await;

    // Recorded in exactly one place so no early return can forget to. The
    // inner function has six return sites; duplicating this at each of them
    // would be a bug waiting to happen.
    if let Ok(resp) = &mut result {
        let status = resp.status();
        ctx.metrics
            .record_status(is_h2, StatusClass::from_code(status.as_u16()));
        let elapsed = started.elapsed();
        ctx.metrics.request_duration.observe(elapsed.as_secs_f64());

        if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
            resp.headers_mut().insert("x-request-id", value);
        }

        // Unconditional on every response from a qualifying listener, not
        // just successful proxied ones: HSTS is a property of the host, and
        // a client that gets a 429 or a 503 needs the policy applied to it
        // exactly as much as one that gets a 200.
        if let Some(max_age) = ctx.hsts_max_age_secs {
            if let Ok(value) = HeaderValue::from_str(&format!("max-age={max_age}")) {
                resp.headers_mut()
                    .insert(header::STRICT_TRANSPORT_SECURITY, value);
            }
        }

        if ctx.access_log.should_log() {
            tracing::info!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = status.as_u16(),
                duration_ms = elapsed.as_millis() as u64,
                "request"
            );
        }
    }
    result
}

async fn handle_inner<R, C>(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext<R, C>>,
    peer_ip: IpAddr,
) -> Result<Response<ProxyBody>, Infallible>
where
    R: RateLimiter,
    C: Clock,
{
    let key = extract_key(&req, &ctx.rate_limit_key, peer_ip);
    if let Decision::Deny { retry_after } = ctx.rate_limiter.check(&key) {
        ctx.metrics.ratelimit_rejected_local.inc();
        let mut resp = simple_response(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        if let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return Ok(resp);
    }

    // The cluster budget is consulted only after the local limiter allowed
    // the request: local is free, this is shared state.
    if let Some(cluster) = &ctx.cluster {
        if !cluster.try_admit(&key) {
            ctx.metrics.ratelimit_rejected_cluster.inc();
            return Ok(simple_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            ));
        }
    }

    // Resolved once per request and used for everything below -- the
    // default `pool`/`balancer` for a listener with no `[[listeners.routes]]`
    // or no matching rule, otherwise the matched route's. `path()` alone
    // (never `path_and_query()`): a route's `path_prefix` is about where a
    // request is going, not what it carries in its query string.
    let route = resolve_route(&ctx, req.uri().path(), req.headers());
    let (pool, balancer): (&Arc<BackendPool>, &Arc<dyn LoadBalancer>) = match route {
        Some(r) => (&r.pool, &r.balancer),
        None => (&ctx.pool, &ctx.balancer),
    };

    // CircuitBreaker's Open -> HalfOpen transition is evaluated lazily inside
    // `is_open()`; BackendPool's `circuit_open` flag is a separate cached
    // bool that only this loop keeps in sync. Without refreshing it here, a
    // backend that ever trips its breaker would stay excluded from
    // `eligible_backends()` forever — nothing would call `is_open()` again to
    // notice the cooldown elapsed, since an excluded backend never gets
    // forwarded to. Refreshing once per request (cheap: a handful of
    // backends, one mutex check each) keeps the pool's view current and lets
    // a backend become eligible for a probe request as soon as it's due.
    // Scoped to `pool` (the one resolved above), not every pool this
    // context might hold: a route nobody is hitting has no traffic to keep
    // fresh for, for exactly the same reason a completely idle single-pool
    // listener already didn't refresh anything before routing rules existed
    // -- this loop only ever runs inside a request that is about to use it.
    for id in &pool.all_backend_ids() {
        if let Some(breaker) = ctx.circuit_breakers.get(id) {
            let state = breaker.state();
            pool.set_circuit_open(id, state == lb_healthcheck::CircuitState::Open);
            if let Some(bm) = ctx.backend_metrics.get(id) {
                bm.circuit_state.set(match state {
                    lb_healthcheck::CircuitState::Closed => 0,
                    lb_healthcheck::CircuitState::Open => 1,
                    lb_healthcheck::CircuitState::HalfOpen => 2,
                });
            }
        }
    }

    let (parts, body) = req.into_parts();
    let bytes = match tokio::time::timeout(
        ctx.body_read_timeout,
        read_bounded(body, ctx.max_request_body_bytes),
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(())) => {
            return Ok(simple_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ))
        }
        // 408 is the right answer to a client that took too long, and
        // distinguishes a slow sender from one that sent too much.
        Err(_) => {
            ctx.metrics.timeouts_body.inc();
            return Ok(simple_response(
                StatusCode::REQUEST_TIMEOUT,
                "request body read timed out",
            ));
        }
    };

    let mut last_status = StatusCode::SERVICE_UNAVAILABLE;
    for attempt in 0..2u8 {
        let Some(backend_id) = balancer.pick(pool, &key) else {
            return Ok(simple_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "no healthy backend",
            ));
        };
        let Some(backend) = pool.backend(&backend_id) else {
            continue;
        };
        // Held across the dial+forward below and dropped at the end of this
        // iteration regardless of outcome -- the only way `LeastConnections`
        // has real numbers to compare.
        let _active_guard = pool.track_active(&backend_id);
        let Some(outbound) =
            build_outbound_request(&parts, bytes.clone(), &backend, ctx.backend_tls)
        else {
            // Not retried: every backend of this listener would hit the same
            // misconfiguration, and the one thing we must not do is fall back
            // to plaintext.
            return Ok(simple_response(
                StatusCode::BAD_GATEWAY,
                "backend is missing the server_name its TLS configuration requires",
            ));
        };
        let attempt_started = std::time::Instant::now();

        let client = match &ctx.per_backend_client {
            Some(per_backend) => per_backend.get_or_build(&backend),
            None => ctx.client.clone(),
        };
        match forward(&client, outbound, ctx.forward_timeout).await {
            Ok(resp) => {
                if let Some(bm) = ctx.backend_metrics.get(&backend_id) {
                    bm.requests_success.inc();
                    bm.upstream_duration
                        .observe(attempt_started.elapsed().as_secs_f64());
                }
                if let Some(breaker) = ctx.circuit_breaker(&backend_id) {
                    breaker.record_success();
                }
                // Propagate immediately (not just next request) so a backend
                // that just recovered is usable again within this same burst.
                pool.set_circuit_open(&backend_id, false);
                let (mut resp_parts, resp_body) = resp.into_parts();
                // Direction: backend -> client. Strip before returning so a
                // hop-by-hop header the backend sent us (describing its hop
                // to us) is never carried onto our hop to the client.
                strip_hop_by_hop(&mut resp_parts.headers);
                return Ok(Response::from_parts(resp_parts, resp_body.boxed()));
            }
            Err(err) => {
                if let Some(bm) = ctx.backend_metrics.get(&backend_id) {
                    match err {
                        ForwardError::Timeout => bm.requests_timeout.inc(),
                        ForwardError::Connect => bm.requests_failure.inc(),
                    }
                }
                if let Some(breaker) = ctx.circuit_breaker(&backend_id) {
                    breaker.record_failure();
                    // Propagate immediately so the retry attempt below (if any)
                    // sees a freshly-tripped breaker instead of the stale flag
                    // from the top-of-request refresh.
                    pool.set_circuit_open(&backend_id, breaker.is_open());
                }
                last_status = StatusCode::BAD_GATEWAY;
                if attempt == 1 {
                    break;
                }
            }
        }
    }
    Ok(simple_response(last_status, "upstream error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::build_client;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use lb_core::test_util::FakeClock;
    use lb_core::{Backend, Decision};
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    struct AlwaysDeny;
    impl RateLimiter for AlwaysDeny {
        fn check(&self, _key: &str) -> Decision {
            Decision::Deny {
                retry_after: Duration::from_secs(1),
            }
        }
    }

    struct AlwaysAllow;
    impl RateLimiter for AlwaysAllow {
        fn check(&self, _key: &str) -> Decision {
            Decision::Allow
        }
    }

    struct NoBackend;
    impl LoadBalancer for NoBackend {
        fn pick(&self, _pool: &BackendPool, _key: &str) -> Option<BackendId> {
            None
        }
    }

    struct FixedPick(BackendId);
    impl LoadBalancer for FixedPick {
        fn pick(&self, _pool: &BackendPool, _key: &str) -> Option<BackendId> {
            Some(self.0.clone())
        }
    }

    /// Deterministic double for exercising eligibility exclusion: always
    /// picks whichever eligible backend sorts first in pool order, so a test
    /// can see a specific backend drop out (and later return) without
    /// needing real round-robin cursor semantics from the `lb-balancer` crate
    /// (which `lb-proxy` intentionally doesn't depend on).
    struct PreferFirstEligible;
    impl LoadBalancer for PreferFirstEligible {
        fn pick(&self, pool: &BackendPool, _key: &str) -> Option<BackendId> {
            pool.eligible_backends().into_iter().next()
        }
    }

    async fn spawn_fixed_response_backend(status: StatusCode, body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from_static(body.as_bytes())))
                                .unwrap(),
                        )
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        addr
    }

    /// Drives a real request through our own proxy listener so `handle` sees
    /// a genuine `Request<Incoming>` (the type only a real connection produces).
    async fn run_through_proxy<R, C>(ctx: Arc<ProxyContext<R, C>>) -> Response<Bytes>
    where
        R: RateLimiter + 'static,
        C: Clock + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, ctx.clone(), "127.0.0.1".parse().unwrap()));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });

        let client = build_client(None, HashMap::new(), false);
        let req = Request::builder()
            .uri(format!("http://{addr}/"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        Response::from_parts(parts, bytes)
    }

    /// Like `run_through_proxy`, but for routing-rule tests that need to
    /// choose the request's path and/or `Host` header -- `resolve_route`
    /// matches on both, and neither is reachable through the plain-`/`
    /// helper above.
    async fn run_through_proxy_at<R, C>(
        ctx: Arc<ProxyContext<R, C>>,
        path: &str,
        host: Option<&str>,
    ) -> Response<Bytes>
    where
        R: RateLimiter + 'static,
        C: Clock + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, ctx.clone(), "127.0.0.1".parse().unwrap()));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });

        let client = build_client(None, HashMap::new(), false);
        let mut builder = Request::builder().uri(format!("http://{addr}{path}"));
        if let Some(host) = host {
            builder = builder.header(header::HOST, host);
        }
        let req = builder.body(Full::new(Bytes::new())).unwrap();
        let resp = client.request(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        Response::from_parts(parts, bytes)
    }

    fn empty_pool() -> Arc<BackendPool> {
        Arc::new(BackendPool::new(vec![]))
    }

    /// Metrics are always-on in production, so tests supply real handles
    /// rather than a null object. Nothing scrapes them here; they just need
    /// to exist so the hot path stays branch-free.
    fn test_metrics() -> Arc<ListenerMetrics> {
        let registry = lb_metrics::Metrics::new().expect("metrics registry");
        Arc::new(registry.listener("test"))
    }

    #[tokio::test]
    async fn rate_limited_request_gets_429_without_touching_a_backend() {
        // `C` (the Clock used by CircuitBreaker) is never exercised on this
        // path, but Rust still needs a concrete type to monomorphize
        // ProxyContext — pin it to FakeClock via the annotated HashMap,
        // consistent with the other tests in this module.
        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysDeny),
            balancer: Arc::new(NoBackend), // would return None if reached; proves we short-circuit
            pool: empty_pool(),
            routes: Vec::new(),
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn no_eligible_backend_gets_503() {
        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(NoBackend),
            pool: empty_pool(),
            routes: Vec::new(),
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn successful_forward_returns_backend_response_and_records_success() {
        let backend_addr = spawn_fixed_response_backend(StatusCode::OK, "hi").await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        let mut breakers = HashMap::new();
        breakers.insert(
            backend.id.clone(),
            CircuitBreaker::new(3, Duration::from_secs(5), FakeClock::new()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_backend_with_no_circuit_breaker_entry_still_forwards() {
        let backend_addr = spawn_fixed_response_backend(StatusCode::OK, "hi").await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn failed_forward_retries_once_then_returns_502() {
        // FixedPick always points at a port nobody is listening on.
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let backend = Backend::new("b1", dead_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        let mut breakers = HashMap::new();
        breakers.insert(
            backend.id.clone(),
            CircuitBreaker::new(3, Duration::from_secs(5), FakeClock::new()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn open_circuit_excludes_backend_until_it_recovers() {
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap(); // refused instantly
        let healthy_addr = spawn_fixed_response_backend(StatusCode::OK, "ok").await;

        let dead = Backend::new("dead", dead_addr, 1, None);
        let healthy = Backend::new("healthy", healthy_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![dead.clone(), healthy.clone()]));

        let clock = FakeClock::new();
        let mut breakers = HashMap::new();
        breakers.insert(
            dead.id.clone(),
            CircuitBreaker::new(1, Duration::from_secs(60), clock.clone()),
        );
        breakers.insert(
            healthy.id.clone(),
            CircuitBreaker::new(1, Duration::from_secs(60), clock.clone()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(PreferFirstEligible),
            pool: pool.clone(),
            routes: Vec::new(),
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });

        // "dead" sorts first in pool order, so PreferFirstEligible tries it,
        // fails, trips its breaker (threshold 1), and retries onto "healthy".
        let resp = run_through_proxy(ctx.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(ctx.circuit_breaker(&dead.id).unwrap().is_open());
        assert!(!pool.is_eligible(&dead.id));

        // Now "dead" is excluded up front — the next request goes straight
        // to "healthy" without ever touching the tripped backend.
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The load-bearing positive case for `hsts_max_age_secs`: when wiring
    /// hands `handle` a `Some`, the header goes on the response with exactly
    /// that value.
    #[tokio::test]
    async fn hsts_header_is_added_when_configured() {
        let backend_addr = spawn_fixed_response_backend(StatusCode::OK, "hi").await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        let mut breakers = HashMap::new();
        breakers.insert(
            backend.id.clone(),
            CircuitBreaker::new(3, Duration::from_secs(5), FakeClock::new()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: Some(31_536_000),
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::STRICT_TRANSPORT_SECURITY)
                .expect("Strict-Transport-Security header missing"),
            "max-age=31536000"
        );
    }

    /// The default-path case, and the one that matters most: `None` (which
    /// is what wiring produces whenever `hsts_max_age_secs` is left at its
    /// default of 0, or the listener has no `[listeners.tls]` at all) must
    /// add nothing. A bug here would put an unrequested, hard-to-withdraw
    /// policy on every response by default -- see the doc comment on
    /// `ProxyContext::hsts_max_age_secs` for why `max-age=0` is not an
    /// acceptable stand-in for "nothing" either.
    #[tokio::test]
    async fn hsts_header_is_absent_when_not_configured() {
        let backend_addr = spawn_fixed_response_backend(StatusCode::OK, "hi").await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        let mut breakers = HashMap::new();
        breakers.insert(
            backend.id.clone(),
            CircuitBreaker::new(3, Duration::from_secs(5), FakeClock::new()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::STRICT_TRANSPORT_SECURITY)
                .is_none(),
            "HSTS header must not be sent when hsts_max_age_secs is not configured"
        );
    }

    /// Turns a request into the outbound one the forwarding client would
    /// send, without a live backend: what is being asserted is the URI, and a
    /// real connection would only add flakiness to that.
    fn outbound_uri_for(backend: &Backend, backend_tls: bool) -> Option<String> {
        let (parts, _) = Request::builder()
            .uri("/orders?page=2")
            .body(())
            .unwrap()
            .into_parts();
        build_outbound_request(&parts, Bytes::new(), backend, backend_tls)
            .map(|req| req.uri().to_string())
    }

    /// The whole point of carrying `server_name`: the connection is one
    /// thing, the identity we demand of it is another. Sending the IP as the
    /// authority would make SNI and hostname verification check the address
    /// we happened to dial, which no certificate is issued for.
    #[test]
    fn re_encrypting_forwards_to_the_certificate_name_not_the_address() {
        let backend = Backend::new(
            "b1",
            "10.0.0.5:8443".parse().unwrap(),
            1,
            Some("web1.internal".to_string()),
        );
        assert_eq!(
            outbound_uri_for(&backend, true).as_deref(),
            Some("https://web1.internal:8443/orders?page=2")
        );
    }

    /// Phase 5 behaviour, unchanged: without `backend_tls` the listener
    /// forwards plaintext to the configured address, and a `server_name`
    /// that happens to be set does not quietly upgrade the scheme.
    #[test]
    fn without_backend_tls_the_address_is_used_over_plaintext() {
        let backend = Backend::new(
            "b1",
            "10.0.0.5:8080".parse().unwrap(),
            1,
            Some("web1.internal".to_string()),
        );
        assert_eq!(
            outbound_uri_for(&backend, false).as_deref(),
            Some("http://10.0.0.5:8080/orders?page=2")
        );
    }

    /// Config validation requires a `server_name` on every backend of a
    /// re-encrypting listener. If that guard were ever bypassed, forwarding
    /// in plaintext would silently defeat the encryption that was asked for,
    /// so no request is built at all.
    #[test]
    fn a_re_encrypting_listener_builds_no_request_for_a_nameless_backend() {
        let backend = Backend::new("b1", "10.0.0.5:8443".parse().unwrap(), 1, None);
        assert_eq!(outbound_uri_for(&backend, true), None);
    }

    #[test]
    fn hop_by_hop_headers_are_removed() {
        use hyper::header::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-custom"),
        );
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("upgrade", HeaderValue::from_static("websocket"));
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        headers.insert("x-custom", HeaderValue::from_static("named-by-connection"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        strip_hop_by_hop(&mut headers);

        for gone in [
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
            // Named inside `Connection`, so hop-by-hop by reference. Missing this
            // is the subtle half of the rule.
            "x-custom",
        ] {
            assert!(!headers.contains_key(gone), "{gone} survived stripping");
        }
        // End-to-end headers must be untouched.
        assert_eq!(
            headers.get("content-type").map(|v| v.as_bytes()),
            Some(&b"application/json"[..])
        );
    }

    /// Builds a `ProxyContext` with one default backend and one routed
    /// backend behind `route`'s `path_prefix`/`host` -- the fixture every
    /// routing-rule test below starts from.
    async fn ctx_with_one_route(
        route_path_prefix: Option<&str>,
        route_host: Option<&str>,
    ) -> (
        Arc<ProxyContext<AlwaysAllow, FakeClock>>,
        SocketAddr,
        SocketAddr,
    ) {
        let default_addr = spawn_fixed_response_backend(StatusCode::OK, "default").await;
        let route_addr = spawn_fixed_response_backend(StatusCode::OK, "route").await;
        let default_backend = Backend::new("default-1", default_addr, 1, None);
        let route_backend = Backend::new("route-1", route_addr, 1, None);
        let default_pool = Arc::new(BackendPool::new(vec![default_backend.clone()]));
        let route_pool = Arc::new(BackendPool::new(vec![route_backend.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(default_backend.id.clone())),
            pool: default_pool,
            routes: vec![CompiledRoute {
                path_prefix: route_path_prefix.map(str::to_string),
                host: route_host.map(str::to_string),
                pool: route_pool,
                balancer: Arc::new(FixedPick(route_backend.id.clone())),
            }],
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });
        (ctx, default_addr, route_addr)
    }

    #[tokio::test]
    async fn a_request_matching_a_route_path_prefix_is_served_by_the_routes_backend() {
        let (ctx, _, _) = ctx_with_one_route(Some("/api"), None).await;
        let resp = run_through_proxy_at(ctx, "/api/orders", None).await;
        assert_eq!(resp.body(), "route");
    }

    #[tokio::test]
    async fn a_request_matching_no_route_falls_through_to_the_default() {
        let (ctx, _, _) = ctx_with_one_route(Some("/api"), None).await;
        let resp = run_through_proxy_at(ctx, "/other", None).await;
        assert_eq!(resp.body(), "default");
    }

    /// nginx's own `location /api` gotcha: `/apiary` shares the `/api`
    /// prefix as a string but is not the same path segment, and must not
    /// match.
    #[tokio::test]
    async fn path_prefix_does_not_match_a_longer_segment() {
        let (ctx, _, _) = ctx_with_one_route(Some("/api"), None).await;
        let resp = run_through_proxy_at(ctx, "/apiary", None).await;
        assert_eq!(resp.body(), "default");
    }

    #[tokio::test]
    async fn a_route_with_only_a_host_condition_matches_regardless_of_path() {
        let (ctx, _, _) = ctx_with_one_route(None, Some("api.internal")).await;
        let resp = run_through_proxy_at(ctx, "/anything", Some("api.internal")).await;
        assert_eq!(resp.body(), "route");
    }

    #[tokio::test]
    async fn host_matching_is_case_insensitive() {
        let (ctx, _, _) = ctx_with_one_route(None, Some("api.internal")).await;
        let resp = run_through_proxy_at(ctx, "/anything", Some("API.INTERNAL")).await;
        assert_eq!(resp.body(), "route");
    }

    #[tokio::test]
    async fn a_host_condition_that_does_not_match_falls_through_to_the_default() {
        let (ctx, _, _) = ctx_with_one_route(None, Some("api.internal")).await;
        let resp = run_through_proxy_at(ctx, "/anything", Some("other.internal")).await;
        assert_eq!(resp.body(), "default");
    }

    /// First-match-wins, in declaration order: a second rule that would also
    /// match is never reached once an earlier one already did.
    #[tokio::test]
    async fn first_matching_route_wins_over_a_later_one_that_would_also_match() {
        let default_addr = spawn_fixed_response_backend(StatusCode::OK, "default").await;
        let first_addr = spawn_fixed_response_backend(StatusCode::OK, "first").await;
        let second_addr = spawn_fixed_response_backend(StatusCode::OK, "second").await;
        let default_backend = Backend::new("default-1", default_addr, 1, None);
        let first_backend = Backend::new("first-1", first_addr, 1, None);
        let second_backend = Backend::new("second-1", second_addr, 1, None);

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(default_backend.id.clone())),
            pool: Arc::new(BackendPool::new(vec![default_backend.clone()])),
            routes: vec![
                CompiledRoute {
                    path_prefix: Some("/api".to_string()),
                    host: None,
                    pool: Arc::new(BackendPool::new(vec![first_backend.clone()])),
                    balancer: Arc::new(FixedPick(first_backend.id.clone())),
                },
                CompiledRoute {
                    path_prefix: Some("/api".to_string()),
                    host: None,
                    pool: Arc::new(BackendPool::new(vec![second_backend.clone()])),
                    balancer: Arc::new(FixedPick(second_backend.id.clone())),
                },
            ],
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false),
            per_backend_client: None,
            backend_tls: false,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });

        let resp = run_through_proxy_at(ctx, "/api/orders", None).await;
        assert_eq!(resp.body(), "first");
    }
}
