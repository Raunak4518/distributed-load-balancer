use crate::cache::{self, ResponseCache};
use crate::forward::{backend_scheme_and_authority, forward, ForwardError, ProxyClient};
use crate::sticky::{self, StickyRuntime};
use crate::upgrade;
use crate::waf;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use lb_core::{
    BackendId, BackendPool, Clock, Decision, LoadBalancer, RateLimitKeySource, RateLimiter, WafMode,
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
    /// Weighted traffic-split / canary pools -- see `resolve_default_or_canary_pool`.
    /// Consulted only for a request that matched no rule in `routes` above;
    /// empty for a listener with no `[[listeners.canary]]`, costing one
    /// `is_empty()` check on that path, same as `routes`.
    pub canary: Vec<CompiledCanaryPool>,
    /// Deterministic cursor for `canary`'s weighted roll -- see
    /// `resolve_default_or_canary_pool`. Never consulted when `canary` is
    /// empty.
    pub canary_cursor: std::sync::atomic::AtomicUsize,
    /// Session affinity via a `Set-Cookie` naming the backend a client last
    /// landed on -- see `crate::sticky`'s module docs. Listener-level, so it
    /// applies uniformly to `pool`/`balancer` above and to every entry in
    /// `routes`: a pin naming a backend from a pool other than the one this
    /// request resolved into simply fails `BackendPool::is_eligible` and
    /// falls through, exactly as an absent cookie would.
    pub sticky: Option<StickyRuntime>,
    /// Answers a repeated `GET` straight from memory -- see `crate::cache`'s
    /// module docs. Listener-level for the same reason `sticky` is: a
    /// route's `path_prefix`/`host` are already part of the cache key, so
    /// one cache per listener is already correctly partitioned between
    /// routes without a separate per-route toggle.
    pub cache: Option<Arc<ResponseCache<C>>>,
    /// Blocks (or, in `Log` mode, just records) a request matching one of
    /// the built-in WAF rules -- see `crate::waf`'s module docs. A direct
    /// passthrough of the config enum, not a wrapper struct: unlike
    /// `sticky`'s `secure` flag, nothing here needs deriving from another
    /// listener fact at wiring time (`RateLimitKeySource` is stored the
    /// same way, for the same reason).
    pub waf: Option<WafMode>,
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
    /// The raw connector behind `client`'s pooled backend TLS, needed again
    /// for the WebSocket/Upgrade backend leg's own dedicated, non-pooled
    /// connection -- see `crate::upgrade`'s module docs for why that leg
    /// cannot reuse `client`. `None` for a plaintext-backend listener,
    /// exactly when `backend_tls` above is `false`.
    pub backend_tls_connector: Option<Arc<lb_tls::BackendConnector>>,
    pub rate_limit_key: RateLimitKeySource,
    pub forward_timeout: Duration,
    pub max_request_body_bytes: usize,
    /// See `crate::upgrade`'s module docs: how long a WebSocket/Upgrade
    /// connection may sit idle once the backend accepts the handshake.
    /// `forward_timeout`/`body_read_timeout` never apply past that point.
    pub websocket_idle_timeout: Duration,
    /// See `lb_core::TcpKeepaliveConfig`. Applied to `client`'s pooled
    /// connections via `HttpConnector`'s own native setters at wiring time
    /// (`crate::forward::build_client`) -- this field exists on
    /// `ProxyContext` only so `crate::upgrade`'s dedicated, non-pooled
    /// backend connection (which bypasses `build_client` entirely) can
    /// apply the same setting itself, at request time.
    pub backend_tcp_keepalive: Option<lb_core::TcpKeepaliveConfig>,
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

/// One `[[listeners.canary]]` pool -- see `ProxyContext::canary`. Mirrors
/// `CompiledRoute` minus `path_prefix`/`host` (a canary pool is selected by
/// a weighted roll, not by matching anything about the request) plus
/// `percent`.
pub struct CompiledCanaryPool {
    /// Absolute percentage (1-99) of this listener's total request volume
    /// that matched no route -- not the same unit as a backend's own
    /// `weight`, which biases selection *within* one pool.
    pub percent: u8,
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

/// Chooses the default `pool`/`balancer` or one of `ctx.canary`'s pools, for
/// a request that matched no `[[listeners.routes]]` rule -- a route match
/// always wins outright and never reaches this function.
///
/// `sticky_pin`, when present, is checked *before* rolling the weighted
/// split: if it names a backend that structurally belongs to one of these
/// pools (regardless of that specific backend's current health -- exactly
/// the same "pin the pool, let `balancer.pick` handle an unhealthy pinned
/// backend within it" split `handle`'s retry loop already relies on), that
/// pool is used directly, with no roll. This is what keeps one client's
/// whole session on whichever pool (default or canary) it first landed in,
/// rather than re-rolling the split on every request the way a plain
/// weighted-random pick would.
///
/// The roll itself is a deterministic `AtomicUsize` cursor mod 100 (same
/// pattern as `lb_balancer::RoundRobin`'s own cursor), bucketed by
/// cumulative `percent` -- exact long-run convergence to the configured
/// split, no `rand` dependency.
fn resolve_default_or_canary_pool<'a, R: RateLimiter, C: Clock>(
    ctx: &'a ProxyContext<R, C>,
    sticky_pin: Option<&BackendId>,
) -> (&'a Arc<BackendPool>, &'a Arc<dyn LoadBalancer>) {
    if ctx.canary.is_empty() {
        return (&ctx.pool, &ctx.balancer);
    }
    if let Some(id) = sticky_pin {
        if ctx.pool.all_backend_ids().contains(id) {
            return (&ctx.pool, &ctx.balancer);
        }
        for c in &ctx.canary {
            if c.pool.all_backend_ids().contains(id) {
                return (&c.pool, &c.balancer);
            }
        }
    }
    let bucket = ctx
        .canary_cursor
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        % 100;
    let mut cumulative: u32 = 0;
    for c in &ctx.canary {
        cumulative += c.percent as u32;
        if (bucket as u32) < cumulative {
            return (&c.pool, &c.balancer);
        }
    }
    (&ctx.pool, &ctx.balancer)
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

pub(crate) fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn text_body(text: &'static str) -> ProxyBody {
    Full::new(Bytes::from_static(text.as_bytes()))
        .map_err(|never| match never {})
        .boxed()
}

pub(crate) fn simple_response(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
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
pub(crate) fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
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

    // Checked here -- after the free, local rate limiter, but before the
    // cluster budget below and everything else that follows -- so a request
    // this blocks never consumes shared cluster-rate-limit state, never
    // counts as a cache miss, and never triggers a route lookup.
    if let Some(mode) = ctx.waf {
        let target = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_else(|| req.uri().path());
        if let Some(rule) = waf::matched_rule(target) {
            ctx.metrics.record_waf_block(rule);
            tracing::warn!(rule = rule.as_label(), mode = ?mode, "waf rule matched");
            if mode == WafMode::Block {
                return Ok(simple_response(StatusCode::FORBIDDEN, "request blocked"));
            }
            // Log mode: recorded above, falls through to normal handling.
        }
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

    // Checked before anything else below (route resolution, body read,
    // circuit-breaker refresh, the sticky pin, the retry loop) -- a hit
    // skips all of it, which is the entire point of caching. Correctness
    // doesn't depend on which pool this request would resolve into: the
    // key already carries the request's path/query/Host, so a listener's
    // one cache is already correctly partitioned between routes.
    let cache_key = ctx
        .cache
        .as_ref()
        .filter(|_| req.method() == Method::GET)
        .map(|_| cache::key_for(req.method(), req.uri(), req.headers()));
    if let (Some(cache), Some(key)) = (&ctx.cache, &cache_key) {
        if let Some(cached) = cache.get(key) {
            ctx.metrics.cache_hit.inc();
            let (mut parts, _) = Response::new(()).into_parts();
            parts.status = cached.status;
            parts.headers = cached.headers;
            let body = Full::new(cached.body)
                .map_err(|never| match never {})
                .boxed();
            return Ok(Response::from_parts(parts, body));
        }
        ctx.metrics.cache_miss.inc();
    }

    // Read from the request head, before the body is consumed below --
    // cheap, and needed here (not just at its other use site further down)
    // so `resolve_default_or_canary_pool` can pin a returning client to
    // whichever pool (default or canary) their last session landed in. Used
    // again, unchanged, by the retry loop below: only the first attempt
    // trusts it, since a pin that just failed must not be retried against
    // the same broken backend.
    let sticky_pin = ctx
        .sticky
        .as_ref()
        .and_then(|s| sticky::read_sticky_backend(req.headers(), &s.cookie_name));

    // Resolved once per request and used for everything below -- the
    // default `pool`/`balancer` for a listener with no `[[listeners.routes]]`
    // or no matching rule, otherwise the matched route's. `path()` alone
    // (never `path_and_query()`): a route's `path_prefix` is about where a
    // request is going, not what it carries in its query string. A route
    // match always wins outright; only the fallback case is subject to
    // `[[listeners.canary]]`'s weighted split.
    let route = resolve_route(&ctx, req.uri().path(), req.headers());
    let (pool, balancer): (&Arc<BackendPool>, &Arc<dyn LoadBalancer>) = match route {
        Some(r) => (&r.pool, &r.balancer),
        None => resolve_default_or_canary_pool(&ctx, sticky_pin.as_ref()),
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

    // Bypasses the cache-store/sticky-pin/retry-loop machinery below
    // entirely -- none of it applies to a connection that is about to stop
    // being HTTP. See `crate::upgrade`'s module docs for why this can't be
    // handled by `strip_hop_by_hop` (which runs later, in the ordinary
    // path) instead.
    if upgrade::is_upgrade_request(req.headers()) {
        return Ok(upgrade::handle_upgrade(req, &ctx, pool, balancer, &key).await);
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
        let pinned = (attempt == 0)
            .then(|| sticky_pin.clone())
            .flatten()
            .filter(|id| pool.is_eligible(id));
        let Some(backend_id) = pinned.or_else(|| balancer.pick(pool, &key)) else {
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
                balancer.record_latency(&backend_id, attempt_started.elapsed());
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

                // Decided (and, if cacheable, buffered) before the sticky
                // Set-Cookie below is added: a cached entry must never carry
                // one client's sticky pin, or every future client served
                // from it would be silently pinned to that same backend too.
                let cache_ttl = match (&ctx.cache, &cache_key) {
                    (Some(cache), Some(_)) => cache::cacheable_ttl(
                        &Method::GET,
                        resp_parts.status,
                        &resp_parts.headers,
                        cache.max_entry_bytes(),
                        cache.default_ttl(),
                    ),
                    _ => None,
                };
                let body: ProxyBody = if let (Some(cache), Some(key), Some(ttl)) =
                    (&ctx.cache, &cache_key, cache_ttl)
                {
                    let cache_status = resp_parts.status;
                    let cache_headers = resp_parts.headers.clone();
                    // Content-Length was already checked against
                    // max_entry_bytes above, so this collect is bounded
                    // in size; still time-boxed, since a declared length
                    // is no guarantee the backend delivers it promptly.
                    // A body already being collected can't be handed
                    // back as a live stream on failure -- the same "no
                    // replay after `.collect()`" constraint
                    // `read_bounded` already lives with on the request
                    // side -- so a timeout or transport error here
                    // surfaces as a clean error instead of a truncated
                    // stream.
                    match tokio::time::timeout(ctx.body_read_timeout, resp_body.collect()).await {
                        Ok(Ok(collected)) => {
                            let bytes = collected.to_bytes();
                            cache.put(key.clone(), cache_status, cache_headers, bytes.clone(), ttl);
                            Full::new(bytes).map_err(|never| match never {}).boxed()
                        }
                        _ => {
                            return Ok(simple_response(
                                StatusCode::BAD_GATEWAY,
                                "backend response could not be read",
                            ));
                        }
                    }
                } else {
                    resp_body.boxed()
                };

                // Refreshed on every successful response, whether or not it
                // matches an incoming pin -- this both renews the TTL for an
                // already-pinned client and pins a first-time client
                // starting from their very first response.
                if let Some(sticky) = &ctx.sticky {
                    resp_parts.headers.insert(
                        header::SET_COOKIE,
                        sticky::set_cookie_header(sticky, &backend_id),
                    );
                }
                return Ok(Response::from_parts(resp_parts, body));
            }
            Err(err) => {
                if let Some(bm) = ctx.backend_metrics.get(&backend_id) {
                    match err {
                        ForwardError::Timeout => bm.requests_timeout.inc(),
                        ForwardError::Connect => bm.requests_failure.inc(),
                    }
                }
                balancer.record_latency(&backend_id, attempt_started.elapsed());
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

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

    /// Proves a cache hit skips picking a backend entirely: any call to
    /// `pick` at all is the test failing, not just picking wrong.
    struct PanicIfPicked;
    impl LoadBalancer for PanicIfPicked {
        fn pick(&self, _pool: &BackendPool, _key: &str) -> Option<BackendId> {
            panic!("balancer.pick() must not be called on a cache hit");
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

    /// Like `spawn_fixed_response_backend`, but counts requests and sends an
    /// explicit `Content-Length` (required for `cacheable_ttl` to consider a
    /// response cacheable at all) plus whatever `extra_headers` a
    /// cache-behavior test needs (typically `Cache-Control`).
    async fn spawn_counting_cacheable_backend(
        body: &'static str,
        extra_headers: &'static [(&'static str, &'static str)],
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_clone = count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = TokioIo::new(stream);
                let count = count_clone.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: Request<Incoming>| {
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        async move {
                            let mut builder = Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_LENGTH, body.len().to_string());
                            for (name, value) in extra_headers {
                                builder = builder.header(*name, *value);
                            }
                            Ok::<_, Infallible>(
                                builder
                                    .body(Full::new(Bytes::from_static(body.as_bytes())))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        (addr, count)
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

        let client = build_client(None, HashMap::new(), false, None);
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

        let client = build_client(None, HashMap::new(), false, None);
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

    /// Like `run_through_proxy`, but for sticky-cookie tests that need to
    /// send a `Cookie` request header -- the read side `resolve_route`'s
    /// helpers above have no reason to exercise.
    async fn run_through_proxy_with_cookie<R, C>(
        ctx: Arc<ProxyContext<R, C>>,
        cookie: Option<&str>,
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

        let client = build_client(None, HashMap::new(), false, None);
        let mut builder = Request::builder().uri(format!("http://{addr}/"));
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
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
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            CircuitBreaker::new(3, Duration::from_secs(5), 1, FakeClock::new()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            CircuitBreaker::new(3, Duration::from_secs(5), 1, FakeClock::new()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            CircuitBreaker::new(1, Duration::from_secs(60), 1, clock.clone()),
        );
        breakers.insert(
            healthy.id.clone(),
            CircuitBreaker::new(1, Duration::from_secs(60), 1, clock.clone()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(PreferFirstEligible),
            pool: pool.clone(),
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            CircuitBreaker::new(3, Duration::from_secs(5), 1, FakeClock::new()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            CircuitBreaker::new(3, Duration::from_secs(5), 1, FakeClock::new()),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: breakers,
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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

    /// `resolve_default_or_canary_pool` unit tests -- called directly rather
    /// than through `run_through_proxy_at`, since nothing here forwards a
    /// request and these pools' addresses are never dialed.
    fn ctx_with_canary(canary: Vec<CompiledCanaryPool>) -> ProxyContext<AlwaysAllow, FakeClock> {
        let default_backend = Backend::new("default-1", "127.0.0.1:9301".parse().unwrap(), 1, None);
        ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(default_backend.id.clone())),
            pool: Arc::new(BackendPool::new(vec![default_backend])),
            routes: Vec::new(),
            canary,
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        }
    }

    fn canary_pool(id: &str, port: u16, percent: u8) -> CompiledCanaryPool {
        let backend = Backend::new(id, format!("127.0.0.1:{port}").parse().unwrap(), 1, None);
        CompiledCanaryPool {
            percent,
            pool: Arc::new(BackendPool::new(vec![backend.clone()])),
            balancer: Arc::new(FixedPick(backend.id)),
        }
    }

    #[test]
    fn no_canary_configured_always_uses_the_default_pool() {
        let ctx = ctx_with_canary(Vec::new());
        let (pool, _) = resolve_default_or_canary_pool(&ctx, None);
        assert!(Arc::ptr_eq(pool, &ctx.pool));
    }

    #[test]
    fn weighted_roll_converges_exactly_to_the_configured_percentage() {
        let ctx = ctx_with_canary(vec![canary_pool("canary-1", 9302, 30)]);
        let mut canary_hits = 0;
        let mut default_hits = 0;
        for _ in 0..100 {
            let (pool, _) = resolve_default_or_canary_pool(&ctx, None);
            if Arc::ptr_eq(pool, &ctx.canary[0].pool) {
                canary_hits += 1;
            } else if Arc::ptr_eq(pool, &ctx.pool) {
                default_hits += 1;
            }
        }
        assert_eq!(canary_hits, 30);
        assert_eq!(default_hits, 70);
    }

    #[test]
    fn sticky_pin_naming_a_canary_backend_returns_that_pool_without_rolling() {
        let ctx = ctx_with_canary(vec![canary_pool("canary-1", 9303, 5)]);
        let pinned = ctx.canary[0].pool.all_backend_ids()[0].clone();

        let (pool, _) = resolve_default_or_canary_pool(&ctx, Some(&pinned));

        assert!(Arc::ptr_eq(pool, &ctx.canary[0].pool));
        assert_eq!(
            ctx.canary_cursor.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a pinned pool must not consume a roll slot"
        );
    }

    #[test]
    fn sticky_pin_naming_the_default_pool_returns_it_without_rolling() {
        let ctx = ctx_with_canary(vec![canary_pool("canary-1", 9304, 99)]);
        let pinned = ctx.pool.all_backend_ids()[0].clone();

        let (pool, _) = resolve_default_or_canary_pool(&ctx, Some(&pinned));

        assert!(Arc::ptr_eq(pool, &ctx.pool));
        assert_eq!(
            ctx.canary_cursor.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn sticky_pin_naming_an_unknown_backend_falls_through_to_a_fresh_roll() {
        let ctx = ctx_with_canary(vec![canary_pool("canary-1", 9305, 5)]);
        let unknown = BackendId::new("nobody-here");

        resolve_default_or_canary_pool(&ctx, Some(&unknown));

        assert_eq!(
            ctx.canary_cursor.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "an unrecognised pin must roll fresh, same as no pin at all"
        );
    }

    /// Builds a `ProxyContext` with two backends and `balancer` always
    /// wanting `algorithm_backend` -- the fixture every sticky-cookie test
    /// below starts from, so a pin naming the *other* backend can prove it
    /// actually overrides the algorithm rather than merely agreeing with it.
    async fn ctx_with_two_backends_and_sticky(
        sticky: Option<StickyRuntime>,
    ) -> (Arc<ProxyContext<AlwaysAllow, FakeClock>>, Backend, Backend) {
        let a_addr = spawn_fixed_response_backend(StatusCode::OK, "a").await;
        let b_addr = spawn_fixed_response_backend(StatusCode::OK, "b").await;
        let backend_a = Backend::new("backend-a", a_addr, 1, None);
        let backend_b = Backend::new("backend-b", b_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend_a.clone(), backend_b.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            // The algorithm always wants "b" -- any test where a sticky pin
            // for "a" wins is proof the pin overrode this, not luck.
            balancer: Arc::new(FixedPick(backend_b.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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
        (ctx, backend_a, backend_b)
    }

    fn test_sticky_runtime() -> StickyRuntime {
        StickyRuntime {
            cookie_name: "lb_sticky".to_string(),
            max_age_secs: None,
            secure: false,
        }
    }

    #[tokio::test]
    async fn no_sticky_config_means_no_set_cookie_header() {
        let (ctx, _, _) = ctx_with_two_backends_and_sticky(None).await;
        let resp = run_through_proxy_with_cookie(ctx, None).await;
        assert!(resp.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn a_first_successful_response_sets_a_cookie_naming_the_chosen_backend() {
        let (ctx, _, backend_b) =
            ctx_with_two_backends_and_sticky(Some(test_sticky_runtime())).await;
        let resp = run_through_proxy_with_cookie(ctx, None).await;
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("Set-Cookie header missing")
            .to_str()
            .unwrap();
        // No pin was sent, so the algorithm's own choice ("b") is what gets
        // pinned.
        assert!(set_cookie.starts_with(&format!("lb_sticky={}", backend_b.id)));
    }

    #[tokio::test]
    async fn a_valid_pin_overrides_the_underlying_algorithm() {
        let (ctx, backend_a, _) =
            ctx_with_two_backends_and_sticky(Some(test_sticky_runtime())).await;
        let resp =
            run_through_proxy_with_cookie(ctx, Some(&format!("lb_sticky={}", backend_a.id))).await;
        // The algorithm always wants "b" -- getting "a" back proves the pin
        // won, not that the algorithm happened to agree.
        assert_eq!(resp.body(), "a");
    }

    #[tokio::test]
    async fn a_pin_naming_an_unknown_backend_falls_through_to_the_algorithm() {
        let (ctx, _, _) = ctx_with_two_backends_and_sticky(Some(test_sticky_runtime())).await;
        let resp = run_through_proxy_with_cookie(ctx, Some("lb_sticky=no-such-backend-id")).await;
        assert_eq!(resp.body(), "b");
    }

    #[tokio::test]
    async fn a_pin_naming_a_manually_drained_backend_falls_through_to_the_algorithm() {
        let (ctx, backend_a, _) =
            ctx_with_two_backends_and_sticky(Some(test_sticky_runtime())).await;
        ctx.pool.set_manually_drained(&backend_a.id, true);
        let resp =
            run_through_proxy_with_cookie(ctx, Some(&format!("lb_sticky={}", backend_a.id))).await;
        assert_eq!(resp.body(), "b");
    }

    fn test_cache() -> Arc<ResponseCache<FakeClock>> {
        Arc::new(ResponseCache::new(
            1024 * 1024,
            16 * 1024 * 1024,
            Duration::from_secs(60),
            FakeClock::new(),
        ))
    }

    /// Binds a listener and serves `ctx` on it for as long as the test
    /// runs, accepting any number of connections -- unlike
    /// `run_through_proxy`, which accepts exactly one. Returns the address
    /// immediately, before any request is sent, so a test can pre-populate
    /// a cache keyed on that exact address (the `Host` header a client
    /// dialing it sends) ahead of the first request.
    async fn spawn_proxy_listener<R, C>(ctx: Arc<ProxyContext<R, C>>) -> SocketAddr
    where
        R: RateLimiter + 'static,
        C: Clock + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = TokioIo::new(stream);
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        handle(req, ctx.clone(), "127.0.0.1".parse().unwrap())
                    });
                    // Mirrors the real fix in `lb-server`'s own connection
                    // driver: without this, a WebSocket/Upgrade test through
                    // this harness could never actually complete the
                    // handoff, no matter what `handle` returns.
                    let _ = http1::Builder::new()
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        addr
    }

    async fn get(addr: SocketAddr) -> Response<Bytes> {
        let client = build_client(None, HashMap::new(), false, None);
        let req = Request::builder()
            .uri(format!("http://{addr}/"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        Response::from_parts(parts, bytes)
    }

    #[tokio::test]
    async fn a_cache_hit_never_calls_the_balancer() {
        let cache = test_cache();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // A client dialing `addr` sends `Host: <addr>` -- the key must be
        // built from that same value so the pre-populated entry is what the
        // first (and only) real request actually looks up.
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_str(&addr.to_string()).unwrap(),
        );
        let uri: hyper::Uri = "/".parse().unwrap();
        let key = cache::key_for(&Method::GET, &uri, &headers);
        cache.put(
            key,
            StatusCode::OK,
            hyper::HeaderMap::new(),
            Bytes::from_static(b"cached"),
            Duration::from_secs(60),
        );

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(PanicIfPicked),
            pool: empty_pool(),
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: Some(cache),
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, ctx.clone(), "127.0.0.1".parse().unwrap()));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });

        let resp = get(addr).await;
        assert_eq!(resp.body(), "cached");
    }

    #[tokio::test]
    async fn a_cache_miss_then_hit_only_calls_the_backend_once() {
        let (backend_addr, count) = spawn_counting_cacheable_backend("hello", &[]).await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: Some(test_cache()),
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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

        let addr = spawn_proxy_listener(ctx).await;
        assert_eq!(get(addr).await.body(), "hello");
        assert_eq!(get(addr).await.body(), "hello");
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_no_store_response_is_never_cached() {
        let (backend_addr, count) =
            spawn_counting_cacheable_backend("hello", &[("cache-control", "no-store")]).await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: Some(test_cache()),
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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

        let addr = spawn_proxy_listener(ctx).await;
        get(addr).await;
        get(addr).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn no_cache_config_means_every_request_reaches_the_backend() {
        let (backend_addr, count) = spawn_counting_cacheable_backend("hello", &[]).await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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

        let addr = spawn_proxy_listener(ctx).await;
        get(addr).await;
        get(addr).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn waf_block_mode_returns_403_and_never_reaches_the_backend() {
        let metrics = test_metrics();
        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(PanicIfPicked),
            pool: empty_pool(),
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: Some(WafMode::Block),
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: metrics.clone(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });

        // `xp_cmdshell` rather than a token with a space: this exercises
        // the check through a real, valid `http::Uri`, and a raw space is
        // not a legal URI character without percent-encoding (which the
        // matcher deliberately does not decode -- see the module docs).
        let resp = run_through_proxy_at(ctx, "/exec?cmd=xp_cmdshell", None).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(metrics.waf_blocked_sql_injection.get(), 1);
    }

    #[tokio::test]
    async fn waf_log_mode_still_reaches_the_backend() {
        let (backend_addr, count) = spawn_counting_cacheable_backend("hello", &[]).await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        let metrics = test_metrics();

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: Some(WafMode::Log),
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: metrics.clone(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });

        // `javascript:` rather than `<script>`: `<`/`>` are not legal raw
        // URI characters either, same reasoning as the block-mode test above.
        let resp = run_through_proxy_at(ctx, "/redirect?url=javascript:alert(1)", None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.body(), "hello");
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(metrics.waf_blocked_xss.get(), 1);
    }

    #[tokio::test]
    async fn no_waf_config_means_malicious_looking_paths_still_reach_the_backend() {
        let (backend_addr, count) = spawn_counting_cacheable_backend("hello", &[]).await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(300),
            backend_tcp_keepalive: None,
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

        let resp = run_through_proxy_at(ctx, "/files/../../etc/passwd", None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A backend that itself speaks the HTTP/1.1 upgrade handshake: on
    /// `accept`, answers `101` and echoes whatever bytes arrive after the
    /// upgrade; otherwise answers a plain `200`, i.e. declines. Built on
    /// hyper's own server-side `hyper::upgrade::on`/`.with_upgrades()`,
    /// deliberately -- this is exactly the same mechanism the proxy's own
    /// server side must cooperate with, so a backend built any other way
    /// would prove less.
    async fn spawn_upgrade_backend(accept: bool) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |mut req: Request<Incoming>| async move {
                        if !accept {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(b"no upgrade")).boxed())
                                    .unwrap(),
                            );
                        }
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            let Ok(upgraded) = on_upgrade.await else {
                                return;
                            };
                            let mut io = TokioIo::new(upgraded);
                            let mut buf = [0u8; 1024];
                            loop {
                                match io.read(&mut buf).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => {
                                        if io.write_all(&buf[..n]).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        });
                        let mut resp = Response::new(Empty::<Bytes>::new().boxed());
                        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                        resp.headers_mut()
                            .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
                        resp.headers_mut()
                            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
                        Ok::<_, Infallible>(resp)
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        addr
    }

    /// Reads from `stream` until a blank line ends the HTTP head, returning
    /// the head text and any bytes already read past it (a raw TCP read has
    /// no message boundary, so the first read after the head can easily
    /// contain the start of whatever comes next too).
    async fn read_response_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(
                n > 0,
                "connection closed before the response head completed"
            );
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                let rest = buf[pos + 4..].to_vec();
                return (head, rest);
            }
        }
    }

    #[tokio::test]
    async fn a_websocket_handshake_is_relayed_end_to_end() {
        let backend_addr = spawn_upgrade_backend(true).await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(5),
            backend_tcp_keepalive: None,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(2),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });

        let addr = spawn_proxy_listener(ctx).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

        let (head, mut leftover) = read_response_head(&mut client).await;
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "expected 101, got:\n{head}"
        );
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("connection: upgrade"), "got:\n{head}");
        assert!(lower.contains("upgrade: websocket"), "got:\n{head}");

        client.write_all(b"ping").await.unwrap();
        while leftover.len() < 4 {
            let mut chunk = [0u8; 64];
            let n = client.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before the echo arrived");
            leftover.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(&leftover[..4], b"ping");
    }

    #[tokio::test]
    async fn a_declined_upgrade_is_relayed_as_an_ordinary_response() {
        let backend_addr = spawn_upgrade_backend(false).await;
        let backend = Backend::new("b1", backend_addr, 1, None);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            routes: Vec::new(),
            canary: Vec::new(),
            canary_cursor: std::sync::atomic::AtomicUsize::new(0),
            sticky: None,
            cache: None,
            waf: None,
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(None, HashMap::new(), false, None),
            per_backend_client: None,
            backend_tls: false,
            backend_tls_connector: None,
            websocket_idle_timeout: Duration::from_secs(5),
            backend_tcp_keepalive: None,
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(2),
            max_request_body_bytes: 1024,
            cluster: None,
            metrics: test_metrics(),
            backend_metrics: HashMap::new(),
            access_log: AccessLog::disabled(),
            body_read_timeout: Duration::from_secs(10),
            hsts_max_age_secs: None,
        });

        let addr = spawn_proxy_listener(ctx).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

        let (head, _leftover) = read_response_head(&mut client).await;
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "expected 200, got:\n{head}"
        );
    }
}
