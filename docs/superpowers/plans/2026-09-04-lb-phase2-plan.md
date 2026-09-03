# Distributed Load Balancer — Phase 2 (L4/TCP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add raw TCP (L4) proxying alongside the existing HTTP (L7) proxying, so one process can front both kinds of service simultaneously, configured through a unified listeners list.

**Architecture:** A new `HealthProbe` trait in `lb-core` (implemented by `HttpProbe` and `TcpConnectProbe` in `lb-healthcheck`) makes health checking protocol-agnostic. A new `lb-tcp` crate holds the L4 data plane: a bidirectional byte pump with per-read idle timeouts and correct half-close, plus session handling that reuses the existing `RateLimiter`, `LoadBalancer`, and `CircuitBreaker` unchanged. `lb-core::config` is restructured from one implicit listener to an explicit list, and `lb-server` grows from one accept loop to one per listener.

**Tech Stack:** Rust 2021, `tokio` (net, io, time, sync::watch, task::JoinSet), `hyper` 1.x (unchanged L7 path), `serde`/`toml`, `thiserror`.

**Spec:** [`docs/superpowers/specs/2026-09-04-lb-phase2-design.md`](../specs/2026-09-04-lb-phase2-design.md)

## Global Constraints

- No `unwrap`/`expect` reachable from connection-handling code. `expect` is allowed only on invariants our own code established (e.g. "this backend id came from this pool").
- Every L4 I/O boundary bounded: `connect_timeout` when dialing a backend, `idle_timeout` on every read, drain deadline on shutdown.
- Trait boundaries over concretions; `lb-tcp` depends on `lb-core` traits, never on `lb-proxy` or `lb-balancer` concretely.
- Config validation fails fast at startup, before any socket is bound.
- Rust edition 2021; `cargo fmt` clean and `cargo clippy --workspace --all-targets -- -D warnings` clean at the end.
- Commit messages carry **no** `Co-Authored-By` trailer.

---

## Task 1: `HealthProbe` trait + `HttpProbe`/`TcpConnectProbe`

**Files:**
- Create: `crates/lb-core/src/health.rs`
- Modify: `crates/lb-core/src/lib.rs`
- Create: `crates/lb-healthcheck/src/probe.rs`
- Modify: `crates/lb-healthcheck/src/active.rs`, `crates/lb-healthcheck/src/lib.rs`, `crates/lb-healthcheck/Cargo.toml`
- Modify: `crates/lb-server/src/wiring.rs` (call-site fix so the workspace still compiles)

**Interfaces:**
- Produces: `lb_core::HealthProbe` — `fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send`.
- Produces: `lb_healthcheck::{HttpProbe, TcpConnectProbe}` — `HttpProbe::new(path: impl Into<String>, timeout: Duration)`, `TcpConnectProbe::new(timeout: Duration)`.
- Changes: `spawn_active_checker` becomes `spawn_active_checker<P: HealthProbe + 'static>(backend: Backend, pool: Arc<BackendPool>, config: ActiveCheckConfig, probe: P) -> JoinHandle<()>`; `ActiveCheckConfig` shrinks to `{ interval: Duration }` (path and timeout now live inside the probe).

- [ ] **Step 1: Add the trait to `lb-core`**

`crates/lb-core/src/health.rs`:
```rust
use crate::backend::Backend;
use std::future::Future;

/// A liveness check for one backend. Implementations decide what "alive"
/// means for their protocol — an HTTP 2xx, a successful TCP connect, a
/// protocol-specific handshake.
///
/// The `+ Send` on the returned future is required: active checkers run
/// inside `tokio::spawn`, which needs the future it drives to be Send.
pub trait HealthProbe: Send + Sync {
    fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send;
}
```

`crates/lb-core/src/lib.rs` — add `pub mod health;` and `pub use health::HealthProbe;`.

- [ ] **Step 2: Write the failing probe tests**

`crates/lb-healthcheck/src/probe.rs`:
```rust
use lb_core::{Backend, HealthProbe};
use std::future::Future;
use std::time::Duration;
use tokio::net::TcpStream;

/// Health probe for HTTP backends: GET `<path>`, 2xx means healthy.
pub struct HttpProbe {
    client: reqwest::Client,
    path: String,
    timeout: Duration,
}

impl HttpProbe {
    pub fn new(path: impl Into<String>, timeout: Duration) -> Self {
        HttpProbe { client: reqwest::Client::new(), path: path.into(), timeout }
    }
}

impl HealthProbe for HttpProbe {
    fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send {
        let url = format!("http://{}{}", backend.address, self.path);
        let client = self.client.clone();
        let timeout = self.timeout;
        async move {
            match tokio::time::timeout(timeout, client.get(&url).send()).await {
                Ok(Ok(resp)) => resp.status().is_success(),
                _ => false,
            }
        }
    }
}

/// Health probe for arbitrary TCP backends: if the TCP handshake completes,
/// the backend is alive. This is all you can portably assert about a service
/// that may speak Postgres, Redis, SMTP, or anything else.
pub struct TcpConnectProbe {
    timeout: Duration,
}

impl TcpConnectProbe {
    pub fn new(timeout: Duration) -> Self {
        TcpConnectProbe { timeout }
    }
}

impl HealthProbe for TcpConnectProbe {
    fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send {
        let addr = backend.address;
        let timeout = self.timeout;
        async move {
            // The connection is dropped immediately — establishing it is the
            // entire test.
            matches!(tokio::time::timeout(timeout, TcpStream::connect(addr)).await, Ok(Ok(_)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_probe_reports_healthy_when_port_accepts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    return;
                }
            }
        });

        let probe = TcpConnectProbe::new(Duration::from_millis(500));
        let backend = Backend::new("b1", addr, 1);
        assert!(probe.probe(&backend).await);
    }

    #[tokio::test]
    async fn tcp_probe_reports_unhealthy_when_nothing_listens() {
        // Bind then immediately drop, so the port is almost certainly closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let probe = TcpConnectProbe::new(Duration::from_millis(300));
        let backend = Backend::new("b1", addr, 1);
        assert!(!probe.probe(&backend).await);
    }
}
```

`crates/lb-healthcheck/Cargo.toml` — add `tokio` feature `"net"` to the existing dependency:
```toml
tokio = { version = "1", features = ["rt", "time", "macros", "net"] }
```

- [ ] **Step 3: Make `spawn_active_checker` generic over the probe**

Replace the body of `crates/lb-healthcheck/src/active.rs`:
```rust
use lb_core::{Backend, BackendPool, HealthProbe};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

pub struct ActiveCheckConfig {
    pub interval: Duration,
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

        let backend = Backend::new("b1", *mock.address(), 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        pool.set_active_healthy(&backend.id, false); // start unhealthy to prove the checker flips it

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig { interval: Duration::from_millis(20) },
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

        let backend = Backend::new("b1", *mock.address(), 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig { interval: Duration::from_millis(20) },
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

        let backend = Backend::new("b1", addr, 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig { interval: Duration::from_millis(20) },
            TcpConnectProbe::new(Duration::from_millis(200)),
        );

        time::sleep(Duration::from_millis(80)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }
}
```

`crates/lb-healthcheck/src/lib.rs`:
```rust
mod active;
mod circuit_breaker;
mod probe;

pub use active::{spawn_active_checker, ActiveCheckConfig};
pub use circuit_breaker::{CircuitBreaker, CircuitState};
pub use probe::{HttpProbe, TcpConnectProbe};
```

- [ ] **Step 4: Fix the `lb-server` call site so the workspace compiles**

In `crates/lb-server/src/wiring.rs`, replace the active-checker loop (this file is rewritten wholesale in Task 4; this is the minimal change to keep the tree green now):
```rust
    for b in &backends {
        background_tasks.push(spawn_active_checker(
            b.clone(),
            pool.clone(),
            ActiveCheckConfig {
                interval: Duration::from_millis(config.health_check.interval_ms),
            },
            HttpProbe::new(
                config.health_check.path.clone(),
                Duration::from_millis(config.health_check.timeout_ms),
            ),
        ));
    }
```
Update the imports in that file: `use lb_healthcheck::{spawn_active_checker, ActiveCheckConfig, CircuitBreaker, HttpProbe};` and delete the now-unused `let http_client = reqwest::Client::new();` line.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p lb-core -p lb-healthcheck`
Expected: PASS — including `probe::tests::tcp_probe_*` and the three `active::tests::*`.

Run: `cargo test --workspace --features lb-core/test-util`
Expected: PASS — the whole workspace still builds and Phase 1's tests are unaffected.

- [ ] **Step 6: Commit**

```bash
git add crates/lb-core crates/lb-healthcheck crates/lb-server
git commit -m "feat(lb-healthcheck): make health probing protocol-agnostic via HealthProbe trait"
```

---

## Task 2: `lb-tcp` crate + the bidirectional byte pump

**Files:**
- Create: `crates/lb-tcp/Cargo.toml`, `crates/lb-tcp/src/lib.rs`, `crates/lb-tcp/src/pump.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Produces: `lb_tcp::pump(reader, writer, idle_timeout) -> io::Result<u64>` where `R: AsyncRead + Unpin`, `W: AsyncWrite + Unpin`. Returns bytes copied; propagates EOF as a `shutdown()` on the writer; returns `io::ErrorKind::TimedOut` if a single read stalls longer than `idle_timeout`.

- [ ] **Step 1: Scaffold the crate**

Add `"crates/lb-tcp"` to the workspace `members` list in the root `Cargo.toml`.

`crates/lb-tcp/Cargo.toml`:
```toml
[package]
name = "lb-tcp"
version = "0.1.0"
edition.workspace = true

[dependencies]
lb-core = { path = "../lb-core" }
lb-healthcheck = { path = "../lb-healthcheck" }
tokio = { version = "1", features = ["rt", "net", "io-util", "time", "macros"] }

[dev-dependencies]
lb-core = { path = "../lb-core", features = ["test-util"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "time", "test-util"] }
```

`crates/lb-tcp/src/lib.rs`:
```rust
mod pump;

pub use pump::pump;
```

- [ ] **Step 2: Write the failing pump tests**

`crates/lb-tcp/src/pump.rs`:
```rust
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFFER_SIZE: usize = 8 * 1024;

/// Copies bytes from `reader` to `writer` until EOF, enforcing an *idle*
/// timeout: the clock restarts on every successful read, so a long-lived but
/// active connection is never cut off — only a stalled one is.
///
/// On EOF the writer is explicitly shut down, which propagates the half-close
/// to the peer. That is what lets a caller run two pumps under `try_join!`
/// and still support protocols where one direction finishes early while the
/// other keeps streaming.
pub async fn pump<R, W>(mut reader: R, mut writer: W, idle_timeout: Duration) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut total: u64 = 0;

    loop {
        let read = tokio::time::timeout(idle_timeout, reader.read(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle timeout"))??;

        if read == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        writer.write_all(&buf[..read]).await?;
        total += read as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn copies_bytes_until_eof() {
        let (mut source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, mut sink_rx) = tokio::io::duplex(1024);

        let copied = tokio::spawn(pump(source_rx, sink_tx, Duration::from_secs(5)));

        source_tx.write_all(b"hello world").await.unwrap();
        source_tx.shutdown().await.unwrap();
        drop(source_tx);

        let mut received = Vec::new();
        sink_rx.read_to_end(&mut received).await.unwrap();

        assert_eq!(received, b"hello world");
        assert_eq!(copied.await.unwrap().unwrap(), 11);
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_when_no_data_ever_arrives() {
        // Keep the source alive but silent, so the read simply never resolves.
        let (_source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, _sink_rx) = tokio::io::duplex(1024);

        let err = pump(source_rx, sink_tx, Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timer_resets_on_activity() {
        // Total lifetime (9s) far exceeds the 5s idle timeout, but no single
        // gap does — this must succeed, proving it is an idle timeout and not
        // a maximum-lifetime cap.
        let (mut source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, mut sink_rx) = tokio::io::duplex(1024);

        let copied = tokio::spawn(pump(source_rx, sink_tx, Duration::from_secs(5)));

        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(3)).await;
            source_tx.write_all(b"tick").await.unwrap();
        }
        source_tx.shutdown().await.unwrap();
        drop(source_tx);

        let mut received = Vec::new();
        sink_rx.read_to_end(&mut received).await.unwrap();

        assert_eq!(received, b"tickticktick");
        assert_eq!(copied.await.unwrap().unwrap(), 12);
    }

    #[tokio::test]
    async fn shuts_down_writer_on_eof() {
        let (mut source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, mut sink_rx) = tokio::io::duplex(1024);

        let copied = tokio::spawn(pump(source_rx, sink_tx, Duration::from_secs(5)));

        source_tx.write_all(b"bye").await.unwrap();
        source_tx.shutdown().await.unwrap();
        drop(source_tx);

        // read_to_end only returns once the writer half was shut down.
        let mut received = Vec::new();
        sink_rx.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"bye");
        assert_eq!(copied.await.unwrap().unwrap(), 3);
    }
}
```

Note: `tokio::io::duplex` returns a connected in-memory stream pair, which lets these tests exercise the pump with no sockets involved. `AsyncReadExt::read_to_end` needs to be in scope — add `use tokio::io::AsyncReadExt;` alongside the `AsyncWriteExt` import in the test module if the compiler asks for it.

- [ ] **Step 3: Run the pump tests**

Run: `cargo test -p lb-tcp`
Expected: PASS — all four `pump::tests::*`.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock crates/lb-tcp
git commit -m "feat(lb-tcp): add bidirectional byte pump with idle timeout and half-close"
```

---

## Task 3: `lb-tcp` session handling

**Files:**
- Create: `crates/lb-tcp/src/session.rs`
- Modify: `crates/lb-tcp/src/lib.rs`

**Interfaces:**
- Consumes: `lb_core::{BackendId, BackendPool, Clock, Decision, LoadBalancer, RateLimiter}`, `lb_healthcheck::CircuitBreaker`, `crate::pump`.
- Produces: `lb_tcp::TcpContext<R, L, C> { rate_limiter: Arc<R>, balancer: Arc<L>, pool: Arc<BackendPool>, circuit_breakers: HashMap<BackendId, CircuitBreaker<C>>, connect_timeout: Duration, idle_timeout: Duration }`; `lb_tcp::ConnectionOutcome`; `lb_tcp::handle_connection(inbound: TcpStream, peer: SocketAddr, ctx: Arc<TcpContext<R, L, C>>) -> ConnectionOutcome`.

- [ ] **Step 1: Write the session module**

`crates/lb-tcp/src/session.rs`:
```rust
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
    Completed { bytes_to_backend: u64, bytes_to_client: u64 },
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
        Ok((bytes_to_backend, bytes_to_client)) => {
            ConnectionOutcome::Completed { bytes_to_backend, bytes_to_client }
        }
        Err(_) => ConnectionOutcome::Aborted,
    }
}
```

`crates/lb-tcp/src/lib.rs`:
```rust
mod pump;
mod session;

pub use pump::pump;
pub use session::{handle_connection, ConnectionOutcome, TcpContext};
```

- [ ] **Step 2: Write the session tests**

Append to `crates/lb-tcp/src/session.rs`:
```rust
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
            Decision::Deny { retry_after: Duration::from_secs(1) }
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
                let Ok((mut stream, _)) = listener.accept().await else { return };
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
        let ctx = context(AllowAll, FirstEligible, vec![Backend::new("b1", backend_addr, 1)]);

        let (outcome, echoed) = run_session(ctx, b"ping").await;

        assert_eq!(echoed, b"ping");
        assert_eq!(
            outcome,
            ConnectionOutcome::Completed { bytes_to_backend: 4, bytes_to_client: 4 }
        );
    }

    #[tokio::test]
    async fn rate_limited_connection_is_closed_without_reaching_a_backend() {
        let backend_addr = spawn_echo_backend().await;
        let ctx = context(DenyAll, FirstEligible, vec![Backend::new("b1", backend_addr, 1)]);

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
            vec![Backend::new("dead", dead_addr, 1), Backend::new("alive", healthy_addr, 1)],
        );

        let (outcome, echoed) = run_session(ctx.clone(), b"retry").await;

        assert_eq!(echoed, b"retry");
        assert_eq!(
            outcome,
            ConnectionOutcome::Completed { bytes_to_backend: 5, bytes_to_client: 5 }
        );
        assert!(ctx.circuit_breaker(&BackendId::new("dead")).is_open());
    }
}
```

- [ ] **Step 3: Run the session tests**

Run: `cargo test -p lb-tcp`
Expected: PASS — the four `pump::tests::*` plus the four `session::tests::*`.

- [ ] **Step 4: Commit**

```bash
git add crates/lb-tcp
git commit -m "feat(lb-tcp): add TCP session handling with rate limiting, failover, and circuit breaking"
```

---

## Task 4: Config restructure + `lb-server` multi-listener rewiring

This is one task, not two: a config restructure that leaves the binary uncompilable is not independently reviewable, and the server rewiring is meaningless without the new config shape.

**Files:**
- Modify: `crates/lb-core/src/config.rs` (restructure), `crates/lb-core/src/lib.rs` (exports)
- Modify: `crates/lb-proxy/src/service.rs` (take the real peer IP — see Step 3)
- Rewrite: `crates/lb-server/src/wiring.rs`, `crates/lb-server/src/lib.rs`
- Modify: `crates/lb-server/Cargo.toml` (add `lb-tcp`)
- Modify: `crates/lb-server/tests/support.rs`, `crates/lb-server/tests/integration.rs` (new config shape)

**Interfaces:**
- Produces: `lb_core::{Config, ServerConfig, ListenerConfig, Protocol}` — `Config { server: ServerConfig, listeners: Vec<ListenerConfig> }`; `ListenerConfig::{forward_timeout(), max_request_body_bytes(), connect_timeout(), idle_timeout()}` accessors applying defaults.
- Produces: `lb_server::{ListenerRuntime, WiredApp, build_app, run}`.
- Changes: `lb_proxy::handle(req, ctx, peer_ip: IpAddr)` gains a third parameter.

- [ ] **Step 1: Restructure the config types**

Replace `crates/lb-core/src/config.rs` (keeping `RateLimitKeySource`, `LoadBalancingStrategy`, `BackendConfig`, `RateLimitConfig`, `LoadBalancingConfig` as they are today):
```rust
use crate::error::ConfigError;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig { drain_timeout_ms: default_drain_timeout_ms() }
    }
}

fn default_drain_timeout_ms() -> u64 {
    10_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Tcp,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub protocol: Protocol,
    pub listen: SocketAddr,

    // HTTP-only
    pub forward_timeout_ms: Option<u64>,
    pub max_request_body_bytes: Option<usize>,

    // TCP-only
    pub connect_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,

    pub backends: Vec<BackendConfig>,
    pub health_check: HealthCheckConfig,
    pub rate_limit: RateLimitConfig,
    pub load_balancing: LoadBalancingConfig,
}

impl ListenerConfig {
    pub fn forward_timeout(&self) -> Duration {
        Duration::from_millis(self.forward_timeout_ms.unwrap_or(5_000))
    }

    pub fn max_request_body_bytes(&self) -> usize {
        self.max_request_body_bytes.unwrap_or(1024 * 1024)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.unwrap_or(2_000))
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms.unwrap_or(300_000))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    /// Required for HTTP listeners, forbidden for TCP listeners (there is
    /// nothing to GET on a Postgres port).
    pub path: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
    pub cooldown_ms: u64,
}
```

Keep `BackendConfig`, `RateLimitConfig`, `RateLimitKeySource`, `LoadBalancingConfig`, `LoadBalancingStrategy` exactly as they are in the current file.

Then the loader and validation:
```rust
impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let text = std::fs::read_to_string(path_ref).map_err(|source| ConfigError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::Invalid("at least one listener is required".into()));
        }

        let mut names = HashSet::new();
        let mut addresses = HashSet::new();

        for l in &self.listeners {
            if !names.insert(&l.name) {
                return Err(ConfigError::Invalid(format!("duplicate listener name: {}", l.name)));
            }
            if !addresses.insert(l.listen) {
                return Err(ConfigError::Invalid(format!(
                    "listener '{}' reuses listen address {} — two listeners cannot bind the same address",
                    l.name, l.listen
                )));
            }
            l.validate()?;
        }
        Ok(())
    }
}

impl ListenerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| ConfigError::Invalid(format!("listener '{}': {msg}", self.name));

        if self.backends.is_empty() {
            return Err(invalid("at least one backend is required".into()));
        }
        let mut ids = HashSet::new();
        for b in &self.backends {
            if !ids.insert(&b.id) {
                return Err(invalid(format!("duplicate backend id: {}", b.id)));
            }
        }

        if self.rate_limit.rate_per_sec <= 0.0 {
            return Err(invalid("rate_limit.rate_per_sec must be positive".into()));
        }
        if self.rate_limit.burst == 0 {
            return Err(invalid("rate_limit.burst must be positive".into()));
        }

        match self.protocol {
            Protocol::Http => {
                if self.health_check.path.is_none() {
                    return Err(invalid("health_check.path is required for http listeners".into()));
                }
                if self.connect_timeout_ms.is_some() || self.idle_timeout_ms.is_some() {
                    return Err(invalid(
                        "connect_timeout_ms/idle_timeout_ms are tcp-only settings".into(),
                    ));
                }
            }
            Protocol::Tcp => {
                if self.health_check.path.is_some() {
                    return Err(invalid(
                        "health_check.path is http-only — a tcp backend has no path to probe".into(),
                    ));
                }
                if self.forward_timeout_ms.is_some() || self.max_request_body_bytes.is_some() {
                    return Err(invalid(
                        "forward_timeout_ms/max_request_body_bytes are http-only settings".into(),
                    ));
                }
                if let RateLimitKeySource::Header(name) = &self.rate_limit.key {
                    return Err(invalid(format!(
                        "rate_limit.key 'header:{name}' is http-only — a tcp listener has no headers to read, use 'source_ip'"
                    )));
                }
            }
        }
        Ok(())
    }
}
```

`crates/lb-core/src/lib.rs` — update the config re-export to `pub use config::{BackendConfig, Config, HealthCheckConfig, ListenerConfig, LoadBalancingConfig, LoadBalancingStrategy, Protocol, RateLimitConfig, RateLimitKeySource, ServerConfig};`

- [ ] **Step 2: Replace the config tests**

Replace the `#[cfg(test)] mod tests` block in `config.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        [[listeners]]
        name = "web"
        protocol = "http"
        listen = "0.0.0.0:8080"

          [[listeners.backends]]
          id = "web1"
          address = "127.0.0.1:9001"

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
        name = "postgres"
        protocol = "tcp"
        listen = "0.0.0.0:5432"

          [[listeners.backends]]
          id = "pg1"
          address = "10.0.0.5:5432"

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

    #[test]
    fn parses_mixed_protocol_config() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert_eq!(cfg.listeners.len(), 2);
        assert_eq!(cfg.listeners[0].protocol, Protocol::Http);
        assert_eq!(cfg.listeners[1].protocol, Protocol::Tcp);
        assert_eq!(cfg.server.drain_timeout_ms, 10_000); // default applied
        assert_eq!(cfg.listeners[0].max_request_body_bytes(), 1024 * 1024);
        assert_eq!(cfg.listeners[1].idle_timeout(), Duration::from_millis(300_000));
    }

    #[test]
    fn rejects_empty_listeners() {
        let text = "listeners = []";
        assert!(matches!(Config::parse(text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_duplicate_listener_names() {
        let text = VALID.replace(r#"name = "postgres""#, r#"name = "web""#);
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_duplicate_listen_addresses() {
        let text = VALID.replace(r#"listen = "0.0.0.0:5432""#, r#"listen = "0.0.0.0:8080""#);
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_http_listener_without_health_path() {
        let text = VALID.replace("          path = \"/health\"\n", "");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_tcp_listener_with_health_path() {
        // Give the tcp listener a path by adding one to its health_check.
        let text = VALID.replace(
            "          [listeners.health_check]\n          interval_ms = 2000\n          timeout_ms = 500\n          failure_threshold = 3\n          cooldown_ms = 5000\n\n          [listeners.rate_limit]\n          key = \"source_ip\"\n          rate_per_sec = 10",
            "          [listeners.health_check]\n          path = \"/health\"\n          interval_ms = 2000\n          timeout_ms = 500\n          failure_threshold = 3\n          cooldown_ms = 5000\n\n          [listeners.rate_limit]\n          key = \"source_ip\"\n          rate_per_sec = 10",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_header_rate_limit_key_on_tcp_listener() {
        let text = VALID.replace(
            "          key = \"source_ip\"\n          rate_per_sec = 10",
            "          key = \"header:X-API-Key\"\n          rate_per_sec = 10",
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("http-only"),
            "error should explain headers don't exist at L4, got: {err}"
        );
    }

    #[test]
    fn rejects_http_only_setting_on_tcp_listener() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:5432\"",
            "        listen = \"0.0.0.0:5432\"\n        max_request_body_bytes = 1024",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_tcp_only_setting_on_http_listener() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n        idle_timeout_ms = 1000",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_non_positive_rate() {
        let text = VALID.replace("rate_per_sec = 50", "rate_per_sec = 0");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_duplicate_backend_ids_within_a_listener() {
        let text = VALID.replace(
            "          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9001\"",
            "          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9001\"\n\n          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9002\"",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }
}
```

Note on these string-surgery tests: Phase 1 hit a bug where a `.replace(...)` silently matched nothing and the test passed vacuously. Each replacement above must actually change the string — if a test fails unexpectedly, first print the transformed TOML and confirm the replacement landed.

- [ ] **Step 3: Use the real peer IP for `source_ip` rate limiting**

Phase 1's `extract_key` read `X-Forwarded-For` for `source_ip`, which is wrong twice over: without an upstream proxy setting it, every client shares one `"unknown"` bucket, and worse, a client can *forge* the header to get a fresh rate-limit bucket at will. Now that the accept loop has the real peer address, pass it down. This is in scope because Phase 2 makes `source_ip` the only key available at L4 — leaving it broken at L7 would be incoherent.

In `crates/lb-proxy/src/service.rs`, change the signature and key extraction:
```rust
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

pub async fn handle<R, L, C>(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext<R, L, C>>,
    peer_ip: IpAddr,
) -> Result<Response<ProxyBody>, Infallible>
```
Add `use std::net::IpAddr;`, and update the body's single call to `extract_key(&req, &ctx.rate_limit_key, peer_ip)`.

In `crates/lb-proxy/src/service.rs`'s test module, update `run_through_proxy`'s service closure to pass a peer IP:
```rust
        let svc = service_fn(move |req| handle(req, ctx.clone(), "127.0.0.1".parse().unwrap()));
```

- [ ] **Step 4: Rewrite `lb-server` wiring for N listeners**

`crates/lb-server/Cargo.toml` — add to `[dependencies]`:
```toml
lb-tcp = { path = "../lb-tcp" }
```

Replace `crates/lb-server/src/wiring.rs`:
```rust
use lb_balancer::RoundRobin;
use lb_core::{Backend, BackendPool, Config, ListenerConfig, Protocol, SystemClock};
use lb_healthcheck::{spawn_active_checker, ActiveCheckConfig, CircuitBreaker, HttpProbe, TcpConnectProbe};
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
    Http { name: String, listen: SocketAddr, ctx: Arc<HttpContext> },
    Tcp { name: String, listen: SocketAddr, ctx: Arc<TcpAppContext> },
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
            GcraConfig { rate_per_sec: lc.rate_limit.rate_per_sec, burst: lc.rate_limit.burst },
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
```

- [ ] **Step 5: Rewrite `lb-server::run` to drive N listeners**

Replace `crates/lb-server/src/lib.rs`:
```rust
mod shutdown;
mod wiring;

pub use wiring::{build_app, HttpContext, ListenerRuntime, TcpAppContext, WiredApp};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub async fn run(config: Config) -> std::io::Result<()> {
    let WiredApp { listeners, background_tasks, drain_timeout } = build_app(&config);

    // Bind every listener before serving any of them, so a port conflict or
    // permission error fails startup outright instead of half-starting.
    let mut bound = Vec::with_capacity(listeners.len());
    for runtime in listeners {
        let listener = TcpListener::bind(runtime.listen()).await?;
        let actual = listener.local_addr()?;
        eprintln!("listener '{}' ({}) on {}", runtime.name(), runtime.protocol_name(), actual);
        bound.push((listener, runtime));
    }

    // One shutdown signal fans out to every accept loop.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut listener_tasks = Vec::with_capacity(bound.len());
    for (listener, runtime) in bound {
        listener_tasks.push(tokio::spawn(serve_listener(
            listener,
            runtime,
            shutdown_rx.clone(),
            drain_timeout,
        )));
    }

    shutdown::wait_for_shutdown_signal().await;
    eprintln!("shutdown signal received, draining in-flight connections");
    let _ = shutdown_tx.send(true);

    for task in listener_tasks {
        let _ = task.await;
    }
    for task in background_tasks {
        task.abort();
    }
    Ok(())
}

/// Accept loop for one listener. Owns its own connection JoinSet so it can
/// drain independently when the shutdown signal arrives.
async fn serve_listener(
    listener: TcpListener,
    runtime: ListenerRuntime,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
) {
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => spawn_connection(&runtime, &mut connections, stream, peer),
                // A transient accept error (e.g. fd exhaustion) must not kill
                // the listener permanently.
                Err(err) => eprintln!("accept error on '{}': {err}", runtime.name()),
            },
            _ = shutdown.changed() => break,
        }
    }

    let drained = tokio::time::timeout(drain_timeout, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        eprintln!(
            "listener '{}': drain deadline exceeded, aborting {} connection(s)",
            runtime.name(),
            connections.len()
        );
        connections.abort_all();
    }
}

fn spawn_connection(
    runtime: &ListenerRuntime,
    connections: &mut JoinSet<()>,
    stream: TcpStream,
    peer: SocketAddr,
) {
    match runtime {
        ListenerRuntime::Http { ctx, .. } => {
            let ctx = Arc::clone(ctx);
            let io = TokioIo::new(stream);
            let peer_ip = peer.ip();
            connections.spawn(async move {
                let svc = service_fn(move |req| lb_proxy::handle(req, Arc::clone(&ctx), peer_ip));
                if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                    eprintln!("connection error: {err}");
                }
            });
        }
        ListenerRuntime::Tcp { ctx, .. } => {
            let ctx = Arc::clone(ctx);
            connections.spawn(async move {
                lb_tcp::handle_connection(stream, peer, ctx).await;
            });
        }
    }
}
```

- [ ] **Step 6: Update the existing integration tests to the new config shape**

In `crates/lb-server/tests/support.rs`, replace `config_toml` (the fake-backend helper is unchanged):
```rust
pub fn config_toml(listen: &str, backends: &[(&str, SocketAddr)], rate_per_sec: f64, burst: u32) -> String {
    let backends_toml: String = backends
        .iter()
        .map(|(id, addr)| {
            format!("  [[listeners.backends]]\n  id = \"{id}\"\n  address = \"{addr}\"\n\n")
        })
        .collect();
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

{backends_toml}
  [listeners.health_check]
  path = "/health"
  interval_ms = 50
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "header:X-Client"
  rate_per_sec = {rate_per_sec}
  burst = {burst}

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}
```
`crates/lb-server/tests/integration.rs` needs no changes — it only calls `config_toml`.

- [ ] **Step 7: Run everything**

Run: `cargo test --workspace --features lb-core/test-util`
Expected: PASS across all crates — Phase 1's three HTTP integration tests included, proving L7 was not regressed by the restructure.

- [ ] **Step 8: Commit**

```bash
git add crates Cargo.lock
git commit -m "feat(lb-server): restructure config around listeners and serve N listeners of mixed protocols"
```

---

## Task 5: TCP and mixed-protocol integration tests

**Files:**
- Modify: `crates/lb-server/tests/support.rs` (TCP echo backend + config builders)
- Create: `crates/lb-server/tests/tcp_integration.rs`

**Interfaces:**
- Consumes: `lb_server::run`, `lb_core::Config`.
- Produces: nothing — this is the end-to-end proof that Phase 2 works.

- [ ] **Step 1: Add TCP test helpers**

Append to `crates/lb-server/tests/support.rs`:
```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A TCP backend that echoes whatever it receives, and counts connections.
pub async fn spawn_echo_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            count_clone.fetch_add(1, Ordering::SeqCst);
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

    (addr, count)
}

/// Sends `payload` through a TCP listener and reads the echo back.
pub async fn tcp_roundtrip(listen: SocketAddr, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut client = TcpStream::connect(listen).await?;
    client.write_all(payload).await?;
    client.shutdown().await?;
    let mut received = Vec::new();
    client.read_to_end(&mut received).await?;
    Ok(received)
}

pub fn tcp_config_toml(
    listen: &str,
    backends: &[(&str, SocketAddr)],
    rate_per_sec: f64,
    burst: u32,
) -> String {
    let backends_toml: String = backends
        .iter()
        .map(|(id, addr)| {
            format!("  [[listeners.backends]]\n  id = \"{id}\"\n  address = \"{addr}\"\n\n")
        })
        .collect();
    format!(
        r#"
[[listeners]]
name = "tcp-front"
protocol = "tcp"
listen = "{listen}"
connect_timeout_ms = 500
idle_timeout_ms = 5000

{backends_toml}
  [listeners.health_check]
  interval_ms = 50
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = {rate_per_sec}
  burst = {burst}

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}
```
Add `use tokio::net::TcpListener;` to the imports if not already present.

`crates/lb-server/Cargo.toml` — the `AsyncReadExt`/`AsyncWriteExt` traits need tokio's `io-util` feature. It currently arrives only transitively via hyper's feature unification, which is fragile; declare it explicitly:
```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "signal", "time", "io-util"] }
```

- [ ] **Step 2: Write the TCP integration tests**

`crates/lb-server/tests/tcp_integration.rs`:
```rust
mod support;

use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::{spawn_echo_backend, tcp_config_toml, tcp_roundtrip};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn proxies_tcp_bytes_end_to_end() {
    let (backend_addr, _count) = spawn_echo_backend().await;
    let listen = free_addr().await;

    let config =
        Config::parse(&tcp_config_toml(&listen.to_string(), &[("b1", backend_addr)], 1000.0, 1000))
            .unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let echoed = tcp_roundtrip(listen, b"hello over tcp").await.unwrap();
    assert_eq!(echoed, b"hello over tcp");
}

#[tokio::test]
async fn rate_limited_tcp_connection_is_closed_with_no_data() {
    let (backend_addr, count) = spawn_echo_backend().await;
    let listen = free_addr().await;

    // burst of 2: the first two connections pass, the third is refused.
    let config =
        Config::parse(&tcp_config_toml(&listen.to_string(), &[("b1", backend_addr)], 2.0, 2))
            .unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(tcp_roundtrip(listen, b"one").await.unwrap(), b"one");
    assert_eq!(tcp_roundtrip(listen, b"two").await.unwrap(), b"two");

    // Third connection is accepted at the TCP level then immediately closed,
    // so the client sees an empty read rather than an error — that silence
    // *is* the L4 rejection.
    let third = tcp_roundtrip(listen, b"three").await.unwrap_or_default();
    assert!(third.is_empty(), "rate-limited connection should carry no data, got {third:?}");

    // The backend only ever saw the two allowed connections.
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn fails_over_to_a_healthy_tcp_backend() {
    // A port that nothing listens on, plus a real echo backend.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = closed.local_addr().unwrap();
    drop(closed);

    let (healthy_addr, count) = spawn_echo_backend().await;
    let listen = free_addr().await;

    let config = Config::parse(&tcp_config_toml(
        &listen.to_string(),
        &[("dead", dead_addr), ("alive", healthy_addr)],
        1000.0,
        1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(150)).await;

    for _ in 0..4 {
        let echoed = tcp_roundtrip(listen, b"ping").await.unwrap();
        assert_eq!(echoed, b"ping");
    }
    assert_eq!(count.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn serves_http_and_tcp_listeners_from_one_process() {
    // The headline Phase 2 capability: both protocols, one process.
    let (http_backend, _http_count) = support::spawn_counting_backend(hyper::StatusCode::OK).await;
    let (tcp_backend, _tcp_count) = spawn_echo_backend().await;
    let http_listen = free_addr().await;
    let tcp_listen = free_addr().await;

    let config_text = format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{http_listen}"

  [[listeners.backends]]
  id = "w1"
  address = "{http_backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 50
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"

[[listeners]]
name = "db"
protocol = "tcp"
listen = "{tcp_listen}"

  [[listeners.backends]]
  id = "t1"
  address = "{tcp_backend}"

  [listeners.health_check]
  interval_ms = 50
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    );

    let config = Config::parse(&config_text).unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // HTTP side works...
    let resp = reqwest::Client::new()
        .get(format!("http://{http_listen}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // ...and the TCP side works, from the same process.
    let echoed = tcp_roundtrip(tcp_listen, b"both at once").await.unwrap();
    assert_eq!(echoed, b"both at once");
}
```

`crates/lb-server/Cargo.toml` — add `hyper = { version = "1", features = ["server", "http1"] }` is already a dependency; the test also needs it, which it inherits. No change expected; add `hyper` to `[dev-dependencies]` only if the compiler complains.

- [ ] **Step 3: Run the TCP integration tests**

Run: `cargo test -p lb-server --test tcp_integration`
Expected: PASS — all four tests, including the mixed-protocol one.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --workspace --features lb-core/test-util`
Expected: PASS everywhere.

- [ ] **Step 5: Commit**

```bash
git add crates/lb-server/tests crates/lb-server/Cargo.toml
git commit -m "test(lb-server): add TCP and mixed-protocol integration tests"
```

---

## Task 6: Update example config and README

**Files:**
- Modify: `config.example.toml`, `README.md`

- [ ] **Step 1: Replace `config.example.toml`**

```toml
[server]
drain_timeout_ms = 10000

# ── HTTP (L7) listener ────────────────────────────────────────────────
[[listeners]]
name     = "web"
protocol = "http"
listen   = "0.0.0.0:8080"
forward_timeout_ms     = 5000
max_request_body_bytes = 1048576

  [[listeners.backends]]
  id = "web1"
  address = "127.0.0.1:9001"
  weight  = 1

  [[listeners.backends]]
  id = "web2"
  address = "127.0.0.1:9002"
  weight  = 1

  [listeners.health_check]
  path = "/health"
  interval_ms = 2000
  timeout_ms = 500
  failure_threshold = 3
  cooldown_ms = 5000

  [listeners.rate_limit]
  key = "source_ip"          # or "header:X-API-Key"
  rate_per_sec = 50
  burst = 100

  [listeners.load_balancing]
  strategy = "round_robin"

# ── TCP (L4) listener ─────────────────────────────────────────────────
[[listeners]]
name     = "postgres"
protocol = "tcp"
listen   = "0.0.0.0:5432"
connect_timeout_ms = 2000
idle_timeout_ms    = 300000

  [[listeners.backends]]
  id = "pg1"
  address = "10.0.0.5:5432"

  [listeners.health_check]
  # no `path` — a TCP backend is probed by connecting, not by GET
  interval_ms = 2000
  timeout_ms = 500
  failure_threshold = 3
  cooldown_ms = 5000

  [listeners.rate_limit]
  key = "source_ip"          # the only valid key at L4 — there are no headers
  rate_per_sec = 10
  burst = 20

  [listeners.load_balancing]
  strategy = "round_robin"
```

- [ ] **Step 2: Update `README.md`**

Replace the title/intro, add `lb-tcp` to the crate list, and add an L4 section:
```markdown
# Distributed Load Balancer — Phases 1 & 2

A single-node load balancer that proxies both **HTTP (L7)** and **raw TCP (L4)**
traffic, with GCRA rate limiting, round-robin backend selection, and active +
passive (circuit breaker) health checking, built from scratch on `hyper`/`tokio`.

One process runs any number of listeners, each with its own protocol, backend
pool, rate limit, and health checks — so it can front an HTTP API on :8080 and
a Postgres cluster on :5432 at the same time.

Design docs:
- [Phase 1 — L7 HTTP](docs/superpowers/specs/2026-09-03-lb-phase1-design.md)
- [Phase 2 — L4 TCP](docs/superpowers/specs/2026-09-04-lb-phase2-design.md)

## Run it

1. Copy `config.example.toml` to `config.toml` and point the listeners at your
   real backends.
2. `cargo run -p lb-server -- config.toml`

## Workspace layout

- `lb-core` — shared types and the `RateLimiter`/`LoadBalancer`/`HealthProbe`/`Clock` traits (no I/O)
- `lb-ratelimit` — GCRA rate limiter
- `lb-balancer` — round-robin `LoadBalancer`
- `lb-healthcheck` — active probes (HTTP + TCP-connect) and the passive circuit breaker
- `lb-proxy` — the L7 HTTP data plane
- `lb-tcp` — the L4 TCP data plane
- `lb-server` — the binary: config loading, listener wiring, graceful shutdown

## L4 vs L7 — what differs

At L4 you move bytes, not requests, and that shapes everything:

| | HTTP (L7) | TCP (L4) |
|---|---|---|
| Unit of work | one request | one connection |
| Rate-limit key | source IP or a header | source IP only |
| Over the limit | `429` + `Retry-After` | connection closed, silently |
| Health probe | `GET /health` → 2xx | TCP connect succeeds |
| Retry on failure | needs body buffering | free — no bytes have moved yet |

## Test

`cargo test --workspace --features lb-core/test-util`

## Scope

Phases 1 and 2 are complete. Deliberately deferred: TLS termination, config
hot-reload, metrics/structured logging, admin API, UDP, PROXY protocol, and
multi-node coordination (Phase 3).
```

- [ ] **Step 3: Verify the example config actually parses**

Run: `cargo run -p lb-server -- config.example.toml`
Expected: it prints two `listener '...' on ...` lines and then serves (the backends don't exist, which is fine — the point is that config validation and binding succeed). Stop it with Ctrl+C and confirm it logs the shutdown message and exits cleanly — this is also the manual verification of graceful shutdown, which has no automated test.

- [ ] **Step 4: Commit**

```bash
git add config.example.toml README.md
git commit -m "docs: document L4 listeners in example config and README"
```

---

## Post-Plan Verification

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings
cargo test --workspace --features lb-core/test-util
```

All three must be clean. Commit any formatting changes separately.
