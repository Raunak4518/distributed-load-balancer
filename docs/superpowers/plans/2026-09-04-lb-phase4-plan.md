# Distributed Load Balancer — Phase 4 (Measurement & Safety Net) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the load balancer observable and safely changeable — Prometheus metrics, structured logging, liveness/readiness endpoints, CI, and a benchmark baseline — without altering any data-plane behaviour.

**Architecture:** A new `lb-metrics` crate owns the Prometheus registry and, critically, **pre-resolved metric handles**: label lookups happen once at wiring time, so recording a request is a few atomic increments rather than a string-keyed map lookup on a 50k req/s hot path. A separate **admin listener** (private-bound) serves `/metrics`, `/healthz` and `/ready`; it is never exposed on a traffic port. `tracing` replaces every `eprintln!`.

**Tech Stack:** Rust 2021, `prometheus`, `tracing` + `tracing-subscriber`, `uuid`, `hyper` (admin server), `criterion` (benchmarks), GitHub Actions.

**Spec:** [`docs/superpowers/specs/2026-09-04-lb-phase4-design.md`](../specs/2026-09-04-lb-phase4-design.md)

## Global Constraints

- **No data-plane behaviour changes.** All 102 existing tests must pass untouched at every commit. If one needs modifying, stop — that means behaviour moved.
- Metric recording is hot-path code: atomics only, no mutexes, **no string label lookup per request**.
- **No client-controlled value may become a metric label** (§2.3 of the spec). Not client IP, API key, path, or Host.
- Admin listener binds privately and is optional; omitting `[admin]` leaves Phases 1–3 behaviour identical.
- No `unwrap`/`expect` reachable from network input.
- `cargo fmt` and `cargo clippy --workspace --all-targets -- -D warnings` clean at the end.
- Commit messages carry **no** `Co-Authored-By` trailer.

---

## Task 1: CI workflow

Done first because it is cheap, gates every task after it, and makes the manual verification ritual automatic.

**Files:** Create `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  check:
    name: fmt / clippy / test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Cache cargo
        uses: Swatinem/rust-cache@v2

      - name: Format
        run: cargo fmt --all -- --check

      - name: Clippy
        run: cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings

      - name: Test
        run: cargo test --workspace --features lb-core/test-util
```

These are exactly the three commands run by hand at the end of every phase so far.

- [ ] **Step 2: Verify the commands pass locally before pushing**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings && cargo test --workspace --features lb-core/test-util`
Expected: all three clean. (CI cannot be run locally; this is the same gate.)

- [ ] **Step 3: Commit and confirm the run is green on GitHub**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run fmt, clippy and tests on push and pull request"
git push origin main
```
Then check the Actions tab. If the run fails on something that passes locally, it is almost certainly a platform difference (this repo is developed on Windows, CI runs Linux) — investigate rather than disabling the check.

---

## Task 2: `lb-metrics` crate — registry and pre-resolved handles

**Files:**
- Modify: `Cargo.toml` (workspace members)
- Create: `crates/lb-metrics/Cargo.toml`, `src/lib.rs`, `src/handles.rs`

**Interfaces:**
- Produces `lb_metrics::Metrics` — owns the registry and the metric families; `Metrics::new() -> Result<Self, prometheus::Error>`, `.gather_text() -> String`, `.listener(name) -> ListenerMetrics`, `.backend(listener, backend) -> BackendMetrics`, plus cluster/global handles.
- Produces `lb_metrics::{ListenerMetrics, BackendMetrics, StatusClass}`.

- [ ] **Step 1: Scaffold**

Add `"crates/lb-metrics"` to workspace `members` (before `lb-server`).

`crates/lb-metrics/Cargo.toml`:
```toml
[package]
name = "lb-metrics"
version = "0.1.0"
edition.workspace = true

[dependencies]
prometheus = { version = "0.13", default-features = false }
```

- [ ] **Step 2: Write the handles module**

`crates/lb-metrics/src/handles.rs`:
```rust
use prometheus::{Histogram, IntCounter, IntGauge};

/// Status codes are recorded by *class*, not exact code.
///
/// Two reasons. Alerting cares about error rate (5xx) rather than the
/// difference between 502 and 504, and — more importantly — a bounded set of
/// classes means the counter handles can be resolved once at wiring time
/// instead of doing a string-keyed lookup on every request at 50k req/s.
/// Rate-limit rejections, the one 4xx worth isolating, get their own metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    Success,
    Redirect,
    ClientError,
    ServerError,
}

impl StatusClass {
    pub fn from_code(code: u16) -> Self {
        match code {
            200..=299 => StatusClass::Success,
            300..=399 => StatusClass::Redirect,
            400..=499 => StatusClass::ClientError,
            _ => StatusClass::ServerError,
        }
    }

    pub fn as_label(self) -> &'static str {
        match self {
            StatusClass::Success => "2xx",
            StatusClass::Redirect => "3xx",
            StatusClass::ClientError => "4xx",
            StatusClass::ServerError => "5xx",
        }
    }
}

/// Metric handles for one listener, resolved once at wiring time.
///
/// Every field is a concrete handle wrapping an atomic. Recording a request
/// costs a couple of atomic increments and one histogram observation — no
/// map lookup, no string hashing, no lock.
pub struct ListenerMetrics {
    pub requests_2xx: IntCounter,
    pub requests_3xx: IntCounter,
    pub requests_4xx: IntCounter,
    pub requests_5xx: IntCounter,
    pub request_duration: Histogram,
    pub active_connections: IntGauge,
    pub connections_total: IntCounter,
    pub ratelimit_rejected_local: IntCounter,
    pub ratelimit_rejected_cluster: IntCounter,
}

impl ListenerMetrics {
    pub fn record_status(&self, class: StatusClass) {
        match class {
            StatusClass::Success => self.requests_2xx.inc(),
            StatusClass::Redirect => self.requests_3xx.inc(),
            StatusClass::ClientError => self.requests_4xx.inc(),
            StatusClass::ServerError => self.requests_5xx.inc(),
        }
    }
}

/// Metric handles for one backend of one listener.
pub struct BackendMetrics {
    pub healthy: IntGauge,
    pub circuit_state: IntGauge,
    pub requests_success: IntCounter,
    pub requests_failure: IntCounter,
    pub requests_timeout: IntCounter,
    pub upstream_duration: Histogram,
}
```

- [ ] **Step 3: Write the registry**

`crates/lb-metrics/src/lib.rs`:
```rust
mod handles;

pub use handles::{BackendMetrics, ListenerMetrics, StatusClass};

use prometheus::{
    exponential_buckets, Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};

/// Process-wide metric families. Per-listener and per-backend handles are
/// resolved from these once, at wiring time.
pub struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    request_duration: HistogramVec,
    active_connections: IntGaugeVec,
    connections_total: IntCounterVec,
    ratelimit_rejected: IntCounterVec,
    backend_healthy: IntGaugeVec,
    backend_circuit_state: IntGaugeVec,
    backend_requests: IntCounterVec,
    upstream_duration: HistogramVec,
    pub cluster_peer_sync: IntCounterVec,
    pub cluster_tracked_keys: IntGauge,
}

/// Latency buckets from 1ms to ~16s. An edge load balancer cares about the
/// tail, so the buckets are dense where p99 lives rather than uniformly
/// spaced.
fn latency_buckets() -> Vec<f64> {
    exponential_buckets(0.001, 2.0, 15).expect("valid bucket parameters")
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("lb_requests_total", "Requests handled, by status class"),
            &["listener", "protocol", "status"],
        )?;
        let request_duration = HistogramVec::new(
            HistogramOpts::new("lb_request_duration_seconds", "End-to-end request duration")
                .buckets(latency_buckets()),
            &["listener"],
        )?;
        let active_connections = IntGaugeVec::new(
            Opts::new("lb_active_connections", "Currently open client connections"),
            &["listener"],
        )?;
        let connections_total = IntCounterVec::new(
            Opts::new("lb_connections_total", "Client connections accepted"),
            &["listener"],
        )?;
        let ratelimit_rejected = IntCounterVec::new(
            Opts::new(
                "lb_ratelimit_rejected_total",
                "Requests rejected by rate limiting, by layer",
            ),
            &["listener", "layer"],
        )?;
        let backend_healthy = IntGaugeVec::new(
            Opts::new("lb_backend_healthy", "Backend health (1 healthy, 0 unhealthy)"),
            &["listener", "backend"],
        )?;
        let backend_circuit_state = IntGaugeVec::new(
            Opts::new(
                "lb_backend_circuit_state",
                "Circuit breaker state (0 closed, 1 open, 2 half-open)",
            ),
            &["listener", "backend"],
        )?;
        let backend_requests = IntCounterVec::new(
            Opts::new("lb_backend_requests_total", "Requests forwarded, by outcome"),
            &["listener", "backend", "outcome"],
        )?;
        let upstream_duration = HistogramVec::new(
            HistogramOpts::new("lb_upstream_duration_seconds", "Backend response duration")
                .buckets(latency_buckets()),
            &["listener", "backend"],
        )?;
        let cluster_peer_sync = IntCounterVec::new(
            Opts::new("lb_cluster_peer_sync_total", "Peer sync attempts, by outcome"),
            &["peer", "outcome"],
        )?;
        let cluster_tracked_keys = IntGauge::new(
            "lb_cluster_tracked_keys",
            "Distinct rate-limit keys currently tracked",
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(request_duration.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(connections_total.clone()))?;
        registry.register(Box::new(ratelimit_rejected.clone()))?;
        registry.register(Box::new(backend_healthy.clone()))?;
        registry.register(Box::new(backend_circuit_state.clone()))?;
        registry.register(Box::new(backend_requests.clone()))?;
        registry.register(Box::new(upstream_duration.clone()))?;
        registry.register(Box::new(cluster_peer_sync.clone()))?;
        registry.register(Box::new(cluster_tracked_keys.clone()))?;

        Ok(Metrics {
            registry,
            requests_total,
            request_duration,
            active_connections,
            connections_total,
            ratelimit_rejected,
            backend_healthy,
            backend_circuit_state,
            backend_requests,
            upstream_duration,
            cluster_peer_sync,
            cluster_tracked_keys,
        })
    }

    /// Resolve one listener's handles. Called once per listener at startup —
    /// never on the request path.
    pub fn listener(&self, name: &str, protocol: &str) -> ListenerMetrics {
        ListenerMetrics {
            requests_2xx: self.requests_total.with_label_values(&[name, protocol, "2xx"]),
            requests_3xx: self.requests_total.with_label_values(&[name, protocol, "3xx"]),
            requests_4xx: self.requests_total.with_label_values(&[name, protocol, "4xx"]),
            requests_5xx: self.requests_total.with_label_values(&[name, protocol, "5xx"]),
            request_duration: self.request_duration.with_label_values(&[name]),
            active_connections: self.active_connections.with_label_values(&[name]),
            connections_total: self.connections_total.with_label_values(&[name]),
            ratelimit_rejected_local: self
                .ratelimit_rejected
                .with_label_values(&[name, "local"]),
            ratelimit_rejected_cluster: self
                .ratelimit_rejected
                .with_label_values(&[name, "cluster"]),
        }
    }

    /// Resolve one backend's handles. Called once per backend at startup.
    pub fn backend(&self, listener: &str, backend: &str) -> BackendMetrics {
        BackendMetrics {
            healthy: self.backend_healthy.with_label_values(&[listener, backend]),
            circuit_state: self
                .backend_circuit_state
                .with_label_values(&[listener, backend]),
            requests_success: self
                .backend_requests
                .with_label_values(&[listener, backend, "success"]),
            requests_failure: self
                .backend_requests
                .with_label_values(&[listener, backend, "failure"]),
            requests_timeout: self
                .backend_requests
                .with_label_values(&[listener, backend, "timeout"]),
            upstream_duration: self
                .upstream_duration
                .with_label_values(&[listener, backend]),
        }
    }

    /// Prometheus text exposition format.
    pub fn gather_text(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        if encoder.encode(&self.registry.gather(), &mut buf).is_err() {
            return String::new();
        }
        String::from_utf8(buf).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classes_map_correctly() {
        assert_eq!(StatusClass::from_code(200).as_label(), "2xx");
        assert_eq!(StatusClass::from_code(301).as_label(), "3xx");
        assert_eq!(StatusClass::from_code(429).as_label(), "4xx");
        assert_eq!(StatusClass::from_code(502).as_label(), "5xx");
    }

    #[test]
    fn recording_a_request_shows_up_in_exposition() {
        let metrics = Metrics::new().unwrap();
        let listener = metrics.listener("web", "http");
        listener.record_status(StatusClass::Success);
        listener.record_status(StatusClass::ServerError);

        let text = metrics.gather_text();
        assert!(text.contains(r#"lb_requests_total{listener="web",protocol="http",status="2xx"} 1"#));
        assert!(text.contains(r#"lb_requests_total{listener="web",protocol="http",status="5xx"} 1"#));
    }

    #[test]
    fn rate_limit_layers_are_counted_separately() {
        let metrics = Metrics::new().unwrap();
        let listener = metrics.listener("web", "http");
        listener.ratelimit_rejected_local.inc();
        listener.ratelimit_rejected_cluster.inc();
        listener.ratelimit_rejected_cluster.inc();

        let text = metrics.gather_text();
        assert!(text.contains(r#"lb_ratelimit_rejected_total{layer="local",listener="web"} 1"#));
        assert!(text.contains(r#"lb_ratelimit_rejected_total{layer="cluster",listener="web"} 2"#));
    }

    #[test]
    fn backend_handles_record_health_and_outcomes() {
        let metrics = Metrics::new().unwrap();
        let backend = metrics.backend("web", "b1");
        backend.healthy.set(1);
        backend.requests_success.inc();
        backend.requests_timeout.inc();

        let text = metrics.gather_text();
        assert!(text.contains(r#"lb_backend_healthy{backend="b1",listener="web"} 1"#));
        assert!(text.contains(r#"outcome="success""#));
        assert!(text.contains(r#"outcome="timeout""#));
    }

    #[test]
    fn exposition_is_valid_prometheus_text_format() {
        let metrics = Metrics::new().unwrap();
        metrics.listener("web", "http").record_status(StatusClass::Success);
        let text = metrics.gather_text();

        // Every metric family carries HELP and TYPE lines, and no line is
        // malformed (a bare label brace would break scraping).
        assert!(text.contains("# HELP lb_requests_total"));
        assert!(text.contains("# TYPE lb_requests_total counter"));
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            assert!(
                line.split_whitespace().count() >= 2,
                "malformed exposition line: {line}"
            );
        }
    }

    /// Encodes spec §2.3 as an executable rule: every label name in the
    /// exposition must come from a known, config-derived set. A client IP or
    /// path label would explode Prometheus's series count.
    #[test]
    fn no_unbounded_label_names_are_exposed() {
        let metrics = Metrics::new().unwrap();
        metrics.listener("web", "http").record_status(StatusClass::Success);
        metrics.backend("web", "b1").healthy.set(1);
        let text = metrics.gather_text();

        const ALLOWED: [&str; 6] = ["listener", "protocol", "status", "backend", "outcome", "layer"];
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let Some(start) = line.find('{') else { continue };
            let Some(end) = line.find('}') else { continue };
            for pair in line[start + 1..end].split(',') {
                let Some(name) = pair.split('=').next() else { continue };
                assert!(
                    ALLOWED.contains(&name.trim()),
                    "unexpected metric label '{name}' — client-derived labels are forbidden"
                );
            }
        }
    }
}
```

- [ ] **Step 4: Run**

Run: `cargo test -p lb-metrics`
Expected: PASS, six tests. If an exposition assertion fails on label *ordering*, note that the `prometheus` crate sorts labels alphabetically — adjust the expected string to match actual output rather than assuming insertion order.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/lb-metrics
git commit -m "feat(lb-metrics): add Prometheus registry with pre-resolved metric handles"
```

---

## Task 3: Config — `[admin]` and `[logging]` sections

**Files:** Modify `crates/lb-core/src/config.rs`, `crates/lb-core/src/lib.rs`

**Interfaces:** Produces `lb_core::{AdminConfig, LoggingConfig, LogFormat}`; `Config` gains `admin: Option<AdminConfig>` and `logging: LoggingConfig` (defaulted).

- [ ] **Step 1: Add the types**

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    /// Bind privately. This surface exposes internal topology (backend names,
    /// health, traffic volumes) and must never face the public internet.
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub format: LogFormat,
    /// Off by default: at 50k req/s, one line per request is ~50,000 lines a
    /// second. Turning this on is a capacity decision, not a preference.
    #[serde(default)]
    pub log_requests: bool,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            format: LogFormat::default(),
            log_requests: false,
            sample_rate: default_sample_rate(),
        }
    }
}

fn default_sample_rate() -> f64 {
    0.01
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Json,
    Pretty,
}
```

Add to `Config`:
```rust
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
```

- [ ] **Step 2: Validate**

In `Config::validate`, after the cluster block:
```rust
        if let Some(admin) = &self.admin {
            if let Some(clash) = self.listeners.iter().find(|l| l.listen == admin.listen) {
                return Err(ConfigError::Invalid(format!(
                    "admin.listen {} is already used by listener '{}'",
                    admin.listen, clash.name
                )));
            }
            if let Some(cluster) = &self.cluster {
                if cluster.listen == admin.listen {
                    return Err(ConfigError::Invalid(format!(
                        "admin.listen {} is already used by cluster.listen",
                        admin.listen
                    )));
                }
            }
        }
        if !(0.0..=1.0).contains(&self.logging.sample_rate) {
            return Err(ConfigError::Invalid(
                "logging.sample_rate must be between 0.0 and 1.0".into(),
            ));
        }
```

Export `AdminConfig, LoggingConfig, LogFormat` from `lib.rs`.

- [ ] **Step 3: Tests**

Add to `config.rs` tests:
```rust
    #[test]
    fn admin_and_logging_are_optional_with_defaults() {
        let cfg = Config::parse(VALID).unwrap();
        assert!(cfg.admin.is_none());
        assert!(!cfg.logging.log_requests);
        assert_eq!(cfg.logging.format, LogFormat::Json);
    }

    #[test]
    fn parses_admin_and_logging_sections() {
        let text = format!(
            "{}\n{}",
            "[admin]\nlisten = \"127.0.0.1:9090\"\n\n[logging]\nformat = \"pretty\"\nlog_requests = true\nsample_rate = 0.5\n",
            VALID
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.admin.unwrap().listen.port(), 9090);
        assert_eq!(cfg.logging.format, LogFormat::Pretty);
        assert!(cfg.logging.log_requests);
    }

    #[test]
    fn rejects_admin_listen_clashing_with_a_traffic_listener() {
        let text = format!("[admin]\nlisten = \"0.0.0.0:8080\"\n\n{VALID}");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_out_of_range_sample_rate() {
        let text = format!("[logging]\nsample_rate = 1.5\n\n{VALID}");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }
```

- [ ] **Step 4: Run and commit**

Run: `cargo test -p lb-core`
Expected: PASS, existing tests plus four new.

```bash
git add crates/lb-core
git commit -m "feat(lb-core): add admin and logging config sections"
```

---

## Task 4: Admin server — `/metrics`, `/healthz`, `/ready`

**Files:** Create `crates/lb-metrics/src/admin.rs`; modify `crates/lb-metrics/src/lib.rs`, `Cargo.toml`

**Interfaces:** Produces `lb_metrics::{spawn_admin_server, ReadinessCheck}` where `ReadinessCheck = Arc<dyn Fn() -> bool + Send + Sync>`; `spawn_admin_server(metrics: Arc<Metrics>, listener: TcpListener, readiness: ReadinessCheck) -> JoinHandle<()>`.

Takes a bound `TcpListener` (not an address) so `lb-server` binds every port up front and fails fast, and so tests can bind port 0.

- [ ] **Step 1: Add dependencies**

`crates/lb-metrics/Cargo.toml`:
```toml
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
bytes = "1"
tokio = { version = "1", features = ["rt", "net", "macros"] }
tracing = "0.1"

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time"] }
reqwest = "0.12"
```

- [ ] **Step 2: Write the admin server**

`crates/lb-metrics/src/admin.rs`:
```rust
use crate::Metrics;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Returns true when this instance should receive traffic.
pub type ReadinessCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Serves `/metrics`, `/healthz` and `/ready` on a private listener.
///
/// Deliberately separate from the traffic listeners: this surface exposes
/// internal topology and must not face the public internet.
pub fn spawn_admin_server(
    metrics: Arc<Metrics>,
    listener: TcpListener,
    readiness: ReadinessCheck,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let io = TokioIo::new(stream);
            let metrics = Arc::clone(&metrics);
            let readiness = Arc::clone(&readiness);
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let metrics = Arc::clone(&metrics);
                    let readiness = Arc::clone(&readiness);
                    async move { route(req, metrics, readiness).await }
                });
                if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                    tracing::debug!(error = %err, "admin connection error");
                }
            });
        }
    })
}

async fn route(
    req: Request<Incoming>,
    metrics: Arc<Metrics>,
    readiness: ReadinessCheck,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match req.uri().path() {
        "/metrics" => text(StatusCode::OK, metrics.gather_text()),

        // Liveness: is the process functioning? Deliberately independent of
        // backend health — a failing liveness probe restarts the process, and
        // restarting cannot fix an unhealthy backend. Coupling them turns a
        // partial outage into a crash loop.
        "/healthz" => text(StatusCode::OK, "ok".to_string()),

        // Readiness: should this instance receive traffic? False when there is
        // nowhere to forward, which removes it from rotation without killing it.
        "/ready" => {
            if readiness() {
                text(StatusCode::OK, "ready".to_string())
            } else {
                text(StatusCode::SERVICE_UNAVAILABLE, "no eligible backend".to_string())
            }
        }

        _ => text(StatusCode::NOT_FOUND, "not found".to_string()),
    };
    Ok(response)
}

fn text(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(Full::new(Bytes::from_static(b"")));
            *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatusClass;
    use std::sync::atomic::{AtomicBool, Ordering};

    async fn start(ready: bool) -> (String, Arc<AtomicBool>) {
        let metrics = Arc::new(Metrics::new().unwrap());
        metrics.listener("web", "http").record_status(StatusClass::Success);

        let flag = Arc::new(AtomicBool::new(ready));
        let flag_clone = Arc::clone(&flag);
        let readiness: ReadinessCheck = Arc::new(move || flag_clone.load(Ordering::SeqCst));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_admin_server(metrics, listener, readiness);
        (format!("http://{addr}"), flag)
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_exposition() {
        let (base, _) = start(true).await;
        let body = reqwest::get(format!("{base}/metrics"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(body.contains("lb_requests_total"));
        assert!(body.contains("# TYPE"));
    }

    #[tokio::test]
    async fn healthz_is_ok_even_when_not_ready() {
        // The core distinction: liveness must not follow backend health, or a
        // backend outage would restart the load balancer in a loop.
        let (base, _) = start(false).await;
        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn ready_reflects_the_readiness_check() {
        let (base, flag) = start(true).await;
        assert_eq!(
            reqwest::get(format!("{base}/ready")).await.unwrap().status(),
            200
        );

        flag.store(false, Ordering::SeqCst);
        assert_eq!(
            reqwest::get(format!("{base}/ready")).await.unwrap().status(),
            503
        );
    }

    #[tokio::test]
    async fn unknown_paths_are_404() {
        let (base, _) = start(true).await;
        assert_eq!(
            reqwest::get(format!("{base}/admin")).await.unwrap().status(),
            404
        );
    }
}
```

Export from `lib.rs`: `mod admin; pub use admin::{spawn_admin_server, ReadinessCheck};`

- [ ] **Step 3: Run and commit**

Run: `cargo test -p lb-metrics`
Expected: PASS, including the four admin tests.

```bash
git add crates/lb-metrics Cargo.lock
git commit -m "feat(lb-metrics): serve /metrics, /healthz and /ready on a private admin listener"
```

---

## Task 5: Instrument the data plane

**Files:** Modify `crates/lb-proxy/src/service.rs`, `crates/lb-tcp/src/session.rs`, `crates/lb-healthcheck/src/active.rs`, `crates/lb-server/src/wiring.rs` and `src/lib.rs`, plus the three `Cargo.toml`s.

**Interfaces:** `ProxyContext` and `TcpContext` each gain `metrics: Arc<ListenerMetrics>` and `backend_metrics: HashMap<BackendId, BackendMetrics>`. Not `Option` — metrics are always recorded (a few atomics); `[admin]` only controls *exposure*. That keeps the hot path branch-free.

- [ ] **Step 1: Instrument `lb-proxy`**

In `handle`, after computing `key` and before returning any response, wrap the whole flow in timing:

```rust
    let started = std::time::Instant::now();
```

At the local rate-limit rejection: `ctx.metrics.ratelimit_rejected_local.inc();`
At the cluster rejection: `ctx.metrics.ratelimit_rejected_cluster.inc();`

For backend outcomes, inside the forward loop:
```rust
            Ok(resp) => {
                if let Some(bm) = ctx.backend_metrics.get(&backend_id) {
                    bm.requests_success.inc();
                    bm.upstream_duration.observe(attempt_started.elapsed().as_secs_f64());
                }
                ...
            }
            Err(err) => {
                if let Some(bm) = ctx.backend_metrics.get(&backend_id) {
                    match err {
                        ForwardError::Timeout => bm.requests_timeout.inc(),
                        ForwardError::Connect => bm.requests_failure.inc(),
                    }
                }
                ...
            }
```
(`ForwardError` currently has no `Debug`-free match in that arm — change the arm from `Err(ForwardError::Connect | ForwardError::Timeout)` to `Err(err)` and match inside.)

Record status and duration at every return point. Rather than duplicating that at six `return` sites, restructure `handle` to delegate to an inner function and record once:

```rust
pub async fn handle<R, L, C>(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext<R, L, C>>,
    peer_ip: IpAddr,
) -> Result<Response<ProxyBody>, Infallible>
where
    R: RateLimiter,
    L: LoadBalancer,
    C: Clock,
{
    let started = std::time::Instant::now();
    let result = handle_inner(req, Arc::clone(&ctx), peer_ip).await;

    // Single place where status and duration are recorded, so no return path
    // can forget to.
    if let Ok(resp) = &result {
        ctx.metrics
            .record_status(StatusClass::from_code(resp.status().as_u16()));
        ctx.metrics
            .request_duration
            .observe(started.elapsed().as_secs_f64());
    }
    result
}
```
Rename the existing body to `handle_inner` with the same signature.

- [ ] **Step 2: Instrument `lb-tcp`**

In `handle_connection`: increment `connections_total` and `active_connections` on entry; decrement `active_connections` on exit (use a guard struct so every early return decrements). Record rate-limit rejections by layer, and backend connect outcomes.

```rust
/// Decrements the active-connection gauge on drop, so every early return
/// path is accounted for without repeating the decrement.
struct ConnectionGuard(IntGauge);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}
```

- [ ] **Step 3: Instrument health checks and circuit state**

In `lb-healthcheck::spawn_active_checker`, accept an optional `IntGauge` for `healthy` and set it alongside `pool.set_active_healthy`. In `lb-proxy`/`lb-tcp` where the circuit refresh loop runs, set `circuit_state` from the breaker's state.

- [ ] **Step 4: Wire in `lb-server`**

`build_app` creates `Arc<Metrics>` once, then per listener calls `metrics.listener(&lc.name, protocol_str)` and `metrics.backend(&lc.name, &b.id.0)` for each backend, storing them in the contexts. `WiredApp` gains `metrics: Arc<Metrics>` and `admin_listen: Option<SocketAddr>`.

In `run`, bind the admin listener alongside the others (fail fast on clash) and spawn the admin server with a readiness closure:
```rust
    // Ready when any listener has at least one eligible backend — if there is
    // nowhere to forward, this instance should leave rotation.
    let pools: Vec<Arc<BackendPool>> = /* collected from listeners */;
    let readiness: ReadinessCheck = Arc::new(move || {
        pools.iter().any(|p| !p.eligible_backends().is_empty())
    });
```

- [ ] **Step 5: Verify no behaviour changed**

Run: `cargo test --workspace --features lb-core/test-util`
Expected: **all 102 pre-existing tests still pass with no modification.** If any existing test needs changing, stop and investigate — this task must not move data-plane behaviour.

- [ ] **Step 6: Add instrumentation integration tests**

`crates/lb-server/tests/metrics_integration.rs`: start a server with `[admin]`, send traffic, scrape `/metrics`, assert `lb_requests_total{status="2xx"}` increased; drive a rate-limited request and assert `lb_ratelimit_rejected_total{layer="local"}` increased; assert `/metrics` on the **traffic** port is proxied to the backend rather than serving metrics.

- [ ] **Step 7: Commit**

```bash
git add crates Cargo.lock
git commit -m "feat: instrument the data plane with Prometheus metrics"
```

---

## Task 6: Structured logging

**Files:** Modify `crates/lb-server/src/main.rs`, `src/lib.rs`, `crates/lb-proxy/src/service.rs`, and every crate currently using `eprintln!`.

- [ ] **Step 1: Initialise the subscriber**

In `main.rs`, before anything else, from `config.logging`:
```rust
fn init_logging(cfg: &LoggingConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match cfg.format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        LogFormat::Pretty => tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(filter)
            .init(),
    }
}
```

- [ ] **Step 2: Replace every `eprintln!`**

Convert to `tracing::info!` / `warn!` / `error!` with structured fields rather than interpolated strings — e.g.

```rust
tracing::info!(listener = %runtime.name(), protocol = runtime.protocol_name(), addr = %actual, "listener bound");
tracing::warn!(peer = %peer, node_id = %msg.node_id, "duplicate node_id detected in cluster");
tracing::error!(listener = %runtime.name(), error = %err, "accept failed");
```

Structured fields are the point: `listener="web"` is queryable in a log backend, `"listener web failed"` is not.

- [ ] **Step 3: Request ids and sampled access logging**

In `lb-proxy::handle`, generate a request id, attach it to the response as `X-Request-Id`, and log the access line only when `log_requests` is on and the sample admits it.

```rust
// An inbound X-Request-Id is NOT trusted: at the edge it is
// attacker-controlled and could be used to forge or collide log entries.
let request_id = uuid::Uuid::new_v4();
```

Sampling without a per-request RNG call:
```rust
// Deterministic sampling off a counter rather than drawing a random number
// per request — cheaper, and gives an exact 1-in-N rate.
let sample_every = (1.0 / cfg.sample_rate).round().max(1.0) as u64;
if counter.fetch_add(1, Ordering::Relaxed) % sample_every == 0 { /* log */ }
```

- [ ] **Step 4: Test**

- JSON output parses as JSON and contains the expected fields.
- With `log_requests = false`, no per-request lines are emitted.
- The response carries an `X-Request-Id` header.

- [ ] **Step 5: Commit**

```bash
git add crates Cargo.lock
git commit -m "feat: replace eprintln with structured tracing and add request ids"
```

---

## Task 7: Benchmarks and baseline

**Files:** Create `crates/lb-core/benches/hot_path.rs`, `crates/lb-cluster/benches/coordinator.rs`, `crates/loadgen/` (binary), `docs/BASELINE.md`

- [ ] **Step 1: Micro-benchmarks for the four identified costs**

`criterion` benches over backend counts 1, 5 and 20, targeting exactly:
- `BackendPool::eligible_backends()` (Vec + `BackendId` String clones per pick)
- `Gcra::check()` (`key.to_string()` per call)
- `ListenerCoordinator::try_admit()` (`format!()` per call)
- the circuit-breaker refresh loop (two mutex acquisitions per backend per request)

Add to each crate's `Cargo.toml`:
```toml
[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "hot_path"
harness = false
```

- [ ] **Step 2: In-repo load generator**

`crates/loadgen`: a binary taking `--target`, `--connections`, `--duration`, reporting throughput and p50/p95/p99/p99.9 latency plus error counts. In-repo rather than `wrk`/`oha` so it runs anywhere `cargo` does — including this Windows machine — and can move into CI later.

- [ ] **Step 3: Capture the baseline**

Run both, and record results in `docs/BASELINE.md` together with machine specs.

**State the caveat in the document itself, not as a footnote:** the load generator, the load balancer and the backends all share one machine, so absolute throughput is not a capacity measurement — the client competes with the server for cores and loopback is not a network. These figures are a **relative baseline** for detecting regressions and validating Phase 7. Any SLA commitment requires a separate load-generation host and production-like hardware.

- [ ] **Step 4: Commit**

```bash
git add crates docs/BASELINE.md Cargo.lock
git commit -m "test: add hot-path micro-benchmarks, load generator, and baseline measurements"
```

---

## Post-Plan Verification

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings
cargo test --workspace --features lb-core/test-util
```

Plus the phase-specific gate: **the 102 pre-existing tests must pass unmodified**, confirming Phase 4 added instruments without moving behaviour.
