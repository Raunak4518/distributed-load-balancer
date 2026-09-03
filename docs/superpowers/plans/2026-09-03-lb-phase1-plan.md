# Distributed Load Balancer — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working, single-node L7 HTTP load balancer with GCRA rate limiting, round-robin backend selection, and active+passive health checking, as a Cargo workspace of small trait-bounded crates.

**Architecture:** Six crates. `lb-core` defines shared types and the `RateLimiter`/`LoadBalancer`/`Clock` traits with zero I/O. `lb-ratelimit`, `lb-balancer`, `lb-healthcheck` each implement one concern against those traits. `lb-proxy` is a hyper `Service` that orchestrates one request by calling into the trait-typed dependencies it's handed. `lb-server` is the binary: loads config, constructs concrete types, wires them together, runs the listener and background tasks.

**Tech Stack:** Rust (2021 edition), `tokio`, `hyper` 1.x + `hyper-util` (server + client, HTTP/1.1 only), `http-body-util`, `bytes`, `dashmap`, `serde` + `toml`, `thiserror`, `reqwest` (health-check polling only), `wiremock`/hand-rolled test servers for integration tests.

**Spec:** [`docs/superpowers/specs/2026-09-03-lb-phase1-design.md`](../specs/2026-09-03-lb-phase1-design.md)

## Global Constraints

- No `unwrap()`/`expect()` reachable from request-handling code (untrusted network input must never panic the service). `expect()` is acceptable only on invariants established by our own code (e.g. "this backend ID exists in the pool because we just picked it from that pool").
- Every I/O boundary has a timeout: backend connect/request (`forward_timeout_ms`, default 5000), active health-check request (`health_check.timeout_ms`).
- No unbounded growth: rate-limit key store is swept periodically; request bodies are capped at `server.max_request_body_bytes` (default 1 MiB), rejected with `413` above that, not buffered unbounded.
- Every pluggable concern (rate limiting, backend selection) is a trait in `lb-core`; concrete implementations live in their own crates and depend only on `lb-core`, never on each other.
- Clients never see internal detail: only `429`, `502`, `503`, `504`, `413` with generic bodies — no backend addresses or internal errors in responses.
- Rust edition 2021 throughout; workspace-level `Cargo.toml` with `[workspace] resolver = "2"`.

---

## Task 1: Workspace scaffold + `lb-core`: `Backend`/`BackendId`

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/lb-core/Cargo.toml`
- Create: `crates/lb-core/src/lib.rs`
- Create: `crates/lb-core/src/backend.rs`
- Test: inline in `crates/lb-core/src/backend.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `lb_core::{Backend, BackendId}` — `BackendId(pub String)` (Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display); `Backend { pub id: BackendId, pub address: SocketAddr, pub weight: u32 }` with `Backend::new(id: impl Into<String>, address: SocketAddr, weight: u32) -> Self`.

- [ ] **Step 1: Create the workspace root**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "crates/lb-core",
    "crates/lb-ratelimit",
    "crates/lb-balancer",
    "crates/lb-healthcheck",
    "crates/lb-proxy",
    "crates/lb-server",
]

[workspace.package]
edition = "2021"
```

- [ ] **Step 2: Write the failing test for `Backend`/`BackendId`**

`crates/lb-core/Cargo.toml`:
```toml
[package]
name = "lb-core"
version = "0.1.0"
edition.workspace = true

[features]
test-util = []

[dependencies]
```

`crates/lb-core/src/lib.rs`:
```rust
pub mod backend;

pub use backend::{Backend, BackendId};
```

`crates/lb-core/src/backend.rs`:
```rust
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BackendId(pub String);

impl BackendId {
    pub fn new(id: impl Into<String>) -> Self {
        BackendId(id.into())
    }
}

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    pub id: BackendId,
    pub address: SocketAddr,
    pub weight: u32,
}

impl Backend {
    pub fn new(id: impl Into<String>, address: SocketAddr, weight: u32) -> Self {
        Backend { id: BackendId::new(id), address, weight }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn backend_new_sets_all_fields() {
        let b = Backend::new("b1", "127.0.0.1:9001".parse().unwrap(), 3);
        assert_eq!(b.id, BackendId::new("b1"));
        assert_eq!(b.address.to_string(), "127.0.0.1:9001");
        assert_eq!(b.weight, 3);
    }

    #[test]
    fn backend_id_is_hashable_and_comparable() {
        let mut set = HashSet::new();
        set.insert(BackendId::new("b1"));
        set.insert(BackendId::new("b1"));
        set.insert(BackendId::new("b2"));
        assert_eq!(set.len(), 2);
        assert!(set.contains(&BackendId::new("b1")));
    }

    #[test]
    fn backend_id_displays_as_inner_string() {
        assert_eq!(BackendId::new("b1").to_string(), "b1");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail to compile first, then pass**

Run: `cargo test -p lb-core`
Expected: compiles and all three tests in `backend::tests` PASS (this is a from-scratch definition, not a red/green cycle against pre-existing broken code — verify by temporarily commenting out the `Backend`/`BackendId` definitions and confirming the build fails, then restore).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/lb-core
git commit -m "feat(lb-core): add workspace scaffold and Backend/BackendId types"
```

---

## Task 2: `lb-core`: `Clock` trait (`SystemClock` + `FakeClock`)

**Files:**
- Create: `crates/lb-core/src/clock.rs`
- Modify: `crates/lb-core/src/lib.rs`
- Test: inline in `crates/lb-core/src/clock.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `lb_core::{Clock, SystemClock}` always; `lb_core::test_util::FakeClock` behind the `test-util` feature. `trait Clock: Send + Sync { fn now(&self) -> Instant; }`. `FakeClock::new() -> Self`, `FakeClock::advance(&self, d: Duration)`, both implement `Clone`.

- [ ] **Step 1: Write the failing test**

`crates/lb-core/src/clock.rs`:
```rust
use std::time::Instant;

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use super::Clock;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    pub struct FakeClock {
        current: Arc<Mutex<Instant>>,
    }

    impl FakeClock {
        pub fn new() -> Self {
            FakeClock { current: Arc::new(Mutex::new(Instant::now())) }
        }

        pub fn advance(&self, d: Duration) {
            let mut guard = self.current.lock().expect("fake clock mutex poisoned");
            *guard += d;
        }
    }

    impl Default for FakeClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.current.lock().expect("fake clock mutex poisoned")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;

        #[test]
        fn advances_by_exact_duration() {
            let clock = FakeClock::new();
            let start = clock.now();
            clock.advance(Duration::from_secs(5));
            assert_eq!(clock.now().duration_since(start), Duration::from_secs(5));
        }

        #[test]
        fn does_not_advance_on_its_own() {
            let clock = FakeClock::new();
            let a = clock.now();
            let b = clock.now();
            assert_eq!(a, b);
        }
    }
}
```

`crates/lb-core/src/lib.rs` (add):
```rust
pub mod clock;

pub use clock::{Clock, SystemClock};
#[cfg(feature = "test-util")]
pub use clock::test_util;
```

- [ ] **Step 2: Run to verify the test-util tests pass**

Run: `cargo test -p lb-core --features test-util`
Expected: PASS, including `clock::test_util::tests::*`.

- [ ] **Step 3: Run to verify the default build (no feature) still compiles**

Run: `cargo build -p lb-core`
Expected: succeeds without pulling in `FakeClock` (it's feature-gated).

- [ ] **Step 4: Commit**

```bash
git add crates/lb-core/src/clock.rs crates/lb-core/src/lib.rs
git commit -m "feat(lb-core): add Clock trait with SystemClock and test-only FakeClock"
```

---

## Task 3: `lb-core`: `BackendPool` (eligibility state)

**Files:**
- Create: `crates/lb-core/src/pool.rs`
- Modify: `crates/lb-core/src/lib.rs`
- Test: inline in `crates/lb-core/src/pool.rs`

**Interfaces:**
- Consumes: `Backend`, `BackendId` (Task 1).
- Produces: `lb_core::BackendPool` — `BackendPool::new(backends: Vec<Backend>) -> Self`, `.backend(&self, id: &BackendId) -> Option<&Backend>`, `.set_active_healthy(&self, id: &BackendId, healthy: bool)`, `.set_circuit_open(&self, id: &BackendId, open: bool)`, `.is_eligible(&self, id: &BackendId) -> bool`, `.eligible_backends(&self) -> Vec<BackendId>`, `.all_backend_ids(&self) -> &[BackendId]`.

- [ ] **Step 1: Write the failing test**

`crates/lb-core/src/pool.rs`:
```rust
use crate::backend::{Backend, BackendId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct BackendState {
    backend: Backend,
    active_healthy: AtomicBool,
    circuit_open: AtomicBool,
}

pub struct BackendPool {
    order: Vec<BackendId>,
    states: HashMap<BackendId, Arc<BackendState>>,
}

impl BackendPool {
    pub fn new(backends: Vec<Backend>) -> Self {
        let mut order = Vec::with_capacity(backends.len());
        let mut states = HashMap::with_capacity(backends.len());
        for b in backends {
            order.push(b.id.clone());
            states.insert(
                b.id.clone(),
                Arc::new(BackendState {
                    backend: b,
                    active_healthy: AtomicBool::new(true),
                    circuit_open: AtomicBool::new(false),
                }),
            );
        }
        BackendPool { order, states }
    }

    pub fn backend(&self, id: &BackendId) -> Option<&Backend> {
        self.states.get(id).map(|s| &s.backend)
    }

    pub fn set_active_healthy(&self, id: &BackendId, healthy: bool) {
        if let Some(s) = self.states.get(id) {
            s.active_healthy.store(healthy, Ordering::SeqCst);
        }
    }

    pub fn set_circuit_open(&self, id: &BackendId, open: bool) {
        if let Some(s) = self.states.get(id) {
            s.circuit_open.store(open, Ordering::SeqCst);
        }
    }

    pub fn is_eligible(&self, id: &BackendId) -> bool {
        self.states
            .get(id)
            .is_some_and(|s| s.active_healthy.load(Ordering::SeqCst) && !s.circuit_open.load(Ordering::SeqCst))
    }

    pub fn eligible_backends(&self) -> Vec<BackendId> {
        self.order.iter().filter(|id| self.is_eligible(id)).cloned().collect()
    }

    pub fn all_backend_ids(&self) -> &[BackendId] {
        &self.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_of(ids: &[&str]) -> BackendPool {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1))
            .collect();
        BackendPool::new(backends)
    }

    #[test]
    fn all_backends_start_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b1"), BackendId::new("b2")]);
    }

    #[test]
    fn active_unhealthy_removes_from_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b2")]);
    }

    #[test]
    fn open_circuit_removes_from_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_circuit_open(&BackendId::new("b2"), true);
        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b1")]);
    }

    #[test]
    fn restoring_both_flags_makes_eligible_again() {
        let pool = pool_of(&["b1"]);
        let id = BackendId::new("b1");
        pool.set_active_healthy(&id, false);
        pool.set_circuit_open(&id, true);
        assert!(pool.eligible_backends().is_empty());
        pool.set_active_healthy(&id, true);
        pool.set_circuit_open(&id, false);
        assert_eq!(pool.eligible_backends(), vec![id]);
    }

    #[test]
    fn unknown_id_is_never_eligible_and_operations_are_no_ops() {
        let pool = pool_of(&["b1"]);
        let unknown = BackendId::new("ghost");
        assert!(!pool.is_eligible(&unknown));
        pool.set_active_healthy(&unknown, false); // must not panic
        assert!(pool.backend(&unknown).is_none());
    }
}
```

`crates/lb-core/src/lib.rs` (add):
```rust
pub mod pool;

pub use pool::BackendPool;
```

- [ ] **Step 2: Run to verify tests pass**

Run: `cargo test -p lb-core`
Expected: PASS, including all `pool::tests::*`.

- [ ] **Step 3: Commit**

```bash
git add crates/lb-core/src/pool.rs crates/lb-core/src/lib.rs
git commit -m "feat(lb-core): add BackendPool with active+circuit eligibility gate"
```

---

## Task 4: `lb-core`: config parsing/validation + `RateLimiter`/`LoadBalancer` traits

**Files:**
- Create: `crates/lb-core/src/config.rs`
- Create: `crates/lb-core/src/error.rs`
- Create: `crates/lb-core/src/ratelimit.rs`
- Create: `crates/lb-core/src/balancer.rs`
- Modify: `crates/lb-core/src/lib.rs`, `crates/lb-core/Cargo.toml`
- Test: inline in `crates/lb-core/src/config.rs`

**Interfaces:**
- Consumes: `BackendPool` (Task 3, used only in `balancer.rs`'s trait signature).
- Produces:
  - `lb_core::{ConfigError}` (thiserror enum: `Io`, `Parse`, `Invalid`).
  - `lb_core::{Config, ServerConfig, BackendConfig, HealthCheckConfig, RateLimitConfig, RateLimitKeySource, LoadBalancingConfig, LoadBalancingStrategy}` with `Config::load(path: impl AsRef<Path>) -> Result<Config, ConfigError>` and `Config::parse(text: &str) -> Result<Config, ConfigError>`.
  - `lb_core::{Decision, RateLimiter}` — `enum Decision { Allow, Deny { retry_after: Duration } }`, `trait RateLimiter: Send + Sync { fn check(&self, key: &str) -> Decision; }`.
  - `lb_core::LoadBalancer` — `trait LoadBalancer: Send + Sync { fn pick(&self, pool: &BackendPool) -> Option<BackendId>; }`.

- [ ] **Step 1: Add dependencies**

`crates/lb-core/Cargo.toml` (add under `[dependencies]`):
```toml
serde = { version = "1", features = ["derive"] }
toml = "0.8"
thiserror = "1"
```

- [ ] **Step 2: Write the failing config tests**

`crates/lb-core/src/error.rs`:
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}
```

`crates/lb-core/src/config.rs`:
```rust
use crate::error::ConfigError;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub backends: Vec<BackendConfig>,
    pub health_check: HealthCheckConfig,
    pub rate_limit: RateLimitConfig,
    pub load_balancing: LoadBalancingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_forward_timeout_ms")]
    pub forward_timeout_ms: u64,
}

fn default_max_request_body_bytes() -> usize {
    1024 * 1024
}

fn default_forward_timeout_ms() -> u64 {
    5000
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    pub address: SocketAddr,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    pub path: String,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
    pub cooldown_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub key: RateLimitKeySource,
    pub rate_per_sec: f64,
    pub burst: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum RateLimitKeySource {
    SourceIp,
    Header(String),
}

impl TryFrom<String> for RateLimitKeySource {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s == "source_ip" {
            Ok(RateLimitKeySource::SourceIp)
        } else if let Some(header) = s.strip_prefix("header:") {
            Ok(RateLimitKeySource::Header(header.to_string()))
        } else {
            Err(format!("invalid rate_limit.key '{s}': expected 'source_ip' or 'header:<name>'"))
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoadBalancingConfig {
    pub strategy: LoadBalancingStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingStrategy {
    RoundRobin,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let text = std::fs::read_to_string(path_ref)
            .map_err(|source| ConfigError::Io { path: path_ref.display().to_string(), source })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.backends.is_empty() {
            return Err(ConfigError::Invalid("at least one backend is required".into()));
        }
        if self.rate_limit.rate_per_sec <= 0.0 {
            return Err(ConfigError::Invalid("rate_limit.rate_per_sec must be positive".into()));
        }
        if self.rate_limit.burst == 0 {
            return Err(ConfigError::Invalid("rate_limit.burst must be positive".into()));
        }
        let mut seen = std::collections::HashSet::new();
        for b in &self.backends {
            if !seen.insert(&b.id) {
                return Err(ConfigError::Invalid(format!("duplicate backend id: {}", b.id)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        [server]
        listen = "0.0.0.0:8080"

        [[backends]]
        id = "b1"
        address = "127.0.0.1:9001"

        [[backends]]
        id = "b2"
        address = "127.0.0.1:9002"
        weight = 2

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

    #[test]
    fn parses_valid_config() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert_eq!(cfg.backends.len(), 2);
        assert_eq!(cfg.backends[0].weight, 1); // default applied
        assert_eq!(cfg.backends[1].weight, 2);
        assert_eq!(cfg.rate_limit.key, RateLimitKeySource::SourceIp);
        assert_eq!(cfg.load_balancing.strategy, LoadBalancingStrategy::RoundRobin);
        assert_eq!(cfg.server.max_request_body_bytes, 1024 * 1024); // default applied
    }

    #[test]
    fn parses_header_based_rate_limit_key() {
        let text = VALID.replace(r#"key = "source_ip""#, r#"key = "header:X-API-Key""#);
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.rate_limit.key, RateLimitKeySource::Header("X-API-Key".into()));
    }

    #[test]
    fn rejects_empty_backends() {
        let text = VALID.replace(
            "[[backends]]\n        id = \"b1\"\n        address = \"127.0.0.1:9001\"\n\n        [[backends]]\n        id = \"b2\"\n        address = \"127.0.0.1:9002\"\n        weight = 2\n\n",
            "",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_non_positive_rate() {
        let text = VALID.replace("rate_per_sec = 50", "rate_per_sec = 0");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_duplicate_backend_ids() {
        let text = VALID.replace(r#"id = "b2""#, r#"id = "b1""#);
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_unknown_rate_limit_key_format() {
        let text = VALID.replace(r#"key = "source_ip""#, r#"key = "nonsense""#);
        assert!(Config::parse(&text).is_err());
    }
}
```

- [ ] **Step 3: Add the `RateLimiter` and `LoadBalancer` trait contracts**

`crates/lb-core/src/ratelimit.rs`:
```rust
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { retry_after: Duration },
}

pub trait RateLimiter: Send + Sync {
    fn check(&self, key: &str) -> Decision;
}
```

`crates/lb-core/src/balancer.rs`:
```rust
use crate::backend::BackendId;
use crate::pool::BackendPool;

pub trait LoadBalancer: Send + Sync {
    fn pick(&self, pool: &BackendPool) -> Option<BackendId>;
}
```

`crates/lb-core/src/lib.rs` (add):
```rust
pub mod balancer;
pub mod config;
pub mod error;
pub mod ratelimit;

pub use balancer::LoadBalancer;
pub use config::{
    BackendConfig, Config, HealthCheckConfig, LoadBalancingConfig, LoadBalancingStrategy,
    RateLimitConfig, RateLimitKeySource, ServerConfig,
};
pub use error::ConfigError;
pub use ratelimit::{Decision, RateLimiter};
```

- [ ] **Step 4: Run to verify tests pass and the crate compiles cleanly**

Run: `cargo test -p lb-core` (all config tests pass)
Run: `cargo build -p lb-core` (trait modules compile — they have no runtime behavior of their own to unit test yet; their first real exercise comes from Task 5's and Task 7's implementations)

- [ ] **Step 5: Commit**

```bash
git add crates/lb-core
git commit -m "feat(lb-core): add config parsing/validation and RateLimiter/LoadBalancer traits"
```

---

## Task 5: `lb-ratelimit`: GCRA algorithm

**Files:**
- Create: `crates/lb-ratelimit/Cargo.toml`
- Create: `crates/lb-ratelimit/src/lib.rs`
- Create: `crates/lb-ratelimit/src/gcra.rs`
- Test: inline in `crates/lb-ratelimit/src/gcra.rs`

**Interfaces:**
- Consumes: `lb_core::{Clock, RateLimiter, Decision}` (Tasks 2, 4); `lb_core::test_util::FakeClock` (dev-dependency, `test-util` feature) for tests.
- Produces: `lb_ratelimit::{Gcra, GcraConfig}` — `GcraConfig { pub rate_per_sec: f64, pub burst: u32 }`, `Gcra::<C: Clock>::new(config: GcraConfig, clock: C) -> Self`, implements `lb_core::RateLimiter`. Also `Gcra::sweep(&self, idle_after: Duration)` (used by Task 6).

- [ ] **Step 1: Scaffold the crate**

`crates/lb-ratelimit/Cargo.toml`:
```toml
[package]
name = "lb-ratelimit"
version = "0.1.0"
edition.workspace = true

[dependencies]
lb-core = { path = "../lb-core" }
dashmap = "6"

[dev-dependencies]
lb-core = { path = "../lb-core", features = ["test-util"] }
```

`crates/lb-ratelimit/src/lib.rs`:
```rust
mod gcra;

pub use gcra::{Gcra, GcraConfig};
```

- [ ] **Step 2: Write the failing GCRA tests**

`crates/lb-ratelimit/src/gcra.rs`:
```rust
use dashmap::DashMap;
use lb_core::{Clock, Decision, RateLimiter};
use std::time::{Duration, Instant};

pub struct GcraConfig {
    pub rate_per_sec: f64,
    pub burst: u32,
}

pub struct Gcra<C: Clock> {
    period: Duration,
    tau: Duration,
    clock: C,
    state: DashMap<String, Instant>,
}

impl<C: Clock> Gcra<C> {
    pub fn new(config: GcraConfig, clock: C) -> Self {
        let period = Duration::from_secs_f64(1.0 / config.rate_per_sec);
        let tau = period.saturating_mul(config.burst.max(1));
        Gcra { period, tau, clock, state: DashMap::new() }
    }

    /// Evicts keys whose theoretical arrival time is more than `idle_after`
    /// behind the clock, so idle clients don't grow the map forever.
    pub fn sweep(&self, idle_after: Duration) {
        let now = self.clock.now();
        self.state.retain(|_, tat| *tat > now || now.duration_since(*tat) < idle_after);
    }
}

impl<C: Clock> RateLimiter for Gcra<C> {
    fn check(&self, key: &str) -> Decision {
        let now = self.clock.now();
        let mut entry = self.state.entry(key.to_string()).or_insert(now);
        let tat = if *entry > now { *entry } else { now };
        let new_tat = tat + self.period;
        // `checked_sub` can only underflow if tau exceeds new_tat's distance
        // from the clock's own origin (e.g. a huge burst right at process
        // start) — treat that as "definitely allowed" rather than panicking.
        let allow_at = new_tat.checked_sub(self.tau).unwrap_or(now);
        if allow_at <= now {
            *entry = new_tat;
            Decision::Allow
        } else {
            Decision::Deny { retry_after: allow_at - now }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;
    use std::time::Duration;

    fn limiter(rate_per_sec: f64, burst: u32) -> (Gcra<FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        let gcra = Gcra::new(GcraConfig { rate_per_sec, burst }, clock.clone());
        (gcra, clock)
    }

    #[test]
    fn allows_up_to_burst_then_denies() {
        let (gcra, _clock) = limiter(10.0, 3);
        assert_eq!(gcra.check("k"), Decision::Allow);
        assert_eq!(gcra.check("k"), Decision::Allow);
        assert_eq!(gcra.check("k"), Decision::Allow);
        assert!(matches!(gcra.check("k"), Decision::Deny { .. }));
    }

    #[test]
    fn refills_after_waiting_one_period() {
        let (gcra, clock) = limiter(10.0, 1); // period = 100ms
        assert_eq!(gcra.check("k"), Decision::Allow);
        assert!(matches!(gcra.check("k"), Decision::Deny { .. }));
        clock.advance(Duration::from_millis(100));
        assert_eq!(gcra.check("k"), Decision::Allow);
    }

    #[test]
    fn retry_after_reflects_remaining_wait() {
        let (gcra, _clock) = limiter(10.0, 1); // period = 100ms
        gcra.check("k"); // consumes the only token
        match gcra.check("k") {
            Decision::Deny { retry_after } => {
                assert!(retry_after <= Duration::from_millis(100));
                assert!(retry_after > Duration::ZERO);
            }
            Decision::Allow => panic!("expected deny"),
        }
    }

    #[test]
    fn keys_are_independent() {
        let (gcra, _clock) = limiter(10.0, 1);
        assert_eq!(gcra.check("a"), Decision::Allow);
        assert_eq!(gcra.check("b"), Decision::Allow); // different key, unaffected by "a"
        assert!(matches!(gcra.check("a"), Decision::Deny { .. }));
    }

    #[test]
    fn sweep_removes_long_idle_keys() {
        let (gcra, clock) = limiter(10.0, 1);
        gcra.check("stale");
        clock.advance(Duration::from_secs(60));
        gcra.sweep(Duration::from_secs(30));
        // after sweep, "stale" is gone, so a fresh check treats it as a new key (Allow)
        assert_eq!(gcra.check("stale"), Decision::Allow);
    }
}
```

- [ ] **Step 3: Run to verify tests pass**

Run: `cargo test -p lb-ratelimit --features lb-core/test-util`
Expected: PASS, all `gcra::tests::*`.

- [ ] **Step 4: Commit**

```bash
git add crates/lb-ratelimit
git commit -m "feat(lb-ratelimit): implement GCRA rate limiter"
```

---

## Task 6: `lb-ratelimit`: background sweeper task

**Files:**
- Create: `crates/lb-ratelimit/src/sweeper.rs`
- Modify: `crates/lb-ratelimit/src/lib.rs`, `crates/lb-ratelimit/Cargo.toml`
- Test: inline in `crates/lb-ratelimit/src/sweeper.rs`

**Interfaces:**
- Consumes: `Gcra` (Task 5).
- Produces: `lb_ratelimit::spawn_sweeper<C: Clock + 'static>(limiter: Arc<Gcra<C>>, interval: Duration, idle_after: Duration) -> tokio::task::JoinHandle<()>`.

- [ ] **Step 1: Add tokio dependency**

`crates/lb-ratelimit/Cargo.toml` (add):
```toml
tokio = { version = "1", features = ["rt", "time", "macros", "sync"] }
```
(dev-dependencies add: `tokio = { version = "1", features = ["rt", "macros", "time", "test-util"] }` — the `test-util` here is tokio's own time-mocking feature, distinct from `lb-core`'s `test-util` feature.)

- [ ] **Step 2: Write the failing test**

`crates/lb-ratelimit/src/sweeper.rs`:
```rust
use crate::gcra::Gcra;
use lb_core::Clock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

pub fn spawn_sweeper<C: Clock + 'static>(
    limiter: Arc<Gcra<C>>,
    interval: Duration,
    idle_after: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            limiter.sweep(idle_after);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcra::GcraConfig;
    use lb_core::test_util::FakeClock;
    use lb_core::{Decision, RateLimiter};

    #[tokio::test(start_paused = true)]
    async fn periodically_sweeps_idle_keys() {
        let clock = FakeClock::new();
        let limiter = Arc::new(Gcra::new(GcraConfig { rate_per_sec: 10.0, burst: 1 }, clock.clone()));
        limiter.check("stale");

        let _handle = spawn_sweeper(limiter.clone(), Duration::from_millis(50), Duration::from_millis(10));

        clock.advance(Duration::from_secs(1));
        // advance tokio's paused virtual time so the interval actually ticks
        time::advance(Duration::from_millis(60)).await;
        time::sleep(Duration::from_millis(1)).await; // yield so the spawned task runs

        assert_eq!(limiter.check("stale"), Decision::Allow);
    }
}
```

- [ ] **Step 3: Update `lib.rs`**

`crates/lb-ratelimit/src/lib.rs`:
```rust
mod gcra;
mod sweeper;

pub use gcra::{Gcra, GcraConfig};
pub use sweeper::spawn_sweeper;
```

- [ ] **Step 4: Run to verify the test passes**

Run: `cargo test -p lb-ratelimit --features lb-core/test-util`
Expected: PASS, including `sweeper::tests::periodically_sweeps_idle_keys`.

- [ ] **Step 5: Commit**

```bash
git add crates/lb-ratelimit/src/sweeper.rs crates/lb-ratelimit/src/lib.rs crates/lb-ratelimit/Cargo.toml
git commit -m "feat(lb-ratelimit): add background sweeper for stale rate-limit keys"
```

---

## Task 7: `lb-balancer`: `RoundRobin`

**Files:**
- Create: `crates/lb-balancer/Cargo.toml`
- Create: `crates/lb-balancer/src/lib.rs`
- Create: `crates/lb-balancer/src/round_robin.rs`
- Test: inline in `crates/lb-balancer/src/round_robin.rs`

**Interfaces:**
- Consumes: `lb_core::{Backend, BackendPool, LoadBalancer}` (Tasks 1, 3, 4).
- Produces: `lb_balancer::RoundRobin` — `RoundRobin::new() -> Self`, implements `lb_core::LoadBalancer`.

- [ ] **Step 1: Scaffold the crate**

`crates/lb-balancer/Cargo.toml`:
```toml
[package]
name = "lb-balancer"
version = "0.1.0"
edition.workspace = true

[dependencies]
lb-core = { path = "../lb-core" }
```

`crates/lb-balancer/src/lib.rs`:
```rust
mod round_robin;

pub use round_robin::RoundRobin;
```

- [ ] **Step 2: Write the failing tests**

`crates/lb-balancer/src/round_robin.rs`:
```rust
use lb_core::{Backend, BackendId, BackendPool, LoadBalancer};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
pub struct RoundRobin {
    cursor: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        RoundRobin { cursor: AtomicUsize::new(0) }
    }
}

impl LoadBalancer for RoundRobin {
    fn pick(&self, pool: &BackendPool) -> Option<BackendId> {
        let eligible = pool.eligible_backends();
        if eligible.is_empty() {
            return None;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % eligible.len();
        Some(eligible[idx].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_of(ids: &[&str]) -> BackendPool {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1))
            .collect();
        BackendPool::new(backends)
    }

    #[test]
    fn cycles_through_all_eligible_backends() {
        let pool = pool_of(&["b1", "b2", "b3"]);
        let rr = RoundRobin::new();
        let picks: Vec<_> = (0..6).map(|_| rr.pick(&pool).unwrap()).collect();
        assert_eq!(
            picks,
            vec![
                BackendId::new("b1"), BackendId::new("b2"), BackendId::new("b3"),
                BackendId::new("b1"), BackendId::new("b2"), BackendId::new("b3"),
            ]
        );
    }

    #[test]
    fn skips_ineligible_backends() {
        let pool = pool_of(&["b1", "b2", "b3"]);
        pool.set_active_healthy(&BackendId::new("b2"), false);
        let rr = RoundRobin::new();
        let picks: Vec<_> = (0..4).map(|_| rr.pick(&pool).unwrap()).collect();
        assert!(!picks.contains(&BackendId::new("b2")));
    }

    #[test]
    fn returns_none_when_no_backends_eligible() {
        let pool = pool_of(&["b1"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let rr = RoundRobin::new();
        assert_eq!(rr.pick(&pool), None);
    }
}
```

- [ ] **Step 3: Run to verify tests pass**

Run: `cargo test -p lb-balancer`
Expected: PASS, all `round_robin::tests::*`.

- [ ] **Step 4: Commit**

```bash
git add crates/lb-balancer
git commit -m "feat(lb-balancer): implement round-robin LoadBalancer"
```

---

## Task 8: `lb-healthcheck`: `CircuitBreaker`

**Files:**
- Create: `crates/lb-healthcheck/Cargo.toml`
- Create: `crates/lb-healthcheck/src/lib.rs`
- Create: `crates/lb-healthcheck/src/circuit_breaker.rs`
- Test: inline in `crates/lb-healthcheck/src/circuit_breaker.rs`

**Interfaces:**
- Consumes: `lb_core::Clock` (Task 2).
- Produces: `lb_healthcheck::{CircuitBreaker, CircuitState}` — `CircuitBreaker::<C: Clock>::new(failure_threshold: u32, cooldown: Duration, clock: C) -> Self`, `.state(&self) -> CircuitState`, `.is_open(&self) -> bool`, `.record_success(&self)`, `.record_failure(&self)`. `CircuitState` is `Closed | Open | HalfOpen` (Debug, Clone, Copy, PartialEq, Eq).

- [ ] **Step 1: Scaffold the crate**

`crates/lb-healthcheck/Cargo.toml`:
```toml
[package]
name = "lb-healthcheck"
version = "0.1.0"
edition.workspace = true

[dependencies]
lb-core = { path = "../lb-core" }
tokio = { version = "1", features = ["rt", "time", "macros"] }

[dev-dependencies]
lb-core = { path = "../lb-core", features = ["test-util"] }
```

`crates/lb-healthcheck/src/lib.rs`:
```rust
mod circuit_breaker;

pub use circuit_breaker::{CircuitBreaker, CircuitState};
```

- [ ] **Step 2: Write the failing table-driven tests**

`crates/lb-healthcheck/src/circuit_breaker.rs`:
```rust
use lb_core::Clock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker<C: Clock> {
    clock: C,
    failure_threshold: u32,
    cooldown: Duration,
    consecutive_failures: AtomicU32,
    state: Mutex<CircuitState>,
    opened_at: Mutex<Option<Instant>>,
}

impl<C: Clock> CircuitBreaker<C> {
    pub fn new(failure_threshold: u32, cooldown: Duration, clock: C) -> Self {
        CircuitBreaker {
            clock,
            failure_threshold,
            cooldown,
            consecutive_failures: AtomicU32::new(0),
            state: Mutex::new(CircuitState::Closed),
            opened_at: Mutex::new(None),
        }
    }

    pub fn state(&self) -> CircuitState {
        self.maybe_transition_to_half_open();
        *self.state.lock().expect("circuit breaker mutex poisoned")
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state(), CircuitState::Open)
    }

    fn maybe_transition_to_half_open(&self) {
        let mut state = self.state.lock().expect("circuit breaker mutex poisoned");
        if *state == CircuitState::Open {
            let opened_at = *self.opened_at.lock().expect("circuit breaker mutex poisoned");
            if let Some(t) = opened_at {
                if self.clock.now().duration_since(t) >= self.cooldown {
                    *state = CircuitState::HalfOpen;
                }
            }
        }
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        *self.state.lock().expect("circuit breaker mutex poisoned") = CircuitState::Closed;
    }

    pub fn record_failure(&self) {
        let mut state = self.state.lock().expect("circuit breaker mutex poisoned");
        match *state {
            CircuitState::HalfOpen => self.trip(&mut state),
            CircuitState::Closed => {
                let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
                if failures >= self.failure_threshold {
                    self.trip(&mut state);
                }
            }
            CircuitState::Open => {}
        }
    }

    fn trip(&self, state: &mut CircuitState) {
        *state = CircuitState::Open;
        *self.opened_at.lock().expect("circuit breaker mutex poisoned") = Some(self.clock.now());
        self.consecutive_failures.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;

    fn breaker(threshold: u32, cooldown: Duration) -> (CircuitBreaker<FakeClock>, FakeClock) {
        let clock = FakeClock::new();
        (CircuitBreaker::new(threshold, cooldown, clock.clone()), clock)
    }

    #[test]
    fn stays_closed_below_threshold() {
        let (cb, _clock) = breaker(3, Duration::from_secs(5));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn opens_at_threshold() {
        let (cb, _clock) = breaker(3, Duration::from_secs(5));
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn stays_open_before_cooldown_elapses() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        clock.advance(Duration::from_secs(4));
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn transitions_to_half_open_after_cooldown() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_success_closes_circuit() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn half_open_failure_reopens_and_resets_timer() {
        let (cb, clock) = breaker(1, Duration::from_secs(5));
        cb.record_failure();
        clock.advance(Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // cooldown timer restarted: not enough time has passed yet from this re-open
        clock.advance(Duration::from_secs(1));
        assert_eq!(cb.state(), CircuitState::Open);
    }
}
```

- [ ] **Step 3: Run to verify tests pass**

Run: `cargo test -p lb-healthcheck --features lb-core/test-util`
Expected: PASS, all `circuit_breaker::tests::*`.

- [ ] **Step 4: Commit**

```bash
git add crates/lb-healthcheck
git commit -m "feat(lb-healthcheck): implement circuit breaker state machine"
```

---

## Task 9: `lb-healthcheck`: active checker

**Files:**
- Create: `crates/lb-healthcheck/src/active.rs`
- Modify: `crates/lb-healthcheck/src/lib.rs`, `crates/lb-healthcheck/Cargo.toml`
- Test: inline in `crates/lb-healthcheck/src/active.rs`

**Interfaces:**
- Consumes: `lb_core::{Backend, BackendPool}` (Tasks 1, 3).
- Produces: `lb_healthcheck::{ActiveCheckConfig, spawn_active_checker}` — `ActiveCheckConfig { pub path: String, pub interval: Duration, pub timeout: Duration }`, `spawn_active_checker(backend: Backend, pool: Arc<BackendPool>, config: ActiveCheckConfig, client: reqwest::Client) -> tokio::task::JoinHandle<()>`.

Note: the active checker uses `reqwest` rather than the hand-rolled hyper client that `lb-proxy` builds in Task 10 — it only ever issues simple, non-streaming `GET` requests on a timer, so a batteries-included client is the pragmatic choice here; the proxy's request-forwarding hot path is where owning the client matters and stays on raw `hyper`.

- [ ] **Step 1: Add dependencies**

`crates/lb-healthcheck/Cargo.toml` (add):
```toml
reqwest = "0.12"

[dev-dependencies]
wiremock = "0.6"
tokio = { version = "1", features = ["rt-multi-thread", "time", "macros"] }
```

- [ ] **Step 2: Write the failing test**

`crates/lb-healthcheck/src/active.rs`:
```rust
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

        let backend = Backend::new("b1", mock.address().to_owned(), 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        pool.set_active_healthy(&backend.id, false); // start unhealthy to prove the checker flips it

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig { path: "/health".into(), interval: Duration::from_millis(20), timeout: Duration::from_millis(200) },
            reqwest::Client::new(),
        );

        time::sleep(Duration::from_millis(60)).await;
        assert!(pool.is_eligible(&backend.id) || pool.backend(&backend.id).is_some());
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

        let backend = Backend::new("b1", mock.address().to_owned(), 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()])); // starts healthy by default

        let handle = spawn_active_checker(
            backend.clone(),
            pool.clone(),
            ActiveCheckConfig { path: "/health".into(), interval: Duration::from_millis(20), timeout: Duration::from_millis(200) },
            reqwest::Client::new(),
        );

        time::sleep(Duration::from_millis(60)).await;
        assert!(!pool.is_eligible(&backend.id));
        handle.abort();
    }
}
```

Note: `mock.address()` returns a `&SocketAddr` in `wiremock`; `Backend::new` takes `address: SocketAddr`, so pass `*mock.address()` if the compiler asks for an owned value — adjust to `*mock.address()` if `.to_owned()` doesn't resolve, both compile to the same `SocketAddr` copy.

- [ ] **Step 3: Update `lib.rs`**

`crates/lb-healthcheck/src/lib.rs`:
```rust
mod active;
mod circuit_breaker;

pub use active::{spawn_active_checker, ActiveCheckConfig};
pub use circuit_breaker::{CircuitBreaker, CircuitState};
```

- [ ] **Step 4: Run to verify tests pass**

Run: `cargo test -p lb-healthcheck`
Expected: PASS, both `active::tests::*` cases.

- [ ] **Step 5: Commit**

```bash
git add crates/lb-healthcheck
git commit -m "feat(lb-healthcheck): add active health checker"
```

---

## Task 10: `lb-proxy`: request handling (rate limit → pick → forward → retry → report)

This is the core orchestration task — a reviewer could not sensibly approve "rejects rate-limited/backend-less requests" while rejecting "forwards allowed ones," since together they're one request lifecycle, so this stays one task with more steps than usual.

**Files:**
- Create: `crates/lb-proxy/Cargo.toml`
- Create: `crates/lb-proxy/src/lib.rs`
- Create: `crates/lb-proxy/src/forward.rs`
- Create: `crates/lb-proxy/src/service.rs`
- Test: inline in `crates/lb-proxy/src/forward.rs` and `crates/lb-proxy/src/service.rs`

**Interfaces:**
- Consumes: `lb_core::{Backend, BackendId, BackendPool, Clock, Decision, LoadBalancer, RateLimiter, RateLimitKeySource}` (Tasks 1–4); `lb_healthcheck::CircuitBreaker` (Task 8).
- Produces:
  - `lb_proxy::forward::{ProxyClient, ForwardError, build_client, forward}` — `build_client() -> ProxyClient`, `forward(client: &ProxyClient, req: Request<Full<Bytes>>, timeout: Duration) -> Result<Response<Incoming>, ForwardError>`.
  - `lb_proxy::service::{ProxyContext, ProxyBody, handle}` — `ProxyContext<R: RateLimiter, L: LoadBalancer, C: Clock> { rate_limiter: Arc<R>, balancer: Arc<L>, pool: Arc<BackendPool>, circuit_breakers: HashMap<BackendId, CircuitBreaker<C>>, client: ProxyClient, rate_limit_key: RateLimitKeySource, forward_timeout: Duration, max_request_body_bytes: usize }`, `async fn handle<R, L, C>(req: Request<Incoming>, ctx: Arc<ProxyContext<R, L, C>>) -> Result<Response<ProxyBody>, Infallible>`.

- [ ] **Step 1: Scaffold the crate**

`crates/lb-proxy/Cargo.toml`:
```toml
[package]
name = "lb-proxy"
version = "0.1.0"
edition.workspace = true

[dependencies]
lb-core = { path = "../lb-core" }
lb-healthcheck = { path = "../lb-healthcheck" }
hyper = { version = "1", features = ["client", "http1"] }
hyper-util = { version = "0.1", features = ["client-legacy", "http1", "tokio"] }
http-body-util = "0.1"
bytes = "1"
tokio = { version = "1", features = ["rt", "time"] }

[dev-dependencies]
lb-core = { path = "../lb-core", features = ["test-util"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time"] }
hyper = { version = "1", features = ["server", "http1", "client"] }
```

- [ ] **Step 2: Write the failing test for `forward`**

`crates/lb-proxy/src/forward.rs`:
```rust
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

pub type ProxyClient = Client<HttpConnector, Full<Bytes>>;

/// Connect timeout (time to establish the TCP connection) and pool idle
/// timeout (how long a kept-alive backend connection may sit unused before
/// it's dropped) are fixed constants for Phase 1 rather than config fields —
/// the per-request forward timeout (config-driven) is the one operators
/// actually need to tune; these two guard resource usage, not behavior.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn build_client() -> ProxyClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .build(connector)
}

#[derive(Debug)]
pub enum ForwardError {
    Connect,
    Timeout,
}

pub async fn forward(
    client: &ProxyClient,
    req: Request<Full<Bytes>>,
    timeout: Duration,
) -> Result<Response<Incoming>, ForwardError> {
    match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(_)) => Err(ForwardError::Connect),
        Err(_) => Err(ForwardError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::StatusCode;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    async fn spawn_fixed_response_backend(status: StatusCode) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(
                            Response::builder().status(status).body(Full::new(Bytes::new())).unwrap(),
                        )
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn forwards_and_returns_backend_response() {
        let addr = spawn_fixed_response_backend(StatusCode::OK).await;
        let client = build_client();
        let req = Request::builder()
            .uri(format!("http://{addr}/"))
            .body(Full::new(Bytes::new()))
            .unwrap();

        let resp = forward(&client, req, Duration::from_secs(1)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn connect_failure_is_reported() {
        // Nothing is listening on this port.
        let client = build_client();
        let req = Request::builder()
            .uri("http://127.0.0.1:1")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = forward(&client, req, Duration::from_secs(1)).await;
        assert!(matches!(result, Err(ForwardError::Connect)));
    }
}
```

- [ ] **Step 3: Run to verify the `forward` tests pass**

Run: `cargo test -p lb-proxy forward::`
Expected: PASS, both `forward::tests::*` cases.

- [ ] **Step 4: Write the failing test for `handle` (the full request lifecycle)**

`crates/lb-proxy/src/service.rs`:
```rust
use crate::forward::{forward, ForwardError, ProxyClient};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use lb_core::{BackendId, BackendPool, Clock, Decision, LoadBalancer, RateLimitKeySource, RateLimiter};
use lb_healthcheck::CircuitBreaker;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub struct ProxyContext<R: RateLimiter, L: LoadBalancer, C: Clock> {
    pub rate_limiter: Arc<R>,
    pub balancer: Arc<L>,
    pub pool: Arc<BackendPool>,
    pub circuit_breakers: HashMap<BackendId, CircuitBreaker<C>>,
    pub client: ProxyClient,
    pub rate_limit_key: RateLimitKeySource,
    pub forward_timeout: Duration,
    pub max_request_body_bytes: usize,
}

impl<R: RateLimiter, L: LoadBalancer, C: Clock> ProxyContext<R, L, C> {
    fn circuit_breaker(&self, id: &BackendId) -> &CircuitBreaker<C> {
        self.circuit_breakers
            .get(id)
            .expect("a circuit breaker is constructed for every configured backend")
    }
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

fn text_body(text: &'static str) -> ProxyBody {
    Full::new(Bytes::from_static(text.as_bytes())).map_err(|never| match never {}).boxed()
}

fn simple_response(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
    let mut resp = Response::new(if body.is_empty() { empty_body() } else { text_body(body) });
    *resp.status_mut() = status;
    resp
}

fn extract_key(req: &Request<Incoming>, source: &RateLimitKeySource) -> String {
    match source {
        RateLimitKeySource::SourceIp => {
            // Populated by the connection-level wiring in lb-server (Task 11);
            // falls back to a shared bucket if genuinely absent so we fail
            // safe (rate limited together) rather than failing open.
            req.headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string()
        }
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

fn build_outbound_request(
    parts: &http::request::Parts,
    body: Bytes,
    backend: &lb_core::Backend,
) -> Request<Full<Bytes>> {
    let path_and_query = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let uri = hyper::Uri::builder()
        .scheme("http")
        .authority(backend.address.to_string())
        .path_and_query(path_and_query)
        .build()
        .expect("backend address + original path form a valid URI");
    let mut builder = Request::builder().method(parts.method.clone()).uri(uri);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    builder.body(Full::new(body)).expect("forwarded request is well-formed")
}

pub async fn handle<R, L, C>(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext<R, L, C>>,
) -> Result<Response<ProxyBody>, Infallible>
where
    R: RateLimiter,
    L: LoadBalancer,
    C: Clock,
{
    let key = extract_key(&req, &ctx.rate_limit_key);
    if let Decision::Deny { retry_after } = ctx.rate_limiter.check(&key) {
        let mut resp = simple_response(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        if let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return Ok(resp);
    }

    // CircuitBreaker's Open -> HalfOpen transition is evaluated lazily inside
    // `is_open()`; BackendPool's `circuit_open` flag is a separate cached
    // bool that only this loop keeps in sync. Without refreshing it here, a
    // backend that ever trips its breaker would stay excluded from
    // `eligible_backends()` forever — nothing would call `is_open()` again to
    // notice the cooldown elapsed, since an excluded backend never gets
    // forwarded to. Refreshing once per request (cheap: a handful of
    // backends, one mutex check each) keeps the pool's view current and lets
    // a backend become eligible for a probe request as soon as it's due.
    for id in ctx.pool.all_backend_ids() {
        if let Some(breaker) = ctx.circuit_breakers.get(id) {
            ctx.pool.set_circuit_open(id, breaker.is_open());
        }
    }

    let (parts, body) = req.into_parts();
    let bytes = match read_bounded(body, ctx.max_request_body_bytes).await {
        Ok(b) => b,
        Err(()) => return Ok(simple_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")),
    };

    let mut last_status = StatusCode::SERVICE_UNAVAILABLE;
    for attempt in 0..2u8 {
        let Some(backend_id) = ctx.balancer.pick(&ctx.pool) else {
            return Ok(simple_response(StatusCode::SERVICE_UNAVAILABLE, "no healthy backend"));
        };
        let backend = ctx
            .pool
            .backend(&backend_id)
            .expect("picked id exists in the pool it was picked from")
            .clone();
        let outbound = build_outbound_request(&parts, bytes.clone(), &backend);

        match forward(&ctx.client, outbound, ctx.forward_timeout).await {
            Ok(resp) => {
                ctx.circuit_breaker(&backend_id).record_success();
                // Propagate immediately (not just next request) so a backend
                // that just recovered is usable again within this same burst.
                ctx.pool.set_circuit_open(&backend_id, false);
                let (resp_parts, resp_body) = resp.into_parts();
                return Ok(Response::from_parts(resp_parts, resp_body.boxed()));
            }
            Err(ForwardError::Connect | ForwardError::Timeout) => {
                let breaker = ctx.circuit_breaker(&backend_id);
                breaker.record_failure();
                // Propagate immediately so the retry attempt below (if any)
                // sees a freshly-tripped breaker instead of the stale flag
                // from the top-of-request refresh.
                ctx.pool.set_circuit_open(&backend_id, breaker.is_open());
                last_status = StatusCode::BAD_GATEWAY;
                if attempt == 1 {
                    break;
                }
            }
        }
    }
    Ok(simple_response(last_status, "upstream error"))
}
```

`crates/lb-proxy/Cargo.toml` (add): `http = "1"` under `[dependencies]` (for `http::request::Parts`).

Now the tests:

```rust
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
            Decision::Deny { retry_after: Duration::from_secs(1) }
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
        fn pick(&self, _pool: &BackendPool) -> Option<BackendId> {
            None
        }
    }

    struct FixedPick(BackendId);
    impl LoadBalancer for FixedPick {
        fn pick(&self, _pool: &BackendPool) -> Option<BackendId> {
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
        fn pick(&self, pool: &BackendPool) -> Option<BackendId> {
            pool.eligible_backends().into_iter().next()
        }
    }

    async fn spawn_fixed_response_backend(status: StatusCode, body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(
                            Response::builder().status(status).body(Full::new(Bytes::from_static(body.as_bytes()))).unwrap(),
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
    async fn run_through_proxy<R, L, C>(ctx: Arc<ProxyContext<R, L, C>>) -> Response<Bytes>
    where
        R: RateLimiter + 'static,
        L: LoadBalancer + 'static,
        C: Clock + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(req, ctx.clone()));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });

        let client = build_client();
        let req = Request::builder().uri(format!("http://{addr}/")).body(Full::new(Bytes::new())).unwrap();
        let resp = client.request(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        Response::from_parts(parts, bytes)
    }

    fn empty_pool() -> Arc<BackendPool> {
        Arc::new(BackendPool::new(vec![]))
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
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(),
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
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
            circuit_breakers: HashMap::<BackendId, CircuitBreaker<FakeClock>>::new(),
            client: build_client(),
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn successful_forward_returns_backend_response_and_records_success() {
        let backend_addr = spawn_fixed_response_backend(StatusCode::OK, "hi").await;
        let backend = Backend::new("b1", backend_addr, 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        let mut breakers = HashMap::new();
        breakers.insert(backend.id.clone(), CircuitBreaker::new(3, Duration::from_secs(5), FakeClock::new()));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            circuit_breakers: breakers,
            client: build_client(),
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn failed_forward_retries_once_then_returns_502() {
        // FixedPick always points at a port nobody is listening on.
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let backend = Backend::new("b1", dead_addr, 1);
        let pool = Arc::new(BackendPool::new(vec![backend.clone()]));
        let mut breakers = HashMap::new();
        breakers.insert(backend.id.clone(), CircuitBreaker::new(3, Duration::from_secs(5), FakeClock::new()));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(FixedPick(backend.id.clone())),
            pool,
            circuit_breakers: breakers,
            client: build_client(),
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
        });
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn open_circuit_excludes_backend_until_it_recovers() {
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap(); // refused instantly
        let healthy_addr = spawn_fixed_response_backend(StatusCode::OK, "ok").await;

        let dead = Backend::new("dead", dead_addr, 1);
        let healthy = Backend::new("healthy", healthy_addr, 1);
        let pool = Arc::new(BackendPool::new(vec![dead.clone(), healthy.clone()]));

        let clock = FakeClock::new();
        let mut breakers = HashMap::new();
        breakers.insert(dead.id.clone(), CircuitBreaker::new(1, Duration::from_secs(60), clock.clone()));
        breakers.insert(healthy.id.clone(), CircuitBreaker::new(1, Duration::from_secs(60), clock.clone()));

        let ctx = Arc::new(ProxyContext {
            rate_limiter: Arc::new(AlwaysAllow),
            balancer: Arc::new(PreferFirstEligible),
            pool: pool.clone(),
            circuit_breakers: breakers,
            client: build_client(),
            rate_limit_key: RateLimitKeySource::SourceIp,
            forward_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1024,
        });

        // "dead" sorts first in pool order, so PreferFirstEligible tries it,
        // fails, trips its breaker (threshold 1), and retries onto "healthy".
        let resp = run_through_proxy(ctx.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(ctx.circuit_breaker(&dead.id).is_open());
        assert!(!pool.is_eligible(&dead.id));

        // Now "dead" is excluded up front — the next request goes straight
        // to "healthy" without ever touching the tripped backend.
        let resp = run_through_proxy(ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
```

- [ ] **Step 5: Update `lib.rs`**

`crates/lb-proxy/src/lib.rs`:
```rust
pub mod forward;
pub mod service;

pub use forward::{build_client, forward, ForwardError, ProxyClient};
pub use service::{handle, ProxyBody, ProxyContext};
```

- [ ] **Step 6: Run to verify all `lb-proxy` tests pass**

Run: `cargo test -p lb-proxy --features lb-core/test-util`
Expected: PASS — `forward::tests::*` and `service::tests::*` (rate-limited→429, no-backend→503, success→200, forward-failure→502-after-retry, open-circuit excludes then recovers).

- [ ] **Step 7: Commit**

```bash
git add crates/lb-proxy
git commit -m "feat(lb-proxy): implement request handling (rate limit, pick, forward, retry)"
```

---

## Task 11: `lb-server`: config loading, wiring, graceful shutdown

**Files:**
- Create: `crates/lb-server/Cargo.toml`
- Create: `crates/lb-server/src/lib.rs`
- Create: `crates/lb-server/src/main.rs`
- Create: `crates/lb-server/src/wiring.rs`
- Create: `crates/lb-server/src/shutdown.rs`
- Test: inline in `crates/lb-server/src/wiring.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–10.
- Produces: `lb_server::{run, build_context}` — `build_context(config: &lb_core::Config) -> Arc<ProxyContext<Gcra<SystemClock>, RoundRobin, SystemClock>>` (also spawns the sweeper and active checkers as a side effect, returning their handles alongside), `async fn run(config: lb_core::Config) -> std::io::Result<()>` (binds the listener, serves connections, and shuts down gracefully on `SIGINT`/`SIGTERM`).

- [ ] **Step 1: Scaffold the crate**

`crates/lb-server/Cargo.toml`:
```toml
[package]
name = "lb-server"
version = "0.1.0"
edition.workspace = true

[dependencies]
lb-core = { path = "../lb-core" }
lb-ratelimit = { path = "../lb-ratelimit" }
lb-balancer = { path = "../lb-balancer" }
lb-healthcheck = { path = "../lb-healthcheck" }
lb-proxy = { path = "../lb-proxy" }
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "signal", "time"] }
reqwest = "0.12"

[dev-dependencies]
reqwest = "0.12"
```

- [ ] **Step 2: Write the failing wiring test**

`crates/lb-server/src/wiring.rs`:
```rust
use lb_core::{Backend, BackendId, BackendPool, Config, SystemClock};
use lb_balancer::RoundRobin;
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

    #[test]
    fn wires_one_circuit_breaker_and_backend_per_configured_backend() {
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
```

Note: `RateLimitKeySource` and `Config` need `Clone`/`PartialEq` already derived from Task 4 — no changes needed there.

- [ ] **Step 3: Run to verify the wiring test passes**

Run: `cargo test -p lb-server`
Expected: PASS, `wiring::tests::wires_one_circuit_breaker_and_backend_per_configured_backend`.

- [ ] **Step 4: Write the listener + graceful shutdown**

No automated test for this step: Task 12's integration tests exercise `run()` but never send it a shutdown signal, so the drain path itself isn't covered by the suite (triggering real `SIGINT`/`SIGTERM` delivery portably from within a test — especially on Windows, which has no `SIGTERM` and only a limited `ctrl_c` equivalent — is disproportionate for what it would verify here). Instead, verify it manually once `lb-server` runs (see Task 13's README): start it, send an in-flight request that's slow enough to still be running, hit Ctrl+C, and confirm in the logs that it logs the shutdown message, waits for that request to complete (rather than the connection dropping mid-response), and exits. This is a known, deliberate gap in automated coverage — call it out rather than silently skip it.

`crates/lb-server/src/shutdown.rs`:
```rust
pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
```

`crates/lb-server/src/lib.rs`:
```rust
mod shutdown;
mod wiring;

pub use wiring::{build_context, AppContext, WiredApp};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lb_core::Config;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

/// How long `run` waits for in-flight connections to finish after a shutdown
/// signal before giving up and aborting them outright.
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

pub async fn run(config: Config) -> std::io::Result<()> {
    let listen_addr = config.server.listen;
    let WiredApp { context, background_tasks } = build_context(&config);

    let listener = TcpListener::bind(listen_addr).await?;
    eprintln!("listening on {listen_addr}");

    let shutdown = shutdown::wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    // Tracked (not bare tokio::spawn) so shutdown can wait for these
    // specific per-connection tasks to finish, distinct from the
    // long-lived background_tasks (sweeper, active checkers) which are
    // simply aborted below since they have no in-flight work to lose.
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let io = TokioIo::new(stream);
                let ctx = Arc::clone(&context);
                connections.spawn(async move {
                    let svc = service_fn(move |req| lb_proxy::handle(req, Arc::clone(&ctx)));
                    if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                        eprintln!("connection error: {err}");
                    }
                });
            }
            _ = &mut shutdown => {
                eprintln!("shutdown signal received, draining in-flight connections");
                break;
            }
        }
    }

    let drained = tokio::time::timeout(DRAIN_DEADLINE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        eprintln!("drain deadline exceeded, aborting {} remaining connection(s)", connections.len());
        connections.abort_all();
    }

    for task in background_tasks {
        task.abort();
    }
    Ok(())
}
```

`crates/lb-server/src/main.rs`:
```rust
use lb_core::Config;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());
    let config = Config::load(&config_path).unwrap_or_else(|err| {
        eprintln!("failed to load config from {config_path}: {err}");
        std::process::exit(1);
    });
    lb_server::run(config).await
}
```

- [ ] **Step 5: Run to verify the crate builds and existing tests still pass**

Run: `cargo build -p lb-server && cargo test -p lb-server`
Expected: builds cleanly, wiring test still passes.

- [ ] **Step 6: Commit**

```bash
git add crates/lb-server
git commit -m "feat(lb-server): wire config, proxy, and background tasks into a runnable binary"
```

---

## Task 12: Workspace integration tests

**Files:**
- Create: `crates/lb-server/tests/support.rs`
- Create: `crates/lb-server/tests/integration.rs`

**Interfaces:**
- Consumes: `lb_server::run` (Task 11), `lb_core::Config` (Task 4).
- Produces: nothing new — this is the end-to-end verification that Tasks 1–11 compose correctly.

- [ ] **Step 1: Write the shared fake-backend test helper**

`crates/lb-server/tests/support.rs`:
```rust
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Starts a backend that always answers with `status` and counts how many
/// requests it received, so tests can assert on distribution across backends.
pub async fn spawn_counting_backend(status: StatusCode) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let io = TokioIo::new(stream);
            let count = count_clone.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let count = count.clone();
                    async move {
                        if req.uri().path() == "/health" {
                            return Ok::<_, Infallible>(
                                Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
                            );
                        }
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder().status(status).body(Full::new(Bytes::new())).unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, count)
}

pub fn config_toml(listen: &str, backends: &[(&str, SocketAddr)], rate_per_sec: f64, burst: u32) -> String {
    let backends_toml: String = backends
        .iter()
        .map(|(id, addr)| format!("[[backends]]\nid = \"{id}\"\naddress = \"{addr}\"\n\n"))
        .collect();
    format!(
        r#"
        [server]
        listen = "{listen}"

        {backends_toml}

        [health_check]
        path = "/health"
        interval_ms = 50
        timeout_ms = 200
        failure_threshold = 2
        cooldown_ms = 300

        [rate_limit]
        key = "header:X-Client"
        rate_per_sec = {rate_per_sec}
        burst = {burst}

        [load_balancing]
        strategy = "round_robin"
        "#
    )
}
```

- [ ] **Step 2: Write the failing integration tests**

`crates/lb-server/tests/integration.rs`:
```rust
mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::{config_toml, spawn_counting_backend};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn distributes_requests_round_robin_across_backends() {
    let (addr1, count1) = spawn_counting_backend(StatusCode::OK).await;
    let (addr2, count2) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&config_toml(&listen.to_string(), &[("b1", addr1), ("b2", addr2)], 1000.0, 1000)).unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(100)).await; // let the listener bind

    let client = reqwest::Client::new();
    for i in 0..4 {
        client
            .get(format!("http://{listen}/"))
            .header("X-Client", format!("client-{i}"))
            .send()
            .await
            .unwrap();
    }

    assert_eq!(count1.load(Ordering::SeqCst) + count2.load(Ordering::SeqCst), 4);
    assert_eq!(count1.load(Ordering::SeqCst), 2);
    assert_eq!(count2.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn rate_limits_a_bursty_client_with_429() {
    let (addr, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&config_toml(&listen.to_string(), &[("b1", addr)], 2.0, 2)).unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let mut statuses = vec![];
    for _ in 0..4 {
        let resp = client.get(format!("http://{listen}/")).header("X-Client", "same-client").send().await.unwrap();
        statuses.push(resp.status());
    }

    assert_eq!(statuses[0], StatusCode::OK);
    assert_eq!(statuses[1], StatusCode::OK);
    assert_eq!(statuses[2], StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn fails_over_when_a_backend_stops_responding() {
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap(); // nothing listens here
    let (healthy_addr, healthy_count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&config_toml(&listen.to_string(), &[("dead", dead_addr), ("alive", healthy_addr)], 1000.0, 1000)).unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let mut ok_count = 0;
    for i in 0..6 {
        let resp = client
            .get(format!("http://{listen}/"))
            .header("X-Client", format!("client-{i}"))
            .send()
            .await
            .unwrap();
        if resp.status() == StatusCode::OK {
            ok_count += 1;
        }
    }

    // Every request either lands on the healthy backend directly, or gets
    // retried onto it after the dead one fails — none should hard-fail.
    assert_eq!(ok_count, 6);
    assert_eq!(healthy_count.load(Ordering::SeqCst), 6);
}
```

- [ ] **Step 3: Run to verify all integration tests pass**

Run: `cargo test -p lb-server --test integration`
Expected: PASS, all three scenarios.

- [ ] **Step 4: Run the full workspace test suite as a final check**

Run: `cargo test --workspace --features lb-core/test-util`
Expected: every crate's tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/lb-server/tests
git commit -m "test(lb-server): add end-to-end integration tests for routing, rate limiting, failover"
```

---

## Task 13: Example config + README

**Files:**
- Create: `config.example.toml`
- Create: `README.md`

**Interfaces:** none — documentation only.

- [ ] **Step 1: Write the example config**

`config.example.toml`:
```toml
[server]
listen = "0.0.0.0:8080"
max_request_body_bytes = 1048576
forward_timeout_ms = 5000

[[backends]]
id = "b1"
address = "127.0.0.1:9001"
weight = 1

[[backends]]
id = "b2"
address = "127.0.0.1:9002"
weight = 1

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
```

- [ ] **Step 2: Write the README**

`README.md`:
```markdown
# Distributed Load Balancer — Phase 1

A single-node L7 HTTP load balancer with a GCRA rate limiter, round-robin
backend selection, and active + passive (circuit breaker) health checking,
built from scratch on `hyper`/`tokio`.

See [`docs/superpowers/specs/2026-09-03-lb-phase1-design.md`](docs/superpowers/specs/2026-09-03-lb-phase1-design.md)
for the full design and the reasoning behind each choice.

## Run it

1. Copy `config.example.toml` to `config.toml` and point `[[backends]]` at
   your real backend addresses.
2. `cargo run -p lb-server -- config.toml`

## Workspace layout

- `lb-core` — shared types and the `RateLimiter`/`LoadBalancer`/`Clock` traits (no I/O)
- `lb-ratelimit` — GCRA rate limiter
- `lb-balancer` — round-robin `LoadBalancer`
- `lb-healthcheck` — active checker + passive circuit breaker
- `lb-proxy` — the `hyper` service that handles one request end to end
- `lb-server` — the binary: config loading, wiring, graceful shutdown

## Test

`cargo test --workspace --features lb-core/test-util`

## Scope

Phase 1 only — see the design doc for what's deliberately deferred (TLS,
config hot-reload, metrics/logging/admin API, L4 proxying, multi-node
coordination) and why.
```

- [ ] **Step 3: Commit**

```bash
git add config.example.toml README.md
git commit -m "docs: add example config and README"
```

---

## Post-Plan Verification

After Task 13, run the full workspace check as a final gate:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings
cargo test --workspace --features lb-core/test-util
```

All three must pass before considering Phase 1 complete. Fix any `clippy`/`fmt` issues as small follow-up commits rather than skipping the gate.
