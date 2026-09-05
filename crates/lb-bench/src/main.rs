//! Hot-path micro-benchmarks.
//!
//! These target exactly the four costs identified in the Phase 4 assessment,
//! so Phase 7 can prove its optimisations rather than assert them:
//!
//! 1. `BackendPool::eligible_backends()` — allocates a `Vec` and clones every
//!    `BackendId` (each holding a `String`) on every backend selection.
//! 2. `Gcra::check()` — `key.to_string()` allocation per call.
//! 3. `ListenerCoordinator::try_admit()` — `format!()` allocation per call.
//! 4. The circuit-breaker refresh loop — two mutex acquisitions per backend
//!    per request, contended across worker threads in production.
//!
//! Deliberately hand-rolled rather than using `criterion`: this has to build
//! and run on the development machine, and criterion's dependency tree does
//! not currently do so. The trade is statistical rigour (no outlier analysis
//! or confidence intervals) for numbers we can actually obtain. Treat the
//! output as relative, for regression detection — not as absolute capacity.

mod tls;

use lb_balancer::RoundRobin;
use lb_cluster::{ClusterNode, ListenerCoordinator};
use lb_core::{Backend, BackendPool, ClusterCoordinator, LoadBalancer, RateLimiter, SystemClock};
use lb_healthcheck::{CircuitBreaker, CircuitState};
use lb_ratelimit::{Gcra, GcraConfig};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ITERATIONS: u64 = 200_000;

pub fn bench<F: FnMut()>(name: &str, iterations: u64, mut f: F) {
    // Warm up so the first-touch costs (page faults, branch predictor,
    // lazily-allocated map buckets) are not attributed to the measurement.
    for _ in 0..(iterations / 10).max(1) {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();

    let ns_per_op = elapsed.as_nanos() as f64 / iterations as f64;
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    println!("  {name:<46} {ns_per_op:>9.1} ns/op   {ops_per_sec:>12.0} ops/s");
}

fn pool_of(n: usize) -> BackendPool {
    let backends = (0..n)
        .map(|i| {
            Backend::new(
                format!("backend-{i}"),
                format!("127.0.0.1:{}", 9000 + i).parse().unwrap(),
                1,
                None,
            )
        })
        .collect();
    BackendPool::new(backends)
}

fn breakers_for(pool: &BackendPool) -> HashMap<lb_core::BackendId, CircuitBreaker<SystemClock>> {
    pool.all_backend_ids()
        .iter()
        .map(|id| {
            (
                id.clone(),
                CircuitBreaker::new(3, Duration::from_secs(5), SystemClock),
            )
        })
        .collect()
}

fn bench_eligible_backends() {
    println!("\nBackendPool::eligible_backends()  [allocates Vec + clones every BackendId]");
    for n in [1usize, 5, 20] {
        let pool = pool_of(n);
        bench(&format!("{n} backend(s)"), ITERATIONS, || {
            black_box(pool.eligible_backends());
        });
    }
}

fn bench_round_robin_pick() {
    println!("\nRoundRobin::pick()  [eligible_backends() plus cursor arithmetic]");
    for n in [1usize, 5, 20] {
        let pool = pool_of(n);
        let rr = RoundRobin::new();
        bench(&format!("{n} backend(s)"), ITERATIONS, || {
            black_box(rr.pick(&pool));
        });
    }
}

fn bench_gcra_check() {
    println!("\nGcra::check()  [key.to_string() allocation per call]");
    // A high rate so the limiter admits throughout and we measure the
    // allow path, which is the one every real request takes.
    let gcra = Gcra::new(
        GcraConfig {
            rate_per_sec: 1e9,
            burst: 1_000_000,
            // Unbounded here so the benchmark measures GCRA itself rather
            // than the cardinality cap.
            max_tracked_keys: usize::MAX,
        },
        SystemClock,
    );
    bench("single key", ITERATIONS, || {
        black_box(gcra.check("192.168.1.100"));
    });
}

fn bench_cluster_try_admit() {
    println!("\nListenerCoordinator::try_admit()  [format!() allocation per call]");
    let node = Arc::new(ClusterNode::new(
        "bench-node",
        10,
        SystemClock,
        b"bench-secret".to_vec(),
    ));
    let coord = ListenerCoordinator::new(node, "web", u64::MAX);
    bench("single key", ITERATIONS, || {
        black_box(coord.try_admit("192.168.1.100"));
    });
}

fn bench_circuit_refresh() {
    println!("\nCircuit-breaker refresh loop  [2 mutex acquisitions per backend]");
    for n in [1usize, 5, 20] {
        let pool = pool_of(n);
        let breakers = breakers_for(&pool);
        bench(&format!("{n} backend(s)"), ITERATIONS, || {
            // Exactly what lb-proxy::handle does on every request.
            for id in pool.all_backend_ids() {
                if let Some(breaker) = breakers.get(id) {
                    let state = breaker.state();
                    pool.set_circuit_open(id, state == CircuitState::Open);
                }
            }
        });
    }
}

fn main() {
    println!("lb-bench — hot-path micro-benchmarks");
    println!("{}", "=".repeat(78));
    println!(
        "iterations per measurement: {ITERATIONS}\n\
         NOTE: relative figures for regression detection, not absolute capacity."
    );

    bench_eligible_backends();
    bench_round_robin_pick();
    bench_gcra_check();
    bench_cluster_try_admit();
    bench_circuit_refresh();
    tls::bench_tls_handshakes();

    println!("\n{}", "=".repeat(78));
    println!("Phase 7 should reduce ns/op on every line above.");
}
