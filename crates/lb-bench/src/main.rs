//! Hot-path micro-benchmarks.
//!
//! These target exactly the four costs identified in the Phase 4 assessment,
//! so Phase 7 can prove its optimisations rather than assert them:
//!
//! 1. `BackendPool::eligible_backends()` — allocates a `Vec` and clones every
//!    `BackendId` (each holding a `String`) on every backend selection.
//! 2. `Gcra::check()` — `key.to_string()` allocation per call.
//! 3. `ListenerCoordinator::try_admit()` — `format!()` allocation per call.
//! 4. The circuit-breaker refresh loop — several atomic loads per backend
//!    per request. Used to be two mutex acquisitions per backend until
//!    Phase 7 target 1 replaced them (see `docs/BASELINE.md`); this harness
//!    is single-threaded and uncontended, so it cannot show that win --
//!    only a concurrent benchmark or production traffic can.
//!
//! Deliberately hand-rolled rather than using `criterion`: this has to build
//! and run on the development machine, and criterion's dependency tree does
//! not currently do so. The trade is statistical rigour (no outlier analysis
//! or confidence intervals) for numbers we can actually obtain. Treat the
//! output as relative, for regression detection — not as absolute capacity.

mod tls;

use lb_balancer::{ConsistentHash, LeastConnections, PeakEwmaP2c, RoundRobin, WeightedRoundRobin};
use lb_cluster::protocol::{encode, KeyEntry, SyncMessage};
use lb_cluster::{ClusterNode, CounterStore, ListenerCoordinator};
use lb_core::{
    Backend, BackendId, BackendPool, Clock, ClusterCoordinator, LoadBalancer, RateLimiter,
    SystemClock,
};
use lb_healthcheck::{CircuitBreaker, CircuitState};
use lb_ratelimit::{Gcra, GcraConfig};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const ITERATIONS: u64 = 200_000;
const COUNTER_STORE_KEY_COUNTS: [usize; 4] = [100, 1_000, 10_000, 100_000];
const COUNTER_STORE_WINDOW_SECS: u64 = 30;
const COUNTER_STORE_SECRET: &[u8] = b"lb-bench-counter-store-secret";

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
                CircuitBreaker::new(
                    3,
                    Duration::from_secs(5),
                    1,
                    1.0,
                    Duration::from_secs(1_000_000_000),
                    Duration::from_secs(60),
                    None,
                    None,
                    SystemClock,
                ),
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
            black_box(rr.pick(&pool, ""));
        });
    }
}

fn bench_consistent_hash_pick() {
    println!("\nConsistentHash::pick()  [cached ring: no hash/sort/rebuild once warm]");
    for n in [10usize, 100, 1000] {
        let pool = pool_of(n);
        let ch = ConsistentHash::new();
        bench(&format!("{n} backend(s)"), ITERATIONS, || {
            black_box(ch.pick(&pool, "client-key"));
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
    println!("\nCircuit-breaker refresh loop  [atomic loads per backend, no mutex]");
    for n in [1usize, 5, 20] {
        let pool = pool_of(n);
        let breakers = breakers_for(&pool);
        bench(&format!("{n} backend(s)"), ITERATIONS, || {
            // Exactly what lb-proxy::handle does on every request.
            for id in &pool.all_backend_ids() {
                if let Some(breaker) = breakers.get(id) {
                    let state = breaker.state();
                    pool.set_circuit_open(id, state == CircuitState::Open);
                }
            }
        });
    }
}

const POOL_SIZES: [usize; 6] = [1, 5, 20, 100, 500, 1000];
const CONTENTION_DURATION: Duration = Duration::from_millis(2_500);
const CONTENTION_PICKER_THREADS: usize = 4;
const CONTENTION_SAMPLE_STRIDE: u64 = 64;

fn iterations_for(n: usize) -> u64 {
    match n {
        0..=20 => ITERATIONS,
        21..=100 => 100_000,
        101..=500 => 20_000,
        _ => 5_000,
    }
}

fn backend_list(n: usize) -> Vec<Backend> {
    (0..n)
        .map(|i| {
            Backend::new(
                format!("backend-{i}"),
                format!("127.0.0.1:{}", 9000 + i).parse().unwrap(),
                1,
                None,
            )
        })
        .collect()
}

fn bench_pick_at_scale(strategy_name: &str, lb: &dyn LoadBalancer) {
    println!("\n{strategy_name}::pick()  [backend-pool scaling, item 4]");
    for n in POOL_SIZES {
        let pool = pool_of(n);
        let iterations = iterations_for(n);
        bench(&format!("{n} backend(s)"), iterations, || {
            black_box(lb.pick(&pool, "client-key"));
        });
    }
}

fn bench_apply_resolved_at_scale() {
    println!(
        "\nBackendPool::apply_resolved()  [membership/weight update: rebuild + one ArcSwap::store]"
    );
    for n in POOL_SIZES {
        let pool = pool_of(n);
        let backends = backend_list(n);
        let iterations = iterations_for(n);
        bench(&format!("{n} backend(s)"), iterations, || {
            pool.apply_resolved(backends.clone());
        });
    }
}

fn print_memory_estimate() {
    println!("\nPer-backend memory estimate  [rough floor via std::mem::size_of on public types]");

    let backend_bytes = std::mem::size_of::<Backend>();
    let backend_id_bytes = std::mem::size_of::<BackendId>();
    let atomic_bool_bytes = std::mem::size_of::<AtomicBool>();
    let atomic_usize_bytes = std::mem::size_of::<std::sync::atomic::AtomicUsize>();
    let thin_arc_ptr_bytes = std::mem::size_of::<Arc<u8>>();
    let arc_refcount_header_bytes = 2 * std::mem::size_of::<usize>();

    let backend_state_fields_bytes = backend_bytes + 4 * atomic_bool_bytes + atomic_usize_bytes;
    let backend_state_heap_alloc_bytes = arc_refcount_header_bytes + backend_state_fields_bytes;
    let pool_state_inline_bytes = 2 * backend_id_bytes + thin_arc_ptr_bytes;
    let per_backend_floor_bytes = backend_state_heap_alloc_bytes + pool_state_inline_bytes;

    println!("  size_of::<Backend>()                        {backend_bytes:>6} bytes");
    println!("  size_of::<BackendId>() (Arc<str> fat ptr)   {backend_id_bytes:>6} bytes");
    println!(
        "  4x AtomicBool + 1x AtomicUsize              {:>6} bytes",
        4 * atomic_bool_bytes + atomic_usize_bytes
    );
    println!("  BackendState fields (Backend + flags)       {backend_state_fields_bytes:>6} bytes");
    println!(
        "  + Arc<BackendState> refcount header (est.)  {backend_state_heap_alloc_bytes:>6} bytes  (one heap allocation)"
    );
    println!(
        "  order Vec entry + states map key+value      {pool_state_inline_bytes:>6} bytes  (inline in PoolState)"
    );
    println!("  {}", "-".repeat(58));
    println!("  rough floor per backend                     {per_backend_floor_bytes:>6} bytes");
    println!(
        "  at 1000 backends: ~{:.1} KiB (rough floor only)",
        per_backend_floor_bytes as f64 * 1000.0 / 1024.0
    );
    println!("  NOT counted here, and why an exact number isn't reliable on this platform:");
    println!("    - the id/server_name string bytes themselves (heap-allocated separately)");
    println!("    - the system allocator's own per-allocation bookkeeping overhead");
    println!("    - HashMap's real bucket/control-byte layout and load-factor slack");
    println!("    - Vec/HashMap growth over-allocation (capacity commonly exceeds len)");
    println!("    - ConsistentHash's separately cached ring (Vec<(u64, BackendId)>,");
    println!("      10 virtual nodes per unit of weight, rebuilt on membership change)");
}

fn counter_store_bench_iterations(n: usize) -> u64 {
    match n {
        0..=100 => 2_000,
        101..=1_000 => 500,
        1_001..=10_000 => 100,
        _ => 20,
    }
}

fn build_counter_store(n: usize, now: u64) -> CounterStore {
    let store = CounterStore::new(COUNTER_STORE_WINDOW_SECS);
    for i in 0..n {
        store.try_admit(&format!("scale-key-{i}"), "self", now, u64::MAX);
    }
    store
}

fn bench_counter_store_at_scale() {
    println!(
        "\nCounterStore at scale (backlog item 33): snapshot_own() and merge(), {COUNTER_STORE_KEY_COUNTS:?} tracked keys"
    );
    for n in COUNTER_STORE_KEY_COUNTS {
        let now = SystemClock.unix_secs();
        let store = build_counter_store(n, now);
        let iterations = counter_store_bench_iterations(n);

        let snap = store.snapshot_own("self", now);
        let entry_count = snap.len();
        let bucket_entry_count: usize = snap.iter().map(|(_, buckets)| buckets.len()).sum();
        let msg = SyncMessage {
            node_id: "self".to_string(),
            entries: snap
                .iter()
                .map(|(key, buckets)| KeyEntry {
                    key: key.clone(),
                    buckets: buckets.clone(),
                })
                .collect(),
        };
        let encoded = encode(&msg, COUNTER_STORE_SECRET).unwrap();

        println!(
            "\n  {n:>7} tracked keys: snapshot entries={entry_count:>5}   bucket-entries={bucket_entry_count:>5}   encoded bytes={:>7}",
            encoded.len()
        );

        bench(
            &format!("snapshot_own() @ {n} tracked keys"),
            iterations,
            || {
                black_box(store.snapshot_own("self", now));
            },
        );

        bench(
            &format!("merge() one snapshot @ {n} tracked keys ({entry_count} entries)"),
            iterations,
            || {
                let receiver = CounterStore::new(COUNTER_STORE_WINDOW_SECS);
                for (key, buckets) in &snap {
                    receiver.merge(key, "peer", buckets, now);
                }
                black_box(&receiver);
            },
        );
    }
}

fn print_counter_store_memory_estimate() {
    println!(
        "\nCounterStore per-key memory estimate  [component arithmetic on counters.rs's KeyCounts {{ per_node: HashMap<String, HashMap<u64, u64>> }} fields]"
    );

    let string_bytes = std::mem::size_of::<String>();
    let key_counts_bytes = std::mem::size_of::<HashMap<String, HashMap<u64, u64>>>();
    let per_node_bucket_map_bytes = std::mem::size_of::<HashMap<u64, u64>>();
    let bucket_entry_bytes = std::mem::size_of::<(u64, u64)>();

    let per_tracked_key_floor_bytes = string_bytes + key_counts_bytes;
    let per_key_node_pair_floor_bytes = string_bytes + per_node_bucket_map_bytes;
    let per_bucket_cell_floor_bytes = bucket_entry_bytes;

    println!("  size_of::<String>() (DashMap key / node-id key)          {string_bytes:>6} bytes");
    println!(
        "  size_of::<HashMap<String, HashMap<u64,u64>>>() (KeyCounts) {key_counts_bytes:>6} bytes"
    );
    println!("  size_of::<HashMap<u64, u64>>() (per-node bucket map)     {per_node_bucket_map_bytes:>6} bytes");
    println!(
        "  size_of::<(u64, u64)>() (one bucket cell)                 {bucket_entry_bytes:>6} bytes"
    );
    println!("  {}", "-".repeat(58));
    println!("  per tracked key (DashMap slot + KeyCounts)               {per_tracked_key_floor_bytes:>6} bytes");
    println!("  + per (key, node) pair (node-id key + bucket map header) {per_key_node_pair_floor_bytes:>6} bytes");
    println!("  + per (key, node, epoch-second) bucket cell               {per_bucket_cell_floor_bytes:>6} bytes");
    println!();
    for n in COUNTER_STORE_KEY_COUNTS {
        let floor_bytes = n
            * (per_tracked_key_floor_bytes
                + per_key_node_pair_floor_bytes
                + per_bucket_cell_floor_bytes);
        println!(
            "  at {n:>7} keys, 1 node, 1 bucket each: ~{:.1} KiB rough floor",
            floor_bytes as f64 / 1024.0
        );
    }
    println!(
        "  at 100000 keys is also MAX_TRACKED_KEYS, the hard cap this store enforces at merge()"
    );
    println!("  NOT counted here, and why an exact number isn't reliable on this platform:");
    println!("    - the key string bytes themselves and node-id string bytes (heap-allocated separately per String)");
    println!("    - the system allocator's own per-allocation bookkeeping overhead");
    println!(
        "    - HashMap's real bucket/control-byte layout and load-factor slack (both the outer per_node map and each inner epoch-bucket map)"
    );
    println!(
        "    - DashMap's own shard count, per-shard RwLock<HashMap<...>>, and hashing overhead"
    );
}

fn run_contention_case(strategy_name: &str, lb: Arc<dyn LoadBalancer>, n: usize) {
    let pool = Arc::new(pool_of(n));
    let stop = Arc::new(AtomicBool::new(false));
    let max_latency_nanos = Arc::new(AtomicU64::new(0));
    let total_calls = Arc::new(AtomicU64::new(0));

    let updater = {
        let pool = Arc::clone(&pool);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(1));
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                pool.apply_resolved(backend_list(n));
            }
        })
    };

    let start = Instant::now();
    let handles: Vec<_> = (0..CONTENTION_PICKER_THREADS)
        .map(|t| {
            let pool = Arc::clone(&pool);
            let lb = Arc::clone(&lb);
            let stop = Arc::clone(&stop);
            let max_latency_nanos = Arc::clone(&max_latency_nanos);
            let total_calls = Arc::clone(&total_calls);
            thread::spawn(move || {
                let key = format!("client-{t}");
                let mut samples: Vec<u64> = Vec::new();
                let mut calls: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let call_start = Instant::now();
                    black_box(lb.pick(&pool, &key));
                    let elapsed_nanos = call_start.elapsed().as_nanos() as u64;
                    max_latency_nanos.fetch_max(elapsed_nanos, Ordering::Relaxed);
                    if calls.is_multiple_of(CONTENTION_SAMPLE_STRIDE) {
                        samples.push(elapsed_nanos);
                    }
                    calls += 1;
                }
                total_calls.fetch_add(calls, Ordering::Relaxed);
                samples
            })
        })
        .collect();

    thread::sleep(CONTENTION_DURATION);
    stop.store(true, Ordering::Relaxed);

    let mut all_samples: Vec<u64> = Vec::new();
    for h in handles {
        all_samples.extend(h.join().unwrap());
    }
    updater.join().unwrap();

    let elapsed_secs = start.elapsed().as_secs_f64();
    all_samples.sort_unstable();
    let sample_count = all_samples.len();
    let p50 = all_samples[sample_count / 2];
    let p99 = all_samples[(sample_count * 99 / 100).min(sample_count - 1)];
    let max = max_latency_nanos.load(Ordering::Relaxed);
    let calls = total_calls.load(Ordering::Relaxed);
    let ops_per_sec = calls as f64 / elapsed_secs;

    println!(
        "  {strategy_name:<16} {n:>5} backend(s)   p50 {p50:>8} ns   p99 {p99:>9} ns   max {max:>10} ns   {ops_per_sec:>12.0} ops/s"
    );
}

fn bench_pick_under_concurrent_apply_resolved() {
    println!(
        "\npick() latency while apply_resolved() runs concurrently, once per second [DNS-poll cadence]"
    );
    println!(
        "  {CONTENTION_PICKER_THREADS} picker threads hammering pick() for {:.1}s; p50/p99 from a 1-in-{CONTENTION_SAMPLE_STRIDE} sampled\n  subset, max is the true max across every call (atomic fetch_max, unsampled)",
        CONTENTION_DURATION.as_secs_f64()
    );
    for n in POOL_SIZES {
        run_contention_case("RoundRobin", Arc::new(RoundRobin::new()), n);
        run_contention_case("ConsistentHash", Arc::new(ConsistentHash::new()), n);
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
    bench_consistent_hash_pick();
    bench_gcra_check();
    bench_cluster_try_admit();
    bench_circuit_refresh();
    tls::bench_tls_handshakes();

    println!("\n{}", "=".repeat(78));
    println!("Phase 7 should reduce ns/op on every line above.");

    println!("\n{}", "=".repeat(78));
    println!(
        "Backend-pool scaling characteristics (backlog item 4): pick(), apply_resolved(),\n\
         memory, and pick()-under-concurrent-apply_resolved(), across 1/5/20/100/500/1000 backends."
    );

    bench_pick_at_scale("RoundRobin", &RoundRobin::new());
    bench_pick_at_scale("LeastConnections", &LeastConnections::new());
    bench_pick_at_scale("WeightedRoundRobin", &WeightedRoundRobin::new());
    bench_pick_at_scale("ConsistentHash", &ConsistentHash::new());
    bench_pick_at_scale("PeakEwmaP2c", &PeakEwmaP2c::new(SystemClock));
    bench_apply_resolved_at_scale();
    print_memory_estimate();
    bench_pick_under_concurrent_apply_resolved();

    println!("\n{}", "=".repeat(78));
    println!(
        "CounterStore scaling characteristics (backlog item 33): snapshot_own()/merge() cost,\n\
         snapshot size, and per-key memory, across {COUNTER_STORE_KEY_COUNTS:?} tracked keys."
    );
    bench_counter_store_at_scale();
    print_counter_store_memory_estimate();
}
