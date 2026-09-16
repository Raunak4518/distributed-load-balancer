use lb_cluster::{
    convergence_over_admission_bound, spawn_peer_listener, spawn_sync_loop, ClusterNode,
    ListenerCoordinator,
};
use lb_core::{Clock, ClusterCoordinator, SystemClock};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;
use tokio::task::JoinHandle;

const NAMESPACE: &str = "bench";
const KEY: &str = "shared-key";
const WINDOW_SECS: u64 = 30;
const CONFIGURED_LIMIT: u64 = 100;
const RATE_PER_SEC: f64 = 20.0;
const BURST_DURATION: Duration = Duration::from_millis(2_500);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const SECRET: &[u8] = b"lb-bench-cluster-secret";

const NODE_COUNTS: &[usize] = &[3, 5, 10];
const GOSSIP_INTERVALS_MS: &[u64] = &[100, 500, 1_000, 5_000];

struct RelayHandle {
    addr: SocketAddr,
    attempted: Arc<AtomicU64>,
    successful: Arc<AtomicU64>,
    partitioned: Arc<AtomicBool>,
}

async fn spawn_relay(target: SocketAddr) -> (RelayHandle, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let attempted = Arc::new(AtomicU64::new(0));
    let successful = Arc::new(AtomicU64::new(0));
    let partitioned = Arc::new(AtomicBool::new(false));
    let attempted_task = Arc::clone(&attempted);
    let successful_task = Arc::clone(&successful);
    let partitioned_task = Arc::clone(&partitioned);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                continue;
            };
            attempted_task.fetch_add(1, Ordering::Relaxed);
            if partitioned_task.load(Ordering::Relaxed) {
                continue;
            }
            let successful_task = Arc::clone(&successful_task);
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(target).await {
                    if tokio::io::copy(&mut inbound, &mut outbound).await.is_ok() {
                        let _ = outbound.shutdown().await;
                        successful_task.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    (
        RelayHandle {
            addr,
            attempted,
            successful,
            partitioned,
        },
        task,
    )
}

struct ClusterSetup {
    nodes: Vec<Arc<ClusterNode<SystemClock>>>,
    relays: HashMap<(usize, usize), RelayHandle>,
    tasks: Vec<JoinHandle<()>>,
}

async fn setup_cluster(n: usize, interval: Duration) -> ClusterSetup {
    let mut nodes = Vec::with_capacity(n);
    let mut listener_addrs = Vec::with_capacity(n);
    let mut tasks = Vec::new();
    for i in 0..n {
        let node = Arc::new(ClusterNode::new(
            format!("node-{i}"),
            WINDOW_SECS,
            SystemClock,
            SECRET.to_vec(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener_addrs.push(listener.local_addr().unwrap());
        tasks.push(spawn_peer_listener(Arc::clone(&node), listener, None));
        nodes.push(node);
    }

    let mut relays = HashMap::new();
    for i in 0..n {
        for (j, &target) in listener_addrs.iter().enumerate() {
            if i == j {
                continue;
            }
            let (relay, task) = spawn_relay(target).await;
            tasks.push(task);
            relays.insert((i, j), relay);
        }
    }

    for i in 0..n {
        let peers: Vec<SocketAddr> = (0..n)
            .filter(|&j| j != i)
            .map(|j| relays[&(i, j)].addr)
            .collect();
        tasks.push(spawn_sync_loop(
            Arc::clone(&nodes[i]),
            peers,
            interval,
            CONNECT_TIMEOUT,
            None,
        ));
    }

    ClusterSetup {
        nodes,
        relays,
        tasks,
    }
}

async fn run_synchronized_burst(
    nodes: &[Arc<ClusterNode<SystemClock>>],
    duration: Duration,
) -> Vec<u64> {
    let n = nodes.len();
    let barrier = Arc::new(Barrier::new(n));
    let successes: Vec<Arc<AtomicU64>> = (0..n).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let node = Arc::clone(&nodes[i]);
        let barrier = Arc::clone(&barrier);
        let succ = Arc::clone(&successes[i]);
        handles.push(tokio::spawn(async move {
            let coord = ListenerCoordinator::new(node, NAMESPACE, CONFIGURED_LIMIT);
            barrier.wait().await;
            let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / RATE_PER_SEC));
            let deadline = Instant::now() + duration;
            while Instant::now() < deadline {
                ticker.tick().await;
                if coord.try_admit(KEY) {
                    succ.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    successes
        .iter()
        .map(|s| s.load(Ordering::Relaxed))
        .collect()
}

async fn wait_for_convergence(
    nodes: &[Arc<ClusterNode<SystemClock>>],
    namespaced_key: &str,
    target: u64,
    timeout: Duration,
) -> Option<Duration> {
    let start = Instant::now();
    let deadline = start + timeout;
    loop {
        let now_secs = SystemClock.unix_secs();
        if nodes
            .iter()
            .all(|node| node.store().total_in_window(namespaced_key, now_secs) == target)
        {
            return Some(start.elapsed());
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn settle_timeout_for(interval: Duration) -> Duration {
    (interval * 6).clamp(Duration::from_secs(2), Duration::from_secs(20))
}

#[cfg(windows)]
fn process_mem_mb(pid: u32) -> Option<f64> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p) {{ Write-Output \"$($p.WorkingSet64)\" }}"
            ),
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?;
    let bytes: f64 = line.trim().parse().ok()?;
    Some(bytes / (1024.0 * 1024.0))
}

#[cfg(not(windows))]
fn process_mem_mb(_pid: u32) -> Option<f64> {
    None
}

struct ComboResult {
    n: usize,
    interval_ms: u64,
    true_total: u64,
    configured_limit: u64,
    predicted_bound: u64,
    within_bound: bool,
    converged: bool,
    convergence_ms: Option<f64>,
    messages_successful: u64,
    messages_attempted: u64,
    mem_mb: Option<f64>,
}

async fn run_combo(n: usize, interval_ms: u64) -> ComboResult {
    let interval = Duration::from_millis(interval_ms);
    let setup = setup_cluster(n, interval).await;

    let per_node = run_synchronized_burst(&setup.nodes, BURST_DURATION).await;
    let true_total: u64 = per_node.iter().sum();

    let namespaced_key = format!("{NAMESPACE}\u{1}{KEY}");
    let settle = settle_timeout_for(interval);
    let convergence = wait_for_convergence(&setup.nodes, &namespaced_key, true_total, settle).await;
    let converged = convergence.is_some();
    let convergence_ms = convergence.map(|d| d.as_secs_f64() * 1000.0);

    let messages_successful: u64 = setup
        .relays
        .values()
        .map(|r| r.successful.load(Ordering::Relaxed))
        .sum();
    let messages_attempted: u64 = setup
        .relays
        .values()
        .map(|r| r.attempted.load(Ordering::Relaxed))
        .sum();

    let bound = convergence_over_admission_bound(RATE_PER_SEC, interval_ms, n - 1);
    let predicted_bound = CONFIGURED_LIMIT + bound;
    let within_bound = true_total <= predicted_bound;

    let mem_mb = process_mem_mb(std::process::id());

    for task in setup.tasks {
        task.abort();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    ComboResult {
        n,
        interval_ms,
        true_total,
        configured_limit: CONFIGURED_LIMIT,
        predicted_bound,
        within_bound,
        converged,
        convergence_ms,
        messages_successful,
        messages_attempted,
        mem_mb,
    }
}

fn print_combo_header() {
    println!(
        "{:>4} | {:>7} | {:>8} | {:>8} | {:>12} | {:>7} | {:>9} | {:>9} | {:>10} | {:>8}",
        "N",
        "gossip",
        "actual",
        "limit",
        "limit+bound",
        "in-bnd",
        "converge",
        "msgs-ok",
        "msgs-tot",
        "mem-MB"
    );
}

fn print_combo_row(r: &ComboResult) {
    let conv_str = match r.convergence_ms {
        Some(ms) => format!("{ms:.0}ms"),
        None => "TIMEOUT".to_string(),
    };
    let mem_str = r
        .mem_mb
        .map(|m| format!("{m:.0}"))
        .unwrap_or_else(|| "n/a".to_string());
    println!(
        "{:>4} | {:>7} | {:>8} | {:>8} | {:>12} | {:>7} | {:>9} | {:>9} | {:>10} | {:>8}",
        r.n,
        format!("{}ms", r.interval_ms),
        r.true_total,
        r.configured_limit,
        r.predicted_bound,
        if r.within_bound { "YES" } else { "NO" },
        conv_str,
        r.messages_successful,
        r.messages_attempted,
        mem_str,
    );
    if !r.within_bound {
        println!(
            "  !!! EMPIRICAL OVERSHOOT ({}) EXCEEDED THE PREDICTED BOUND ({}) for N={} interval={}ms !!!",
            r.true_total, r.predicted_bound, r.n, r.interval_ms
        );
    }
    if !r.converged {
        println!(
            "  note: did not fully converge within the settle timeout for N={} interval={}ms (actual above is the true total; some node's local view may still lag)",
            r.n, r.interval_ms
        );
    }
}

async fn run_partition_scenario() {
    println!("=== Partition-and-restore scenario (N=5, gossip=500ms) ===");
    let n = 5;
    let interval = Duration::from_millis(500);
    let setup = setup_cluster(n, interval).await;
    let group_a: Vec<usize> = vec![0, 1];
    let group_b: Vec<usize> = vec![2, 3, 4];
    let namespaced_key = format!("{NAMESPACE}\u{1}{KEY}");

    println!("  phase 1: partitioning group A=node-{{0,1}} from group B=node-{{2,3,4}} before any traffic (fresh cluster, nothing to lose)");
    for &i in &group_a {
        for &j in &group_b {
            setup.relays[&(i, j)]
                .partitioned
                .store(true, Ordering::Relaxed);
            setup.relays[&(j, i)]
                .partitioned
                .store(true, Ordering::Relaxed);
        }
    }

    println!("  phase 2: each side independently bursts against the shared key while split");
    let burst = run_synchronized_burst(&setup.nodes, Duration::from_millis(3_000)).await;
    tokio::time::sleep(interval * 3).await;

    let now_secs = SystemClock.unix_secs();
    let a_view: Vec<u64> = group_a
        .iter()
        .map(|&i| {
            setup.nodes[i]
                .store()
                .total_in_window(&namespaced_key, now_secs)
        })
        .collect();
    let b_view: Vec<u64> = group_b
        .iter()
        .map(|&i| {
            setup.nodes[i]
                .store()
                .total_in_window(&namespaced_key, now_secs)
        })
        .collect();
    let true_total: u64 = burst.iter().sum();
    let a_admitted: u64 = group_a.iter().map(|&i| burst[i]).sum();
    let b_admitted: u64 = group_b.iter().map(|&i| burst[i]).sum();

    let (cross_attempted, cross_successful) = setup
        .relays
        .iter()
        .filter(|((i, j), _)| {
            (group_a.contains(i) && group_b.contains(j))
                || (group_b.contains(i) && group_a.contains(j))
        })
        .fold((0u64, 0u64), |(att, succ), (_, r)| {
            (
                att + r.attempted.load(Ordering::Relaxed),
                succ + r.successful.load(Ordering::Relaxed),
            )
        });

    println!(
        "    per-node admits during partition = {burst:?} (group A admitted {a_admitted}, group B admitted {b_admitted}; every node kept admitting locally, none blocked or hung)"
    );
    println!(
        "    during partition: group A local views = {a_view:?}, group B local views = {b_view:?} (each group internally consistent, but the two disagree -- neither can see the other)"
    );
    println!(
        "    cross-group gossip while partitioned: {cross_successful}/{cross_attempted} delivered (0 expected: the relay is dropping every cross-group push)"
    );
    if a_admitted > 0 && b_admitted > 0 && a_admitted + b_admitted > CONFIGURED_LIMIT {
        println!(
            "    combined admitted ({}) exceeds the nominal cluster-wide limit ({CONFIGURED_LIMIT}) -- expected and correct: a genuine partition means neither side can learn of the other's admissions, so the shared budget cannot be enforced in real time during the split (the bound this harness validates elsewhere assumes a live, if lagging, gossip channel -- a full partition is outside that model by design)",
            a_admitted + b_admitted
        );
    }

    println!("  phase 3: restoring connectivity");
    for &i in &group_a {
        for &j in &group_b {
            setup.relays[&(i, j)]
                .partitioned
                .store(false, Ordering::Relaxed);
            setup.relays[&(j, i)]
                .partitioned
                .store(false, Ordering::Relaxed);
        }
    }
    let restore_timeout = settle_timeout_for(interval) * 2;
    let restore_convergence =
        wait_for_convergence(&setup.nodes, &namespaced_key, true_total, restore_timeout).await;

    let messages_successful: u64 = setup
        .relays
        .values()
        .map(|r| r.successful.load(Ordering::Relaxed))
        .sum();
    let messages_attempted: u64 = setup
        .relays
        .values()
        .map(|r| r.attempted.load(Ordering::Relaxed))
        .sum();

    match restore_convergence {
        Some(d) => println!(
            "    post-restore: converged in {:.0}ms, final true total = {true_total}, messages ok/attempted = {messages_successful}/{messages_attempted}",
            d.as_secs_f64() * 1000.0
        ),
        None => println!(
            "    !!! did not fully converge within {restore_timeout:?} after restoring connectivity (target total = {true_total}) !!!"
        ),
    }
    if restore_convergence.is_some() {
        println!("    every node's local view now equals the true total -- CRDT max-merge correctly reconciled the partition, no lost or double-counted admits");
    }

    for task in setup.tasks {
        task.abort();
    }
    println!();
}

fn print_methodology() {
    println!(
        "lb-bench-cluster -- empirical validation of the cluster rate-limit convergence bound"
    );
    println!();
    println!("Methodology:");
    println!("  Every node is a real ClusterNode driven over real tokio::net::TcpListener sockets via spawn_peer_listener and spawn_sync_loop, run in-process as separate tokio tasks (not separate OS processes).");
    println!("  Every node peers with every other node (full mesh), matching ClusterConfig.peers.");
    println!("  Gossip traffic is routed through a small per-directed-pair TCP relay this harness owns, so every gossip push can be counted (and, for the partition scenario, dropped) without any change to lb-cluster's production code.");
    println!(
        "  Scenario: at t=0 every node's local view of the shared key is fresh. All N nodes simultaneously start a paced admission burst against one shared rate-limit key ({NAMESPACE}/{KEY}), each attempting {RATE_PER_SEC} req/s against a single cluster-wide limit of {CONFIGURED_LIMIT}, for {}ms.",
        BURST_DURATION.as_millis()
    );
    println!("  After the burst, the harness polls every node's local CounterStore until all of them agree with the true total (the harness's own ground-truth count of every locally-successful admit), or a settle timeout elapses.");
    println!("  actual = the true converged total admitted across the whole cluster for that key.");
    println!("  limit+bound = configured_limit + convergence_over_admission_bound(rate_per_sec, sync_interval_ms, N-1), the theoretical worst case.");
    println!("  Caveat: loopback-only, in-process (all N nodes and the relays share one process's CPU and memory), debug or release build as invoked, single physical machine -- treat as this machine's numbers, not a general capacity claim.");
    println!();
}

#[tokio::main]
async fn main() {
    print_methodology();
    println!("=== Convergence matrix: N nodes x gossip interval ===");
    print_combo_header();
    let mut any_violation = false;
    for &n in NODE_COUNTS {
        for &interval_ms in GOSSIP_INTERVALS_MS {
            let result = run_combo(n, interval_ms).await;
            if !result.within_bound {
                any_violation = true;
            }
            print_combo_row(&result);
        }
    }
    println!();
    if any_violation {
        println!("!!! at least one combination's empirical over-admission EXCEEDED the documented convergence bound -- see flagged rows above !!!");
    } else {
        println!("every combination's empirical over-admission stayed within convergence_over_admission_bound.");
    }
    println!();

    run_partition_scenario().await;
}
