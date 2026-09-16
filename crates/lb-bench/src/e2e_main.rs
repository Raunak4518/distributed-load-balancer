use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

type ProxyClient = Client<HttpConnector, Full<Bytes>>;

const STRATEGIES: &[&str] = &[
    "round_robin",
    "least_connections",
    "weighted_round_robin",
    "consistent_hash",
    "peak_ewma_p2c",
];

enum Cli {
    Run { strategy: &'static str },
    CompareAll,
    Heterogeneous,
    Help,
}

fn parse_args(args: &[String]) -> Cli {
    match args {
        [] => Cli::Run {
            strategy: STRATEGIES[0],
        },
        [flag] if flag == "--compare-all-strategies" => Cli::CompareAll,
        [flag] if flag == "--heterogeneous" => Cli::Heterogeneous,
        [flag] if flag == "--help" || flag == "-h" => Cli::Help,
        [flag, name] if flag == "--strategy" => {
            match STRATEGIES.iter().copied().find(|s| *s == name.as_str()) {
                Some(strategy) => Cli::Run { strategy },
                None => Cli::Help,
            }
        }
        _ => Cli::Help,
    }
}

fn print_help() {
    println!("lb-bench-e2e");
    println!();
    println!("USAGE:");
    println!("    lb-bench-e2e");
    println!("    lb-bench-e2e --strategy <STRATEGY>");
    println!("    lb-bench-e2e --compare-all-strategies");
    println!("    lb-bench-e2e --heterogeneous");
    println!("    lb-bench-e2e --help");
    println!();
    println!("STRATEGY one of: {}", STRATEGIES.join(", "));
    println!("    [default: {}]", STRATEGIES[0]);
}

fn build_client() -> ProxyClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
}

struct SpawnedBackend {
    addr: SocketAddr,
    count: Arc<AtomicU64>,
    delay_ms: Arc<AtomicU64>,
    handle: tokio::task::JoinHandle<()>,
}

async fn spawn_backend(initial_delay_ms: u64) -> SpawnedBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicU64::new(0));
    let delay_ms = Arc::new(AtomicU64::new(initial_delay_ms));
    let count_for_task = Arc::clone(&count);
    let delay_for_task = Arc::clone(&delay_ms);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let _ = stream.set_nodelay(true);
            let io = TokioIo::new(stream);
            let count = Arc::clone(&count_for_task);
            let delay_ms = Arc::clone(&delay_for_task);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let count = Arc::clone(&count);
                    let delay_ms = Arc::clone(&delay_ms);
                    async move {
                        if req.uri().path() == "/health" {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        let delay = delay_ms.load(Ordering::Relaxed);
                        if delay > 0 {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                        }
                        count.fetch_add(1, Ordering::Relaxed);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"ok")))
                                .unwrap(),
                        )
                    }
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    SpawnedBackend {
        addr,
        count,
        delay_ms,
        handle,
    }
}

fn lb_server_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    let name = if cfg!(windows) {
        "lb-server.exe"
    } else {
        "lb-server"
    };
    path.push(name);
    if !path.exists() {
        eprintln!(
            "{} not found -- build it first: cargo build -p lb-server (or --release, matching how lb-bench-e2e itself was built)",
            path.display()
        );
        std::process::exit(1);
    }
    path
}

fn write_config(path: &Path, listen: SocketAddr, backends: &[SocketAddr], strategy: &str) {
    let backends_toml: String = backends
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            format!("  [[listeners.backends]]\n  id = \"b{i}\"\n  address = \"{addr}\"\n\n")
        })
        .collect();
    let toml = format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
max_connections = 1000000
max_connections_per_ip = 1000000

{backends_toml}
  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 1000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000000
  burst = 10000000

  [listeners.load_balancing]
  strategy = "{strategy}"
"#
    );
    std::fs::write(path, toml).expect("write config");
}

async fn spawn_lb_server(config_path: &Path) -> Child {
    Command::new(lb_server_path())
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn lb-server")
}

async fn wait_until_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing listening on {addr} after 10s");
}

struct RunResult {
    total: u64,
    errors: u64,
    latencies_ns: Vec<u64>,
    wall: Duration,
}

async fn run_closed_loop(
    client: &ProxyClient,
    target: SocketAddr,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
    live: bool,
) -> RunResult {
    let start = Instant::now();
    let warmup_over_at = start + warmup;
    let stop_at = warmup_over_at + duration;
    let total = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let latencies: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let uri: hyper::Uri = format!("http://{target}/").parse().unwrap();

    let reporter = if live {
        let total = Arc::clone(&total);
        let errors = Arc::clone(&errors);
        Some(tokio::spawn(async move {
            let mut last_total = 0u64;
            let mut last_errors = 0u64;
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                let now = Instant::now();
                if now >= stop_at {
                    break;
                }
                let t = total.load(Ordering::Relaxed);
                let e = errors.load(Ordering::Relaxed);
                println!(
                    "      t={:>5.1}s  {:>8} req/s  {:>6} errors/s",
                    now.duration_since(start).as_secs_f64(),
                    t - last_total,
                    e - last_errors
                );
                last_total = t;
                last_errors = e;
            }
        }))
    } else {
        None
    };

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let total = Arc::clone(&total);
        let errors = Arc::clone(&errors);
        let latencies = Arc::clone(&latencies);
        let uri = uri.clone();
        handles.push(tokio::spawn(async move {
            let mut local_lat = Vec::new();
            while Instant::now() < stop_at {
                let req_started = Instant::now();
                let req = Request::builder()
                    .uri(uri.clone())
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let ok = match client.request(req).await {
                    Ok(resp) => {
                        let (parts, body) = resp.into_parts();
                        body.collect().await.is_ok() && parts.status.is_success()
                    }
                    Err(_) => false,
                };
                let elapsed = req_started.elapsed();
                if req_started >= warmup_over_at {
                    total.fetch_add(1, Ordering::Relaxed);
                    if !ok {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                    local_lat.push(elapsed.as_nanos() as u64);
                }
            }
            latencies.lock().unwrap().extend(local_lat);
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    if let Some(r) = reporter {
        r.abort();
    }

    let wall = Instant::now().duration_since(warmup_over_at);
    RunResult {
        total: total.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        latencies_ns: Arc::try_unwrap(latencies).unwrap().into_inner().unwrap(),
        wall,
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx]
}

fn ms(ns: u64) -> f64 {
    ns as f64 / 1_000_000.0
}

fn print_row(concurrency: usize, result: &RunResult, cpu_cores: Option<f64>, mem_mb: Option<f64>) {
    let mut sorted = result.latencies_ns.clone();
    sorted.sort_unstable();
    let rps = result.total as f64 / result.wall.as_secs_f64();
    let err_pct = if result.total > 0 {
        100.0 * result.errors as f64 / result.total as f64
    } else {
        0.0
    };
    let cpu_str = cpu_cores
        .map(|c| format!("{c:.2}"))
        .unwrap_or_else(|| "n/a".to_string());
    let mem_str = mem_mb
        .map(|m| format!("{m:.0}"))
        .unwrap_or_else(|| "n/a".to_string());
    println!(
        "{:>6} | {:>10.0} | {:>8} | {:>7.2}% | {:>8.2} | {:>8.2} | {:>8.2} | {:>8.2} | {:>8} | {:>8}",
        concurrency,
        rps,
        result.total,
        err_pct,
        ms(percentile(&sorted, 0.50)),
        ms(percentile(&sorted, 0.95)),
        ms(percentile(&sorted, 0.99)),
        ms(percentile(&sorted, 0.999)),
        cpu_str,
        mem_str,
    );
}

#[cfg(windows)]
fn sample_process(pid: u32) -> Option<(f64, f64)> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p) {{ Write-Output \"$($p.CPU),$($p.WorkingSet64)\" }}"
            ),
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?;
    let mut parts = line.trim().split(',');
    let cpu_secs: f64 = parts.next()?.trim().parse().ok()?;
    let mem_bytes: f64 = parts.next()?.trim().parse().ok()?;
    Some((cpu_secs, mem_bytes / (1024.0 * 1024.0)))
}

#[cfg(not(windows))]
fn sample_process(_pid: u32) -> Option<(f64, f64)> {
    None
}

fn print_methodology() {
    println!("Methodology / environment (recorded so this is reproducible, not just a number):");
    println!("  Host: AMD Ryzen 7 7435HS, 8 physical / 16 logical cores, 16 GiB RAM");
    println!("  OS: Windows 11 Home Single Language, build 26200");
    println!(
        "  Toolchain: {} / {}",
        rustc_version(),
        std::env::var("CARGO_PKG_VERSION").unwrap_or_default()
    );
    println!("  lb-server: real, separate OS process, driven over real loopback TCP sockets");
    println!("  Backends: in-process hyper HTTP/1.1 servers answering a fixed 2-byte body");
    println!("  Load generator: closed-loop, N persistent HTTP/1.1 connections via one pooled hyper_util client, 2s warmup discarded per run");
    println!("  Caveat: loopback-only (no real network latency/loss), debug or release build as invoked, single physical machine also running the load generator itself -- treat as this machine's numbers, not a general capacity claim.");
    println!();
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn throughput_matrix(client: &ProxyClient, target: SocketAddr, child_pid: Option<u32>) {
    println!("=== Throughput / latency across concurrency levels ===");
    println!(
        "{:>6} | {:>10} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8}",
        "conc", "req/s", "total", "err%", "p50ms", "p95ms", "p99ms", "p999ms", "cpu-s", "mem-MB"
    );
    for concurrency in [1usize, 8, 32, 128, 256] {
        let before = child_pid.and_then(sample_process);
        let result = run_closed_loop(
            client,
            target,
            concurrency,
            Duration::from_secs(5),
            Duration::from_secs(2),
            false,
        )
        .await;
        let after = child_pid.and_then(sample_process);
        let cpu_cores = match (before, after) {
            (Some((cpu0, _)), Some((cpu1, _))) => Some((cpu1 - cpu0) / result.wall.as_secs_f64()),
            _ => None,
        };
        let mem_mb = after.map(|(_, mem)| mem);
        print_row(concurrency, &result, cpu_cores, mem_mb);
    }
    println!();
}

async fn failure_scenario(
    client: &ProxyClient,
    target: SocketAddr,
    backend_handles: Vec<tokio::task::JoinHandle<()>>,
) {
    println!("=== Failure scenario: kill one of four backends mid-run (concurrency=64, 16s) ===");
    let concurrency = 64;
    let duration = Duration::from_secs(16);
    let kill_after = Duration::from_secs(5);

    let run = run_closed_loop(
        client,
        target,
        concurrency,
        duration,
        Duration::from_secs(0),
        true,
    );
    let kill = async {
        tokio::time::sleep(kill_after).await;
        println!("      -- killing backend[0] now (simulated crash: listener dropped, connections refused) --");
        backend_handles[0].abort();
    };
    let (result, _) = tokio::join!(run, kill);

    println!();
    println!(
        "  aggregate over {:.1}s: {} requests, {} errors ({:.2}%)",
        result.wall.as_secs_f64(),
        result.total,
        result.errors,
        100.0 * result.errors as f64 / result.total.max(1) as f64
    );
    let mut sorted = result.latencies_ns.clone();
    sorted.sort_unstable();
    println!(
        "  p50={:.2}ms p95={:.2}ms p99={:.2}ms p999={:.2}ms (the failed backend's own requests both time out and get retried once, which is what the tail captures)",
        ms(percentile(&sorted, 0.50)),
        ms(percentile(&sorted, 0.95)),
        ms(percentile(&sorted, 0.99)),
        ms(percentile(&sorted, 0.999)),
    );
    println!();
}

async fn start_lb_server_for(strategy: &str, backend_addrs: &[SocketAddr]) -> (Child, SocketAddr) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(listen).await.unwrap();
    let listen = listener.local_addr().unwrap();
    drop(listener);

    let config_dir = std::env::temp_dir().join("lb-bench-e2e");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    write_config(&config_path, listen, backend_addrs, strategy);

    let child = spawn_lb_server(&config_path).await;
    wait_until_listening(listen).await;

    (child, listen)
}

async fn start_harness(
    strategy: &str,
) -> (
    Child,
    Vec<tokio::task::JoinHandle<()>>,
    SocketAddr,
    Vec<SocketAddr>,
) {
    let mut backend_handles = Vec::new();
    let mut backend_addrs = Vec::new();
    for _ in 0..4 {
        let backend = spawn_backend(0).await;
        backend_addrs.push(backend.addr);
        backend_handles.push(backend.handle);
    }

    let (child, listen) = start_lb_server_for(strategy, &backend_addrs).await;

    (child, backend_handles, listen, backend_addrs)
}

async fn run_single(strategy: &str) {
    let (mut child, backend_handles, listen, backend_addrs) = start_harness(strategy).await;
    let child_pid = child.id();
    if strategy == STRATEGIES[0] {
        println!(
            "lb-server listening on {listen} (pid {child_pid:?}), 4 backends on {backend_addrs:?}"
        );
    } else {
        println!(
            "lb-server listening on {listen} (pid {child_pid:?}), 4 backends on {backend_addrs:?}, strategy={strategy}"
        );
    }
    println!();

    let client = build_client();

    throughput_matrix(&client, listen, child_pid).await;
    failure_scenario(&client, listen, backend_handles).await;

    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn run_strategy_workload(client: &ProxyClient, strategy: &str) -> RunResult {
    let (mut child, backend_handles, listen, _backend_addrs) = start_harness(strategy).await;

    let result = run_closed_loop(
        client,
        listen,
        128,
        Duration::from_secs(5),
        Duration::from_secs(2),
        false,
    )
    .await;

    let _ = child.start_kill();
    let _ = child.wait().await;
    for handle in backend_handles {
        handle.abort();
    }

    result
}

fn print_comparison_row(strategy: &str, result: &RunResult) {
    let mut sorted = result.latencies_ns.clone();
    sorted.sort_unstable();
    let rps = result.total as f64 / result.wall.as_secs_f64();
    println!(
        "{:<22} | {:>10.0} | {:>7.2} | {:>7.2} | {:>7.2} | {:>7.2} | {:>8}",
        strategy,
        rps,
        ms(percentile(&sorted, 0.50)),
        ms(percentile(&sorted, 0.95)),
        ms(percentile(&sorted, 0.99)),
        ms(percentile(&sorted, 0.999)),
        result.errors,
    );
}

async fn compare_all_strategies() {
    println!(
        "=== Strategy comparison: fixed workload (4 backends, concurrency=128, 5s + 2s warmup) ==="
    );
    println!(
        "{:<22} | {:>10} | {:>7} | {:>7} | {:>7} | {:>7} | {:>8}",
        "strategy", "req/s", "p50ms", "p95ms", "p99ms", "p999ms", "errors"
    );
    let client = build_client();
    for strategy in STRATEGIES {
        let result = run_strategy_workload(&client, strategy).await;
        print_comparison_row(strategy, &result);
    }
    println!();
}

const HETEROGENEOUS_DELAYS_MS: [u64; 4] = [10, 20, 100, 500];
const HETEROGENEOUS_STRATEGIES: &[&str] = &["round_robin", "least_connections", "peak_ewma_p2c"];

async fn heterogeneous_static_comparison() {
    println!(
        "=== Heterogeneous backends: fixed latency profile (A={}ms B={}ms C={}ms D={}ms) ===",
        HETEROGENEOUS_DELAYS_MS[0],
        HETEROGENEOUS_DELAYS_MS[1],
        HETEROGENEOUS_DELAYS_MS[2],
        HETEROGENEOUS_DELAYS_MS[3]
    );
    println!(
        "{:<22} | {:>6} | {:>6} | {:>6} | {:>6} | {:>10} | {:>7} | {:>7} | {:>7} | {:>7}",
        "strategy",
        "A req%",
        "B req%",
        "C req%",
        "D req%",
        "req/s",
        "p50ms",
        "p95ms",
        "p99ms",
        "p999ms"
    );
    let client = build_client();
    for strategy in HETEROGENEOUS_STRATEGIES {
        let mut backends = Vec::with_capacity(4);
        for delay in HETEROGENEOUS_DELAYS_MS {
            backends.push(spawn_backend(delay).await);
        }
        let addrs: Vec<SocketAddr> = backends.iter().map(|b| b.addr).collect();
        let (mut child, listen) = start_lb_server_for(strategy, &addrs).await;

        let result = run_closed_loop(
            &client,
            listen,
            64,
            Duration::from_secs(8),
            Duration::from_secs(2),
            false,
        )
        .await;

        let counts: Vec<u64> = backends
            .iter()
            .map(|b| b.count.load(Ordering::Relaxed))
            .collect();
        let total: u64 = counts.iter().sum::<u64>().max(1);
        let pct: Vec<f64> = counts
            .iter()
            .map(|c| 100.0 * *c as f64 / total as f64)
            .collect();
        let mut sorted = result.latencies_ns.clone();
        sorted.sort_unstable();
        let rps = result.total as f64 / result.wall.as_secs_f64();
        println!(
            "{:<22} | {:>5.1}% | {:>5.1}% | {:>5.1}% | {:>5.1}% | {:>10.0} | {:>7.2} | {:>7.2} | {:>7.2} | {:>7.2}",
            strategy,
            pct[0],
            pct[1],
            pct[2],
            pct[3],
            rps,
            ms(percentile(&sorted, 0.50)),
            ms(percentile(&sorted, 0.95)),
            ms(percentile(&sorted, 0.99)),
            ms(percentile(&sorted, 0.999)),
        );

        let _ = child.start_kill();
        let _ = child.wait().await;
        for backend in backends {
            backend.handle.abort();
        }
    }
    println!();
}

async fn heterogeneous_dynamic_adaptation() {
    println!(
        "=== Heterogeneous backends: dynamic conditions (backend C slows to 300ms at t=10s, recovers at t=20s) ==="
    );
    for strategy in ["round_robin", "peak_ewma_p2c"] {
        println!("--- strategy={strategy} ---");
        let mut backends = Vec::with_capacity(4);
        for _ in 0..4 {
            backends.push(spawn_backend(10).await);
        }
        let addrs: Vec<SocketAddr> = backends.iter().map(|b| b.addr).collect();
        let (mut child, listen) = start_lb_server_for(strategy, &addrs).await;
        let client = build_client();
        let c_delay = Arc::clone(&backends[2].delay_ms);

        let load = run_closed_loop(
            &client,
            listen,
            64,
            Duration::from_secs(30),
            Duration::from_secs(0),
            false,
        );

        let controller = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            c_delay.store(300, Ordering::Relaxed);
            println!("      -- t=10s: backend C latency raised to 300ms --");
            tokio::time::sleep(Duration::from_secs(10)).await;
            c_delay.store(10, Ordering::Relaxed);
            println!("      -- t=20s: backend C latency restored to 10ms --");
            tokio::time::sleep(Duration::from_secs(10)).await;
        };

        let sampler = async {
            println!(
                "      {:>5} | {:>6} | {:>6} | {:>6} | {:>6}",
                "t", "A", "B", "C", "D"
            );
            let mut last = [0u64; 4];
            for sec in 1..=30u64 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let now: Vec<u64> = backends
                    .iter()
                    .map(|b| b.count.load(Ordering::Relaxed))
                    .collect();
                let deltas: Vec<u64> = now
                    .iter()
                    .zip(last.iter())
                    .map(|(n, l)| n.saturating_sub(*l))
                    .collect();
                last.copy_from_slice(&now);
                println!(
                    "      {:>4}s | {:>6} | {:>6} | {:>6} | {:>6}",
                    sec, deltas[0], deltas[1], deltas[2], deltas[3]
                );
            }
        };

        let (_, _, _) = tokio::join!(load, controller, sampler);

        let _ = child.start_kill();
        let _ = child.wait().await;
        for backend in backends {
            backend.handle.abort();
        }
        println!();
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Cli::Help => print_help(),
        Cli::CompareAll => {
            print_methodology();
            compare_all_strategies().await;
        }
        Cli::Heterogeneous => {
            print_methodology();
            heterogeneous_static_comparison().await;
            heterogeneous_dynamic_adaptation().await;
        }
        Cli::Run { strategy } => {
            print_methodology();
            run_single(strategy).await;
        }
    }
}
