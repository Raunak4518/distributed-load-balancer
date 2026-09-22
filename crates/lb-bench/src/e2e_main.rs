use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

mod results;

use std::sync::OnceLock;

static RESULTS: OnceLock<results::ResultsWriter> = OnceLock::new();

fn results() -> &'static results::ResultsWriter {
    RESULTS.get_or_init(results::ResultsWriter::new)
}

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
    RetryAmplification,
    Reliability,
    Convergence,
    FailurePatterns,
    ConcurrencySignal,
    Help,
}

fn parse_args(args: &[String]) -> Cli {
    match args {
        [] => Cli::Run {
            strategy: STRATEGIES[0],
        },
        [flag] if flag == "--compare-all-strategies" => Cli::CompareAll,
        [flag] if flag == "--heterogeneous" => Cli::Heterogeneous,
        [flag] if flag == "--retry-amplification" => Cli::RetryAmplification,
        [flag] if flag == "--reliability" => Cli::Reliability,
        [flag] if flag == "--convergence" => Cli::Convergence,
        [flag] if flag == "--failure-patterns" => Cli::FailurePatterns,
        [flag] if flag == "--concurrency-signal" => Cli::ConcurrencySignal,
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
    println!("    lb-bench-e2e --retry-amplification");
    println!("    lb-bench-e2e --reliability");
    println!("    lb-bench-e2e --convergence");
    println!("    lb-bench-e2e --failure-patterns");
    println!("    lb-bench-e2e --concurrency-signal");
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
    received: Arc<AtomicU64>,
    delay_ms: Arc<AtomicU64>,
    fail_pct: Arc<AtomicU64>,
    jitter_ms: Arc<AtomicU64>,
    slow_pct: Arc<AtomicU64>,
    slow_extra_ms: Arc<AtomicU64>,
    concurrency_coeff_ms: Arc<AtomicU64>,
    handle: tokio::task::JoinHandle<()>,
}

fn roll(state: &AtomicU64) -> u64 {
    let mut x = state.load(Ordering::Relaxed);
    if x == 0 {
        x = 0x9E3779B97F4A7C15;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state.store(x, Ordering::Relaxed);
    x
}

async fn spawn_backend(initial_delay_ms: u64) -> SpawnedBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let delay_ms = Arc::new(AtomicU64::new(initial_delay_ms));
    let fail_pct = Arc::new(AtomicU64::new(0));
    let jitter_ms = Arc::new(AtomicU64::new(0));
    let slow_pct = Arc::new(AtomicU64::new(0));
    let slow_extra_ms = Arc::new(AtomicU64::new(0));
    let concurrency_coeff_ms = Arc::new(AtomicU64::new(0));
    let in_flight = Arc::new(AtomicU64::new(0));
    let rng_state = Arc::new(AtomicU64::new(addr.port() as u64));
    let count_for_task = Arc::clone(&count);
    let received_for_task = Arc::clone(&received);
    let delay_for_task = Arc::clone(&delay_ms);
    let fail_for_task = Arc::clone(&fail_pct);
    let jitter_for_task = Arc::clone(&jitter_ms);
    let slow_pct_for_task = Arc::clone(&slow_pct);
    let slow_extra_for_task = Arc::clone(&slow_extra_ms);
    let concurrency_coeff_for_task = Arc::clone(&concurrency_coeff_ms);
    let in_flight_for_task = Arc::clone(&in_flight);
    let rng_for_task = Arc::clone(&rng_state);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let _ = stream.set_nodelay(true);
            let io = TokioIo::new(stream);
            let count = Arc::clone(&count_for_task);
            let received = Arc::clone(&received_for_task);
            let delay_ms = Arc::clone(&delay_for_task);
            let fail_pct = Arc::clone(&fail_for_task);
            let jitter_ms = Arc::clone(&jitter_for_task);
            let slow_pct = Arc::clone(&slow_pct_for_task);
            let slow_extra_ms = Arc::clone(&slow_extra_for_task);
            let concurrency_coeff_ms = Arc::clone(&concurrency_coeff_for_task);
            let in_flight = Arc::clone(&in_flight_for_task);
            let rng_state = Arc::clone(&rng_for_task);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let count = Arc::clone(&count);
                    let received = Arc::clone(&received);
                    let delay_ms = Arc::clone(&delay_ms);
                    let fail_pct = Arc::clone(&fail_pct);
                    let jitter_ms = Arc::clone(&jitter_ms);
                    let slow_pct = Arc::clone(&slow_pct);
                    let slow_extra_ms = Arc::clone(&slow_extra_ms);
                    let concurrency_coeff_ms = Arc::clone(&concurrency_coeff_ms);
                    let in_flight = Arc::clone(&in_flight);
                    let rng_state = Arc::clone(&rng_state);
                    async move {
                        if req.uri().path() == "/health" {
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
                                .unwrap());
                        }
                        received.fetch_add(1, Ordering::Relaxed);
                        let pct = fail_pct.load(Ordering::Relaxed);
                        if pct > 0 && roll(&rng_state) % 100 < pct {
                            if roll(&rng_state).is_multiple_of(2) {
                                return Err(std::io::Error::other("simulated backend failure"));
                            }
                            return Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(Bytes::from_static(b"err")))
                                .unwrap());
                        }
                        let n = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                        let mut delay = delay_ms.load(Ordering::Relaxed);
                        let jitter = jitter_ms.load(Ordering::Relaxed);
                        if jitter > 0 {
                            delay += roll(&rng_state) % jitter;
                        }
                        let slow = slow_pct.load(Ordering::Relaxed);
                        if slow > 0 && roll(&rng_state) % 100 < slow {
                            delay += slow_extra_ms.load(Ordering::Relaxed);
                        }
                        let coeff = concurrency_coeff_ms.load(Ordering::Relaxed);
                        if coeff > 0 {
                            delay += n * coeff;
                        }
                        if delay > 0 {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                        }
                        in_flight.fetch_sub(1, Ordering::Relaxed);
                        count.fetch_add(1, Ordering::Relaxed);
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap())
                    }
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    SpawnedBackend {
        addr,
        count,
        received,
        delay_ms,
        fail_pct,
        jitter_ms,
        slow_pct,
        slow_extra_ms,
        concurrency_coeff_ms,
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

fn write_config(
    path: &Path,
    listen: SocketAddr,
    backends: &[SocketAddr],
    strategy: &str,
    retry_budget: Option<(f64, u32)>,
) {
    let backends_toml: String = backends
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            format!("  [[listeners.backends]]\n  id = \"b{i}\"\n  address = \"{addr}\"\n\n")
        })
        .collect();
    let retry_budget_toml = match retry_budget {
        Some((rate_per_sec, burst)) => format!(
            "\n  [listeners.retry_budget]\n  rate_per_sec = {rate_per_sec}\n  burst = {burst}\n"
        ),
        None => String::new(),
    };
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
{retry_budget_toml}
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

struct ProcessSample {
    cpu_secs: f64,
    mem_mb: f64,
    threads: Option<u64>,
    fds: Option<u64>,
    voluntary_ctxt_switches: Option<u64>,
    nonvoluntary_ctxt_switches: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
fn print_row(
    concurrency: usize,
    result: &RunResult,
    cpu_cores: Option<f64>,
    mem_mb: Option<f64>,
    threads: Option<u64>,
    fds: Option<u64>,
    ctxsw: Option<u64>,
) {
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
    let threads_str = threads
        .map(|t| t.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let fds_str = fds
        .map(|f| f.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let ctxsw_str = ctxsw
        .map(|c| c.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let scenario = format!("throughput_matrix/conc={concurrency}");
    results().record(&scenario, "req_s", rps);
    results().record(&scenario, "total", result.total);
    results().record(&scenario, "err_pct", err_pct);
    results().record(&scenario, "p50_ms", ms(percentile(&sorted, 0.50)));
    results().record(&scenario, "p95_ms", ms(percentile(&sorted, 0.95)));
    results().record(&scenario, "p99_ms", ms(percentile(&sorted, 0.99)));
    results().record(&scenario, "p999_ms", ms(percentile(&sorted, 0.999)));
    println!(
        "{:>6} | {:>10.0} | {:>8} | {:>7.2}% | {:>8.2} | {:>8.2} | {:>8.2} | {:>8.2} | {:>8} | {:>8} | {:>7} | {:>6} | {:>8}",
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
        threads_str,
        fds_str,
        ctxsw_str,
    );
}

#[cfg(windows)]
fn sample_process(pid: u32) -> Option<ProcessSample> {
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
    Some(ProcessSample {
        cpu_secs,
        mem_mb: mem_bytes / (1024.0 * 1024.0),
        threads: None,
        fds: None,
        voluntary_ctxt_switches: None,
        nonvoluntary_ctxt_switches: None,
    })
}

#[cfg(not(windows))]
fn sample_process(pid: u32) -> Option<ProcessSample> {
    const CLK_TCK_HZ: f64 = 100.0;

    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let utime: f64 = fields.get(11)?.parse().ok()?;
    let stime: f64 = fields.get(12)?.parse().ok()?;
    let cpu_secs = (utime + stime) / CLK_TCK_HZ;

    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut mem_mb: Option<f64> = None;
    let mut threads: Option<u64> = None;
    let mut voluntary_ctxt_switches: Option<u64> = None;
    let mut nonvoluntary_ctxt_switches: Option<u64> = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            mem_mb = rest
                .split_whitespace()
                .next()
                .and_then(|kb| kb.parse::<f64>().ok())
                .map(|kb| kb / 1024.0);
        } else if let Some(rest) = line.strip_prefix("Threads:") {
            threads = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("voluntary_ctxt_switches:") {
            voluntary_ctxt_switches = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
            nonvoluntary_ctxt_switches = rest.trim().parse().ok();
        }
    }
    let mem_mb = mem_mb?;

    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .map(|entries| entries.count() as u64);

    Some(ProcessSample {
        cpu_secs,
        mem_mb,
        threads,
        fds,
        voluntary_ctxt_switches,
        nonvoluntary_ctxt_switches,
    })
}

#[cfg(windows)]
fn powershell_query(script: &str) -> Option<String> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}

#[cfg(windows)]
fn detect_host_line() -> String {
    let cpu = powershell_query("(Get-CimInstance Win32_Processor).Name")
        .unwrap_or_else(|| "unknown CPU".to_string());
    let physical = powershell_query("(Get-CimInstance Win32_Processor).NumberOfCores")
        .unwrap_or_else(|| "?".to_string());
    let logical = std::thread::available_parallelism()
        .map(|n| n.get().to_string())
        .unwrap_or_else(|_| "?".to_string());
    let mem_gib = powershell_query(
        "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)",
    )
    .unwrap_or_else(|| "?".to_string());
    format!("{cpu}, {physical} physical / {logical} logical cores, {mem_gib} GiB RAM")
}

#[cfg(windows)]
fn detect_os_line() -> String {
    let caption = powershell_query("(Get-CimInstance Win32_OperatingSystem).Caption")
        .unwrap_or_else(|| "Windows".to_string());
    let build = powershell_query("[System.Environment]::OSVersion.Version.Build")
        .unwrap_or_else(|| "?".to_string());
    format!("{caption}, build {build}")
}

#[cfg(not(windows))]
fn detect_host_line() -> String {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_else(|| "unknown CPU".to_string());
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let mem_str = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<f64>().ok())
        })
        .map(|kb| format!("{:.0}", kb / (1024.0 * 1024.0)))
        .unwrap_or_else(|| "?".to_string());
    format!("{cpu}, {logical} logical cores, {mem_str} GiB RAM")
}

#[cfg(not(windows))]
fn detect_os_line() -> String {
    let pretty = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| {
                    l.trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string()
                })
        });
    let kernel = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    match (pretty, kernel) {
        (Some(p), Some(k)) => format!("{p}, kernel {k}"),
        (Some(p), None) => p,
        (None, Some(k)) => format!("Linux, kernel {k}"),
        (None, None) => "Linux".to_string(),
    }
}

fn print_methodology() {
    println!("Methodology / environment (recorded so this is reproducible, not just a number):");
    println!("  Host: {}", detect_host_line());
    println!("  OS: {}", detect_os_line());
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
        "{:>6} | {:>10} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>7} | {:>6} | {:>8}",
        "conc",
        "req/s",
        "total",
        "err%",
        "p50ms",
        "p95ms",
        "p99ms",
        "p999ms",
        "cpu-s",
        "mem-MB",
        "threads",
        "fds",
        "ctxsw"
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
        let cpu_cores = match (&before, &after) {
            (Some(b), Some(a)) => Some((a.cpu_secs - b.cpu_secs) / result.wall.as_secs_f64()),
            _ => None,
        };
        let mem_mb = after.as_ref().map(|a| a.mem_mb);
        let threads = after.as_ref().and_then(|a| a.threads);
        let fds = after.as_ref().and_then(|a| a.fds);
        let ctxsw = match (&before, &after) {
            (Some(b), Some(a)) => {
                match (
                    b.voluntary_ctxt_switches,
                    b.nonvoluntary_ctxt_switches,
                    a.voluntary_ctxt_switches,
                    a.nonvoluntary_ctxt_switches,
                ) {
                    (Some(bv), Some(bn), Some(av), Some(an)) => {
                        Some((av + an).saturating_sub(bv + bn))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        print_row(concurrency, &result, cpu_cores, mem_mb, threads, fds, ctxsw);
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
    let err_pct = 100.0 * result.errors as f64 / result.total.max(1) as f64;
    results().record("failure_scenario", "total_requests", result.total);
    results().record("failure_scenario", "errors", result.errors);
    results().record("failure_scenario", "err_pct", err_pct);
    println!(
        "  aggregate over {:.1}s: {} requests, {} errors ({:.2}%)",
        result.wall.as_secs_f64(),
        result.total,
        result.errors,
        err_pct
    );
    let mut sorted = result.latencies_ns.clone();
    sorted.sort_unstable();
    results().record("failure_scenario", "p50_ms", ms(percentile(&sorted, 0.50)));
    results().record("failure_scenario", "p95_ms", ms(percentile(&sorted, 0.95)));
    results().record("failure_scenario", "p99_ms", ms(percentile(&sorted, 0.99)));
    results().record(
        "failure_scenario",
        "p999_ms",
        ms(percentile(&sorted, 0.999)),
    );
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
    start_lb_server_with_retry_budget(strategy, backend_addrs, None).await
}

async fn start_lb_server_with_retry_budget(
    strategy: &str,
    backend_addrs: &[SocketAddr],
    retry_budget: Option<(f64, u32)>,
) -> (Child, SocketAddr) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(listen).await.unwrap();
    let listen = listener.local_addr().unwrap();
    drop(listener);

    let config_dir = std::env::temp_dir().join("lb-bench-e2e");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    write_config(&config_path, listen, backend_addrs, strategy, retry_budget);

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
    let scenario = format!("compare_all_strategies/{strategy}");
    results().record(&scenario, "req_s", rps);
    results().record(&scenario, "p50_ms", ms(percentile(&sorted, 0.50)));
    results().record(&scenario, "p95_ms", ms(percentile(&sorted, 0.95)));
    results().record(&scenario, "p99_ms", ms(percentile(&sorted, 0.99)));
    results().record(&scenario, "p999_ms", ms(percentile(&sorted, 0.999)));
    results().record(&scenario, "errors", result.errors);
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
        let scenario = format!("heterogeneous_static/{strategy}");
        results().record(&scenario, "a_req_pct", pct[0]);
        results().record(&scenario, "b_req_pct", pct[1]);
        results().record(&scenario, "c_req_pct", pct[2]);
        results().record(&scenario, "d_req_pct", pct[3]);
        results().record(&scenario, "req_s", rps);
        results().record(&scenario, "p50_ms", ms(percentile(&sorted, 0.50)));
        results().record(&scenario, "p95_ms", ms(percentile(&sorted, 0.95)));
        results().record(&scenario, "p99_ms", ms(percentile(&sorted, 0.99)));
        results().record(&scenario, "p999_ms", ms(percentile(&sorted, 0.999)));
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

fn write_convergence_config(
    path: &Path,
    listen: SocketAddr,
    admin_listen: SocketAddr,
    backends: &[SocketAddr],
    strategy: &str,
) {
    let backends_toml: String = backends
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            format!("  [[listeners.backends]]\n  id = \"b{i}\"\n  address = \"{addr}\"\n\n")
        })
        .collect();
    let toml = format!(
        r#"
[admin]
listen = "{admin_listen}"

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

const CONVERGENCE_NEW_BACKEND_DELAY_MS: u64 = 5;

fn uniformity_verdict(pct: &[f64; 4]) -> &'static str {
    let avg = pct.iter().sum::<f64>() / 4.0;
    let max_dev = pct.iter().map(|p| (p - avg).abs()).fold(0.0_f64, f64::max);
    let fast_share = pct[0] + pct[1];
    let slow_share = pct[2] + pct[3];
    if max_dev < 5.0 {
        "still close to uniform/random across all four backends"
    } else if fast_share > slow_share * 1.5 {
        "clearly converged toward favoring the faster backends (A, B)"
    } else {
        "partially skewed toward the faster backends, not yet fully converged"
    }
}

async fn run_convergence_checkpoints(
    client: &ProxyClient,
    target: SocketAddr,
    backends: &[SpawnedBackend],
    checkpoints: &[u64],
    concurrency: usize,
) {
    let final_target = *checkpoints.last().unwrap();
    let total = Arc::new(AtomicU64::new(0));
    let uri: hyper::Uri = format!("http://{target}/").parse().unwrap();

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let uri = uri.clone();
        let total = Arc::clone(&total);
        handles.push(tokio::spawn(async move {
            while total.load(Ordering::Relaxed) < final_target {
                let req = Request::builder()
                    .uri(uri.clone())
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                if let Ok(resp) = client.request(req).await {
                    let (_, body) = resp.into_parts();
                    let _ = body.collect().await;
                }
                total.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    println!(
        "      {:>7} | {:>6} | {:>6} | {:>6} | {:>6} | verdict",
        "at req", "A req%", "B req%", "C req%", "D req%"
    );
    let mut next = 0usize;
    while next < checkpoints.len() {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if total.load(Ordering::Relaxed) < checkpoints[next] {
            continue;
        }
        let counts: Vec<u64> = backends
            .iter()
            .map(|b| b.count.load(Ordering::Relaxed))
            .collect();
        let sum: u64 = counts.iter().sum::<u64>().max(1);
        let pct = [
            100.0 * counts[0] as f64 / sum as f64,
            100.0 * counts[1] as f64 / sum as f64,
            100.0 * counts[2] as f64 / sum as f64,
            100.0 * counts[3] as f64 / sum as f64,
        ];
        let verdict = uniformity_verdict(&pct);
        let scenario = format!("convergence/checkpoint_{}", checkpoints[next]);
        results().record(&scenario, "a_req_pct", pct[0]);
        results().record(&scenario, "b_req_pct", pct[1]);
        results().record(&scenario, "c_req_pct", pct[2]);
        results().record(&scenario, "d_req_pct", pct[3]);
        println!(
            "      {:>7} | {:>5.1}% | {:>5.1}% | {:>5.1}% | {:>5.1}% | {}",
            checkpoints[next], pct[0], pct[1], pct[2], pct[3], verdict
        );
        next += 1;
    }

    for h in handles {
        let _ = h.await;
    }
}

async fn run_discovery_phase(
    client: &ProxyClient,
    target: SocketAddr,
    backends: &[SpawnedBackend],
    concurrency: usize,
    extra_requests: u64,
    window: u64,
) {
    let total = Arc::new(AtomicU64::new(0));
    let uri: hyper::Uri = format!("http://{target}/").parse().unwrap();

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let uri = uri.clone();
        let total = Arc::clone(&total);
        handles.push(tokio::spawn(async move {
            while total.load(Ordering::Relaxed) < extra_requests {
                let req = Request::builder()
                    .uri(uri.clone())
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                if let Ok(resp) = client.request(req).await {
                    let (_, body) = resp.into_parts();
                    let _ = body.collect().await;
                }
                total.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    println!("      {:>10} | {:>10}", "since undrain", "E (new) req%");
    let mut last_e = 0u64;
    let mut last_total = 0u64;
    let mut windows: Vec<f64> = Vec::new();
    let mut window_ends: Vec<u64> = Vec::new();
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let t = total.load(Ordering::Relaxed);
        if t < last_total + window && t < extra_requests {
            continue;
        }
        let e_now = backends[4].count.load(Ordering::Relaxed);
        let delta_e = e_now.saturating_sub(last_e);
        let delta_total = t.saturating_sub(last_total).max(1);
        let e_share = 100.0 * delta_e as f64 / delta_total as f64;
        println!("      {:>10} | {:>9.1}%", t, e_share);
        results().record(
            &format!("convergence/discovery/at_req={t}"),
            "e_req_pct",
            e_share,
        );
        windows.push(e_share);
        window_ends.push(t);
        last_e = e_now;
        last_total = t;
        if t >= extra_requests {
            break;
        }
    }

    for h in handles {
        let _ = h.await;
    }

    if let Some(steady) = windows.last().copied() {
        let mut stabilized_at = None;
        for i in 0..windows.len() {
            if windows[i..]
                .iter()
                .all(|share| (share - steady).abs() <= 3.0)
            {
                stabilized_at = Some(window_ends[i]);
                break;
            }
        }
        match stabilized_at {
            Some(req) => println!(
                "      -- backend E's traffic share first settled within 3pp of its steady-state ({steady:.1}%) by request #{req} after being undrained --"
            ),
            None => println!(
                "      -- backend E's traffic share ({steady:.1}% at the end) never settled within 3pp of itself for two consecutive windows --"
            ),
        }
        results().record("convergence/discovery", "steady_state_e_req_pct", steady);
    }
}

async fn convergence_characterization() {
    println!(
        "=== Cold-start convergence: peak_ewma_p2c from zero samples against the heterogeneous profile (A={}ms B={}ms C={}ms D={}ms) ===",
        HETEROGENEOUS_DELAYS_MS[0],
        HETEROGENEOUS_DELAYS_MS[1],
        HETEROGENEOUS_DELAYS_MS[2],
        HETEROGENEOUS_DELAYS_MS[3]
    );
    let mut backends = Vec::with_capacity(5);
    for delay in HETEROGENEOUS_DELAYS_MS {
        backends.push(spawn_backend(delay).await);
    }
    backends.push(spawn_backend(CONVERGENCE_NEW_BACKEND_DELAY_MS).await);
    let addrs: Vec<SocketAddr> = backends.iter().map(|b| b.addr).collect();

    let listen_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listen_listener.local_addr().unwrap();
    drop(listen_listener);
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    drop(admin_listener);

    let config_dir = std::env::temp_dir().join("lb-bench-e2e-convergence");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    write_convergence_config(&config_path, listen, admin_addr, &addrs, "peak_ewma_p2c");

    let mut child = spawn_lb_server(&config_path).await;
    wait_until_listening(listen).await;
    wait_until_listening(admin_addr).await;
    let client = build_client();

    let drained = post_admin(&client, admin_addr, "/backends/web/b4/drain").await;
    println!(
        "      backend E ({}ms, id=b4) added to the pool but drained -- excluded from routing until discovery phase: {}",
        CONVERGENCE_NEW_BACKEND_DELAY_MS,
        if drained { "ok" } else { "FAILED" }
    );
    println!();

    let checkpoints = [100u64, 1000, 10_000];
    run_convergence_checkpoints(&client, listen, &backends, &checkpoints, 16).await;
    println!();

    println!(
        "=== Discovery speed: backend E ({}ms) undrained into an already-warmed-up pool ===",
        CONVERGENCE_NEW_BACKEND_DELAY_MS
    );
    let undrained = post_admin(&client, admin_addr, "/backends/web/b4/undrain").await;
    println!(
        "      backend E undrained: {}",
        if undrained { "ok" } else { "FAILED" }
    );
    run_discovery_phase(&client, listen, &backends, 16, 20_000, 500).await;
    println!();

    let _ = child.start_kill();
    let _ = child.wait().await;
    for backend in backends {
        backend.handle.abort();
    }
}

async fn spawn_pattern_harness(
    baseline_delay_ms: u64,
) -> (Vec<SpawnedBackend>, Child, SocketAddr, ProxyClient) {
    let mut backends = Vec::with_capacity(4);
    for _ in 0..4 {
        backends.push(spawn_backend(baseline_delay_ms).await);
    }
    let addrs: Vec<SocketAddr> = backends.iter().map(|b| b.addr).collect();
    let (child, listen) = start_lb_server_for("peak_ewma_p2c", &addrs).await;
    let client = build_client();
    (backends, child, listen, client)
}

async fn teardown_pattern_harness(mut child: Child, backends: Vec<SpawnedBackend>) {
    let _ = child.start_kill();
    let _ = child.wait().await;
    for backend in backends {
        backend.handle.abort();
    }
}

async fn sample_traffic_shares(
    backends: &[SpawnedBackend],
    tick: Duration,
    ticks: u64,
    scenario: &str,
) {
    println!(
        "      {:>7} | {:>6} | {:>6} | {:>6} | {:>6}",
        "t", "A", "B", "C", "D"
    );
    let mut last = [0u64; 4];
    let start = Instant::now();
    for _ in 0..ticks {
        tokio::time::sleep(tick).await;
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
        let t = start.elapsed().as_secs_f64();
        println!(
            "      {:>6.1}s | {:>6} | {:>6} | {:>6} | {:>6}",
            t, deltas[0], deltas[1], deltas[2], deltas[3]
        );
        let total: u64 = deltas.iter().sum::<u64>().max(1);
        let c_share = 100.0 * deltas[2] as f64 / total as f64;
        results().record(&format!("{scenario}/t={t:.1}"), "c_req_share_pct", c_share);
    }
}

async fn failure_pattern_gradual_ramp() {
    println!(
        "--- pattern: gradual linear ramp (backend C: 10ms -> 300ms over 6s, holds 3s, ramps back over 3s) ---"
    );
    let (backends, child, listen, client) = spawn_pattern_harness(10).await;
    let c_delay = Arc::clone(&backends[2].delay_ms);
    let total = Duration::from_secs(18);
    let load = run_closed_loop(&client, listen, 64, total, Duration::from_secs(0), false);
    let controller = async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        for step in 0..12u64 {
            c_delay.store(10 + step * 24, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        c_delay.store(300, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(3)).await;
        for step in (0..12u64).rev() {
            c_delay.store(10 + step * 24, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        c_delay.store(10, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(3)).await;
    };
    let sampler = sample_traffic_shares(
        &backends,
        Duration::from_secs(1),
        18,
        "failure_patterns/gradual_ramp",
    );
    tokio::join!(load, controller, sampler);
    teardown_pattern_harness(child, backends).await;
    println!();
}

async fn failure_pattern_periodic_spikes() {
    println!("--- pattern: periodic spikes (backend C: every 2s, 200ms spike to 400ms) ---");
    let (backends, child, listen, client) = spawn_pattern_harness(10).await;
    let c_delay = Arc::clone(&backends[2].delay_ms);
    let total = Duration::from_secs(10);
    let load = run_closed_loop(&client, listen, 64, total, Duration::from_secs(0), false);
    let controller = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        for _ in 0..3 {
            c_delay.store(400, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(200)).await;
            c_delay.store(10, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(1800)).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let sampler = sample_traffic_shares(
        &backends,
        Duration::from_millis(250),
        40,
        "failure_patterns/periodic_spikes",
    );
    tokio::join!(load, controller, sampler);
    teardown_pattern_harness(child, backends).await;
    println!();
}

async fn failure_pattern_randomized_jitter() {
    println!("--- pattern: randomized per-request jitter (backend C: 10ms base + 0-400ms jitter for 6s) ---");
    let (backends, child, listen, client) = spawn_pattern_harness(10).await;
    let c_jitter = Arc::clone(&backends[2].jitter_ms);
    let total = Duration::from_secs(10);
    let load = run_closed_loop(&client, listen, 64, total, Duration::from_secs(0), false);
    let controller = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        c_jitter.store(400, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(6)).await;
        c_jitter.store(0, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let sampler = sample_traffic_shares(
        &backends,
        Duration::from_secs(1),
        10,
        "failure_patterns/randomized_jitter",
    );
    tokio::join!(load, controller, sampler);
    teardown_pattern_harness(child, backends).await;
    println!();
}

async fn failure_pattern_slow_fraction(pct: u64) {
    println!("--- pattern: fractional slow requests (backend C: {pct}% of requests take +2000ms for 5s) ---");
    let (backends, child, listen, client) = spawn_pattern_harness(10).await;
    let c_slow_pct = Arc::clone(&backends[2].slow_pct);
    backends[2].slow_extra_ms.store(2000, Ordering::Relaxed);
    let total = Duration::from_secs(9);
    let load = run_closed_loop(&client, listen, 64, total, Duration::from_secs(0), false);
    let controller = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        c_slow_pct.store(pct, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(5)).await;
        c_slow_pct.store(0, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let scenario = format!("failure_patterns/slow_fraction_{pct}pct");
    let sampler = sample_traffic_shares(&backends, Duration::from_secs(1), 9, &scenario);
    tokio::join!(load, controller, sampler);
    teardown_pattern_harness(child, backends).await;
    println!();
}

async fn failure_pattern_full_stall() {
    println!("--- pattern: full backend stall (backend C stops responding for 6s: delay=4000ms), then recovers ---");
    let (backends, child, listen, client) = spawn_pattern_harness(10).await;
    let c_delay = Arc::clone(&backends[2].delay_ms);
    let total = Duration::from_secs(12);
    let load = run_closed_loop(&client, listen, 64, total, Duration::from_secs(0), false);
    let controller = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        c_delay.store(4000, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(6)).await;
        c_delay.store(10, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(4)).await;
    };
    let sampler = sample_traffic_shares(
        &backends,
        Duration::from_secs(1),
        12,
        "failure_patterns/full_stall",
    );
    tokio::join!(load, controller, sampler);
    teardown_pattern_harness(child, backends).await;
    println!();
}

async fn heterogeneous_failure_patterns() {
    println!(
        "=== Adaptive routing under varied failure patterns (peak_ewma_p2c; backend C is degraded each time, A/B/D stay at 10ms) ==="
    );
    println!(
        "      (the sudden-step pattern, C: 10ms -> 300ms -> 10ms, is already covered by --heterogeneous's dynamic scenario; not re-run here)"
    );
    println!();
    failure_pattern_gradual_ramp().await;
    failure_pattern_periodic_spikes().await;
    failure_pattern_randomized_jitter().await;
    for pct in [1u64, 10, 50] {
        failure_pattern_slow_fraction(pct).await;
    }
    failure_pattern_full_stall().await;
}

const CONCURRENCY_SIGNAL_FAST_MS: u64 = 10;
const CONCURRENCY_SIGNAL_SLOW_MS: u64 = 150;
const CONCURRENCY_SIGNAL_COEFF_MS: u64 = 3;
const CONCURRENCY_SIGNAL_STRATEGIES: &[&str] =
    &["round_robin", "least_connections", "peak_ewma_p2c"];

async fn heterogeneous_concurrency_signal() {
    println!(
        "=== Heterogeneous backends: latency-matched, concurrency-sensitivity-varied (A=fast/low-load B=fast/high-load C=slow/low-load D=slow/high-load) ==="
    );
    println!(
        "    A/C base delay never changes with load; B/D add {}ms of extra delay per concurrently in-flight request on top of their base delay, on the backend itself -- a backend that visibly slows down under its own concurrent load, independent of any routing choice.",
        CONCURRENCY_SIGNAL_COEFF_MS
    );
    println!(
        "    A/B base delay = {}ms, C/D base delay = {}ms.",
        CONCURRENCY_SIGNAL_FAST_MS, CONCURRENCY_SIGNAL_SLOW_MS
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
    for strategy in CONCURRENCY_SIGNAL_STRATEGIES {
        let a = spawn_backend(CONCURRENCY_SIGNAL_FAST_MS).await;
        let b = spawn_backend(CONCURRENCY_SIGNAL_FAST_MS).await;
        b.concurrency_coeff_ms
            .store(CONCURRENCY_SIGNAL_COEFF_MS, Ordering::Relaxed);
        let c = spawn_backend(CONCURRENCY_SIGNAL_SLOW_MS).await;
        let d = spawn_backend(CONCURRENCY_SIGNAL_SLOW_MS).await;
        d.concurrency_coeff_ms
            .store(CONCURRENCY_SIGNAL_COEFF_MS, Ordering::Relaxed);
        let backends = vec![a, b, c, d];
        let addrs: Vec<SocketAddr> = backends.iter().map(|be| be.addr).collect();
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
        let scenario = format!("concurrency_signal/{strategy}");
        results().record(&scenario, "a_req_pct", pct[0]);
        results().record(&scenario, "b_req_pct", pct[1]);
        results().record(&scenario, "c_req_pct", pct[2]);
        results().record(&scenario, "d_req_pct", pct[3]);
        results().record(&scenario, "req_s", rps);
        results().record(&scenario, "p50_ms", ms(percentile(&sorted, 0.50)));
        results().record(&scenario, "p95_ms", ms(percentile(&sorted, 0.95)));
        results().record(&scenario, "p99_ms", ms(percentile(&sorted, 0.99)));
        results().record(&scenario, "p999_ms", ms(percentile(&sorted, 0.999)));
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
    println!(
        "    round_robin ignores both latency and pending load, so its split is the baseline for \"no adaptive signal at all\"."
    );
    println!(
        "    least_connections uses pending load only (no latency); peak_ewma_p2c uses both -- comparing B's share across the three shows whether the pending-load signal is doing independent work."
    );
    println!();
}

async fn spawn_amplification_backend(fail_pct: u64) -> (SocketAddr, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let attempts = Arc::new(AtomicU64::new(0));
    let sequence = Arc::new(AtomicU64::new(0));
    let attempts_for_task = Arc::clone(&attempts);
    let sequence_for_task = Arc::clone(&sequence);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let _ = stream.set_nodelay(true);
            let attempts = Arc::clone(&attempts_for_task);
            let sequence = Arc::clone(&sequence_for_task);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let n = match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                if buf[..n].starts_with(b"GET /health") {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    return;
                }
                attempts.fetch_add(1, Ordering::Relaxed);
                let seq = sequence.fetch_add(1, Ordering::Relaxed);
                if fail_pct > 0 && seq % 100 < fail_pct {
                    let _ = stream.write_all(b"not a valid http response\r\n\r\n").await;
                } else {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                }
            });
        }
    });
    (addr, attempts)
}

const AMPLIFICATION_FAIL_PCTS: [u64; 3] = [0, 50, 100];
const AMPLIFICATION_MODES: [(&str, Option<(f64, u32)>); 3] = [
    ("unbudgeted (today's default)", None),
    ("budgeted (200 r/s, burst 50)", Some((200.0, 50))),
    ("near-zero budget (~disabled)", Some((0.01, 1))),
];

async fn retry_amplification_matrix() {
    println!("=== Backend amplification under retries (concurrency=32, 4s + 1s warmup) ===");
    println!(
        "Every failed attempt is a genuine transport-level failure (the backend answers with an \
         unparsable response), which is the only failure kind lb-proxy's retry loop reacts to -- \
         a plain 5xx from a healthy backend is returned to the client immediately, never retried."
    );
    println!(
        "\"near-zero budget\" is this codebase's only way to approximate \"retries off\": the \
         default one-retry is otherwise unconditional, so a budget with essentially no burst \
         allowance is the closest stand-in for a literal disable switch."
    );
    println!();
    println!(
        "{:<10} | {:<30} | {:>10} | {:>10} | {:>13} | {:>8}",
        "fail%", "retry policy", "client req", "backend req", "amplification", "err%"
    );
    for fail_pct in AMPLIFICATION_FAIL_PCTS {
        for (mode_name, retry_budget) in AMPLIFICATION_MODES {
            let (addr, attempts) = spawn_amplification_backend(fail_pct).await;
            let (mut child, listen) =
                start_lb_server_with_retry_budget("round_robin", &[addr], retry_budget).await;
            let client = build_client();

            let result = run_closed_loop(
                &client,
                listen,
                32,
                Duration::from_secs(4),
                Duration::from_secs(1),
                false,
            )
            .await;

            let backend_attempts = attempts.load(Ordering::Relaxed);
            let amplification = backend_attempts as f64 / result.total.max(1) as f64;
            let err_pct = 100.0 * result.errors as f64 / result.total.max(1) as f64;
            let scenario = format!("retry_amplification/fail={fail_pct}/{mode_name}");
            results().record(&scenario, "client_req", result.total);
            results().record(&scenario, "backend_req", backend_attempts);
            results().record(&scenario, "amplification_x", amplification);
            results().record(&scenario, "err_pct", err_pct);
            println!(
                "{:>8}% | {:<30} | {:>10} | {:>10} | {:>12.2}x | {:>7.2}%",
                fail_pct, mode_name, result.total, backend_attempts, amplification, err_pct
            );

            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
    println!();
}

fn write_reliability_config(
    path: &Path,
    listen: SocketAddr,
    admin_listen: SocketAddr,
    backends: &[SocketAddr],
) {
    let ids = ["a", "b", "c", "d"];
    let backends_toml: String = backends
        .iter()
        .zip(ids.iter())
        .map(|(addr, id)| {
            format!("  [[listeners.backends]]\n  id = \"{id}\"\n  address = \"{addr}\"\n\n")
        })
        .collect();
    let toml = format!(
        r#"
[admin]
listen = "{admin_listen}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
max_connections = 1000000
max_connections_per_ip = 1000000

{backends_toml}
  [listeners.health_check]
  path = "/health"
  interval_ms = 100
  timeout_ms = 200
  failure_threshold = 3
  cooldown_ms = 2000
  half_open_successes_required = 2
  unhealthy_latency_ms = 50
  max_ejected_fraction = 0.5

  [listeners.health_check.outlier_detection]
  min_volume = 10
  min_hosts = 3
  stddev_factor = 1.0

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000000
  burst = 10000000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    );
    std::fs::write(path, toml).expect("write config");
}

#[derive(Clone, Copy)]
enum Degradation {
    Latency(u64),
    Failure(u64),
}

impl Degradation {
    fn apply(&self, backend: &SpawnedBackend) {
        match self {
            Degradation::Latency(ms) => backend.delay_ms.store(*ms, Ordering::Relaxed),
            Degradation::Failure(pct) => backend.fail_pct.store(*pct, Ordering::Relaxed),
        }
    }

    fn revert(&self, backend: &SpawnedBackend) {
        match self {
            Degradation::Latency(_) => backend.delay_ms.store(10, Ordering::Relaxed),
            Degradation::Failure(_) => backend.fail_pct.store(0, Ordering::Relaxed),
        }
    }

    fn label(&self) -> String {
        match self {
            Degradation::Latency(ms) => format!("D -> {ms}ms"),
            Degradation::Failure(pct) => format!("D -> intermittent {pct}%"),
        }
    }
}

struct Sample {
    t_ms: f64,
    counts: [u64; 4],
    d_circuit_state: Option<i64>,
}

async fn fetch_admin_text(client: &ProxyClient, admin_addr: SocketAddr) -> Option<String> {
    let uri: hyper::Uri = format!("http://{admin_addr}/metrics").parse().ok()?;
    let req = Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .ok()?;
    let resp = client.request(req).await.ok()?;
    let (parts, body) = resp.into_parts();
    if !parts.status.is_success() {
        return None;
    }
    let bytes = body.collect().await.ok()?.to_bytes();
    String::from_utf8(bytes.to_vec()).ok()
}

async fn post_admin(client: &ProxyClient, admin_addr: SocketAddr, path: &str) -> bool {
    let uri: hyper::Uri = match format!("http://{admin_addr}{path}").parse() {
        Ok(uri) => uri,
        Err(_) => return false,
    };
    let req = match Request::builder()
        .method("POST")
        .uri(uri)
        .body(Full::new(Bytes::new()))
    {
        Ok(req) => req,
        Err(_) => return false,
    };
    matches!(client.request(req).await, Ok(resp) if resp.status().is_success())
}

fn extract_gauge(text: &str, key: &str) -> Option<i64> {
    let idx = text.find(key)?;
    let rest = &text[idx + key.len()..];
    let end = rest.find('\n').unwrap_or(rest.len());
    rest[..end].trim().parse::<i64>().ok()
}

struct ScenarioResult {
    label: String,
    time_to_detection_ms: Option<f64>,
    time_to_ejection_ms: Option<f64>,
    baseline_d_share_pct: f64,
    degraded_d_share_pct: f64,
    time_to_recovery_ms: Option<f64>,
    false_ejection: bool,
    abc_max_deviation_pct: f64,
}

fn share_series(samples: &[Sample], backend_idx: usize) -> Vec<(f64, f64)> {
    let mut out = Vec::with_capacity(samples.len());
    for w in samples.windows(2) {
        let (prev, cur) = (&w[0], &w[1]);
        let deltas: Vec<i64> = (0..4)
            .map(|i| cur.counts[i] as i64 - prev.counts[i] as i64)
            .collect();
        let total: i64 = deltas.iter().sum();
        let share = if total > 0 {
            100.0 * deltas[backend_idx] as f64 / total as f64
        } else {
            0.0
        };
        out.push((cur.t_ms, share));
    }
    out
}

fn analyze(samples: Vec<Sample>, baseline_ms: f64, hold_ms: f64, label: String) -> ScenarioResult {
    let d_share = share_series(&samples, 3);
    let degrade_at = baseline_ms;
    let revert_at = baseline_ms + hold_ms;

    let baseline_shares: Vec<f64> = d_share
        .iter()
        .filter(|(t, _)| *t < degrade_at)
        .map(|(_, s)| *s)
        .collect();
    let baseline_d_share_pct = if baseline_shares.is_empty() {
        0.0
    } else {
        baseline_shares.iter().sum::<f64>() / baseline_shares.len() as f64
    };

    let degraded_shares: Vec<f64> = d_share
        .iter()
        .filter(|(t, _)| *t >= degrade_at + 1000.0 && *t < revert_at)
        .map(|(_, s)| *s)
        .collect();
    let degraded_d_share_pct = if degraded_shares.is_empty() {
        0.0
    } else {
        degraded_shares.iter().sum::<f64>() / degraded_shares.len() as f64
    };

    let mut time_to_detection_ms = None;
    for s in samples.iter().filter(|s| s.t_ms >= degrade_at) {
        if let Some(state) = s.d_circuit_state {
            if state != 0 {
                time_to_detection_ms = Some(s.t_ms - degrade_at);
                break;
            }
        }
    }
    if time_to_detection_ms.is_none() {
        for (t, share) in d_share.iter().filter(|(t, _)| *t >= degrade_at) {
            if *share < 12.5 {
                time_to_detection_ms = Some(t - degrade_at);
                break;
            }
        }
    }

    let mut time_to_ejection_ms = None;
    let degraded_series: Vec<&(f64, f64)> =
        d_share.iter().filter(|(t, _)| *t >= degrade_at).collect();
    for w in degraded_series.windows(3) {
        if w.iter().all(|(_, s)| *s < 2.0) {
            time_to_ejection_ms = Some(w[0].0 - degrade_at);
            break;
        }
    }

    let mut time_to_recovery_ms = None;
    let recovery_series: Vec<&(f64, f64)> =
        d_share.iter().filter(|(t, _)| *t >= revert_at).collect();
    for w in recovery_series.windows(2) {
        if w.iter().all(|(_, s)| *s >= 15.0) {
            time_to_recovery_ms = Some(w[0].0 - revert_at);
            break;
        }
    }

    let mut abc_max_deviation_pct: f64 = 0.0;
    let mut false_ejection = false;
    let a_share = share_series(&samples, 0);
    let b_share = share_series(&samples, 1);
    let c_share = share_series(&samples, 2);
    for i in 0..a_share.len() {
        let (t, a) = a_share[i];
        if t < degrade_at || t >= revert_at {
            continue;
        }
        let b = b_share[i].1;
        let c = c_share[i].1;
        let avg = (a + b + c) / 3.0;
        let dev = [a, b, c]
            .iter()
            .map(|v| (v - avg).abs())
            .fold(0.0_f64, f64::max);
        abc_max_deviation_pct = abc_max_deviation_pct.max(dev);
        if a < avg * 0.3 || b < avg * 0.3 || c < avg * 0.3 {
            false_ejection = true;
        }
    }

    ScenarioResult {
        label,
        time_to_detection_ms,
        time_to_ejection_ms,
        baseline_d_share_pct,
        degraded_d_share_pct,
        time_to_recovery_ms,
        false_ejection,
        abc_max_deviation_pct,
    }
}

async fn run_reliability_scenario(degradation: Degradation) -> ScenarioResult {
    let mut backends = Vec::with_capacity(4);
    for _ in 0..4 {
        backends.push(spawn_backend(10).await);
    }
    let addrs: Vec<SocketAddr> = backends.iter().map(|b| b.addr).collect();

    let listen_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listen_listener.local_addr().unwrap();
    drop(listen_listener);
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    drop(admin_listener);

    let config_dir = std::env::temp_dir().join("lb-bench-e2e-reliability");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join(format!("config-{}.toml", listen.port()));
    write_reliability_config(&config_path, listen, admin_addr, &addrs);

    let mut child = spawn_lb_server(&config_path).await;
    wait_until_listening(listen).await;
    wait_until_listening(admin_addr).await;

    let client = build_client();
    let concurrency = 40;
    let baseline = Duration::from_secs(3);
    let hold = Duration::from_secs(8);
    let recover = Duration::from_secs(5);
    let total = baseline + hold + recover;
    let sample_every = Duration::from_millis(100);

    let load = run_closed_loop(
        &client,
        listen,
        concurrency,
        total,
        Duration::from_secs(0),
        false,
    );

    let d_index = 3;
    let controller = async {
        tokio::time::sleep(baseline).await;
        degradation.apply(&backends[d_index]);
        tokio::time::sleep(hold).await;
        degradation.revert(&backends[d_index]);
        tokio::time::sleep(recover).await;
    };

    let sampler = async {
        let start = Instant::now();
        let stop_at = start + total;
        let mut samples = Vec::new();
        samples.push(Sample {
            t_ms: 0.0,
            counts: [
                backends[0].received.load(Ordering::Relaxed),
                backends[1].received.load(Ordering::Relaxed),
                backends[2].received.load(Ordering::Relaxed),
                backends[3].received.load(Ordering::Relaxed),
            ],
            d_circuit_state: None,
        });
        while Instant::now() < stop_at {
            tokio::time::sleep(sample_every).await;
            let t_ms = start.elapsed().as_secs_f64() * 1000.0;
            let counts = [
                backends[0].received.load(Ordering::Relaxed),
                backends[1].received.load(Ordering::Relaxed),
                backends[2].received.load(Ordering::Relaxed),
                backends[3].received.load(Ordering::Relaxed),
            ];
            let text = fetch_admin_text(&client, admin_addr).await;
            let d_circuit_state = text.as_deref().and_then(|t| {
                extract_gauge(
                    t,
                    "lb_backend_circuit_state{backend=\"d\",listener=\"web\"} ",
                )
            });
            samples.push(Sample {
                t_ms,
                counts,
                d_circuit_state,
            });
        }
        samples
    };

    let (_, _, samples) = tokio::join!(load, controller, sampler);

    let _ = child.start_kill();
    let _ = child.wait().await;
    for b in backends {
        b.handle.abort();
    }

    analyze(
        samples,
        baseline.as_secs_f64() * 1000.0,
        hold.as_secs_f64() * 1000.0,
        degradation.label(),
    )
}

fn print_reliability_row(r: &ScenarioResult) {
    let fmt_ms = |v: Option<f64>| match v {
        Some(ms) => format!("{:.0}ms", ms),
        None => "never".to_string(),
    };
    let scenario = format!("reliability/{}", r.label);
    if let Some(v) = r.time_to_detection_ms {
        results().record(&scenario, "time_to_detection_ms", v);
    }
    if let Some(v) = r.time_to_ejection_ms {
        results().record(&scenario, "time_to_ejection_ms", v);
    }
    results().record(&scenario, "baseline_d_share_pct", r.baseline_d_share_pct);
    results().record(&scenario, "degraded_d_share_pct", r.degraded_d_share_pct);
    if let Some(v) = r.time_to_recovery_ms {
        results().record(&scenario, "time_to_recovery_ms", v);
    }
    results().record(&scenario, "false_ejection", r.false_ejection);
    results().record(&scenario, "abc_max_deviation_pct", r.abc_max_deviation_pct);
    println!(
        "{:<22} | {:>12} | {:>12} | {:>9.1}% | {:>9.1}% | {:>12} | {:>7} | {:>7.1}%",
        r.label,
        fmt_ms(r.time_to_detection_ms),
        fmt_ms(r.time_to_ejection_ms),
        r.baseline_d_share_pct,
        r.degraded_d_share_pct,
        fmt_ms(r.time_to_recovery_ms),
        if r.false_ejection { "YES" } else { "no" },
        r.abc_max_deviation_pct,
    );
}

async fn reliability_characterization() {
    println!(
        "=== Failure-control characterization: A/B/C=10ms baseline, D degrades then recovers ==="
    );
    println!(
        "Config: interval_ms=100 timeout_ms=200 failure_threshold=3 cooldown_ms=2000 half_open_successes_required=2"
    );
    println!(
        "        unhealthy_latency_ms=50 outlier_detection{{min_volume=10,min_hosts=3,stddev_factor=1.0}} max_ejected_fraction=0.5"
    );
    println!("        concurrency=40 closed-loop, per scenario: 3s baseline + 8s degraded + 5s recovery, 100ms sampling");
    println!();

    let scenarios = [
        Degradation::Latency(100),
        Degradation::Latency(500),
        Degradation::Latency(2000),
        Degradation::Failure(30),
    ];

    let mut results = Vec::new();
    for scenario in scenarios {
        println!("--- running {} ---", scenario.label());
        let result = run_reliability_scenario(scenario).await;
        println!(
            "    detection={} ejection={} baseline_share={:.1}% degraded_share={:.1}% recovery={} false_ejection={} abc_max_dev={:.1}%",
            result
                .time_to_detection_ms
                .map(|v| format!("{v:.0}ms"))
                .unwrap_or_else(|| "never".to_string()),
            result
                .time_to_ejection_ms
                .map(|v| format!("{v:.0}ms"))
                .unwrap_or_else(|| "never".to_string()),
            result.baseline_d_share_pct,
            result.degraded_d_share_pct,
            result
                .time_to_recovery_ms
                .map(|v| format!("{v:.0}ms"))
                .unwrap_or_else(|| "never within 5s".to_string()),
            result.false_ejection,
            result.abc_max_deviation_pct,
        );
        results.push(result);
    }

    println!();
    println!("=== Results table ===");
    println!(
        "{:<22} | {:>12} | {:>12} | {:>10} | {:>10} | {:>12} | {:>7} | {:>8}",
        "scenario",
        "detection",
        "ejection",
        "D share(base)",
        "D share(deg)",
        "recovery",
        "false_ej",
        "abc_dev"
    );
    for r in &results {
        print_reliability_row(r);
    }
    println!();
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode_and_params: Option<(&str, Vec<(&str, String)>)> = match parse_args(&args) {
        Cli::Help => {
            print_help();
            None
        }
        Cli::CompareAll => {
            print_methodology();
            compare_all_strategies().await;
            Some(("compare-all-strategies", vec![]))
        }
        Cli::Heterogeneous => {
            print_methodology();
            heterogeneous_static_comparison().await;
            heterogeneous_dynamic_adaptation().await;
            Some(("heterogeneous", vec![]))
        }
        Cli::RetryAmplification => {
            print_methodology();
            retry_amplification_matrix().await;
            Some(("retry-amplification", vec![]))
        }
        Cli::Reliability => {
            print_methodology();
            reliability_characterization().await;
            Some(("reliability", vec![]))
        }
        Cli::Convergence => {
            print_methodology();
            convergence_characterization().await;
            Some(("convergence", vec![]))
        }
        Cli::FailurePatterns => {
            print_methodology();
            heterogeneous_failure_patterns().await;
            Some(("failure-patterns", vec![]))
        }
        Cli::ConcurrencySignal => {
            print_methodology();
            heterogeneous_concurrency_signal().await;
            Some(("concurrency-signal", vec![]))
        }
        Cli::Run { strategy } => {
            print_methodology();
            run_single(strategy).await;
            Some(("run", vec![("strategy", strategy.to_string())]))
        }
    };

    if let Some((mode, params)) = mode_and_params {
        match results().finish(mode, &params) {
            Ok(dir) => println!("results persisted to {}", dir.display()),
            Err(err) => eprintln!("failed to persist results: {err}"),
        }
    }
}
