// This module is compiled independently into each integration-test binary,
// so helpers used by only one of them look unused to the others.
#![allow(dead_code)]

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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Starts a backend that always answers with `status` and counts how many
/// requests it received, so tests can assert on distribution across backends.
pub async fn spawn_counting_backend(status: StatusCode) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let count = count_clone.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let count = count.clone();
                    async move {
                        if req.uri().path() == "/health" {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::new()))
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

pub fn config_toml(
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

/// Like `spawn_counting_backend`, but waits `delay` before answering each
/// request -- long enough that the proxy's active-connection guard for this
/// backend is still held when other concurrent requests are routed, which is
/// the only way a `least_connections` test can observe anything.
pub async fn spawn_slow_counting_backend(
    status: StatusCode,
    delay: std::time::Duration,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let count = count_clone.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let count = count.clone();
                    async move {
                        if req.uri().path() == "/health" {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        tokio::time::sleep(delay).await;
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::new()))
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

pub fn least_connections_config_toml(listen: &str, backends: &[(&str, SocketAddr)]) -> String {
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
  key = "source_ip"
  rate_per_sec = 1000.0
  burst = 1000

  [listeners.load_balancing]
  strategy = "least_connections"
"#
    )
}

/// A backend that answers every non-health request with a `body_len`-byte
/// body. Used to test the load balancer's write-side timeout: a small
/// response fits entirely in the kernel's send buffer and "succeeds"
/// immediately no matter whether the peer ever reads it, so proving a
/// stalled write actually times out needs a body large enough that writing
/// it genuinely blocks once the client stops draining its socket.
pub async fn spawn_large_body_backend(body_len: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| async move {
                    if req.uri().path() == "/health" {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        );
                    }
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(vec![0u8; body_len])))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    addr
}

/// A TCP backend that echoes whatever it receives, and counts connections.
pub async fn spawn_echo_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let count = count_clone.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                let mut counted = false;
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if !counted {
                                // Count only connections that actually carry
                                // data. The TcpConnectProbe health check
                                // opens a socket and closes it without
                                // sending anything, and at L4 that is
                                // otherwise indistinguishable from a real
                                // client connecting — there is no path or
                                // header to filter on the way there is at L7.
                                count.fetch_add(1, Ordering::SeqCst);
                                counted = true;
                            }
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

/// One HTTP listener plus a `[cluster]` section, for multi-node tests.
#[allow(clippy::too_many_arguments)]
pub fn cluster_config_toml(
    node_id: &str,
    cluster_listen: SocketAddr,
    peers: &[SocketAddr],
    traffic_listen: SocketAddr,
    backend: SocketAddr,
    rate_per_sec: f64,
    burst: u32,
    window_secs: u64,
) -> String {
    let peer_list: Vec<String> = peers.iter().map(|p| format!("\"{p}\"")).collect();
    format!(
        r#"
[cluster]
node_id = "{node_id}"
listen = "{cluster_listen}"
peers = [{peers}]
sync_interval_ms = 50
window_secs = {window_secs}
shared_secret = "integration-test-secret"

[[listeners]]
name = "web"
protocol = "http"
listen = "{traffic_listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = {rate_per_sec}
  burst = {burst}

  [listeners.load_balancing]
  strategy = "round_robin"
"#,
        peers = peer_list.join(", ")
    )
}

/// Same shape as `cluster_config_toml`, plus a `[cluster.tls]` section --
/// for tests proving the peer channel actually works end to end when
/// mutual TLS is configured, not just that the config parses.
#[allow(clippy::too_many_arguments)]
pub fn cluster_config_toml_with_tls(
    node_id: &str,
    cluster_listen: SocketAddr,
    peers: &[SocketAddr],
    traffic_listen: SocketAddr,
    backend: SocketAddr,
    rate_per_sec: f64,
    burst: u32,
    window_secs: u64,
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
    ca_file: &std::path::Path,
) -> String {
    let peer_list: Vec<String> = peers.iter().map(|p| format!("\"{p}\"")).collect();
    format!(
        r#"
[cluster]
node_id = "{node_id}"
listen = "{cluster_listen}"
peers = [{peers}]
sync_interval_ms = 50
window_secs = {window_secs}
shared_secret = "integration-test-secret"

  [cluster.tls]
  cert_file = "{cert_file}"
  key_file = "{key_file}"
  ca_file = "{ca_file}"
  handshake_timeout_ms = 2000

[[listeners]]
name = "web"
protocol = "http"
listen = "{traffic_listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = {rate_per_sec}
  burst = {burst}

  [listeners.load_balancing]
  strategy = "round_robin"
"#,
        peers = peer_list.join(", "),
        cert_file = cert_file.display().to_string().replace('\\', "\\\\"),
        key_file = key_file.display().to_string().replace('\\', "\\\\"),
        ca_file = ca_file.display().to_string().replace('\\', "\\\\"),
    )
}

/// An HTTP listener plus an `[admin]` section, for metrics tests.
pub fn admin_config_toml(
    admin_listen: SocketAddr,
    traffic_listen: SocketAddr,
    backend: SocketAddr,
    rate_per_sec: f64,
    burst: u32,
) -> String {
    format!(
        r#"
[admin]
listen = "{admin_listen}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{traffic_listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
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

/// Same shape as `admin_config_toml`, but with two backends on the traffic
/// listener -- for tests proving the admin API's drain/undrain actually
/// changes which backend receives traffic, not just that the pool method
/// gets called.
pub fn admin_config_toml_two_backends(
    admin_listen: SocketAddr,
    traffic_listen: SocketAddr,
    backend_a: SocketAddr,
    backend_b: SocketAddr,
) -> String {
    format!(
        r#"
[admin]
listen = "{admin_listen}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{traffic_listen}"

  [[listeners.backends]]
  id = "a"
  address = "{backend_a}"

  [[listeners.backends]]
  id = "b"
  address = "{backend_b}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
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
    )
}

/// A backend that speaks the HTTP/1.1 upgrade handshake itself: on
/// `accept`, answers `101` and echoes whatever bytes arrive after the
/// upgrade; otherwise answers a plain `200` (declines). Built on hyper's
/// own server-side `hyper::upgrade::on`/`.with_upgrades()`, the same
/// mechanism the load balancer's own server side must cooperate with.
pub async fn spawn_upgrade_backend(accept: bool) -> SocketAddr {
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
                    let is_upgrade_request = req.headers().get(hyper::header::UPGRADE).is_some();
                    if !accept || !is_upgrade_request {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
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
                    let mut resp = Response::new(Full::new(Bytes::new()));
                    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    resp.headers_mut().insert(
                        hyper::header::CONNECTION,
                        hyper::header::HeaderValue::from_static("Upgrade"),
                    );
                    resp.headers_mut().insert(
                        hyper::header::UPGRADE,
                        hyper::header::HeaderValue::from_static("websocket"),
                    );
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

/// Reads from `stream` until a blank line ends the HTTP head, returning the
/// head text and any bytes already read past it (a raw TCP read has no
/// message boundary, so the first read after the head can easily contain
/// the start of whatever comes next too).
pub async fn read_response_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
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

/// Waits until `addr` accepts a TCP connection, or the deadline passes.
///
/// Replaces `sleep(150ms)` after starting a server. A fixed sleep is a race:
/// it passes on an idle machine and fails under load, which is exactly the
/// kind of flake that trains people to ignore test failures.
pub async fn wait_until_listening(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("nothing listening on {addr} after 10s");
}
