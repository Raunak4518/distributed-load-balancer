mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use support::{spawn_counting_backend, spawn_large_body_backend};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn free_addr_v6() -> SocketAddr {
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// An HTTP listener with tight, explicit hardening limits so the tests stay
/// fast. Timeouts are hundreds of milliseconds rather than seconds.
#[allow(clippy::too_many_arguments)]
fn hardened_config(
    listen: SocketAddr,
    backend: SocketAddr,
    max_connections: usize,
    max_per_ip: usize,
    header_timeout_ms: u64,
    body_timeout_ms: u64,
) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
max_connections = {max_connections}
max_connections_per_ip = {max_per_ip}
header_read_timeout_ms = {header_timeout_ms}
body_read_timeout_ms = {body_timeout_ms}

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
  rate_per_sec = 10000
  burst = 10000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

/// Like `hardened_config`, but with a tight `write_timeout_ms` instead of
/// the read-side timeouts — the write-side counterpart used by the slow
/// reader test below.
fn write_timeout_config(listen: SocketAddr, backend: SocketAddr, write_timeout_ms: u64) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
write_timeout_ms = {write_timeout_ms}

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
  rate_per_sec = 10000
  burst = 10000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

/// Slowloris: send a partial request head and never finish it. The server
/// must close the connection on its own rather than holding it forever.
#[tokio::test]
async fn a_connection_dribbling_headers_is_closed() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&hardened_config(listen, backend, 100, 100, 300, 10_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut victim = TcpStream::connect(listen).await.unwrap();
    // A request head that is never terminated by the blank line.
    victim
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();

    let started = Instant::now();
    let mut buf = [0u8; 64];
    // Returns 0 (EOF) or errors once the server gives up on us.
    let closed = tokio::time::timeout(Duration::from_secs(5), victim.read(&mut buf)).await;

    assert!(
        closed.is_ok(),
        "server never closed a slowloris connection within 5s"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "connection was held for {:?}, far longer than the 300ms header timeout",
        started.elapsed()
    );
}

/// Slow POST: announce a body and then dribble it. A size limit alone would
/// not catch this — the body is small, it is just arriving impossibly slowly.
#[tokio::test]
async fn a_connection_dribbling_a_body_is_timed_out() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&hardened_config(listen, backend, 100, 100, 5_000, 300)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut victim = TcpStream::connect(listen).await.unwrap();
    // Complete head promising 1000 bytes, then send only one.
    victim
        .write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nA")
        .await
        .unwrap();

    let started = Instant::now();
    let mut response = Vec::new();
    let outcome =
        tokio::time::timeout(Duration::from_secs(5), victim.read_to_end(&mut response)).await;

    assert!(outcome.is_ok(), "server never gave up on a slow body");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "slow body held the connection for {:?}",
        started.elapsed()
    );
    // Either a 408 or a bare close is acceptable; what matters is that the
    // connection did not persist.
    let text = String::from_utf8_lossy(&response);
    if !text.is_empty() {
        assert!(
            text.contains("408"),
            "expected a 408 for a timed-out body, got: {text}"
        );
    }
}

/// The per-IP cap must refuse a single source beyond its budget while the
/// global cap still has plenty of room.
#[tokio::test]
async fn a_single_source_cannot_exceed_its_per_ip_budget() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    // Global 50, per-IP 3: the global cap is nowhere near binding.
    let config = Config::parse(&hardened_config(listen, backend, 50, 3, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    // Hold three idle connections open — all from 127.0.0.1.
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(TcpStream::connect(listen).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A fourth is accepted at the TCP level then immediately closed by the
    // per-IP cap, so a read returns EOF rather than a response.
    let mut extra = TcpStream::connect(listen).await.unwrap();
    extra
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap_or(());

    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), extra.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "over-budget connection was neither served nor closed"
    );
    assert!(
        buf.is_empty(),
        "a connection over the per-IP cap was served: {}",
        String::from_utf8_lossy(&buf)
    );

    // Releasing one frees a slot for the same source.
    held.pop();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut allowed = TcpStream::connect(listen).await.unwrap();
    allowed
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(3), allowed.read(&mut buf))
        .await
        .expect("no response after a slot was freed")
        .expect("read failed");
    assert!(n > 0, "no bytes after freeing a per-IP slot");
    assert!(String::from_utf8_lossy(&buf[..n]).contains("200"));
}

async fn connect_from(listen: SocketAddr, source_octet: u8) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket
        .bind(SocketAddr::from(([127, 0, 0, source_octet], 0)))
        .unwrap();
    socket.connect(listen).await.unwrap()
}

#[tokio::test]
async fn exhausting_the_global_cap_stops_accepting_until_a_slot_frees() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&hardened_config(listen, backend, 3, 2, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut held = vec![
        connect_from(listen, 1).await,
        connect_from(listen, 2).await,
        connect_from(listen, 3).await,
    ];
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut extra = connect_from(listen, 4).await;
    let mut buf = [0u8; 1];
    let stuck = tokio::time::timeout(Duration::from_millis(300), extra.read(&mut buf)).await;
    assert!(
        stuck.is_err(),
        "a connection over the global cap got a response before any slot freed, \
         even though its own source IP was nowhere near its per-IP budget"
    );

    held.remove(0);
    tokio::time::sleep(Duration::from_millis(150)).await;

    extra
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let n = tokio::time::timeout(Duration::from_secs(3), extra.read(&mut buf))
        .await
        .expect("no response after a global slot was freed")
        .expect("read failed");
    assert!(n > 0, "no bytes after freeing a global slot");
}

/// The write-side counterpart of the slowloris tests above: a client that
/// reads its response, then simply stops draining its socket, must not be
/// able to hold the connection open forever either.
#[tokio::test]
async fn a_client_that_stops_reading_the_response_is_disconnected() {
    // Far larger than any default OS socket buffer, so the server's write
    // genuinely blocks once the client below stops draining it -- a small
    // response would fit entirely in the kernel's send buffer and "succeed"
    // immediately regardless of whether the peer ever reads it.
    let backend = spawn_large_body_backend(8 * 1024 * 1024).await;
    let listen = free_addr().await;
    let config = Config::parse(&write_timeout_config(listen, backend, 300)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    // A tiny receive buffer makes the client's side fill (and so the
    // server's write stall) almost immediately, rather than depending on
    // exactly how large the OS's default buffers happen to be.
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(1024).unwrap();
    let mut victim = socket.connect(listen).await.unwrap();
    victim
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();

    // Read once, to receive the response headers and the start of the body
    // -- an established response, not a first-byte stall (that is
    // `FirstByteDeadline`'s problem, not this one's).
    let mut buf = [0u8; 256];
    let n = victim
        .read(&mut buf)
        .await
        .expect("no response headers at all");
    assert!(n > 0, "connection closed before any response arrived");

    // Then stop reading entirely. The server must give up and close its
    // side rather than hold the connection (and the 8 MiB still unsent)
    // open indefinitely.
    let started = Instant::now();
    let closed = tokio::time::timeout(Duration::from_secs(5), victim.read(&mut buf)).await;
    assert!(
        closed.is_ok(),
        "server never closed a connection whose write stalled, within 5s"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "connection held for {:?}, far longer than the 300ms write timeout",
        started.elapsed()
    );
}

/// Ordinary traffic must be unaffected by the limits being present.
#[tokio::test]
async fn normal_requests_are_unaffected_by_the_limits() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&hardened_config(listen, backend, 100, 100, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    for _ in 0..5 {
        let status = reqwest::get(format!("http://{listen}/"))
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200);
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_global_cap_holds_under_a_stress_scale_burst_and_permits_are_not_leaked() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let max_connections = 200usize;
    let config = Config::parse(&hardened_config(
        listen,
        backend,
        max_connections,
        max_connections,
        5_000,
        5_000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let attempts = max_connections * 3;
    let mut connect_tasks = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        connect_tasks.push(tokio::spawn(TcpStream::connect(listen)));
    }
    let mut streams = Vec::with_capacity(attempts);
    for t in connect_tasks {
        if let Ok(Ok(s)) = t.await {
            streams.push(s);
        }
    }
    assert!(
        streams.len() >= max_connections,
        "the OS backlog only admitted {} of a {attempts}-connection burst, fewer than the \
         configured cap of {max_connections}",
        streams.len()
    );

    let mut probe_tasks = Vec::with_capacity(streams.len());
    for mut s in streams {
        probe_tasks.push(tokio::spawn(async move {
            let _ = s
                .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
                .await;
            let mut buf = [0u8; 64];
            let got = tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await;
            (matches!(got, Ok(Ok(n)) if n > 0), s)
        }));
    }
    let mut admitted = 0usize;
    let mut streams = Vec::with_capacity(probe_tasks.len());
    for t in probe_tasks {
        let (ok, s) = t.await.unwrap();
        if ok {
            admitted += 1;
        }
        streams.push(s);
    }
    assert_eq!(
        admitted, max_connections,
        "expected exactly the configured global cap to be admitted out of a {attempts}-connection burst, got {admitted}"
    );

    drop(streams);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut fresh = Vec::with_capacity(max_connections);
    for _ in 0..max_connections {
        fresh.push(TcpStream::connect(listen).await.unwrap());
    }
    let mut fresh_tasks = Vec::with_capacity(fresh.len());
    for mut s in fresh {
        fresh_tasks.push(tokio::spawn(async move {
            let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
            let mut buf = [0u8; 64];
            let got = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await;
            matches!(got, Ok(Ok(n)) if n > 0)
        }));
    }
    let mut reacquired = 0usize;
    for t in fresh_tasks {
        if t.await.unwrap() {
            reacquired += 1;
        }
    }
    assert_eq!(
        reacquired, max_connections,
        "global permits were not fully returned after every held connection closed: only {reacquired} of {max_connections} reacquired"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_source_hammering_far_past_its_per_ip_budget_is_cleanly_bounded() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let max_per_ip = 20usize;
    let config = Config::parse(&hardened_config(
        listen, backend, 500, max_per_ip, 5_000, 5_000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let attempts = max_per_ip * 10;
    let mut connect_tasks = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        connect_tasks.push(tokio::spawn(TcpStream::connect(listen)));
    }
    let mut streams = Vec::with_capacity(attempts);
    for t in connect_tasks {
        streams.push(t.await.unwrap().unwrap());
    }

    let mut probe_tasks = Vec::with_capacity(streams.len());
    for mut s in streams {
        probe_tasks.push(tokio::spawn(async move {
            let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
            let mut buf = [0u8; 64];
            let got = tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await;
            (matches!(got, Ok(Ok(n)) if n > 0), s)
        }));
    }
    let mut admitted = 0usize;
    let mut streams = Vec::with_capacity(probe_tasks.len());
    for t in probe_tasks {
        let (ok, s) = t.await.unwrap();
        if ok {
            admitted += 1;
        }
        streams.push(s);
    }
    assert_eq!(
        admitted, max_per_ip,
        "expected exactly the per-IP cap to be admitted out of a {attempts}-connection burst from one source, got {admitted}"
    );

    drop(streams);
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut allowed = TcpStream::connect(listen).await.unwrap();
    allowed
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(3), allowed.read(&mut buf))
        .await
        .expect("no response after the burst's connections closed")
        .expect("read failed");
    assert!(
        n > 0 && String::from_utf8_lossy(&buf[..n]).contains("200"),
        "per-IP slots were not fully returned after the burst closed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_distinct_ips_each_within_budget_are_not_throttled_by_a_shared_counter() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let per_ip = 3usize;
    let ip_count = 60u8;
    let config =
        Config::parse(&hardened_config(listen, backend, 400, per_ip, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut connect_tasks = Vec::with_capacity(ip_count as usize * per_ip);
    for octet in 1..=ip_count {
        for _ in 0..per_ip {
            connect_tasks.push(tokio::spawn(
                async move { connect_from(listen, octet).await },
            ));
        }
    }
    let mut streams = Vec::with_capacity(connect_tasks.len());
    for t in connect_tasks {
        streams.push(t.await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut probe_tasks = Vec::with_capacity(streams.len());
    for mut s in streams {
        probe_tasks.push(tokio::spawn(async move {
            let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
            let mut buf = [0u8; 64];
            let got = tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await;
            (matches!(got, Ok(Ok(n)) if n > 0), s)
        }));
    }
    let mut admitted = 0usize;
    let mut streams = Vec::with_capacity(probe_tasks.len());
    for t in probe_tasks {
        let (ok, s) = t.await.unwrap();
        if ok {
            admitted += 1;
        }
        streams.push(s);
    }
    assert_eq!(
        admitted,
        ip_count as usize * per_ip,
        "every source stayed within its own per-IP budget, yet not all {} connections were \
         admitted (only {admitted} were) -- per-IP state may be shared across sources instead of isolated",
        ip_count as usize * per_ip
    );

    let mut extra = connect_from(listen, 1).await;
    extra
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap_or(());
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(2), extra.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "an over-budget connection was never closed");
    assert!(
        buf.is_empty(),
        "a source already at its own per-IP budget was admitted anyway"
    );

    let mut fresh_ip = connect_from(listen, 200).await;
    fresh_ip
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(3), fresh_ip.read(&mut buf))
        .await
        .expect("a never-before-seen source was not served even though its budget is untouched")
        .expect("read failed");
    assert!(n > 0 && String::from_utf8_lossy(&buf[..n]).contains("200"));

    drop(streams);
}

#[tokio::test]
async fn per_ip_limits_apply_correctly_to_ipv6_sources() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr_v6().await;
    let config = Config::parse(&hardened_config(listen, backend, 50, 2, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(TcpStream::connect(listen).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut extra = TcpStream::connect(listen).await.unwrap();
    extra
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap_or(());
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), extra.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "an over-budget IPv6 connection was neither served nor closed"
    );
    assert!(
        buf.is_empty(),
        "an IPv6 connection over its per-IP cap was served: {}",
        String::from_utf8_lossy(&buf)
    );

    held.pop();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut allowed = TcpStream::connect(listen).await.unwrap();
    allowed
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(3), allowed.read(&mut buf))
        .await
        .expect("no response after freeing an IPv6 per-IP slot")
        .expect("read failed");
    assert!(n > 0, "no bytes after freeing an IPv6 per-IP slot");
    assert!(String::from_utf8_lossy(&buf[..n]).contains("200"));
}
