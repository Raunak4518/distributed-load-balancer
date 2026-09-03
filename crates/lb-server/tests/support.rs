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
