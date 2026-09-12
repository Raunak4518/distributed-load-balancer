mod support;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lb_core::Config;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use support::spawn_counting_backend;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A stand-in OTLP collector: accepts any POST and counts how many it got.
/// Proving spans actually leave the process over the wire is the point --
/// asserting the config parses is not the same claim.
async fn spawn_fake_otlp_receiver() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let hits = Arc::clone(&hits_clone);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        let _ = req.into_body().collect().await;
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, hits)
}

/// The real proof for `[tracing]`: a request through a running `lb-server`
/// must produce a span, and that span must actually leave the process as an
/// OTLP export -- not just that the config section parses. See
/// `lb_proxy::service::handle`'s span and `lb-tracing`'s exporter wiring.
// Multi-threaded, not the default single-threaded flavor: `guard.shutdown()`
// below blocks synchronously while it flushes the export, and on a
// single-threaded runtime that starves the fake receiver's own tokio-spawned
// accept/serve task -- confirmed by actually hitting the deadlock, not
// assumed (the connect succeeded; the read of the response then timed out,
// because the runtime thread reading it was the same one stuck in
// `shutdown()`).
#[tokio::test(flavor = "multi_thread")]
async fn spans_are_exported_to_the_configured_otlp_collector() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let (receiver, hits) = spawn_fake_otlp_receiver().await;
    let listen = free_addr().await;

    let config = Config::parse(&format!(
        r#"
[tracing]
otlp_endpoint = "http://{receiver}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

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
  rate_per_sec = 100
  burst = 100

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    ))
    .unwrap();

    let guard = lb_tracing::init(&config.logging, config.tracing.as_ref()).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    for _ in 0..5 {
        let _ = reqwest::get(format!("http://127.0.0.1:{}/", listen.port())).await;
    }

    // The batch span processor flushes on its own schedule; `shutdown`
    // forces a final flush rather than waiting on it.
    guard.shutdown();

    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "the fake OTLP collector never received a span export POST"
    );
}
