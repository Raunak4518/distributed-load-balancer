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
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
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
        // Nothing is listening on this port. Whether the OS reports this as
        // an instant refusal (Connect) or the attempt just hangs until our
        // own timeout fires (Timeout) is platform-dependent — on Windows,
        // unlike most Unix TCP stacks, a closed loopback port does not
        // reliably send an immediate RST, so this test accepts either
        // variant. lb-proxy's own retry logic treats them identically.
        let client = build_client();
        let req = Request::builder()
            .uri("http://127.0.0.1:1")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = forward(&client, req, Duration::from_secs(1)).await;
        assert!(matches!(
            result,
            Err(ForwardError::Connect | ForwardError::Timeout)
        ));
    }
}
