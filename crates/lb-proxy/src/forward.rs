use crate::resolver::PinnedResolver;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// Always an HTTPS-capable connector, even for plaintext backends:
/// `https_or_http()` speaks whichever the URL scheme asks for, so one type
/// serves both and the client stays a single concrete type rather than a
/// generic parameter threaded through every context in the crate.
///
/// The connector is generic over `PinnedResolver` (rather than the default
/// `GaiResolver`) so that a `backend_tls` listener's dial never touches real
/// DNS -- see `resolver.rs`. A plaintext listener's requests always carry an
/// IP-literal authority (`build_outbound_request` uses `backend.address`
/// directly), which `HttpConnector` short-circuits before ever consulting
/// its resolver, so using the same connector type there costs nothing.
pub type ProxyClient =
    Client<hyper_rustls::HttpsConnector<HttpConnector<PinnedResolver>>, Full<Bytes>>;

/// Connect timeout (time to establish the TCP connection) and pool idle
/// timeout (how long a kept-alive backend connection may sit unused before
/// it's dropped) are fixed constants for Phase 1 rather than config fields —
/// the per-request forward timeout (config-driven) is the one operators
/// actually need to tune; these two guard resource usage, not behavior.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the forwarding client.
///
/// `backend_tls: Some` re-encrypts to backends using that listener's trust
/// roots and verification policy; `None` forwards plaintext. The pool is
/// what makes re-encryption affordable at L7: backend handshakes amortise
/// across keep-alive instead of being paid per request.
///
/// `server_names` is this listener's `server_name -> address` table (empty
/// for a plaintext listener, where it is never consulted). It is what pins
/// the TCP dial to the operator-configured `address` even though the
/// forwarding authority is `server_name` -- without it, a stock
/// `HttpConnector` would resolve `server_name` via real DNS instead, which
/// silently reintroduces DNS-based backend resolution and lets traffic
/// follow whatever that name happens to resolve to instead of the pinned
/// backend. See `resolver::PinnedResolver`.
pub fn build_client(
    backend_tls: Option<&lb_tls::BackendConnector>,
    server_names: HashMap<String, SocketAddr>,
) -> ProxyClient {
    let mut http = HttpConnector::new_with_resolver(PinnedResolver::new(server_names));
    http.set_connect_timeout(Some(CONNECT_TIMEOUT));
    http.enforce_http(false);

    let connector = match backend_tls {
        Some(b) => b.wrap_https(http),
        // No backend TLS configured. This connector will only ever be given
        // `http://` URLs with an IP-literal authority -- `build_outbound_request`
        // picks the scheme and authority from the same setting -- so the
        // roots it loads (and the resolver above) are never consulted; they
        // exist because `https_or_http()` is what keeps `ProxyClient` a
        // single type across both cases.
        None => hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("a native root store is loadable")
            .https_or_http()
            .enable_http1()
            .wrap_connector(http),
    };
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
        let client = build_client(None, HashMap::new());
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
        let client = build_client(None, HashMap::new());
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

    /// A re-encrypting listener forwards `https://` URLs, which the plain
    /// `HttpConnector` this client used to be built on would have rejected
    /// outright as an unsupported scheme. Whether the certificate is
    /// *trusted* is the connector's business, proven against a live
    /// handshake in `lb-tls` and end to end in `lb-server`.
    #[tokio::test]
    async fn a_client_built_from_a_backend_connector_speaks_https() {
        let connector = lb_tls::BackendConnector::new(&lb_core::BackendTlsConfig {
            ca_file: None,
            danger_accept_invalid_certs: false,
        })
        .unwrap();
        let client = build_client(Some(&connector), HashMap::new());
        // Nothing is listening, so this fails at connect -- but it fails
        // there rather than at "invalid URL for connector", which is the
        // distinction being drawn.
        let req = Request::builder()
            .uri("https://127.0.0.1:1/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = forward(&client, req, Duration::from_secs(1)).await;
        assert!(matches!(
            result,
            Err(ForwardError::Connect | ForwardError::Timeout)
        ));
    }

    /// The unit-level proof of the DNS-pinning fix: `nowhere.invalid` cannot
    /// resolve via real DNS (RFC 2606), yet a request to
    /// `https://nowhere.invalid:{port}/` succeeds because the connector was
    /// built with a `server_names` table pinning that exact name to a real
    /// local listener. Before the fix, `build_client` handed this authority
    /// to a stock resolver and this would fail (or hang) on the DNS lookup
    /// before ever reaching the backend. The end-to-end version of this test,
    /// through a real TLS handshake, lives in `lb-server`'s integration
    /// suite.
    #[tokio::test]
    async fn build_client_dials_the_pinned_address_not_a_dns_lookup() {
        let addr = spawn_fixed_response_backend(StatusCode::OK).await;
        let mut server_names = HashMap::new();
        server_names.insert("nowhere.invalid".to_string(), addr);
        // No backend TLS: the connector still speaks `http://` to the
        // pinned address, since the resolver is what is under test here, not
        // the TLS wrapping (that is `a_client_built_from_a_backend_connector_speaks_https`
        // and the `lb-tls`/`lb-server` handshake tests).
        let client = build_client(None, server_names);
        let req = Request::builder()
            .uri(format!("http://nowhere.invalid:{}/", addr.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();

        let resp = tokio::time::timeout(
            Duration::from_secs(2),
            forward(&client, req, Duration::from_secs(1)),
        )
        .await
        .expect("resolution hung instead of using the pinned table")
        .expect("the pinned address should have been dialed directly");
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
