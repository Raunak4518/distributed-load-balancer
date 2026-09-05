use crate::resolver::PinnedResolver;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
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

/// How much of a health-check response body we are willing to read.
///
/// Not a tuning knob and deliberately not configurable: a `/health`
/// endpoint answers with a status line, and at most a short JSON summary.
/// 64 KiB is absurdly generous for that -- it is sized to never reject a
/// legitimate health response, not to be tight. Its job is to put *some*
/// ceiling on what a broken or hostile backend can make the probe allocate,
/// once per backend per interval, for as long as the process runs.
const MAX_PROBE_BODY_BYTES: usize = 64 * 1024;

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
        // roots below (and the resolver above) are never consulted; an empty
        // `RootCertStore` exists only because `https_or_http()` is what
        // keeps `ProxyClient` a single type across both cases.
        //
        // Deliberately *empty*, not `with_native_roots()`: this listener
        // needs zero TLS material, so loading (and validating non-empty) the
        // OS trust store here would be pure downside -- a scratch/distroless
        // container with no `ca-certificates` package would fail to start a
        // plaintext-only listener for no reason. Building the config
        // directly like this is also infallible, unlike
        // `with_native_roots()`, which can fail if the store turns out
        // empty -- there is nothing to fail here.
        None => {
            let roots = rustls::RootCertStore::empty();
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls_config)
                .https_or_http()
                .enable_http1()
                .wrap_connector(http)
        }
    };
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .build(connector)
}

/// The scheme and authority a request to `backend` must be addressed with.
///
/// **The single decision site.** `service::build_outbound_request` (real
/// traffic) and `ProbeCapableClient::get` (health probes) both call this, so
/// a probe cannot end up addressing a backend differently from the traffic it
/// is supposed to be predicting the fate of. Writing the decision out twice
/// and keeping the two in sync by hand is exactly how a probe ends up
/// reporting a backend healthy that every real request fails against.
///
/// `None` means this backend cannot be addressed at all: the listener
/// re-encrypts but the backend has no `server_name`. Config validation makes
/// that unreachable, and it is spelled out rather than folded into the
/// plaintext arm because falling back to `http` would silently defeat the
/// encryption that was asked for.
pub(crate) fn backend_scheme_and_authority(
    backend: &lb_core::Backend,
    backend_tls: bool,
) -> Option<(&'static str, String)> {
    match (backend_tls, backend.server_name.as_deref()) {
        // The authority is the name on the certificate, not the address we
        // dial. That is what makes SNI and hostname verification check the
        // certificate's own name rather than an IP literal no certificate is
        // ever issued for. The dial itself is pinned back to `address` by
        // `PinnedResolver`.
        (true, Some(name)) => Some(("https", format!("{name}:{}", backend.address.port()))),
        (true, None) => None,
        (false, _) => Some(("http", backend.address.to_string())),
    }
}

/// A [`ProxyClient`] that can also serve as an [`lb_core::ProbeClient`].
///
/// The wrapper exists only because Rust's orphan rule forbids implementing a
/// foreign trait (`ProbeClient`, from `lb-core`) for a foreign type
/// (`ProxyClient`, a `hyper_util` type alias) directly. It changes nothing
/// about the client itself: `Client` is a cheap handle whose connection pool
/// and connector live behind an `Arc`, so a clone of one *is* the same
/// client -- same pool, same trust roots, same verification policy, same
/// pinned resolver -- not a similar one.
///
/// That is the whole point. A probe built on a separately-constructed client
/// would carry its own TLS stack and its own trust configuration, and could
/// report a backend healthy that every real request fails against.
pub struct ProbeCapableClient(pub ProxyClient);

impl lb_core::ProbeClient for ProbeCapableClient {
    fn get(
        &self,
        backend: &lb_core::Backend,
        path: &str,
        backend_tls: bool,
        timeout: Duration,
    ) -> lb_core::ProbeFuture<'_> {
        // Everything borrowed from the caller is consumed here, before the
        // future is built, so the returned future borrows only `self`.
        let Some((scheme, authority)) = backend_scheme_and_authority(backend, backend_tls) else {
            return Box::pin(std::future::ready(None));
        };
        // Fallible rather than `expect`: `health_check.path` is free text
        // from a config file and, unlike the forwarding path, has not been
        // through a URI parser already. An unusable path makes the backend
        // unprobeable, which is a health verdict, not a reason to kill the
        // checker task.
        let Ok(uri) = hyper::Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query(path)
            .build()
        else {
            return Box::pin(std::future::ready(None));
        };
        let Ok(req) = Request::builder().uri(uri).body(Full::new(Bytes::new())) else {
            return Box::pin(std::future::ready(None));
        };
        Box::pin(async move {
            let resp = forward(&self.0, req, timeout).await.ok()?;
            let status = resp.status().as_u16();
            // The body is drained so the pooled connection can be reused
            // instead of being closed after every probe -- otherwise a
            // re-encrypting listener pays a full backend TLS handshake on
            // every health check.
            //
            // Both bounds on that drain are load-bearing, and neither is
            // redundant. The timeout stops a backend that answers a status
            // and then dribbles bytes forever from pinning this task. The
            // *size* cap stops one that answers and then pushes as fast as it
            // can from making us allocate whatever fits in `timeout` -- per
            // backend, per interval, forever. This project does not trust its
            // backends: verifying their certificates is the entire reason
            // this crate re-encrypts at all, and an unbounded read from one
            // would reintroduce exactly the unbounded-resource-consumption
            // class the request path already caps
            // (`max_request_body_bytes`).
            let limited = Limited::new(resp.into_body(), MAX_PROBE_BODY_BYTES);
            match tokio::time::timeout(timeout, limited.collect()).await {
                Ok(Ok(_)) => Some(status),
                // Named separately from the catch-all below only so an
                // operator sees *why* a backend that answered 200 still
                // reports unhealthy -- without this, hitting the cap looks
                // identical to a timeout or a dropped connection, and size
                // is the one cause among the three that config
                // (`MAX_PROBE_BODY_BYTES` is not a tuning knob, but the
                // backend's response is) can actually explain.
                Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
                    tracing::debug!(
                        cap_bytes = MAX_PROBE_BODY_BYTES,
                        "health probe response body exceeded the size cap; reporting unreachable"
                    );
                    None
                }
                // Over the cap, or the body failed mid-read, or it never
                // finished. Reported as unreachable rather than as the status
                // we already hold: a `/health` endpoint that streams
                // megabytes is not healthy under any useful definition, and
                // the connection is not safe to pool either way.
                _ => None,
            }
        })
    }
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

    /// `build_client(None, ..)` (no `[listeners.backend_tls]`) must not call
    /// any fallible root-store constructor: `with_native_roots()` (what this
    /// branch used to call) can fail on a scratch/distroless container with
    /// no OS certificate store, even though a plaintext-only listener needs
    /// zero TLS material. There is no practical way to force this test
    /// machine's *actual* native store empty, so this instead confirms the
    /// only thing that matters -- that the plaintext path builds a fully
    /// working client with no root store loaded at all. If the fallible
    /// constructor ever crept back in, this would still pass on a normal
    /// dev machine; `forwards_and_returns_backend_response` above and
    /// `connect_failure_is_reported` below are the ones that would start
    /// failing (intermittently, machine-dependently) if it panicked.
    #[test]
    fn a_plaintext_only_client_builds_without_needing_any_trust_store() {
        let _client = build_client(None, HashMap::new());
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

    fn backend(name: Option<&str>, addr: SocketAddr) -> lb_core::Backend {
        lb_core::Backend::new("b1", addr, 1, name.map(str::to_string))
    }

    /// A backend that answers 200 with a body of exactly `len` bytes, for
    /// exercising the probe's body cap from both sides.
    async fn spawn_sized_body_backend(len: usize) -> SocketAddr {
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
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(vec![b'x'; len]))))
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        addr
    }

    /// The probe reports the status it got, over the same client and the same
    /// connector real traffic uses -- not over a client of its own.
    #[tokio::test]
    async fn the_probe_client_reports_the_backend_status() {
        use lb_core::ProbeClient;

        let addr = spawn_fixed_response_backend(StatusCode::NO_CONTENT).await;
        let probe = ProbeCapableClient(build_client(None, HashMap::new()));
        let status = probe
            .get(
                &backend(None, addr),
                "/health",
                false,
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(status, Some(204));
    }

    /// A backend that cannot be reached at all is `None`, not a status. This
    /// is the arm a refused backend certificate arrives through, and the
    /// probe's whole verdict rests on it not being mistaken for "no answer,
    /// assume fine".
    #[tokio::test]
    async fn the_probe_client_reports_none_when_the_backend_cannot_be_reached() {
        use lb_core::ProbeClient;

        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let probe = ProbeCapableClient(build_client(None, HashMap::new()));
        let status = probe
            .get(
                &backend(None, dead),
                "/health",
                false,
                Duration::from_millis(500),
            )
            .await;
        assert_eq!(status, None);
    }

    /// A re-encrypting listener with a nameless backend has nothing to verify
    /// against, so the probe reports it unreachable rather than quietly
    /// probing it in plaintext -- exactly what `build_outbound_request` does
    /// with the same backend, because both go through
    /// `backend_scheme_and_authority`.
    #[tokio::test]
    async fn the_probe_client_refuses_a_nameless_backend_on_a_re_encrypting_listener() {
        use lb_core::ProbeClient;

        let addr = spawn_fixed_response_backend(StatusCode::OK).await;
        let probe = ProbeCapableClient(build_client(None, HashMap::new()));
        let status = probe
            .get(
                &backend(None, addr),
                "/health",
                true,
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(
            status, None,
            "a nameless backend was probed anyway -- in plaintext, since there \
             is no name to demand a certificate for"
        );
    }

    /// A backend is not trusted -- verifying its certificate is the whole
    /// reason this crate re-encrypts -- so it must not be able to make the
    /// probe allocate without bound. A `/health` that answers 200 and then
    /// pushes far more than any health response could legitimately carry is
    /// reported as unreachable, not as a 200.
    #[tokio::test]
    async fn the_probe_client_refuses_an_oversized_health_response() {
        use lb_core::ProbeClient;

        let addr = spawn_sized_body_backend(MAX_PROBE_BODY_BYTES + 1).await;
        let probe = ProbeCapableClient(build_client(None, HashMap::new()));
        let status = probe
            .get(
                &backend(None, addr),
                "/health",
                false,
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(
            status, None,
            "an unbounded health-check body was buffered and reported as healthy"
        );
    }

    /// The matched control: a body that fits is read and the status reported,
    /// so the test above cannot pass by rejecting every body.
    #[tokio::test]
    async fn the_probe_client_accepts_a_health_response_within_the_cap() {
        use lb_core::ProbeClient;

        let addr = spawn_sized_body_backend(MAX_PROBE_BODY_BYTES).await;
        let probe = ProbeCapableClient(build_client(None, HashMap::new()));
        let status = probe
            .get(
                &backend(None, addr),
                "/health",
                false,
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(status, Some(200));
    }

    /// The decision itself. Both the forwarding path and the probe read the
    /// scheme and authority from here, so this is the one place either could
    /// be wrong -- and if someone re-inlines the match in `service.rs`, the
    /// URI test over there and this one can start to disagree, which is the
    /// drift the shared helper exists to make impossible.
    #[test]
    fn a_re_encrypting_backend_is_addressed_by_its_certificate_name() {
        let b = backend(Some("web1.internal"), "10.0.0.5:8443".parse().unwrap());
        assert_eq!(
            backend_scheme_and_authority(&b, true),
            Some(("https", "web1.internal:8443".to_string()))
        );
        // The same backend on a plaintext listener: the address, not the
        // name, and no silent upgrade of the scheme.
        assert_eq!(
            backend_scheme_and_authority(&b, false),
            Some(("http", "10.0.0.5:8443".to_string()))
        );
        assert_eq!(
            backend_scheme_and_authority(&backend(None, "10.0.0.5:8443".parse().unwrap()), true),
            None
        );
    }
}
