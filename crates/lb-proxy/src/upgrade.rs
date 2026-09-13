//! WebSocket / HTTP `Upgrade` proxying -- see `ProxyContext::websocket_idle_timeout`.
//!
//! `strip_hop_by_hop` removes `Connection`/`Upgrade` on every ordinary
//! request, which is correct for ordinary requests and fatal to a WebSocket
//! handshake -- this module is the separate path an `Upgrade` request takes
//! instead, bypassing `strip_hop_by_hop` (and the cache, the sticky pin, and
//! the retry loop, none of which apply to it) entirely.
//!
//! The backend leg cannot reuse `ProxyContext::client`/`per_backend_client`
//! (the pooled `hyper_util::client::legacy::Client`): that client has no
//! special-casing for a `101` response before deciding whether to return a
//! connection to its idle pool, and reusing a socket that's mid-WebSocket-
//! stream for an unrelated pooled request would be a real cross-talk bug.
//! This dials its own dedicated, one-off, non-pooled HTTP/1.1 connection per
//! upgrade instead, via `hyper::client::conn::http1::handshake` directly --
//! which also lets it pin ALPN to `http/1.1` only on a TLS backend
//! (`BackendConnector::tls_connector_http1_only`), since
//! `hyper::client::conn::http1` cannot parse an h2 byte stream and a pooled
//! connection's `[h2, http/1.1]` ALPN list would risk exactly that.
//!
//! v1 scope, deliberately: HTTP/1.1 only on both legs (h2's own upgrade
//! mechanism, RFC 8441 extended CONNECT, is a materially different
//! bootstrapping protocol and not attempted here -- an h2 client connection
//! has no `Upgrade` header semantics anyway, so it's naturally excluded by
//! `is_upgrade_request` rather than specially guarded against), and one
//! backend attempt with no retry onto a second backend on failure (unlike
//! the ordinary path's 2-attempt retry loop).

use crate::forward::backend_scheme_and_authority;
use crate::service::{empty_body, simple_response, strip_hop_by_hop, ProxyBody, ProxyContext};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, UPGRADE};
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lb_core::{BackendPool, Clock, LoadBalancer, ProxyStream, RateLimiter};
use lb_metrics::WebsocketUpgradeResult;
use std::sync::Arc;
use tokio::net::TcpStream;

/// True when this request is asking to switch protocols: `Connection`
/// contains an `upgrade` token (case-insensitive, comma-separated -- a
/// client may list several directives, e.g. `Connection: keep-alive,
/// Upgrade`) and `Upgrade` names something non-empty. Detected generically,
/// not specifically `websocket`: the mechanics below (dedicated backend
/// connection, `hyper::upgrade` on both legs, byte-pump relay) are the same
/// for any HTTP/1.1 `Upgrade`, not just WebSocket.
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let has_upgrade_token = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    let has_upgrade_header = headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty());
    has_upgrade_token && has_upgrade_header
}

/// Picks a backend, dials it directly (bypassing the pooled client), relays
/// the handshake, and -- on a `101` -- hands the two connections off to a
/// background byte-pump. Returns the response to send the client; the
/// actual relay (when it happens at all) runs in a spawned task, since the
/// client's own upgrade only completes once hyper has sent this response
/// and handed off the connection.
pub async fn handle_upgrade<R, C>(
    mut req: Request<Incoming>,
    ctx: &ProxyContext<R, C>,
    pool: &Arc<BackendPool>,
    balancer: &Arc<dyn LoadBalancer>,
    key: &str,
) -> Response<ProxyBody>
where
    R: RateLimiter,
    C: Clock,
{
    let Some(backend_id) = balancer.pick(pool, key) else {
        return simple_response(StatusCode::SERVICE_UNAVAILABLE, "no healthy backend");
    };
    let Some(backend) = pool.backend(&backend_id) else {
        return simple_response(StatusCode::SERVICE_UNAVAILABLE, "no healthy backend");
    };

    // Also tells us, by construction, that `backend.server_name` is present
    // whenever `ctx.backend_tls` is set -- `backend_scheme_and_authority`
    // only returns `Some` for `(backend_tls: true, server_name: None)`'s
    // opposite case, same invariant the ordinary request path relies on.
    let Some((scheme, authority)) = backend_scheme_and_authority(&backend, ctx.backend_tls) else {
        return simple_response(
            StatusCode::BAD_GATEWAY,
            "backend is missing the server_name its TLS configuration requires",
        );
    };
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let Ok(uri) = hyper::Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
    else {
        return simple_response(StatusCode::BAD_GATEWAY, "backend could not be addressed");
    };

    let connect_and_handshake = async {
        let tcp = TcpStream::connect(backend.address).await?;
        if let Some(keepalive) = &ctx.backend_tcp_keepalive {
            apply_tcp_keepalive(&tcp, keepalive);
        }
        let io: Box<dyn ProxyStream> = if let Some(connector) = &ctx.backend_tls_connector {
            let server_name = backend
                .server_name
                .clone()
                .expect("validated: server_name is required when backend_tls is set");
            let name = rustls::pki_types::ServerName::try_from(server_name).map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string())
            })?;
            let tls = connector
                .tls_connector_http1_only()
                .connect(name, tcp)
                .await?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };
        hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(|err| std::io::Error::other(err.to_string()))
    };
    let (mut sender, conn) =
        match tokio::time::timeout(ctx.forward_timeout, connect_and_handshake).await {
            Ok(Ok(pair)) => pair,
            _ => {
                ctx.metrics
                    .record_websocket_upgrade(WebsocketUpgradeResult::BackendUnreachable);
                return simple_response(StatusCode::BAD_GATEWAY, "backend unreachable");
            }
        };
    // Never pooled: this task's only job is driving this one connection,
    // including its eventual upgrade handoff.
    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            tracing::debug!(error = %err, "websocket backend connection driver ended");
        }
    });

    // Headers copied verbatim -- unlike the ordinary path's
    // `build_outbound_request`, `strip_hop_by_hop` must NOT run here:
    // `Connection`, `Upgrade`, and `Sec-WebSocket-*` all have to reach the
    // backend intact for it to answer the handshake correctly.
    let mut builder = Request::builder().method(req.method().clone()).uri(uri);
    for (name, value) in req.headers().iter() {
        builder = builder.header(name, value);
    }
    let Ok(outbound) = builder.body(Empty::<Bytes>::new()) else {
        return simple_response(StatusCode::BAD_GATEWAY, "backend could not be addressed");
    };

    let mut backend_resp =
        match tokio::time::timeout(ctx.forward_timeout, sender.send_request(outbound)).await {
            Ok(Ok(resp)) => resp,
            _ => {
                ctx.metrics
                    .record_websocket_upgrade(WebsocketUpgradeResult::BackendUnreachable);
                return simple_response(StatusCode::BAD_GATEWAY, "backend unreachable");
            }
        };

    if backend_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        // The backend declined (or doesn't support) the upgrade -- there is
        // nothing left to relay, so this becomes an ordinary response,
        // hop-by-hop stripped normally like any other.
        ctx.metrics
            .record_websocket_upgrade(WebsocketUpgradeResult::BackendDeclined);
        let (mut parts, body) = backend_resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        return Response::from_parts(parts, body.boxed());
    }

    // Must happen before `req`/`backend_resp` are dropped -- `on_upgrade`
    // registers against the message, not against anything with a shorter
    // lifetime, so the futures below outlive this function returning.
    let client_upgrade = hyper::upgrade::on(&mut req);
    let backend_upgrade = hyper::upgrade::on(&mut backend_resp);
    let (parts, _body) = backend_resp.into_parts();

    ctx.metrics
        .record_websocket_upgrade(WebsocketUpgradeResult::Success);
    let idle_timeout = ctx.websocket_idle_timeout;
    tokio::spawn(async move {
        // Resolves only once hyper has actually sent the `101` response
        // this function is about to return and handed off the connection --
        // the relay cannot start any earlier than that.
        match tokio::try_join!(client_upgrade, backend_upgrade) {
            Ok((client_upgraded, backend_upgraded)) => {
                let (client_read, client_write) = tokio::io::split(TokioIo::new(client_upgraded));
                let (backend_read, backend_write) =
                    tokio::io::split(TokioIo::new(backend_upgraded));
                // try_join!, not select!: half-close in either direction
                // must not tear down the other, same reasoning as
                // `lb_tcp::session`'s own TCP passthrough.
                let to_backend = lb_tcp::pump(client_read, backend_write, idle_timeout);
                let to_client = lb_tcp::pump(backend_read, client_write, idle_timeout);
                if let Err(err) = tokio::try_join!(to_backend, to_client) {
                    tracing::debug!(error = %err, "websocket relay ended");
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "websocket upgrade handoff failed");
            }
        }
    });

    // The real work happens in the spawned task above; this only carries
    // the `101` and its headers (verbatim -- see the outbound-request
    // comment above for why) back to the client.
    Response::from_parts(parts, empty_body())
}

/// Fire-and-log, never fatal: a keepalive that fails to apply (an unusual
/// platform/socket state) must not take this connection down over a purely
/// advisory setting. Duplicated (not shared across a crate boundary) from
/// `lb_tcp::session`'s own copy -- see `lb-core`'s `Cargo.toml` for why
/// `lb-core` itself cannot host this. `set_tcp_keepalive` also turns on
/// `SO_KEEPALIVE` itself, so no separate call is needed.
fn apply_tcp_keepalive(stream: &TcpStream, cfg: &lb_core::TcpKeepaliveConfig) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(cfg.time_secs))
        .with_interval(std::time::Duration::from_secs(cfg.interval_secs))
        .with_retries(cfg.retries);
    if let Err(err) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        tracing::warn!(error = %err, "failed to set websocket backend tcp keepalive");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn a_websocket_handshake_is_an_upgrade_request() {
        let headers = headers_with(&[("connection", "Upgrade"), ("upgrade", "websocket")]);
        assert!(is_upgrade_request(&headers));
    }

    #[test]
    fn connection_header_with_several_tokens_is_still_detected() {
        let headers = headers_with(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket"),
        ]);
        assert!(is_upgrade_request(&headers));
    }

    #[test]
    fn an_ordinary_request_is_not_an_upgrade_request() {
        let headers = headers_with(&[("connection", "keep-alive")]);
        assert!(!is_upgrade_request(&headers));
    }

    #[test]
    fn connection_upgrade_without_an_upgrade_header_is_not_an_upgrade_request() {
        let headers = headers_with(&[("connection", "Upgrade")]);
        assert!(!is_upgrade_request(&headers));
    }

    #[test]
    fn an_upgrade_header_without_connection_upgrade_is_not_an_upgrade_request() {
        let headers = headers_with(&[("upgrade", "websocket")]);
        assert!(!is_upgrade_request(&headers));
    }

    #[test]
    fn no_headers_at_all_is_not_an_upgrade_request() {
        assert!(!is_upgrade_request(&HeaderMap::new()));
    }

    /// There's no meaningful way to assert on `SO_KEEPALIVE`'s actual
    /// *timing* behavior within a test's timescale -- this calls the real
    /// `apply_tcp_keepalive` against a real connected socket and checks the
    /// one directly observable effect: `SO_KEEPALIVE` itself gets turned on
    /// (a side effect of `set_tcp_keepalive`), which it was not before.
    #[tokio::test]
    async fn applying_tcp_keepalive_turns_on_so_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        assert!(
            !socket2::SockRef::from(&stream).keepalive().unwrap(),
            "keepalive should be off by default"
        );

        apply_tcp_keepalive(
            &stream,
            &lb_core::TcpKeepaliveConfig {
                time_secs: 60,
                interval_secs: 10,
                retries: 6,
            },
        );

        assert!(
            socket2::SockRef::from(&stream).keepalive().unwrap(),
            "apply_tcp_keepalive should have turned SO_KEEPALIVE on"
        );
    }
}
