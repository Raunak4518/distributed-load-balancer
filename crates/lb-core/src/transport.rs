use crate::backend::Backend;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// A duplex byte stream the L4 data plane can pump through.
///
/// Blanket-implemented, so a `TcpStream` and a TLS stream both qualify
/// without either crate naming the other.
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ProxyStream for T {}

/// The future `OutboundTransport::wrap` returns.
///
/// Named rather than spelled out inline purely for legibility -- the shape
/// is a boxed, pinned, `Send` future because the trait has to stay
/// object-safe, and `lb-tcp` holds it as `Arc<dyn OutboundTransport>`.
pub type WrapFuture<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<Box<dyn ProxyStream>>> + Send + 'a>>;

/// Wraps an established outbound connection — in practice by completing a
/// TLS handshake against `server_name`.
///
/// This trait is the reason `lb-tcp` never learns what rustls is: the L4
/// data plane sees only this, and `lb-tls` provides the implementation.
/// `server_name` is the name on the backend's certificate, which is not the
/// address the connection was made to.
pub trait OutboundTransport: Send + Sync {
    fn wrap(
        &self,
        stream: Box<dyn ProxyStream>,
        server_name: String,
        timeout: Duration,
    ) -> WrapFuture<'_>;
}

/// The future `ProbeClient::get` returns.
///
/// Named for the same reason as `WrapFuture`: a boxed, pinned, `Send` future
/// so the trait stays object-safe, spelled out inline only once.
pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = Option<u16>> + Send + 'a>>;

/// Issues a health-probe GET against `backend`, using the same client, trust
/// roots and verification policy real traffic forwards through.
///
/// This trait is the L7 counterpart of `OutboundTransport`: it is what lets
/// `lb-healthcheck` probe over the data plane's own transport while still
/// depending on nothing but `lb-core` -- it must not depend on `lb-proxy`
/// (that would be a cycle, since `lb-proxy` depends on it) nor on `lb-tls`.
///
/// It takes `backend` and the decision inputs (`path`, `backend_tls`) rather
/// than a pre-built URL, so the scheme/authority decision -- https with the
/// certificate's `server_name` as authority, or plain http with `address` --
/// is made in exactly one place, the same helper the implementation already
/// uses to build real forwarded requests. A probe that built its own URL
/// could silently drift from that decision; this cannot.
///
/// Returns the response status, or `None` when the request could not be
/// completed at all -- connect failure, TLS verification failure, timeout, or
/// a backend that cannot be addressed under this listener's configuration at
/// all. Deciding which statuses count as "healthy" belongs to the probe, not
/// here, which is why this returns a code rather than a bool.
pub trait ProbeClient: Send + Sync {
    fn get(
        &self,
        backend: &Backend,
        path: &str,
        backend_tls: bool,
        timeout: Duration,
    ) -> ProbeFuture<'_>;
}
