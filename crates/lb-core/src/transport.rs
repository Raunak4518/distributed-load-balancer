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
