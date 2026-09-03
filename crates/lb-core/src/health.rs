use crate::backend::Backend;
use std::future::Future;

/// A liveness check for one backend. Implementations decide what "alive"
/// means for their protocol — an HTTP 2xx, a successful TCP connect, a
/// protocol-specific handshake.
///
/// The `+ Send` on the returned future is required: active checkers run
/// inside `tokio::spawn`, which needs the future it drives to be Send.
pub trait HealthProbe: Send + Sync {
    fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send;
}
