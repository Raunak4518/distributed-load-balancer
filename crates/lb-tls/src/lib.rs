mod acceptor;
mod certs;
mod connector;
mod error;
mod reload;
mod resolver;
mod transport;

pub use acceptor::{install_crypto_provider, HandshakeError, TlsAcceptor};
pub use certs::{load_certificate, LoadedCert};
pub use connector::BackendConnector;
pub use error::TlsError;
pub use reload::{reload_once, spawn_reloader, FileStamp, ReloadReport};
pub use resolver::{CertStore, SniResolver};
pub use transport::BackendTlsTransport;

// Loaded once here and re-exported via `use` from each module's inline test
// suite, rather than each of them declaring its own `#[path]` mod pointing
// at the same file: three separate `mod` items loading one physical file
// trips `clippy::duplicate_mod`, and rightly so once there are three of
// them, not two -- the fix clippy itself suggests is exactly this.
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub(crate) mod test_support;
