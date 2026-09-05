//! A DNS resolver that never touches real DNS.
//!
//! `service.rs` builds the L7 forwarding URI for a `backend_tls` listener
//! with `server_name` as the authority (`https://{server_name}:{port}...`)
//! so that SNI and hostname verification check the certificate's own name
//! rather than the address the operator configured. Handed to a stock
//! `hyper_util::client::legacy::connect::HttpConnector`, though, that same
//! authority is also what gets **dialed**: the connector resolves it via its
//! `Resolve` implementation (real DNS, by default) and connects to whatever
//! comes back. `backend.address` -- the IP the operator configured -- would
//! never be consulted at all.
//!
//! That silently reintroduces DNS-based backend resolution, which this
//! project explicitly defers to a later phase, and it is security-relevant:
//! if `server_name` resolves to anything via whatever DNS this process can
//! see, traffic would go there instead of the pinned backend, while still
//! presenting a certificate for that name.
//!
//! `PinnedResolver` is the fix. It is a fixed `server_name -> address` table
//! built once per listener from that listener's own (static) backend list,
//! wired into the `HttpConnector` in place of the default resolver -- see
//! `forward::build_client`. It never makes a real DNS query. A name with no
//! entry in the table is a connector error, surfaced the same way a real DNS
//! failure would be -- not a panic -- though it should be unreachable in
//! practice, since every forwarded request's URI host is always one of this
//! listener's own configured `server_name`s.
use hyper_util::client::legacy::connect::dns::Name;
use std::collections::HashMap;
use std::future::{ready, Ready};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_service::Service;

/// A `server_name -> address` table, usable as a custom resolver for
/// `hyper_util::client::legacy::connect::HttpConnector::new_with_resolver`.
///
/// Cheap to clone: `HttpConnector` clones its resolver on every call
/// (`Service::call` takes `&mut self`, and the client clones the whole
/// connector per request), so the table itself is behind an `Arc`.
#[derive(Clone, Debug)]
pub struct PinnedResolver {
    table: Arc<HashMap<String, SocketAddr>>,
}

impl PinnedResolver {
    pub fn new(table: HashMap<String, SocketAddr>) -> Self {
        PinnedResolver {
            table: Arc::new(table),
        }
    }
}

/// A queried name has no pinned address. Should be unreachable in practice
/// -- see the module docs -- but reported as a connector error rather than a
/// panic, exactly as a real DNS failure would be.
#[derive(Debug)]
pub struct UnpinnedServerName(String);

impl std::fmt::Display for UnpinnedServerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no pinned backend address for server_name {:?}", self.0)
    }
}

impl std::error::Error for UnpinnedServerName {}

// The bound hyper-util's `HttpConnector<R>` actually needs is a sealed
// `Resolve` trait, but that trait has a blanket impl for anything
// implementing `tower_service::Service<Name>` whose `Response` is an
// `Iterator<Item = SocketAddr>` and whose `Error` converts into a boxed
// `std::error::Error` -- see hyper-util's `connect::dns` module docs. This is
// that impl.
impl Service<Name> for PinnedResolver {
    type Response = std::iter::Once<SocketAddr>;
    type Error = UnpinnedServerName;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        ready(
            self.table
                .get(name.as_str())
                .copied()
                .map(std::iter::once)
                .ok_or_else(|| UnpinnedServerName(name.as_str().to_string())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn a_pinned_name_resolves_to_its_configured_address_only() {
        let addr: SocketAddr = "203.0.113.7:8443".parse().unwrap();
        let mut table = HashMap::new();
        table.insert("backend.invalid".to_string(), addr);
        let mut resolver = PinnedResolver::new(table);

        let mut addrs = resolver
            .call(Name::from_str("backend.invalid").unwrap())
            .await
            .expect("a pinned name must resolve");
        assert_eq!(addrs.next(), Some(addr));
        assert_eq!(addrs.next(), None, "exactly one address, not a list");
    }

    /// The whole point: this must never fall through to a real DNS lookup.
    /// Querying a name that is not in the table is an error, not a lookup.
    #[tokio::test]
    async fn an_unpinned_name_is_an_error_not_a_panic() {
        let mut resolver = PinnedResolver::new(HashMap::new());
        let result = resolver
            .call(Name::from_str("nowhere.example").unwrap())
            .await;
        assert!(result.is_err());
    }
}
