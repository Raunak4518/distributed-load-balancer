use std::net::SocketAddr;
use std::sync::Arc;

/// `Arc<str>` rather than `String`: this id is cloned on every backend
/// selection (`BackendPool::eligible_backends()`/`all_backend_ids()` clone
/// one per backend per request), and an `Arc` clone is a refcount bump
/// rather than a heap allocation + copy. `PartialEq`/`Eq`/`Hash`/`Ord` on
/// `Arc<str>` all compare the pointed-to string, not the pointer, so
/// equality and map/set behavior are unchanged from the `String` version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BackendId(pub Arc<str>);

impl BackendId {
    pub fn new(id: impl Into<Arc<str>>) -> Self {
        BackendId(id.into())
    }
}

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    pub id: BackendId,
    pub address: SocketAddr,
    /// Consulted only by `WeightedRoundRobin` and `ConsistentHash` (see
    /// `lb-balancer`) -- `RoundRobin` and `LeastConnections` ignore it.
    pub weight: u32,
    /// The name on the backend's certificate, which is a different fact from
    /// the address we dial: backends are addressed as `IP:port`, but
    /// certificates are issued for hostnames. Carrying it separately is what
    /// lets SNI and hostname verification check the certificate's name
    /// rather than the address the connection happened to be made to.
    ///
    /// `None` for backends that are never spoken to over TLS. Config
    /// validation requires it whenever `backend_tls` is set, so an empty
    /// name never reaches a TLS handshake.
    pub server_name: Option<String>,
}

impl Backend {
    pub fn new(
        id: impl Into<Arc<str>>,
        address: SocketAddr,
        weight: u32,
        server_name: Option<String>,
    ) -> Self {
        Backend {
            id: BackendId::new(id),
            address,
            weight,
            server_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn backend_new_sets_all_fields() {
        let b = Backend::new(
            "b1",
            "127.0.0.1:9001".parse().unwrap(),
            3,
            Some("b1.internal".to_string()),
        );
        assert_eq!(b.id, BackendId::new("b1"));
        assert_eq!(b.address.to_string(), "127.0.0.1:9001");
        assert_eq!(b.weight, 3);
        assert_eq!(b.server_name.as_deref(), Some("b1.internal"));
    }

    /// The address is where we dial; the name is what the certificate has to
    /// say. Conflating them is the mistake this field exists to prevent, so
    /// a backend with no configured name must not silently acquire its IP as
    /// one.
    #[test]
    fn a_backend_without_a_configured_name_has_none() {
        let b = Backend::new("b1", "127.0.0.1:9001".parse().unwrap(), 1, None);
        assert_eq!(b.server_name, None);
    }

    #[test]
    fn backend_id_is_hashable_and_comparable() {
        let mut set = HashSet::new();
        set.insert(BackendId::new("b1"));
        set.insert(BackendId::new("b1"));
        set.insert(BackendId::new("b2"));
        assert_eq!(set.len(), 2);
        assert!(set.contains(&BackendId::new("b1")));
    }

    #[test]
    fn backend_id_displays_as_inner_string() {
        assert_eq!(BackendId::new("b1").to_string(), "b1");
    }
}
