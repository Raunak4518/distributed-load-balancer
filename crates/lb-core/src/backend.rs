use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BackendId(pub String);

impl BackendId {
    pub fn new(id: impl Into<String>) -> Self {
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
    pub weight: u32,
}

impl Backend {
    pub fn new(id: impl Into<String>, address: SocketAddr, weight: u32) -> Self {
        Backend {
            id: BackendId::new(id),
            address,
            weight,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn backend_new_sets_all_fields() {
        let b = Backend::new("b1", "127.0.0.1:9001".parse().unwrap(), 3);
        assert_eq!(b.id, BackendId::new("b1"));
        assert_eq!(b.address.to_string(), "127.0.0.1:9001");
        assert_eq!(b.weight, 3);
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
