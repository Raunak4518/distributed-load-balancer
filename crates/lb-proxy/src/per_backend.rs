//! Per-backend HTTP clients for a `dns_discovery` + `backend_tls` listener.
//!
//! `forward::build_client`'s shared `ProxyClient` addresses every backend as
//! `{server_name}:{port}`, on purpose -- see its own docs -- but
//! `hyper_util::client::legacy::Client` pools connections keyed by exactly
//! that `(Scheme, Authority)` pair. When several DNS-resolved addresses share
//! one `server_name`, one shared client would let hyper's pool collapse them
//! onto whichever connection it happened to keep alive, silently defeating
//! round-robin, circuit-breaking and health-check attribution across them.
//!
//! `PerBackendClients` gives each backend id its own `ProxyClient` -- and so
//! its own connection pool -- built from the exact same `build_client`, just
//! with a single-entry `server_name -> address` table instead of the whole
//! listener's. Built lazily, one entry per backend id ever seen: a `Backend`
//! discovered via DNS has an id derived from its address
//! (`lb_server::dns::spawn_dns_poller`'s `dns:{addr}`), so there is nothing
//! to invalidate when DNS re-resolves -- a vanished address just leaves an
//! unused entry, bounded by DNS churn.
use crate::forward::{build_client, ProbeCapableClient, ProxyClient};
use lb_core::{Backend, BackendId, ProbeClient, ProbeFuture};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub struct PerBackendClients {
    server_name: String,
    backend_tls: Arc<lb_tls::BackendConnector>,
    backend_h2c: bool,
    clients: RwLock<HashMap<BackendId, ProxyClient>>,
}

impl PerBackendClients {
    pub fn new(server_name: String, backend_tls: Arc<lb_tls::BackendConnector>, backend_h2c: bool) -> Self {
        PerBackendClients {
            server_name,
            backend_tls,
            backend_h2c,
            clients: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_or_build(&self, backend: &Backend) -> ProxyClient {
        if let Some(client) = self.clients.read().unwrap().get(&backend.id) {
            return client.clone();
        }
        let mut table = HashMap::new();
        table.insert(self.server_name.clone(), backend.address);
        let client = build_client(Some(&self.backend_tls), table, self.backend_h2c);
        self.clients
            .write()
            .unwrap()
            .entry(backend.id.clone())
            .or_insert(client)
            .clone()
    }
}

impl ProbeClient for PerBackendClients {
    fn get(
        &self,
        backend: &Backend,
        path: &str,
        backend_tls: bool,
        timeout: Duration,
    ) -> ProbeFuture<'_> {
        let client = self.get_or_build(backend);
        let backend = backend.clone();
        let path = path.to_string();
        Box::pin(async move {
            ProbeCapableClient(client)
                .get(&backend, &path, backend_tls, timeout)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::BackendId as Id;

    fn connector() -> Arc<lb_tls::BackendConnector> {
        Arc::new(
            lb_tls::BackendConnector::new(&lb_core::BackendTlsConfig {
                ca_file: None,
                danger_accept_invalid_certs: true,
            })
            .unwrap(),
        )
    }

    #[test]
    fn distinct_backends_get_distinct_clients() {
        let clients = PerBackendClients::new("svc.internal".into(), connector(), false);
        let b1 = Backend::new("b1", "127.0.0.1:9001".parse().unwrap(), 1, None);
        let b2 = Backend::new("b2", "127.0.0.1:9002".parse().unwrap(), 1, None);

        clients.get_or_build(&b1);
        clients.get_or_build(&b2);

        let table = clients.clients.read().unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.contains_key(&Id::new("b1")));
        assert!(table.contains_key(&Id::new("b2")));
    }

    #[test]
    fn the_same_backend_id_reuses_its_client() {
        let clients = PerBackendClients::new("svc.internal".into(), connector(), false);
        let b1 = Backend::new("b1", "127.0.0.1:9001".parse().unwrap(), 1, None);

        clients.get_or_build(&b1);
        clients.get_or_build(&b1);

        assert_eq!(clients.clients.read().unwrap().len(), 1);
    }
}
