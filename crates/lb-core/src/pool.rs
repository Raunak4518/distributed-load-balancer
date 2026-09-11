use crate::backend::{Backend, BackendId};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct BackendState {
    backend: Backend,
    active_healthy: AtomicBool,
    circuit_open: AtomicBool,
}

struct PoolState {
    order: Vec<BackendId>,
    states: HashMap<BackendId, Arc<BackendState>>,
}

impl PoolState {
    fn from_backends(backends: Vec<Backend>) -> Self {
        let mut order = Vec::with_capacity(backends.len());
        let mut states = HashMap::with_capacity(backends.len());
        for b in backends {
            order.push(b.id.clone());
            states.insert(
                b.id.clone(),
                Arc::new(BackendState {
                    backend: b,
                    active_healthy: AtomicBool::new(true),
                    circuit_open: AtomicBool::new(false),
                }),
            );
        }
        PoolState { order, states }
    }
}

pub struct BackendPool {
    inner: ArcSwap<PoolState>,
}

impl BackendPool {
    pub fn new(backends: Vec<Backend>) -> Self {
        BackendPool {
            inner: ArcSwap::from_pointee(PoolState::from_backends(backends)),
        }
    }

    pub fn backend(&self, id: &BackendId) -> Option<Backend> {
        self.inner.load().states.get(id).map(|s| s.backend.clone())
    }

    pub fn set_active_healthy(&self, id: &BackendId, healthy: bool) {
        if let Some(s) = self.inner.load().states.get(id) {
            s.active_healthy.store(healthy, Ordering::SeqCst);
        }
    }

    pub fn set_circuit_open(&self, id: &BackendId, open: bool) {
        if let Some(s) = self.inner.load().states.get(id) {
            s.circuit_open.store(open, Ordering::SeqCst);
        }
    }

    pub fn is_eligible(&self, id: &BackendId) -> bool {
        self.inner.load().states.get(id).is_some_and(|s| {
            s.active_healthy.load(Ordering::SeqCst) && !s.circuit_open.load(Ordering::SeqCst)
        })
    }

    pub fn eligible_backends(&self) -> Vec<BackendId> {
        let snapshot = self.inner.load();
        snapshot
            .order
            .iter()
            .filter(|id| {
                snapshot.states.get(*id).is_some_and(|s| {
                    s.active_healthy.load(Ordering::SeqCst)
                        && !s.circuit_open.load(Ordering::SeqCst)
                })
            })
            .cloned()
            .collect()
    }

    pub fn all_backend_ids(&self) -> Vec<BackendId> {
        self.inner.load().order.clone()
    }

    pub fn apply_resolved(&self, backends: Vec<Backend>) {
        let previous = self.inner.load();
        let mut order = Vec::with_capacity(backends.len());
        let mut states = HashMap::with_capacity(backends.len());
        for b in backends {
            order.push(b.id.clone());
            let state = match previous.states.get(&b.id) {
                Some(existing) => Arc::new(BackendState {
                    backend: b,
                    active_healthy: AtomicBool::new(existing.active_healthy.load(Ordering::SeqCst)),
                    circuit_open: AtomicBool::new(existing.circuit_open.load(Ordering::SeqCst)),
                }),
                None => Arc::new(BackendState {
                    backend: b,
                    active_healthy: AtomicBool::new(true),
                    circuit_open: AtomicBool::new(false),
                }),
            };
            states.insert(order.last().unwrap().clone(), state);
        }
        self.inner.store(Arc::new(PoolState { order, states }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_of(ids: &[&str]) -> BackendPool {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1, None))
            .collect();
        BackendPool::new(backends)
    }

    #[test]
    fn all_backends_start_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        assert_eq!(
            pool.eligible_backends(),
            vec![BackendId::new("b1"), BackendId::new("b2")]
        );
    }

    #[test]
    fn active_unhealthy_removes_from_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b2")]);
    }

    #[test]
    fn open_circuit_removes_from_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_circuit_open(&BackendId::new("b2"), true);
        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b1")]);
    }

    #[test]
    fn restoring_both_flags_makes_eligible_again() {
        let pool = pool_of(&["b1"]);
        let id = BackendId::new("b1");
        pool.set_active_healthy(&id, false);
        pool.set_circuit_open(&id, true);
        assert!(pool.eligible_backends().is_empty());
        pool.set_active_healthy(&id, true);
        pool.set_circuit_open(&id, false);
        assert_eq!(pool.eligible_backends(), vec![id]);
    }

    #[test]
    fn unknown_id_is_never_eligible_and_operations_are_no_ops() {
        let pool = pool_of(&["b1"]);
        let unknown = BackendId::new("ghost");
        assert!(!pool.is_eligible(&unknown));
        pool.set_active_healthy(&unknown, false); // must not panic
        assert!(pool.backend(&unknown).is_none());
    }

    #[test]
    fn apply_resolved_preserves_state_for_backends_that_persist() {
        let pool = pool_of(&["b1", "b2"]);
        let id = BackendId::new("b1");
        pool.set_circuit_open(&id, true);

        pool.apply_resolved(vec![
            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("b2", "127.0.0.1:9000".parse().unwrap(), 1, None),
        ]);

        assert!(!pool.is_eligible(&id));
    }

    #[test]
    fn apply_resolved_drops_backends_no_longer_present() {
        let pool = pool_of(&["b1", "b2"]);
        pool.apply_resolved(vec![Backend::new(
            "b1",
            "127.0.0.1:9000".parse().unwrap(),
            1,
            None,
        )]);

        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b1")]);
        assert!(pool.backend(&BackendId::new("b2")).is_none());
    }

    #[test]
    fn apply_resolved_starts_new_backends_healthy() {
        let pool = pool_of(&["b1"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);

        pool.apply_resolved(vec![
            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("b3", "127.0.0.1:9000".parse().unwrap(), 1, None),
        ]);

        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b3")]);
    }

    #[test]
    fn apply_resolved_updates_backend_metadata_for_persisting_ids() {
        let pool = pool_of(&["b1"]);
        pool.apply_resolved(vec![Backend::new(
            "b1",
            "127.0.0.1:9999".parse().unwrap(),
            5,
            None,
        )]);

        let backend = pool.backend(&BackendId::new("b1")).unwrap();
        assert_eq!(backend.address.to_string(), "127.0.0.1:9999");
        assert_eq!(backend.weight, 5);
    }

    #[test]
    fn apply_resolved_preserves_insertion_order() {
        let pool = pool_of(&["b1", "b2", "b3"]);
        pool.apply_resolved(vec![
            Backend::new("b3", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
        ]);

        assert_eq!(
            pool.all_backend_ids(),
            vec![BackendId::new("b3"), BackendId::new("b1")]
        );
    }
}
