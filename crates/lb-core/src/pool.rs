use crate::backend::{Backend, BackendId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct BackendState {
    backend: Backend,
    active_healthy: AtomicBool,
    circuit_open: AtomicBool,
}

pub struct BackendPool {
    order: Vec<BackendId>,
    states: HashMap<BackendId, Arc<BackendState>>,
}

impl BackendPool {
    pub fn new(backends: Vec<Backend>) -> Self {
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
        BackendPool { order, states }
    }

    pub fn backend(&self, id: &BackendId) -> Option<&Backend> {
        self.states.get(id).map(|s| &s.backend)
    }

    pub fn set_active_healthy(&self, id: &BackendId, healthy: bool) {
        if let Some(s) = self.states.get(id) {
            s.active_healthy.store(healthy, Ordering::SeqCst);
        }
    }

    pub fn set_circuit_open(&self, id: &BackendId, open: bool) {
        if let Some(s) = self.states.get(id) {
            s.circuit_open.store(open, Ordering::SeqCst);
        }
    }

    pub fn is_eligible(&self, id: &BackendId) -> bool {
        self.states
            .get(id)
            .is_some_and(|s| s.active_healthy.load(Ordering::SeqCst) && !s.circuit_open.load(Ordering::SeqCst))
    }

    pub fn eligible_backends(&self) -> Vec<BackendId> {
        self.order.iter().filter(|id| self.is_eligible(id)).cloned().collect()
    }

    pub fn all_backend_ids(&self) -> &[BackendId] {
        &self.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_of(ids: &[&str]) -> BackendPool {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1))
            .collect();
        BackendPool::new(backends)
    }

    #[test]
    fn all_backends_start_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b1"), BackendId::new("b2")]);
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
}
