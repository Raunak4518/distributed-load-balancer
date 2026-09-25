use crate::backend::{Backend, BackendId};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

struct BackendState {
    backend: Backend,
    active_healthy: AtomicBool,
    circuit_open: AtomicBool,
    /// Operator-requested drain (the admin API's `POST .../drain`),
    /// independent of `active_healthy`: the active health checker also
    /// writes `active_healthy` on its own probe schedule, so folding a
    /// manual drain into that same flag would just have the next successful
    /// probe undo it. A third, orthogonal flag is what makes "drained" survive
    /// health checks the way "circuit open" already survives them.
    manually_drained: AtomicBool,
    /// Set by `OutlierDetector::recompute` (lb-healthcheck): this backend's
    /// success rate fell too far below its peers' this round, independent
    /// of `circuit_open` -- see that type's docs for why this is a distinct
    /// signal rather than folded into the breaker.
    outlier_ejected: AtomicBool,
    /// In-flight requests/connections currently dialed to this backend --
    /// what `LeastConnections` compares. Incremented/decremented only
    /// through `ActiveConnGuard`, never directly, so a count can't leak on
    /// an early return from the caller.
    active_conns: AtomicUsize,
}

struct PoolState {
    order: Vec<BackendId>,
    ordered: Vec<Arc<BackendState>>,
    states: HashMap<BackendId, Arc<BackendState>>,
}

impl PoolState {
    fn from_backends(backends: Vec<Backend>) -> Self {
        let mut order = Vec::with_capacity(backends.len());
        let mut ordered = Vec::with_capacity(backends.len());
        let mut states = HashMap::with_capacity(backends.len());
        for b in backends {
            let id = b.id.clone();
            let state = Arc::new(BackendState {
                backend: b,
                active_healthy: AtomicBool::new(true),
                circuit_open: AtomicBool::new(false),
                manually_drained: AtomicBool::new(false),
                outlier_ejected: AtomicBool::new(false),
                active_conns: AtomicUsize::new(0),
            });
            order.push(id.clone());
            ordered.push(Arc::clone(&state));
            states.insert(id, state);
        }
        PoolState {
            order,
            ordered,
            states,
        }
    }
}

pub struct BackendPool {
    inner: ArcSwap<PoolState>,
    max_ejected_fraction: Option<f64>,
    version: AtomicU64,
}

impl BackendPool {
    pub fn new(backends: Vec<Backend>) -> Self {
        Self::with_max_ejected_fraction(backends, None)
    }

    pub fn with_max_ejected_fraction(
        backends: Vec<Backend>,
        max_ejected_fraction: Option<f64>,
    ) -> Self {
        BackendPool {
            inner: ArcSwap::from_pointee(PoolState::from_backends(backends)),
            max_ejected_fraction,
            version: AtomicU64::new(0),
        }
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
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
        let snapshot = self.inner.load();
        let Some(s) = snapshot.states.get(id) else {
            return;
        };
        if open && self.exceeds_ejection_ceiling(&snapshot, id) {
            return;
        }
        s.circuit_open.store(open, Ordering::SeqCst);
    }

    pub fn set_outlier_ejected(&self, id: &BackendId, ejected: bool) {
        let snapshot = self.inner.load();
        let Some(s) = snapshot.states.get(id) else {
            return;
        };
        if ejected && self.exceeds_ejection_ceiling(&snapshot, id) {
            return;
        }
        s.outlier_ejected.store(ejected, Ordering::SeqCst);
    }

    fn exceeds_ejection_ceiling(&self, snapshot: &PoolState, id: &BackendId) -> bool {
        let Some(max_fraction) = self.max_ejected_fraction else {
            return false;
        };
        let Some(state) = snapshot.states.get(id) else {
            return false;
        };
        if state.circuit_open.load(Ordering::SeqCst) || state.outlier_ejected.load(Ordering::SeqCst)
        {
            return false;
        }
        let total = snapshot.order.len();
        if total == 0 {
            return false;
        }
        let currently_ejected = snapshot
            .states
            .values()
            .filter(|s| {
                s.circuit_open.load(Ordering::SeqCst) || s.outlier_ejected.load(Ordering::SeqCst)
            })
            .count();
        (currently_ejected + 1) as f64 / total as f64 > max_fraction
    }

    /// The outlier-ejection flag alone, `false` for an unknown id -- see
    /// `is_active_healthy` for why the individual flags are exposed
    /// separately from `is_eligible`.
    pub fn is_outlier_ejected(&self, id: &BackendId) -> bool {
        self.inner
            .load()
            .states
            .get(id)
            .is_some_and(|s| s.outlier_ejected.load(Ordering::SeqCst))
    }

    /// Operator-requested drain, e.g. the admin API's `POST .../drain` --
    /// see `BackendState::manually_drained` for why this is a separate flag
    /// from `active_healthy` rather than reusing it.
    pub fn set_manually_drained(&self, id: &BackendId, drained: bool) {
        if let Some(s) = self.inner.load().states.get(id) {
            s.manually_drained.store(drained, Ordering::SeqCst);
        }
    }

    /// The manual-drain flag alone, `false` for an unknown id -- see
    /// `is_active_healthy` for why the individual flags are exposed
    /// separately from `is_eligible`.
    pub fn is_manually_drained(&self, id: &BackendId) -> bool {
        self.inner
            .load()
            .states
            .get(id)
            .is_some_and(|s| s.manually_drained.load(Ordering::SeqCst))
    }

    /// The active-health-check flag alone, `false` for an unknown id --
    /// distinct from `is_eligible`, which also folds in `circuit_open`.
    /// Exposed so callers (the admin API) can report *why* a backend is
    /// ineligible: manually drained vs. circuit-tripped are different
    /// operational facts even though both exclude it from
    /// `eligible_backends()`.
    pub fn is_active_healthy(&self, id: &BackendId) -> bool {
        self.inner
            .load()
            .states
            .get(id)
            .is_some_and(|s| s.active_healthy.load(Ordering::SeqCst))
    }

    /// The circuit-breaker flag alone, `false` for an unknown id -- see
    /// `is_active_healthy` for why this is exposed separately from
    /// `is_eligible`.
    pub fn is_circuit_open(&self, id: &BackendId) -> bool {
        self.inner
            .load()
            .states
            .get(id)
            .is_some_and(|s| s.circuit_open.load(Ordering::SeqCst))
    }

    pub fn is_eligible(&self, id: &BackendId) -> bool {
        self.inner
            .load()
            .states
            .get(id)
            .is_some_and(|s| state_is_eligible(s))
    }

    pub fn eligible_backends(&self) -> Vec<BackendId> {
        self.inner
            .load()
            .ordered
            .iter()
            .filter(|s| state_is_eligible(s))
            .map(|s| s.backend.id.clone())
            .collect()
    }

    pub fn eligible_with_weights(&self) -> Vec<(BackendId, u32)> {
        self.inner
            .load()
            .ordered
            .iter()
            .filter(|s| state_is_eligible(s))
            .map(|s| (s.backend.id.clone(), s.backend.weight))
            .collect()
    }

    pub fn all_backend_ids(&self) -> Vec<BackendId> {
        self.inner.load().order.clone()
    }

    /// In-flight requests/connections currently dialed to `id`. `0` for an
    /// unknown id, same as every other per-backend accessor here.
    pub fn active_count(&self, id: &BackendId) -> usize {
        self.inner
            .load()
            .states
            .get(id)
            .map(|s| s.active_conns.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Marks one request/connection as in flight against `id` for as long as
    /// the returned guard lives; the count decrements on `Drop` regardless of
    /// how the caller's scope exits, matching the `ConnectionGuard`/`IpGuard`
    /// pattern already used elsewhere for exactly this reason. A no-op guard
    /// (nothing to decrement) if `id` is unknown -- callers should not have
    /// to check `backend()` first just to track load.
    pub fn track_active(self: &Arc<Self>, id: &BackendId) -> ActiveConnGuard {
        let state = self.inner.load().states.get(id).cloned();
        if let Some(s) = &state {
            s.active_conns.fetch_add(1, Ordering::SeqCst);
        }
        ActiveConnGuard { state }
    }

    pub fn apply_resolved(&self, backends: Vec<Backend>) {
        let previous = self.inner.load();
        if resolved_set_unchanged(&previous, &backends) {
            return;
        }
        let mut order = Vec::with_capacity(backends.len());
        let mut ordered = Vec::with_capacity(backends.len());
        let mut states = HashMap::with_capacity(backends.len());
        for b in backends {
            order.push(b.id.clone());
            let state = match previous.states.get(&b.id) {
                Some(existing) => Arc::new(BackendState {
                    backend: b,
                    active_healthy: AtomicBool::new(existing.active_healthy.load(Ordering::SeqCst)),
                    circuit_open: AtomicBool::new(existing.circuit_open.load(Ordering::SeqCst)),
                    manually_drained: AtomicBool::new(
                        existing.manually_drained.load(Ordering::SeqCst),
                    ),
                    outlier_ejected: AtomicBool::new(
                        existing.outlier_ejected.load(Ordering::SeqCst),
                    ),
                    // A persisting backend's in-flight work didn't go
                    // anywhere just because the pool was refreshed.
                    active_conns: AtomicUsize::new(existing.active_conns.load(Ordering::SeqCst)),
                }),
                None => Arc::new(BackendState {
                    backend: b,
                    active_healthy: AtomicBool::new(true),
                    circuit_open: AtomicBool::new(false),
                    manually_drained: AtomicBool::new(false),
                    outlier_ejected: AtomicBool::new(false),
                    active_conns: AtomicUsize::new(0),
                }),
            };
            ordered.push(Arc::clone(&state));
            states.insert(order.last().unwrap().clone(), state);
        }
        self.inner.store(Arc::new(PoolState {
            order,
            ordered,
            states,
        }));
        self.version.fetch_add(1, Ordering::SeqCst);
    }
}

fn state_is_eligible(s: &BackendState) -> bool {
    s.active_healthy.load(Ordering::SeqCst)
        && !s.circuit_open.load(Ordering::SeqCst)
        && !s.manually_drained.load(Ordering::SeqCst)
        && !s.outlier_ejected.load(Ordering::SeqCst)
}

fn resolved_set_unchanged(previous: &PoolState, backends: &[Backend]) -> bool {
    if previous.order.len() != backends.len() {
        return false;
    }
    let mut new_sorted: Vec<&Backend> = backends.iter().collect();
    new_sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let mut prev_sorted: Vec<&Backend> = previous
        .order
        .iter()
        .filter_map(|id| previous.states.get(id).map(|s| &s.backend))
        .collect();
    prev_sorted.sort_by(|a, b| a.id.cmp(&b.id));
    new_sorted == prev_sorted
}

/// Returned by `BackendPool::track_active`. Decrements the count on `Drop`
/// so it cannot be leaked by an early return from the caller's scope.
pub struct ActiveConnGuard {
    state: Option<Arc<BackendState>>,
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        if let Some(s) = &self.state {
            s.active_conns.fetch_sub(1, Ordering::SeqCst);
        }
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

    fn pool_with_ceiling(ids: &[&str], max_ejected_fraction: f64) -> BackendPool {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1, None))
            .collect();
        BackendPool::with_max_ejected_fraction(backends, Some(max_ejected_fraction))
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
    fn outlier_ejection_removes_from_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_outlier_ejected(&BackendId::new("b2"), true);
        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b1")]);
        assert!(pool.is_outlier_ejected(&BackendId::new("b2")));
        assert!(!pool.is_outlier_ejected(&BackendId::new("b1")));
    }

    #[test]
    fn a_ceiling_refuses_a_circuit_trip_that_would_exceed_it() {
        let pool = pool_with_ceiling(&["b1", "b2", "b3"], 0.34);
        pool.set_circuit_open(&BackendId::new("b1"), true);
        assert!(pool.is_circuit_open(&BackendId::new("b1")));
        pool.set_circuit_open(&BackendId::new("b2"), true);
        assert!(!pool.is_circuit_open(&BackendId::new("b2")));
        assert!(pool.is_eligible(&BackendId::new("b2")));
    }

    #[test]
    fn a_ceiling_refuses_an_outlier_ejection_that_would_exceed_it() {
        let pool = pool_with_ceiling(&["b1", "b2", "b3"], 0.34);
        pool.set_outlier_ejected(&BackendId::new("b1"), true);
        assert!(pool.is_outlier_ejected(&BackendId::new("b1")));
        pool.set_outlier_ejected(&BackendId::new("b2"), true);
        assert!(!pool.is_outlier_ejected(&BackendId::new("b2")));
    }

    #[test]
    fn a_ceiling_counts_circuit_open_and_outlier_ejected_together() {
        let pool = pool_with_ceiling(&["b1", "b2", "b3"], 0.34);
        pool.set_circuit_open(&BackendId::new("b1"), true);
        pool.set_outlier_ejected(&BackendId::new("b2"), true);
        assert!(pool.is_circuit_open(&BackendId::new("b1")));
        assert!(!pool.is_outlier_ejected(&BackendId::new("b2")));
    }

    #[test]
    fn a_ceiling_never_blocks_recovery() {
        let pool = pool_with_ceiling(&["b1", "b2", "b3"], 0.4);
        pool.set_circuit_open(&BackendId::new("b1"), true);
        assert!(pool.is_circuit_open(&BackendId::new("b1")));
        pool.set_circuit_open(&BackendId::new("b1"), false);
        assert!(!pool.is_circuit_open(&BackendId::new("b1")));
    }

    #[test]
    fn a_ceiling_does_not_double_count_a_backend_already_ejected() {
        let pool = pool_with_ceiling(&["b1", "b2", "b3"], 0.34);
        pool.set_circuit_open(&BackendId::new("b1"), true);
        assert!(pool.is_circuit_open(&BackendId::new("b1")));
        pool.set_circuit_open(&BackendId::new("b1"), true);
        assert!(pool.is_circuit_open(&BackendId::new("b1")));
    }

    #[test]
    fn without_a_ceiling_every_backend_can_be_ejected() {
        let pool = pool_of(&["b1", "b2", "b3"]);
        for id in ["b1", "b2", "b3"] {
            pool.set_circuit_open(&BackendId::new(id), true);
        }
        assert!(pool.eligible_backends().is_empty());
    }

    #[test]
    fn clearing_outlier_ejection_restores_eligibility() {
        let pool = pool_of(&["b1"]);
        let id = BackendId::new("b1");
        pool.set_outlier_ejected(&id, true);
        assert!(!pool.is_eligible(&id));
        pool.set_outlier_ejected(&id, false);
        assert!(pool.is_eligible(&id));
    }

    #[test]
    fn apply_resolved_preserves_outlier_ejection_for_a_persisting_backend() {
        let pool = pool_of(&["b1", "b2"]);
        let id = BackendId::new("b1");
        pool.set_outlier_ejected(&id, true);

        pool.apply_resolved(vec![
            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("b2", "127.0.0.1:9000".parse().unwrap(), 1, None),
        ]);

        assert!(!pool.is_eligible(&id));
    }

    /// The two flags are independently observable, not just folded into
    /// `is_eligible` -- an admin listing needs to say *why* a backend is
    /// out of rotation, not just that it is.
    #[test]
    fn active_healthy_and_circuit_open_are_independently_observable() {
        let pool = pool_of(&["b1"]);
        let id = BackendId::new("b1");
        assert!(pool.is_active_healthy(&id));
        assert!(!pool.is_circuit_open(&id));

        pool.set_active_healthy(&id, false);
        assert!(!pool.is_active_healthy(&id));
        assert!(!pool.is_circuit_open(&id));

        pool.set_active_healthy(&id, true);
        pool.set_circuit_open(&id, true);
        assert!(pool.is_active_healthy(&id));
        assert!(pool.is_circuit_open(&id));
    }

    #[test]
    fn unknown_id_reports_healthy_flags_as_false() {
        let pool = pool_of(&["b1"]);
        let ghost = BackendId::new("ghost");
        assert!(!pool.is_active_healthy(&ghost));
        assert!(!pool.is_circuit_open(&ghost));
    }

    #[test]
    fn manual_drain_removes_from_eligible() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_manually_drained(&BackendId::new("b1"), true);
        assert_eq!(pool.eligible_backends(), vec![BackendId::new("b2")]);
    }

    /// The whole reason this is a separate flag from `active_healthy`: the
    /// active health checker writes that flag on its own schedule, entirely
    /// oblivious to an operator's drain request. If a drain were folded
    /// into `active_healthy`, the very next successful probe would silently
    /// undo it.
    #[test]
    fn manual_drain_survives_an_unrelated_healthy_report() {
        let pool = pool_of(&["b1"]);
        let id = BackendId::new("b1");
        pool.set_manually_drained(&id, true);
        pool.set_active_healthy(&id, true); // e.g. a passing health probe
        assert!(
            !pool.is_eligible(&id),
            "drain was undone by a health report"
        );
        assert!(pool.is_manually_drained(&id));
    }

    #[test]
    fn undraining_restores_eligibility() {
        let pool = pool_of(&["b1"]);
        let id = BackendId::new("b1");
        pool.set_manually_drained(&id, true);
        assert!(!pool.is_eligible(&id));
        pool.set_manually_drained(&id, false);
        assert!(pool.is_eligible(&id));
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

    #[test]
    fn apply_resolved_with_a_real_membership_change_bumps_the_version() {
        let pool = pool_of(&["b1", "b2"]);
        let before = pool.version();

        pool.apply_resolved(vec![Backend::new(
            "b1",
            "127.0.0.1:9000".parse().unwrap(),
            1,
            None,
        )]);

        assert_eq!(pool.version(), before + 1);
    }

    #[test]
    fn apply_resolved_with_the_identical_set_does_not_bump_the_version() {
        let pool = pool_of(&["b1", "b2"]);
        let before = pool.version();

        pool.apply_resolved(vec![
            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("b2", "127.0.0.1:9000".parse().unwrap(), 1, None),
        ]);

        assert_eq!(pool.version(), before);
    }

    #[test]
    fn apply_resolved_with_the_identical_set_in_a_different_order_does_not_bump_the_version() {
        let pool = pool_of(&["b1", "b2"]);
        let before = pool.version();

        pool.apply_resolved(vec![
            Backend::new("b2", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
        ]);

        assert_eq!(pool.version(), before);
    }

    #[test]
    fn apply_resolved_with_a_changed_weight_bumps_the_version() {
        let pool = pool_of(&["b1"]);
        let before = pool.version();

        pool.apply_resolved(vec![Backend::new(
            "b1",
            "127.0.0.1:9000".parse().unwrap(),
            2,
            None,
        )]);

        assert_eq!(pool.version(), before + 1);
    }

    #[test]
    fn track_active_increments_and_decrements_on_drop() {
        let pool = Arc::new(pool_of(&["b1"]));
        let id = BackendId::new("b1");
        assert_eq!(pool.active_count(&id), 0);

        let guard = pool.track_active(&id);
        assert_eq!(pool.active_count(&id), 1);

        let guard2 = pool.track_active(&id);
        assert_eq!(pool.active_count(&id), 2);

        drop(guard);
        assert_eq!(pool.active_count(&id), 1);
        drop(guard2);
        assert_eq!(pool.active_count(&id), 0);
    }

    #[test]
    fn active_count_survives_apply_resolved_for_a_persisting_backend() {
        let pool = Arc::new(pool_of(&["b1"]));
        let id = BackendId::new("b1");
        let _guard = pool.track_active(&id);

        pool.apply_resolved(vec![Backend::new(
            "b1",
            "127.0.0.1:9999".parse().unwrap(),
            1,
            None,
        )]);

        assert_eq!(pool.active_count(&id), 1);
    }

    #[test]
    fn a_guard_outliving_a_remove_then_readd_cycle_does_not_corrupt_the_new_backends_count() {
        let pool = Arc::new(pool_of(&["b1"]));
        let id = BackendId::new("b1");
        let guard = pool.track_active(&id);
        assert_eq!(pool.active_count(&id), 1);

        pool.apply_resolved(vec![]);
        assert_eq!(pool.active_count(&id), 0);

        pool.apply_resolved(vec![Backend::new(
            "b1",
            "127.0.0.1:9000".parse().unwrap(),
            1,
            None,
        )]);
        assert_eq!(pool.active_count(&id), 0);

        drop(guard);
        assert_eq!(pool.active_count(&id), 0);
    }

    #[test]
    fn active_count_is_zero_for_an_unknown_backend() {
        let pool = Arc::new(pool_of(&["b1"]));
        assert_eq!(pool.active_count(&BackendId::new("ghost")), 0);
        // Must not panic, matching every other per-backend accessor here.
        let _guard = pool.track_active(&BackendId::new("ghost"));
    }
}
