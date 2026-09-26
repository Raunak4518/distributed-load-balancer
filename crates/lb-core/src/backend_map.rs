use crate::backend::BackendId;
use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub struct BackendMap<T> {
    inner: Arc<ArcSwap<HashMap<BackendId, Arc<T>>>>,
}

impl<T> BackendMap<T> {
    pub fn new() -> Self {
        BackendMap {
            inner: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    pub fn get(&self, id: &BackendId) -> Option<Arc<T>> {
        self.inner.load().get(id).cloned()
    }

    pub fn contains(&self, id: &BackendId) -> bool {
        self.inner.load().contains_key(id)
    }

    pub fn snapshot(&self) -> Arc<HashMap<BackendId, Arc<T>>> {
        self.inner.load_full()
    }

    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
    }

    pub fn reconcile(&self, live: &[BackendId], mut make: impl FnMut(&BackendId) -> T) {
        let live_set: HashSet<&BackendId> = live.iter().collect();
        {
            let current = self.inner.load();
            if current.len() == live_set.len()
                && live_set.iter().all(|id| current.contains_key(*id))
            {
                return;
            }
        }
        self.inner.rcu(|current| {
            let mut next: HashMap<BackendId, Arc<T>> = current
                .iter()
                .filter(|(id, _)| live_set.contains(id))
                .map(|(id, value)| (id.clone(), Arc::clone(value)))
                .collect();
            for id in live {
                if !next.contains_key(id) {
                    next.insert(id.clone(), Arc::new(make(id)));
                }
            }
            next
        });
    }
}

impl<T> Clone for BackendMap<T> {
    fn clone(&self) -> Self {
        BackendMap {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Default for BackendMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<HashMap<BackendId, T>> for BackendMap<T> {
    fn from(map: HashMap<BackendId, T>) -> Self {
        BackendMap {
            inner: Arc::new(ArcSwap::from_pointee(
                map.into_iter().map(|(id, v)| (id, Arc::new(v))).collect(),
            )),
        }
    }
}

impl<T> FromIterator<(BackendId, T)> for BackendMap<T> {
    fn from_iter<I: IntoIterator<Item = (BackendId, T)>>(iter: I) -> Self {
        BackendMap::from(iter.into_iter().collect::<HashMap<_, _>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ids(names: &[&str]) -> Vec<BackendId> {
        names.iter().map(|n| BackendId::new(*n)).collect()
    }

    #[test]
    fn reconcile_adds_missing_ids_and_drops_departed_ones() {
        let map: BackendMap<u32> = [(BackendId::new("a"), 1), (BackendId::new("b"), 2)]
            .into_iter()
            .collect();
        map.reconcile(&ids(&["b", "c"]), |_| 3);
        assert!(map.get(&BackendId::new("a")).is_none());
        assert_eq!(*map.get(&BackendId::new("b")).unwrap(), 2);
        assert_eq!(*map.get(&BackendId::new("c")).unwrap(), 3);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn reconcile_keeps_the_same_instance_for_a_persisting_id() {
        let map: BackendMap<AtomicUsize> = BackendMap::new();
        map.reconcile(&ids(&["a"]), |_| AtomicUsize::new(0));
        map.get(&BackendId::new("a"))
            .unwrap()
            .store(7, Ordering::SeqCst);
        map.reconcile(&ids(&["a", "b"]), |_| AtomicUsize::new(0));
        assert_eq!(
            map.get(&BackendId::new("a"))
                .unwrap()
                .load(Ordering::SeqCst),
            7
        );
    }

    #[test]
    fn a_clone_is_a_handle_to_the_same_map() {
        let map: BackendMap<u32> = BackendMap::new();
        let handle = map.clone();
        handle.reconcile(&ids(&["a"]), |_| 1);
        assert!(map.contains(&BackendId::new("a")));
    }

    #[test]
    fn a_snapshot_taken_before_reconcile_is_unaffected_by_it() {
        let map: BackendMap<u32> = [(BackendId::new("a"), 1)].into_iter().collect();
        let before = map.snapshot();
        map.reconcile(&ids(&["b"]), |_| 2);
        assert!(before.contains_key(&BackendId::new("a")));
        assert!(!map.contains(&BackendId::new("a")));
    }
}
