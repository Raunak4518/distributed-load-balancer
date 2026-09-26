mod consistent_hash;
mod least_connections;
mod peak_ewma_p2c;
mod round_robin;
mod weighted_round_robin;

pub use consistent_hash::ConsistentHash;
pub use least_connections::LeastConnections;
pub use peak_ewma_p2c::PeakEwmaP2c;
pub use round_robin::RoundRobin;
pub use weighted_round_robin::WeightedRoundRobin;

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::{Backend, BackendId, BackendPool, LoadBalancer};

    fn pool_of(ids: &[&str]) -> BackendPool {
        BackendPool::new(
            ids.iter()
                .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1, None))
                .collect(),
        )
    }

    fn strategies() -> Vec<(&'static str, Box<dyn LoadBalancer>)> {
        vec![
            ("round_robin", Box::new(RoundRobin::new())),
            ("least_connections", Box::new(LeastConnections::new())),
            ("weighted_round_robin", Box::new(WeightedRoundRobin::new())),
            ("consistent_hash", Box::new(ConsistentHash::new())),
            (
                "peak_ewma_p2c",
                Box::new(PeakEwmaP2c::new(lb_core::SystemClock)),
            ),
        ]
    }

    #[test]
    fn no_strategy_returns_an_excluded_backend_while_another_is_eligible() {
        let pool = pool_of(&["a", "b", "c"]);
        for (name, lb) in strategies() {
            for excluded in ["a", "b", "c"] {
                let excluded = [BackendId::new(excluded)];
                for i in 0..50 {
                    let picked = lb
                        .pick_excluding(&pool, &format!("client-{i}"), &excluded)
                        .unwrap_or_else(|| panic!("{name} returned nothing"));
                    assert_ne!(picked, excluded[0], "{name} returned an excluded backend");
                }
            }
        }
    }

    #[test]
    fn every_strategy_returns_none_when_only_excluded_backends_are_eligible() {
        let pool = pool_of(&["only"]);
        for (name, lb) in strategies() {
            assert_eq!(
                lb.pick_excluding(&pool, "k", &[BackendId::new("only")]),
                None,
                "{name}"
            );
        }
    }

    #[test]
    fn consistent_hash_excluding_moves_to_a_stable_neighbour() {
        let pool = pool_of(&["a", "b", "c", "d"]);
        let ch = ConsistentHash::new();
        let first = ch.pick(&pool, "client-7").unwrap();
        let excluded = [first.clone()];
        let retry = ch.pick_excluding(&pool, "client-7", &excluded).unwrap();
        assert_ne!(retry, first);
        for _ in 0..10 {
            assert_eq!(
                ch.pick_excluding(&pool, "client-7", &excluded),
                Some(retry.clone())
            );
        }
    }
}
