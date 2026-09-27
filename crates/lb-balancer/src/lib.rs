mod consistent_hash;
mod hash;
mod least_connections;
mod maglev;
mod peak_ewma_p2c;
mod random;
mod rendezvous;
mod round_robin;
mod weighted_round_robin;

pub use consistent_hash::ConsistentHash;
pub use least_connections::LeastConnections;
pub use maglev::Maglev;
pub use peak_ewma_p2c::PeakEwmaP2c;
pub use random::{LeastRequest, Random, WeightedRandom};
pub use rendezvous::RendezvousHash;
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
            ("maglev", Box::new(Maglev::new())),
            ("rendezvous_hash", Box::new(RendezvousHash::new())),
            ("random", Box::new(Random::new())),
            ("weighted_random", Box::new(WeightedRandom::new())),
            ("least_request", Box::new(LeastRequest::new())),
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

    fn hashing_strategies() -> Vec<(&'static str, Box<dyn LoadBalancer>)> {
        vec![
            ("consistent_hash", Box::new(ConsistentHash::new())),
            ("maglev", Box::new(Maglev::new())),
            ("rendezvous_hash", Box::new(RendezvousHash::new())),
        ]
    }

    #[test]
    fn removing_one_of_ten_backends_moves_close_to_a_tenth_of_keys() {
        let ids: Vec<String> = (0..10).map(|i| format!("b{i}")).collect();
        let all: Vec<&str> = ids.iter().map(String::as_str).collect();
        let before_pool = pool_of(&all);
        let after_pool = pool_of(&all[1..]);
        let keys: Vec<String> = (0..20_000)
            .map(|i| format!("10.1.{}.{}", i / 256, i % 256))
            .collect();
        for (name, lb) in hashing_strategies() {
            let before: Vec<_> = keys.iter().map(|k| lb.pick(&before_pool, k)).collect();
            let after: Vec<_> = keys.iter().map(|k| lb.pick(&after_pool, k)).collect();
            let moved = before.iter().zip(&after).filter(|(b, a)| b != a).count();
            let fraction = moved as f64 / keys.len() as f64;
            eprintln!(
                "{name}: removing 1 of 10 backends moved {:.1}% of keys",
                fraction * 100.0
            );
            let limit = if name == "consistent_hash" { 0.2 } else { 0.13 };
            assert!(
                fraction <= limit,
                "{name} moved {:.1}% of keys, ideal is 10%",
                fraction * 100.0
            );
        }
    }

    #[test]
    fn hashing_strategies_spread_keys_evenly_over_equal_backends() {
        let ids: Vec<String> = (0..10).map(|i| format!("b{i}")).collect();
        let pool = pool_of(&ids.iter().map(String::as_str).collect::<Vec<_>>());
        for (name, lb) in hashing_strategies() {
            let mut counts = std::collections::HashMap::new();
            for i in 0..20_000 {
                *counts
                    .entry(
                        lb.pick(&pool, &format!("10.2.{}.{}", i / 256, i % 256))
                            .unwrap(),
                    )
                    .or_insert(0usize) += 1;
            }
            let max = *counts.values().max().unwrap();
            let min = *counts.values().min().unwrap();
            eprintln!("{name}: busiest backend {max}, quietest {min} (mean 2000)");
            let limit = if name == "consistent_hash" {
                4_000
            } else {
                2_400
            };
            assert!(max <= limit, "{name} put {max} keys on one backend");
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
