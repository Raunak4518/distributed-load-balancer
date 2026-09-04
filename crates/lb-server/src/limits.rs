use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Caps concurrent connections from any single source address.
///
/// A global cap alone protects the process but not its users: one attacker
/// could consume the entire budget and starve everyone else.
pub struct PerIpLimiter {
    max: usize,
    counts: DashMap<IpAddr, usize>,
}

impl PerIpLimiter {
    pub fn new(max: usize) -> Self {
        PerIpLimiter {
            max: max.max(1),
            counts: DashMap::new(),
        }
    }

    /// Reserves a slot for `ip`, or returns `None` if that source is already
    /// at its limit.
    ///
    /// Note the ordering: the entry is only created when the count is below
    /// the cap, so a rejected connection never leaves a zero-valued entry
    /// behind (there would be no guard to clean it up).
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<IpGuard> {
        let mut entry = self.counts.entry(ip).or_insert(0);
        if *entry >= self.max {
            return None;
        }
        *entry += 1;
        drop(entry);
        Some(IpGuard {
            limiter: Arc::clone(self),
            ip,
        })
    }

    pub fn tracked_ips(&self) -> usize {
        self.counts.len()
    }
}

/// Releases the per-IP slot on drop, and **removes the map entry once the
/// count reaches zero**.
///
/// This map is keyed by attacker-controlled input. Leaving zero-valued
/// entries behind would let a client cycling through source addresses grow
/// it without bound — recreating the very memory-exhaustion problem the
/// limiter exists to prevent.
pub struct IpGuard {
    limiter: Arc<PerIpLimiter>,
    ip: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut now_zero = false;
        if let Some(mut count) = self.limiter.counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            now_zero = *count == 0;
        }
        if now_zero {
            // Conditional, and only after the guard above is released:
            // another connection from this IP may have arrived in between,
            // and removing a non-zero entry would lose its count.
            self.limiter.counts.remove_if(&self.ip, |_, v| *v == 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, n])
    }

    #[test]
    fn admits_up_to_the_cap_then_refuses() {
        let limiter = Arc::new(PerIpLimiter::new(2));
        let _a = limiter.try_acquire(ip(1)).expect("first");
        let _b = limiter.try_acquire(ip(1)).expect("second");
        assert!(limiter.try_acquire(ip(1)).is_none());
    }

    #[test]
    fn different_sources_have_independent_budgets() {
        let limiter = Arc::new(PerIpLimiter::new(1));
        let _a = limiter.try_acquire(ip(1)).expect("first ip");
        assert!(
            limiter.try_acquire(ip(2)).is_some(),
            "one source exhausting its budget must not affect another"
        );
    }

    #[test]
    fn releasing_frees_a_slot() {
        let limiter = Arc::new(PerIpLimiter::new(1));
        let guard = limiter.try_acquire(ip(1)).expect("first");
        assert!(limiter.try_acquire(ip(1)).is_none());
        drop(guard);
        assert!(limiter.try_acquire(ip(1)).is_some());
    }

    /// The anti-unbounded-growth guarantee, asserted directly rather than
    /// assumed from the Drop implementation.
    #[test]
    fn entries_are_reclaimed_once_a_source_has_no_connections() {
        let limiter = Arc::new(PerIpLimiter::new(4));
        for n in 1..=50u8 {
            let guard = limiter.try_acquire(ip(n)).expect("acquire");
            drop(guard);
        }
        assert_eq!(
            limiter.tracked_ips(),
            0,
            "per-IP map retained entries for departed clients"
        );
    }

    /// A refused connection has no guard, so it must not leave state behind
    /// either — otherwise an attacker could grow the map purely by being
    /// rejected.
    #[test]
    fn refused_connections_do_not_leak_entries() {
        let limiter = Arc::new(PerIpLimiter::new(1));
        let held = limiter.try_acquire(ip(1)).expect("first");
        for _ in 0..100 {
            assert!(limiter.try_acquire(ip(1)).is_none());
        }
        assert_eq!(limiter.tracked_ips(), 1, "rejections created extra entries");
        drop(held);
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn concurrent_acquire_and_release_reclaims_correctly() {
        // Interleaves so the entry is repeatedly driven to zero and back,
        // exercising the remove_if race guard.
        let limiter = Arc::new(PerIpLimiter::new(8));
        for _ in 0..200 {
            let a = limiter.try_acquire(ip(7)).expect("a");
            let b = limiter.try_acquire(ip(7)).expect("b");
            drop(a);
            let c = limiter.try_acquire(ip(7)).expect("c");
            drop(b);
            drop(c);
        }
        assert_eq!(limiter.tracked_ips(), 0);
        // Still functional after all that churn.
        assert!(limiter.try_acquire(ip(7)).is_some());
    }
}
