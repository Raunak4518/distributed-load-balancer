mod active;
mod circuit_breaker;
mod probe;

// Doubles for the `ProbeClient` / `OutboundTransport` seams, shared by
// `probe.rs`'s and `active.rs`'s test suites.
#[cfg(test)]
mod test_support;

pub use active::{spawn_active_checker, ActiveCheckConfig};
pub use circuit_breaker::{CircuitBreaker, CircuitState};
pub use probe::{HttpProbe, TcpConnectProbe};
