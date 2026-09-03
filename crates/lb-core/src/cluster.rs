/// Cluster-wide admission control, consulted *after* the node-local rate
/// limiter has already allowed a request.
///
/// Implementations must not perform I/O: this sits on the request path, and
/// coordination happens out of band.
pub trait ClusterCoordinator: Send + Sync {
    /// Returns true if this request fits within the cluster-wide budget for
    /// `key`, recording it if so.
    fn try_admit(&self, key: &str) -> bool;
}
