use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { retry_after: Duration },
}

pub trait RateLimiter: Send + Sync {
    fn check(&self, key: &str) -> Decision;
}
