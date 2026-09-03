use crate::backend::BackendId;
use crate::pool::BackendPool;

pub trait LoadBalancer: Send + Sync {
    fn pick(&self, pool: &BackendPool) -> Option<BackendId>;
}
