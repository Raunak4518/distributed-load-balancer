use std::future::Future;
use std::io;
use std::net::SocketAddr;

pub trait Resolve: Send + Sync {
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
}
