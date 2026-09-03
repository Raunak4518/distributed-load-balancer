mod shutdown;
mod wiring;

pub use wiring::{build_context, AppContext, WiredApp};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lb_core::Config;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

/// How long `run` waits for in-flight connections to finish after a shutdown
/// signal before giving up and aborting them outright.
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

pub async fn run(config: Config) -> std::io::Result<()> {
    let listen_addr = config.server.listen;
    let WiredApp { context, background_tasks } = build_context(&config);

    let listener = TcpListener::bind(listen_addr).await?;
    eprintln!("listening on {listen_addr}");

    let shutdown = shutdown::wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    // Tracked (not bare tokio::spawn) so shutdown can wait for these
    // specific per-connection tasks to finish, distinct from the
    // long-lived background_tasks (sweeper, active checkers) which are
    // simply aborted below since they have no in-flight work to lose.
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let io = TokioIo::new(stream);
                let ctx = Arc::clone(&context);
                connections.spawn(async move {
                    let svc = service_fn(move |req| lb_proxy::handle(req, Arc::clone(&ctx)));
                    if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                        eprintln!("connection error: {err}");
                    }
                });
            }
            _ = &mut shutdown => {
                eprintln!("shutdown signal received, draining in-flight connections");
                break;
            }
        }
    }

    let drained = tokio::time::timeout(DRAIN_DEADLINE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        eprintln!("drain deadline exceeded, aborting {} remaining connection(s)", connections.len());
        connections.abort_all();
    }

    for task in background_tasks {
        task.abort();
    }
    Ok(())
}
