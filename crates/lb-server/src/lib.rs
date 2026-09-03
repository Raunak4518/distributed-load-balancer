mod shutdown;
mod wiring;

pub use wiring::{build_app, HttpContext, ListenerRuntime, TcpAppContext, WiredApp};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub async fn run(config: Config) -> std::io::Result<()> {
    let WiredApp {
        listeners,
        background_tasks,
        drain_timeout,
    } = build_app(&config);

    // Bind every listener before serving any of them, so a port conflict or
    // permission error fails startup outright instead of half-starting.
    let mut bound = Vec::with_capacity(listeners.len());
    for runtime in listeners {
        // Name the listener in the error: a bare "address in use" gives an
        // operator no clue which of several listeners is the problem.
        let listener = TcpListener::bind(runtime.listen()).await.map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!(
                    "listener '{}' could not bind {}: {err}",
                    runtime.name(),
                    runtime.listen()
                ),
            )
        })?;
        let actual = listener.local_addr()?;
        eprintln!(
            "listener '{}' ({}) on {}",
            runtime.name(),
            runtime.protocol_name(),
            actual
        );
        bound.push((listener, runtime));
    }

    // One shutdown signal fans out to every accept loop.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut listener_tasks = Vec::with_capacity(bound.len());
    for (listener, runtime) in bound {
        listener_tasks.push(tokio::spawn(serve_listener(
            listener,
            runtime,
            shutdown_rx.clone(),
            drain_timeout,
        )));
    }

    shutdown::wait_for_shutdown_signal().await;
    eprintln!("shutdown signal received, draining in-flight connections");
    let _ = shutdown_tx.send(true);

    for task in listener_tasks {
        let _ = task.await;
    }
    for task in background_tasks {
        task.abort();
    }
    Ok(())
}

/// Accept loop for one listener. Owns its own connection JoinSet so it can
/// drain independently when the shutdown signal arrives.
async fn serve_listener(
    listener: TcpListener,
    runtime: ListenerRuntime,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
) {
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => spawn_connection(&runtime, &mut connections, stream, peer),
                // A transient accept error (e.g. fd exhaustion) must not kill
                // the listener permanently.
                Err(err) => eprintln!("accept error on '{}': {err}", runtime.name()),
            },
            _ = shutdown.changed() => break,
        }
    }

    let drained = tokio::time::timeout(drain_timeout, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        eprintln!(
            "listener '{}': drain deadline exceeded, aborting {} connection(s)",
            runtime.name(),
            connections.len()
        );
        connections.abort_all();
    }
}

fn spawn_connection(
    runtime: &ListenerRuntime,
    connections: &mut JoinSet<()>,
    stream: TcpStream,
    peer: SocketAddr,
) {
    match runtime {
        ListenerRuntime::Http { ctx, .. } => {
            let ctx = Arc::clone(ctx);
            let io = TokioIo::new(stream);
            let peer_ip = peer.ip();
            connections.spawn(async move {
                let svc = service_fn(move |req| lb_proxy::handle(req, Arc::clone(&ctx), peer_ip));
                if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                    eprintln!("connection error: {err}");
                }
            });
        }
        ListenerRuntime::Tcp { ctx, .. } => {
            let ctx = Arc::clone(ctx);
            connections.spawn(async move {
                lb_tcp::handle_connection(stream, peer, ctx).await;
            });
        }
    }
}
