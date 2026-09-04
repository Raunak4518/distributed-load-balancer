mod shutdown;
mod wiring;

pub use wiring::{
    build_app, AppClusterNode, ClusterSetup, HttpContext, ListenerRuntime, TcpAppContext, WiredApp,
};

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
        cluster,
        metrics,
        admin_listen,
        pools,
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
        tracing::info!(
            listener = %runtime.name(),
            protocol = runtime.protocol_name(),
            addr = %actual,
            "listener bound"
        );
        bound.push((listener, runtime));
    }

    // Bound here alongside the traffic listeners so a port clash fails
    // startup, rather than surfacing once we are already serving.
    let mut cluster_tasks = Vec::new();
    if let Some(setup) = cluster {
        let peer_listener = TcpListener::bind(setup.listen).await.map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!(
                    "cluster peer listener could not bind {}: {err}",
                    setup.listen
                ),
            )
        })?;
        tracing::info!(
            node_id = %setup.node.node_id(),
            addr = %peer_listener.local_addr()?,
            peers = setup.peers.len(),
            "cluster peer listener bound"
        );
        cluster_tasks.push(lb_cluster::spawn_peer_listener(
            Arc::clone(&setup.node),
            peer_listener,
        ));
        cluster_tasks.push(lb_cluster::spawn_sync_loop(
            Arc::clone(&setup.node),
            setup.peers.clone(),
            setup.sync_interval,
            Duration::from_secs(2),
        ));
    }

    // Bound with the others so an admin port clash also fails startup.
    if let Some(admin_addr) = admin_listen {
        let admin_listener = TcpListener::bind(admin_addr).await.map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("admin listener could not bind {admin_addr}: {err}"),
            )
        })?;
        tracing::info!(addr = %admin_listener.local_addr()?, "admin listener bound");

        // Ready when any listener has somewhere to forward. If every backend
        // is down, this instance should leave rotation — but stay alive, since
        // restarting it would not bring the backends back.
        let readiness: lb_metrics::ReadinessCheck =
            Arc::new(move || pools.iter().any(|p| !p.eligible_backends().is_empty()));
        cluster_tasks.push(lb_metrics::spawn_admin_server(
            Arc::clone(&metrics),
            admin_listener,
            readiness,
        ));
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
    tracing::info!("shutdown signal received, draining in-flight connections");
    let _ = shutdown_tx.send(true);

    for task in listener_tasks {
        let _ = task.await;
    }
    for task in background_tasks.into_iter().chain(cluster_tasks) {
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
                Err(err) => tracing::warn!(listener = %runtime.name(), error = %err, "accept failed"),
            },
            _ = shutdown.changed() => break,
        }
    }

    let drained = tokio::time::timeout(drain_timeout, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            listener = %runtime.name(),
            remaining = connections.len(),
            "drain deadline exceeded, aborting connections"
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
                    tracing::debug!(error = %err, "client connection error");
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
