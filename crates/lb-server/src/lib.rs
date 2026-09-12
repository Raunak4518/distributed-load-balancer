mod dns;
mod first_byte;
mod limits;
pub mod reload;
mod shutdown;
mod wiring;
mod write_timeout;

pub use wiring::{
    build_app, AppClusterNode, ClusterSetup, HttpContext, ListenerReloadHandle, ListenerRuntime,
    ReloadState, TcpAppContext, WiredApp,
};

use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lb_core::Config;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

/// `config_path`, when present, is what `reload::spawn_sighup_reloader`
/// re-reads on SIGHUP — `None` (every existing test's inline-TOML config,
/// which was never loaded from a file) means the reload task is not spawned
/// at all, so SIGHUP does nothing, which is the only sound behavior for a
/// config with nowhere to reload *from*.
pub async fn run(config: Config, config_path: Option<PathBuf>) -> std::io::Result<()> {
    run_and_report_reload_handle(config, config_path, None).await
}

/// Same as `run`, but sends the running app's `Arc<ReloadState>` through
/// `report` (if given) once it exists — before entering the shutdown wait,
/// so a test can call `reload::apply_reload` directly against a *real*
/// running instance instead of only against a bare `WiredApp`. SIGHUP is
/// Unix-only and untestable on this project's Windows dev environment (see
/// `reload`'s module docs), so this is what closes the loop on the rest of
/// the reload path elsewhere.
///
/// Not part of the public API surface `run` is: exists to be called from
/// this crate's own `tests/`, not for embedders.
#[doc(hidden)]
pub async fn run_and_report_reload_handle(
    config: Config,
    config_path: Option<PathBuf>,
    report: Option<tokio::sync::oneshot::Sender<Arc<ReloadState>>>,
) -> std::io::Result<()> {
    // Must happen before any rustls type is constructed — `build_app` builds
    // the TLS acceptors. `ring`, matching what every TLS crate in the graph
    // selected; a provider mismatch surfaces at runtime, not compile time.
    lb_tls::install_crypto_provider();

    // Resolved before anything binds: a cluster configured without a usable
    // secret must fail startup, not run unauthenticated.
    let cluster_secret = match config.cluster.as_ref() {
        Some(c) => Some(c.resolve_secret().map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string())
        })?),
        None => None,
    };

    let WiredApp {
        listeners,
        tls_reload_tasks,
        drain_timeout,
        cluster,
        metrics,
        admin_listen,
        pools,
        reload,
    } = build_app(&config, cluster_secret)?;

    if let Some(report) = report {
        let _ = report.send(Arc::clone(&reload));
    }

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
        // Shared from here on: every connection task holds a handle to the
        // runtime it was accepted on, and outlives the accept-loop iteration
        // that spawned it.
        bound.push((listener, Arc::new(runtime)));
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
            setup.peer_tls.clone(),
        ));
        cluster_tasks.push(lb_cluster::spawn_sync_loop(
            Arc::clone(&setup.node),
            setup.peers.clone(),
            setup.sync_interval,
            Duration::from_secs(2),
            setup.peer_tls.clone(),
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

    // Spawned only when this config came from a file at all — see `run`'s
    // doc comment on `config_path`. Its own handle joins `cluster_tasks`:
    // like the cluster/admin tasks, it carries no client-facing state, so
    // an abort at shutdown (rather than a drain) is correct for it too.
    if let Some(path) = config_path {
        cluster_tasks.push(reload::spawn_sighup_reloader(path, Arc::clone(&reload)));
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
    let reloadable_tasks = std::mem::take(&mut *reload.tasks.lock().await);
    for task in tls_reload_tasks
        .into_iter()
        .chain(reloadable_tasks.into_values().flatten())
        .chain(cluster_tasks)
    {
        task.abort();
    }
    Ok(())
}

/// Accept loop for one listener. Owns its own connection JoinSet so it can
/// drain independently when the shutdown signal arrives.
async fn serve_listener(
    listener: TcpListener,
    runtime: Arc<ListenerRuntime>,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
) {
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        // Acquire the global permit BEFORE accepting. At capacity we simply
        // stop calling accept(): the kernel's backlog absorbs the next few
        // and then refuses connections itself. Accepting first and deciding
        // after would spend a file descriptor and a task on a connection we
        // intend to discard — which is what an attacker wants.
        if runtime.limits().global.available_permits() == 0 {
            runtime.metrics().connections_rejected_max.inc();
        }
        let permit = tokio::select! {
            acquired = Arc::clone(&runtime.limits().global).acquire_owned() => match acquired {
                Ok(p) => p,
                Err(_) => break, // semaphore closed
            },
            _ = shutdown.changed() => break,
        };

        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                // A transient accept error (e.g. fd exhaustion) must not kill
                // the listener permanently.
                Err(err) => {
                    tracing::warn!(listener = %runtime.name(), error = %err, "accept failed");
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };

        // Must follow accept(): the peer address is unknowable before it.
        let Some(ip_guard) = runtime.limits().per_ip.try_acquire(peer.ip()) else {
            runtime.metrics().connections_rejected_per_ip.inc();
            tracing::debug!(listener = %runtime.name(), peer = %peer, "per-IP connection cap reached");
            continue; // `stream` drops here, closing it
        };

        spawn_connection(&runtime, &mut connections, stream, peer, permit, ip_guard);
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

/// Spawns the connection handler, moving both limit guards into the task so
/// every exit path — success, error, panic, drain — releases them.
///
/// On a TLS listener the handshake also happens inside the task, never in the
/// accept loop: it is several network round trips, and running it before
/// `spawn` would let one slow client stall every other accept here. Both
/// guards are held across it, so a handshake flood consumes the connection
/// budget — which is correct precisely because the handshake timeout
/// guarantees that budget drains.
fn spawn_connection(
    runtime: &Arc<ListenerRuntime>,
    connections: &mut JoinSet<()>,
    stream: TcpStream,
    peer: SocketAddr,
    permit: tokio::sync::OwnedSemaphorePermit,
    ip_guard: crate::limits::IpGuard,
) {
    let runtime = Arc::clone(runtime);
    connections.spawn(async move {
        // Held for the life of the connection, handshake included.
        let _permit = permit;
        let _ip_guard = ip_guard;

        let Some(acceptor) = runtime.tls() else {
            // No TLS means no ALPN, and this node is the edge: prior-knowledge
            // h2c on an unencrypted port is surface nobody asked for. Passing
            // `false` unconditionally is what keeps "a plaintext listener is
            // HTTP/1.1" true in code rather than only in config.
            drive(&runtime, stream, peer, false).await;
            return;
        };

        let metrics = runtime.metrics();
        let started = std::time::Instant::now();
        match acceptor.accept(stream).await {
            Ok(tls) => {
                metrics.tls_handshakes_success.inc();
                // Recorded separately from request latency, which never
                // includes it: a failed handshake never becomes a request.
                metrics
                    .tls_handshake_duration
                    .observe(started.elapsed().as_secs_f64());
                // Read here, while the concrete `TlsStream` still exists --
                // `drive` is generic and erases it. This is why the dispatch
                // needs no preface sniffing: the handshake that just
                // completed already told us which protocol both ends chose.
                let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                drive(&runtime, tls, peer, is_h2).await;
            }
            Err(lb_tls::HandshakeError::TimedOut) => {
                metrics.tls_handshakes_timeout.inc();
            }
            Err(lb_tls::HandshakeError::Failed(err)) => {
                // No TLS session exists yet, so there is nothing to send an
                // alert over and nothing that would be valid HTTP. Dropping
                // the stream is the entire response. The error is rustls'
                // own description of the protocol failure; the hostname the
                // client asked for is deliberately not recorded anywhere.
                metrics.tls_handshakes_failed.inc();
                tracing::debug!(error = %err, "tls handshake failed");
            }
        }
    });
}

/// Runs the protocol driver over whatever stream it is given.
///
/// Generic so the same code serves a plain `TcpStream` and a `TlsStream`; the
/// data planes never learn which they got, which is why terminating TLS
/// needed no change to `lb-proxy` at all.
///
/// `is_h2` is the protocol the handshake negotiated. It is decided by the
/// caller because only the caller still holds a stream concrete enough to ask,
/// and it is always `false` for a plaintext connection, which has no ALPN.
async fn drive<S>(runtime: &ListenerRuntime, stream: S, peer: SocketAddr, is_h2: bool)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match runtime {
        ListenerRuntime::Http {
            ctx,
            header_read_timeout,
            write_timeout,
            http2,
            ..
        } => {
            // Loaded fresh here, not once at listener startup: this is what
            // lets `reload::apply_reload` change a running listener's
            // backends/rate limit/health checks without dropping a single
            // connection — this one and every connection already in flight
            // keep whichever snapshot they loaded, while the next one to
            // reach this line sees whatever is current then.
            let ctx = ctx.load_full();
            let peer_ip = peer.ip();
            let svc = service_fn(move |req| lb_proxy::handle(req, Arc::clone(&ctx), peer_ip));
            // Read and write sides are policed independently and compose
            // transparently: each is a pure passthrough on the direction it
            // doesn't own, so wrapping order between them doesn't matter.
            let stream = write_timeout::WriteIdleTimeout::new(stream, *write_timeout);
            if is_h2 {
                // Holds by construction, not by hope: `h2` is advertised only
                // when `http2_enabled()` is true, and this field is populated
                // from that same predicate in the same `build_app` arm. A
                // connection therefore cannot negotiate `h2` on a listener
                // with no settings to serve it under -- including the common
                // case of a TLS listener with no `[listeners.http2]` section,
                // which gets `Http2Config::default()`.
                let h2 = http2
                    .as_ref()
                    .expect("h2 is only advertised when http2 config is present");
                // Every limit below exists because one HTTP/2 connection
                // carries many concurrent requests, so Phase 5's per-IP
                // *connection* cap no longer bounds per-IP *work*. Omitting
                // them would quietly undo that hardening.
                if let Err(err) = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    // Same rule as the HTTP/1.1 path below: hyper 1.x has no
                    // built-in timer, and the keep-alive settings panic
                    // without one.
                    .timer(hyper_util::rt::TokioTimer::new())
                    // The h2 analogue of max_connections_per_ip.
                    .max_concurrent_streams(h2.max_concurrent_streams())
                    // Rapid Reset (CVE-2023-44487). Cancelled streams evade
                    // max_concurrent_streams by not being concurrent.
                    .max_pending_accept_reset_streams(h2.max_pending_accept_reset_streams())
                    .max_local_error_reset_streams(h2.max_local_error_reset_streams())
                    // Bounds HPACK and CONTINUATION expansion, where few
                    // frames can become a lot of server-side state.
                    .max_header_list_size(h2.max_header_list_size())
                    .max_frame_size(h2.max_frame_size())
                    // PING polices an *established* connection: once the
                    // preface has arrived, an idle h2 connection is normal
                    // and a dead one is not, and PING tells them apart.
                    // It does not cover the window before that -- hyper
                    // arms it only after the handshake resolves -- which is
                    // what `FirstByteDeadline` below is for.
                    .keep_alive_interval(h2.keep_alive_interval())
                    .keep_alive_timeout(h2.keep_alive_timeout())
                    // The h2 counterpart of `header_read_timeout`, and the
                    // same question: how long may a client take to start
                    // sending? Without it a client that negotiates `h2` and
                    // then goes silent holds its connection permit and its
                    // per-IP slot indefinitely, at no cost to itself.
                    .serve_connection(
                        TokioIo::new(first_byte::FirstByteDeadline::new(
                            stream,
                            *header_read_timeout,
                        )),
                        svc,
                    )
                    .await
                {
                    tracing::debug!(error = %err, "http/2 client connection error");
                }
            } else if let Err(err) = http1::Builder::new()
                // hyper 1.x has no built-in timer: any timeout feature
                // panics unless one is supplied. Must accompany
                // `header_read_timeout`, not be assumed.
                .timer(hyper_util::rt::TokioTimer::new())
                // Caps the time a client may take to send the request
                // head — the direct slowloris defence. There is no h2
                // equivalent above, deliberately; see the keep-alive note.
                .header_read_timeout(*header_read_timeout)
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                tracing::debug!(error = %err, "client connection error");
            }
        }
        ListenerRuntime::Tcp { ctx, .. } => {
            // Loaded fresh per connection, same reasoning as the HTTP arm.
            lb_tcp::handle_connection(stream, peer, ctx.load_full()).await;
        }
    }
}
