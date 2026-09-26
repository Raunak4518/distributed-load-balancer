//! Config hot-reload via SIGHUP.
//!
//! Only a listener's *content* — `backends`, `dns_discovery`, `health_check`,
//! `rate_limit` — reloads without a restart. Deliberately excluded, and
//! refused with a clear message rather than silently ignored:
//!
//! - Adding, removing, or re-addressing a listener (its `protocol`/`listen`
//!   changing). That needs new bind/unbind and per-listener task lifecycle
//!   machinery this project does not have yet.
//! - `tls`, `backend_tls` acceptor settings, `http2`, `max_connections`,
//!   `max_connections_per_ip`, `header_read_timeout_ms`. These live on
//!   `ListenerRuntime` directly, read by the accept loop itself rather than
//!   through the swappable `ctx` — TLS cert *content* already reloads on its
//!   own schedule (`lb_tls::spawn_reloader`), which covers the far more
//!   common need (rotation), so the added complexity of a second swappable
//!   seam for the rest isn't paid for here.
//! - `[server]`/`[admin]`/`[cluster]`/`[logging]`/`[tracing]` — process-wide
//!   sections with no equivalent of `ctx` to swap into.
//!
//! The model is `lb_tls::reload`'s: validate everything a change would touch
//! *before* touching anything, and only if every part succeeds. A reload
//! that would be partially applied is worse than one that is refused.
use crate::wiring::{self, ListenerCoreKind, ListenerReloadHandle, ReloadState};
use lb_core::{Config, ListenerConfig, Protocol};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// Nothing was refused. `changed` names the listeners actually rebuilt —
    /// empty means the new config was identical to the one already running.
    Applied { changed: Vec<String> },
    /// Nothing was touched. The message names what would have required a
    /// restart, for the operator to act on.
    Refused(String),
}

fn identity(lc: &ListenerConfig) -> (Protocol, SocketAddr) {
    (lc.protocol, lc.listen)
}

/// Restart-only fields that live on `ListenerRuntime` rather than inside
/// `ctx` — see the module docs for why these specifically are excluded.
fn restart_only_fields_changed(old: &ListenerConfig, new: &ListenerConfig) -> bool {
    old.tls != new.tls
        || old.backend_tls != new.backend_tls
        || old.http2 != new.http2
        || old.max_connections != new.max_connections
        || old.max_connections_per_ip != new.max_connections_per_ip
        || old.header_read_timeout_ms != new.header_read_timeout_ms
        || old.write_timeout_ms != new.write_timeout_ms
        || old.compression != new.compression
        || old.proxy_protocol != new.proxy_protocol
        || old.proxy_protocol_timeout_ms != new.proxy_protocol_timeout_ms
        || old.client_tcp_keepalive != new.client_tcp_keepalive
}

/// The fully testable core: given a new config, the config it would replace,
/// and the running state to apply it to, either rebuilds exactly the
/// listeners that changed or refuses and touches nothing. Takes no signal,
/// no file path — `spawn_sighup_reloader` is the thin, `#[cfg(unix)]`-only
/// wrapper that gets those from the OS and calls this.
pub async fn apply_reload(
    new_config: &Config,
    current_config: &Config,
    reload: &ReloadState,
) -> ReloadOutcome {
    if new_config.server != current_config.server {
        return ReloadOutcome::Refused("[server] changed -- requires a restart".into());
    }
    if new_config.admin != current_config.admin {
        return ReloadOutcome::Refused("[admin] changed -- requires a restart".into());
    }
    if new_config.cluster != current_config.cluster {
        return ReloadOutcome::Refused("[cluster] changed -- requires a restart".into());
    }
    if new_config.logging != current_config.logging {
        return ReloadOutcome::Refused("[logging] changed -- requires a restart".into());
    }
    if new_config.tracing != current_config.tracing {
        return ReloadOutcome::Refused("[tracing] changed -- requires a restart".into());
    }

    let old_identities: HashMap<&str, (Protocol, SocketAddr)> = current_config
        .listeners
        .iter()
        .map(|lc| (lc.name.as_str(), identity(lc)))
        .collect();
    let new_identities: HashMap<&str, (Protocol, SocketAddr)> = new_config
        .listeners
        .iter()
        .map(|lc| (lc.name.as_str(), identity(lc)))
        .collect();
    if old_identities != new_identities {
        return ReloadOutcome::Refused(
            "adding, removing, or re-addressing a listener requires a restart".into(),
        );
    }

    let mut changed_lcs = Vec::new();
    for new_lc in &new_config.listeners {
        let old_lc = current_config
            .listeners
            .iter()
            .find(|l| l.name == new_lc.name)
            .expect("checked above: every name in new_config also exists in current_config");
        if restart_only_fields_changed(old_lc, new_lc) {
            return ReloadOutcome::Refused(format!(
                "listener '{}': tls, backend_tls, http2, connection limits, write_timeout_ms, \
                 compression, proxy_protocol, proxy_protocol_timeout_ms, or client_tcp_keepalive \
                 changed -- requires a restart",
                new_lc.name
            ));
        }
        if old_lc != new_lc {
            changed_lcs.push(new_lc);
        }
    }

    if changed_lcs.is_empty() {
        return ReloadOutcome::Applied {
            changed: Vec::new(),
        };
    }

    // Phase 1: the one fallible step (real file I/O) for every changed
    // listener, before anything is built or swapped. If any fails, nothing
    // about the running process has changed yet.
    let mut resolved = Vec::with_capacity(changed_lcs.len());
    for lc in &changed_lcs {
        match wiring::build_backend_connector(lc, &reload.metrics) {
            Ok(connector) => resolved.push((*lc, connector)),
            Err(err) => {
                return ReloadOutcome::Refused(format!(
                    "listener '{}': {err} -- reload refused, still serving the previous config",
                    lc.name
                ))
            }
        }
    }

    // Phase 2: infallible from here. Build every changed listener's fresh
    // core and spawn its new tasks *before* touching anything live, so a
    // panic partway through construction (there should be none -- this is
    // the same construction `build_app` already runs at startup -- but the
    // ordering is what makes "no partial apply" true even if one crept in)
    // cannot leave some listeners swapped and others not.
    let mut prepared = Vec::with_capacity(resolved.len());
    for (lc, backend_tls) in resolved {
        let carry_dns_backends = lc.dns_discovery.is_some()
            && current_config
                .listeners
                .iter()
                .any(|old| old.name == lc.name && old.dns_discovery == lc.dns_discovery);
        let previous = match reload.listeners.get(&lc.name) {
            Some(ListenerReloadHandle::Http(swap)) => Some(
                wiring::PreviousListenerState::from_http(&swap.load(), carry_dns_backends),
            ),
            Some(ListenerReloadHandle::Tcp(swap)) => Some(wiring::PreviousListenerState::from_tcp(
                &swap.load(),
                carry_dns_backends,
            )),
            None => None,
        };
        let core = wiring::build_listener_core(
            lc,
            backend_tls,
            reload.cluster_node.as_ref(),
            new_config.cluster.as_ref(),
            &new_config.logging,
            &reload.metrics,
            &reload.acme_challenges,
            previous.as_ref(),
        );
        let tasks = wiring::spawn_listener_tasks(lc, &core, &reload.metrics);
        prepared.push((lc.name.clone(), core.kind, tasks));
    }

    let mut changed = Vec::with_capacity(prepared.len());
    let mut tasks_guard = reload.tasks.lock().await;
    for (name, kind, new_tasks) in prepared {
        match (reload.listeners.get(&name), kind) {
            (Some(ListenerReloadHandle::Http(swap)), ListenerCoreKind::Http(ctx)) => {
                swap.store(Arc::new(*ctx));
            }
            (Some(ListenerReloadHandle::Tcp(swap)), ListenerCoreKind::Tcp(ctx)) => {
                swap.store(Arc::new(*ctx));
            }
            _ => unreachable!(
                "listener identity (name -> protocol) was already confirmed unchanged above"
            ),
        }
        if let Some(old_tasks) = tasks_guard.insert(name.clone(), new_tasks) {
            for task in old_tasks {
                task.abort();
            }
        }
        changed.push(name);
    }
    drop(tasks_guard);

    *reload.config.lock().await = new_config.clone();
    ReloadOutcome::Applied { changed }
}

/// The thin, signal-handling half. SIGHUP does not exist on Windows, so this
/// is Unix-only; everything it calls (`apply_reload`) is plain, portable
/// async code with full test coverage on any platform.
#[cfg(unix)]
pub fn spawn_sighup_reloader(
    config_path: PathBuf,
    reload: Arc<ReloadState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut signal = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(error = %err, "could not install a SIGHUP handler; config hot-reload is disabled");
                return;
            }
        };
        loop {
            signal.recv().await;
            tracing::info!(path = %config_path.display(), "SIGHUP received, reloading config");
            let new_config = match Config::load(&config_path) {
                Ok(c) => c,
                Err(err) => {
                    tracing::error!(error = %err, "reload refused: config failed to parse, still serving the previous config");
                    continue;
                }
            };
            let current = reload.config.lock().await.clone();
            match apply_reload(&new_config, &current, &reload).await {
                ReloadOutcome::Applied { changed } if changed.is_empty() => {
                    tracing::info!("reload: no changes to apply");
                }
                ReloadOutcome::Applied { changed } => {
                    tracing::info!(listeners = ?changed, "reload applied");
                }
                ReloadOutcome::Refused(reason) => {
                    tracing::error!(reason = %reason, "reload refused, still serving the previous config");
                }
            }
        }
    })
}

#[cfg(not(unix))]
pub fn spawn_sighup_reloader(
    _config_path: PathBuf,
    _reload: Arc<ReloadState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(std::future::pending())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wiring::{build_app, ListenerRuntime};

    const TWO_LISTENERS: &str = r#"
        [[listeners]]
        name = "a"
        protocol = "http"
        listen = "127.0.0.1:19801"

          [[listeners.backends]]
          id = "a1"
          address = "127.0.0.1:9001"

          [listeners.health_check]
          path = "/health"
          interval_ms = 2000
          timeout_ms = 500
          failure_threshold = 3
          cooldown_ms = 5000

          [listeners.rate_limit]
          key = "source_ip"
          rate_per_sec = 50
          burst = 100

          [listeners.load_balancing]
          strategy = "round_robin"

        [[listeners]]
        name = "b"
        protocol = "http"
        listen = "127.0.0.1:19802"

          [[listeners.backends]]
          id = "b1"
          address = "127.0.0.1:9002"

          [listeners.health_check]
          path = "/health"
          interval_ms = 2000
          timeout_ms = 500
          failure_threshold = 3
          cooldown_ms = 5000

          [listeners.rate_limit]
          key = "source_ip"
          rate_per_sec = 50
          burst = 100

          [listeners.load_balancing]
          strategy = "round_robin"
    "#;

    fn http_ctx_arc(app_reload: &ReloadState, name: &str) -> Arc<wiring::HttpContext> {
        match app_reload.listeners.get(name) {
            Some(ListenerReloadHandle::Http(swap)) => swap.load_full(),
            _ => panic!("expected an http listener named '{name}'"),
        }
    }

    async fn abort_everything(app: crate::WiredApp) {
        for task in app.tls_reload_tasks {
            task.abort();
        }
        for (_, tasks) in app.reload.tasks.lock().await.drain() {
            for task in tasks {
                task.abort();
            }
        }
    }

    #[tokio::test]
    async fn changing_one_listeners_rate_limit_reloads_only_that_listener() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();
        let a_before = http_ctx_arc(&app.reload, "a");
        let b_before = http_ctx_arc(&app.reload, "b");

        // "a" is declared first, so the first `rate_per_sec = 50` is its own.
        let new =
            Config::parse(&TWO_LISTENERS.replacen("rate_per_sec = 50", "rate_per_sec = 999", 1))
                .unwrap();

        let outcome = apply_reload(&new, &old, &app.reload).await;
        assert_eq!(
            outcome,
            ReloadOutcome::Applied {
                changed: vec!["a".to_string()]
            }
        );

        let a_after = http_ctx_arc(&app.reload, "a");
        let b_after = http_ctx_arc(&app.reload, "b");
        assert!(
            !Arc::ptr_eq(&a_before, &a_after),
            "listener 'a' should have been rebuilt"
        );
        assert!(
            Arc::ptr_eq(&b_before, &b_after),
            "listener 'b' was not touched by the reload and must not have been rebuilt"
        );

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn an_identical_config_applies_with_nothing_changed() {
        let config = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&config, None).unwrap();

        let outcome = apply_reload(&config, &config, &app.reload).await;
        assert_eq!(
            outcome,
            ReloadOutcome::Applied {
                changed: Vec::new()
            }
        );

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn adding_a_listener_is_refused_and_changes_nothing() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();
        let a_before = http_ctx_arc(&app.reload, "a");

        let with_a_third_listener = format!(
            "{TWO_LISTENERS}\n\n        [[listeners]]\n        name = \"c\"\n        protocol = \"http\"\n        listen = \"127.0.0.1:0\"\n\n          [[listeners.backends]]\n          id = \"c1\"\n          address = \"127.0.0.1:9003\"\n\n          [listeners.health_check]\n          path = \"/health\"\n          interval_ms = 2000\n          timeout_ms = 500\n          failure_threshold = 3\n          cooldown_ms = 5000\n\n          [listeners.rate_limit]\n          key = \"source_ip\"\n          rate_per_sec = 50\n          burst = 100\n\n          [listeners.load_balancing]\n          strategy = \"round_robin\"\n"
        );
        let new = Config::parse(&with_a_third_listener).unwrap();

        let outcome = apply_reload(&new, &old, &app.reload).await;
        match outcome {
            ReloadOutcome::Refused(reason) => assert!(reason.contains("restart")),
            other => panic!("expected a refusal, got {other:?}"),
        }

        let a_after = http_ctx_arc(&app.reload, "a");
        assert!(
            Arc::ptr_eq(&a_before, &a_after),
            "a refused reload must not touch any listener"
        );

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn changing_cluster_is_refused() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();

        let with_cluster = format!(
            "[cluster]\nnode_id = \"lb-1\"\nlisten = \"127.0.0.1:0\"\nshared_secret = \"s\"\n\n{TWO_LISTENERS}"
        );
        let new = Config::parse(&with_cluster).unwrap();

        let outcome = apply_reload(&new, &old, &app.reload).await;
        match outcome {
            ReloadOutcome::Refused(reason) => assert!(reason.contains("cluster")),
            other => panic!("expected a refusal, got {other:?}"),
        }

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn changing_compression_is_refused_not_silently_ignored() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();

        let new = Config::parse(&TWO_LISTENERS.replacen(
            "listen = \"127.0.0.1:19801\"",
            "listen = \"127.0.0.1:19801\"\n        compression = true",
            1,
        ))
        .unwrap();

        let outcome = apply_reload(&new, &old, &app.reload).await;
        match outcome {
            ReloadOutcome::Refused(reason) => assert!(reason.contains("compression")),
            other => panic!("expected a refusal, got {other:?}"),
        }

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn changing_proxy_protocol_is_refused_not_silently_ignored() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();

        let new = Config::parse(&TWO_LISTENERS.replacen(
            "listen = \"127.0.0.1:19801\"",
            "listen = \"127.0.0.1:19801\"\n        proxy_protocol = true",
            1,
        ))
        .unwrap();

        let outcome = apply_reload(&new, &old, &app.reload).await;
        match outcome {
            ReloadOutcome::Refused(reason) => assert!(reason.contains("proxy_protocol")),
            other => panic!("expected a refusal, got {other:?}"),
        }

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn a_backend_change_is_reflected_in_the_swapped_pool() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();

        let new_text = TWO_LISTENERS.replacen(
            "[[listeners.backends]]\n          id = \"a1\"\n          address = \"127.0.0.1:9001\"",
            "[[listeners.backends]]\n          id = \"a1\"\n          address = \"127.0.0.1:9001\"\n\n          [[listeners.backends]]\n          id = \"a2\"\n          address = \"127.0.0.1:9099\"",
            1,
        );
        let new = Config::parse(&new_text).unwrap();

        let outcome = apply_reload(&new, &old, &app.reload).await;
        assert_eq!(
            outcome,
            ReloadOutcome::Applied {
                changed: vec!["a".to_string()]
            }
        );

        let a_after = http_ctx_arc(&app.reload, "a");
        assert_eq!(a_after.pool.all_backend_ids().len(), 2);

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn a_manual_drain_survives_an_unrelated_reload() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();
        let a_before = http_ctx_arc(&app.reload, "a");
        a_before
            .pool
            .set_manually_drained(&lb_core::BackendId::new("a1"), true);

        let new =
            Config::parse(&TWO_LISTENERS.replacen("rate_per_sec = 50", "rate_per_sec = 999", 1))
                .unwrap();
        let outcome = apply_reload(&new, &old, &app.reload).await;
        assert_eq!(
            outcome,
            ReloadOutcome::Applied {
                changed: vec!["a".to_string()]
            }
        );

        let a_after = http_ctx_arc(&app.reload, "a");
        assert!(
            a_after
                .pool
                .is_manually_drained(&lb_core::BackendId::new("a1")),
            "a manual drain must not be undone by an unrelated field's reload"
        );

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn a_failed_health_check_survives_an_unrelated_reload() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();
        let id = lb_core::BackendId::new("a1");
        http_ctx_arc(&app.reload, "a")
            .pool
            .set_active_healthy(&id, false);

        let new =
            Config::parse(&TWO_LISTENERS.replacen("rate_per_sec = 50", "rate_per_sec = 999", 1))
                .unwrap();
        let outcome = apply_reload(&new, &old, &app.reload).await;
        assert_eq!(
            outcome,
            ReloadOutcome::Applied {
                changed: vec!["a".to_string()]
            }
        );

        let a_after = http_ctx_arc(&app.reload, "a");
        assert!(!a_after.pool.is_active_healthy(&id));
        assert!(!a_after.pool.is_eligible(&id));

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn a_backend_added_by_reload_waits_for_its_first_probe() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();
        let a1 = lb_core::BackendId::new("a1");
        let a2 = lb_core::BackendId::new("a2");
        http_ctx_arc(&app.reload, "a")
            .pool
            .set_active_healthy(&a1, true);

        let new_text = TWO_LISTENERS.replacen(
            "[[listeners.backends]]\n          id = \"a1\"\n          address = \"127.0.0.1:9001\"",
            "[[listeners.backends]]\n          id = \"a1\"\n          address = \"127.0.0.1:9001\"\n\n          [[listeners.backends]]\n          id = \"a2\"\n          address = \"127.0.0.1:9099\"",
            1,
        );
        let new = Config::parse(&new_text).unwrap();
        let outcome = apply_reload(&new, &old, &app.reload).await;
        assert_eq!(
            outcome,
            ReloadOutcome::Applied {
                changed: vec!["a".to_string()]
            }
        );

        let a_after = http_ctx_arc(&app.reload, "a");
        assert!(a_after.pool.is_awaiting_first_probe(&a2));
        assert!(!a_after.pool.is_awaiting_first_probe(&a1));
        assert_eq!(a_after.pool.eligible_backends(), vec![a1]);

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn an_open_circuit_breaker_survives_an_unrelated_reload() {
        let old = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&old, None).unwrap();
        let a_before = http_ctx_arc(&app.reload, "a");
        let id = lb_core::BackendId::new("a1");
        let breaker = a_before.circuit_breakers.get(&id).unwrap();
        // TWO_LISTENERS sets failure_threshold = 3.
        breaker.record_failure();
        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.state(), lb_healthcheck::CircuitState::Open);

        let new =
            Config::parse(&TWO_LISTENERS.replacen("rate_per_sec = 50", "rate_per_sec = 999", 1))
                .unwrap();
        let outcome = apply_reload(&new, &old, &app.reload).await;
        assert_eq!(
            outcome,
            ReloadOutcome::Applied {
                changed: vec!["a".to_string()]
            }
        );

        let a_after = http_ctx_arc(&app.reload, "a");
        assert_eq!(
            a_after.circuit_breakers.get(&id).unwrap().state(),
            lb_healthcheck::CircuitState::Open,
            "a breaker mid-cooldown must not be reset to Closed by an unrelated field's reload"
        );

        abort_everything(app).await;
    }

    #[tokio::test]
    async fn concurrent_reloads_never_leave_stored_config_disagreeing_with_live_state() {
        for _ in 0..50 {
            let old = Config::parse(TWO_LISTENERS).unwrap();
            let app = build_app(&old, None).unwrap();

            let new_a_text = TWO_LISTENERS.replacen(
                "[[listeners.backends]]\n          id = \"a1\"\n          address = \"127.0.0.1:9001\"",
                "[[listeners.backends]]\n          id = \"a1\"\n          address = \"127.0.0.1:9001\"\n\n          [[listeners.backends]]\n          id = \"a2\"\n          address = \"127.0.0.1:9099\"",
                1,
            );
            let new_b_text = TWO_LISTENERS.replacen(
                "[[listeners.backends]]\n          id = \"a1\"\n          address = \"127.0.0.1:9001\"",
                "[[listeners.backends]]\n          id = \"a1\"\n          address = \"127.0.0.1:9001\"\n\n          [[listeners.backends]]\n          id = \"a3\"\n          address = \"127.0.0.1:9098\"",
                1,
            );
            let new_a = Config::parse(&new_a_text).unwrap();
            let new_b = Config::parse(&new_b_text).unwrap();

            let (outcome_a, outcome_b) = tokio::join!(
                apply_reload(&new_a, &old, &app.reload),
                apply_reload(&new_b, &old, &app.reload),
            );
            assert!(matches!(outcome_a, ReloadOutcome::Applied { .. }));
            assert!(matches!(outcome_b, ReloadOutcome::Applied { .. }));

            let stored_config = app.reload.config.lock().await.clone();
            let stored_a = stored_config
                .listeners
                .iter()
                .find(|l| l.name == "a")
                .unwrap();
            let live_a = http_ctx_arc(&app.reload, "a");
            let live_ids: std::collections::HashSet<_> =
                live_a.pool.all_backend_ids().into_iter().collect();
            let stored_ids: std::collections::HashSet<_> = stored_a
                .backends
                .iter()
                .map(|b| lb_core::BackendId::new(b.id.clone()))
                .collect();
            assert_eq!(
                live_ids, stored_ids,
                "stored config's backend set for listener 'a' must always match \
                 the live pool's backend set, even when two reloads race"
            );

            abort_everything(app).await;
        }
    }

    /// The listener runtime and the reload handle must always point at the
    /// *same* `ArcSwap` -- checked directly, since every other test in this
    /// module only ever reads through the reload handle and would not catch
    /// a bug where the two had silently diverged.
    #[tokio::test]
    async fn the_listener_runtime_and_the_reload_handle_share_one_arc_swap() {
        let config = Config::parse(TWO_LISTENERS).unwrap();
        let app = build_app(&config, None).unwrap();

        let ListenerRuntime::Http {
            ctx: runtime_ctx, ..
        } = app.listeners.iter().find(|l| l.name() == "a").unwrap()
        else {
            panic!("expected an http listener");
        };
        let ListenerReloadHandle::Http(reload_ctx) = app.reload.listeners.get("a").unwrap() else {
            panic!("expected an http reload handle");
        };
        assert!(Arc::ptr_eq(runtime_ctx, reload_ctx));

        abort_everything(app).await;
    }
}
