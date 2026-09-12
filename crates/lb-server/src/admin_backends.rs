//! The admin API's `/backends` routes: `lb_metrics::admin`'s extension
//! point (`AdminExtension`), implemented here because this is where
//! `ReloadState`/`BackendPool` actually live -- `lb-metrics` knows neither.
//!
//! Deliberately narrower than "add or remove backends at runtime": that
//! would need real validation (TLS cert re-checks, address sanity) and a
//! persistence story this doesn't have. What's here are the two primitives
//! nginx paywalls into nginx Plus -- inspecting live backend state, and
//! draining/undraining one without touching the config file:
//!
//! - `GET /backends` -- every listener's backends, with health/circuit/
//!   in-flight state.
//! - `POST /backends/{listener}/{backend_id}/drain` -- marks a backend
//!   manually drained (`BackendPool::set_manually_drained(id, true)`),
//!   removing it from `eligible_backends()` for new traffic without
//!   touching in-flight connections or forgetting the entry, unlike
//!   removing it from config (which a reload would need to reintroduce).
//!   A separate flag from the active health checker's own `active_healthy`
//!   -- folding this into that one would just have the checker's next
//!   successful probe silently undo the drain.
//! - `POST /backends/{listener}/{backend_id}/undrain` -- the reverse.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use lb_core::{BackendId, BackendPool};
use std::sync::Arc;

use crate::wiring::{ListenerReloadHandle, ReloadState};

/// Builds the `lb_metrics::AdminExtension` closure, closing over the app's
/// `ReloadState` -- the same "reach a named listener's live state from
/// outside its own accept loop" mechanism `reload::apply_reload` itself
/// uses.
pub fn extension(reload: Arc<ReloadState>) -> lb_metrics::AdminExtension {
    Arc::new(move |req: Request<Incoming>| {
        let reload = Arc::clone(&reload);
        Box::pin(async move { handle(&req, &reload) })
    })
}

fn pool_for(reload: &ReloadState, listener: &str) -> Option<Arc<BackendPool>> {
    match reload.listeners.get(listener)? {
        ListenerReloadHandle::Http(ctx) => Some(Arc::clone(&ctx.load().pool)),
        ListenerReloadHandle::Tcp(ctx) => Some(Arc::clone(&ctx.load().pool)),
    }
}

fn handle(req: &Request<Incoming>, reload: &ReloadState) -> Response<Full<Bytes>> {
    let path = req.uri().path();
    let segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if req.method() == Method::GET && segments.len() == 1 && segments[0] == "backends" {
        return list_all(reload);
    }

    if req.method() == Method::POST {
        if let [_, listener, id, action] = segments.as_slice() {
            match *action {
                "drain" => return set_drain(reload, listener, id, true),
                "undrain" => return set_drain(reload, listener, id, false),
                _ => {}
            }
        }
    }

    json_response(
        StatusCode::NOT_FOUND,
        serde_json::json!({"error": "not found"}),
    )
}

fn list_all(reload: &ReloadState) -> Response<Full<Bytes>> {
    let mut listeners = serde_json::Map::new();
    for (name, handle) in &reload.listeners {
        let pool = match handle {
            ListenerReloadHandle::Http(ctx) => Arc::clone(&ctx.load().pool),
            ListenerReloadHandle::Tcp(ctx) => Arc::clone(&ctx.load().pool),
        };
        let backends: Vec<serde_json::Value> = pool
            .all_backend_ids()
            .into_iter()
            .filter_map(|id| {
                let backend = pool.backend(&id)?;
                Some(serde_json::json!({
                    "id": id.0.to_string(),
                    "address": backend.address.to_string(),
                    "active_healthy": pool.is_active_healthy(&id),
                    "circuit_open": pool.is_circuit_open(&id),
                    "manually_drained": pool.is_manually_drained(&id),
                    "eligible": pool.is_eligible(&id),
                    "active_conns": pool.active_count(&id),
                }))
            })
            .collect();
        listeners.insert(name.clone(), serde_json::Value::Array(backends));
    }
    json_response(StatusCode::OK, serde_json::Value::Object(listeners))
}

fn set_drain(reload: &ReloadState, listener: &str, id: &str, drain: bool) -> Response<Full<Bytes>> {
    let Some(pool) = pool_for(reload, listener) else {
        return json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({"error": format!("no such listener '{listener}'")}),
        );
    };
    let backend_id = BackendId::new(id);
    if pool.backend(&backend_id).is_none() {
        return json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "error": format!("no such backend '{id}' on listener '{listener}'")
            }),
        );
    }
    pool.set_manually_drained(&backend_id, drain);
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "listener": listener,
            "backend": id,
            "manually_drained": drain,
        }),
    )
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(Full::new(Bytes::from_static(b"{}")));
            *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        })
}
