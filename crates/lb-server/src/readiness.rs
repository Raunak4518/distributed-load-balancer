use crate::wiring::ReloadState;
use std::sync::Arc;

pub(crate) fn is_ready(
    reload: &ReloadState,
    tls_resolvers: &[Arc<lb_tls::SniResolver>],
    now_unix: i64,
) -> bool {
    let every_listener_can_forward = reload.listeners.keys().all(|name| {
        crate::admin_backends::pools_for(reload, name).is_some_and(|pools| {
            pools
                .iter()
                .any(|(_, pool)| !pool.eligible_backends().is_empty())
        })
    });
    let no_expired_certificate = tls_resolvers.iter().all(|resolver| {
        resolver
            .current()
            .certs()
            .iter()
            .all(|cert| cert.not_after_unix > now_unix)
    });
    every_listener_can_forward && no_expired_certificate && !reload.overload.rejects_new_work()
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
