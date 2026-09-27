use crate::wiring::ListenerRuntime;
use lb_core::{
    OverloadConfig, OverloadState, OVERLOAD_NORMAL, OVERLOAD_REJECT, OVERLOAD_SHED_KEEPALIVE,
};
use std::sync::Arc;
use std::time::Duration;

const HYSTERESIS: f64 = 0.05;

pub(crate) fn next_level(pressure: f64, current: u8, cfg: &OverloadConfig) -> u8 {
    let target = if pressure >= cfg.reject_at {
        OVERLOAD_REJECT
    } else if pressure >= cfg.shed_keepalive_at {
        OVERLOAD_SHED_KEEPALIVE
    } else {
        OVERLOAD_NORMAL
    };
    if target >= current {
        return target;
    }
    let current_threshold = if current >= OVERLOAD_REJECT {
        cfg.reject_at
    } else {
        cfg.shed_keepalive_at
    };
    if pressure < current_threshold - HYSTERESIS {
        target
    } else {
        current
    }
}

fn connection_pressure(listeners: &[Arc<ListenerRuntime>]) -> f64 {
    listeners
        .iter()
        .map(|runtime| {
            let limits = runtime.limits();
            let capacity = limits.capacity.max(1) as f64;
            let used = limits
                .capacity
                .saturating_sub(limits.global.available_permits()) as f64;
            used / capacity
        })
        .fold(0.0, f64::max)
}

#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(kib * 1024)
}

#[cfg(not(target_os = "linux"))]
fn resident_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn fd_pressure() -> Option<f64> {
    let open = std::fs::read_dir("/proc/self/fd").ok()?.count() as f64;
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    let soft: f64 = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()?;
    (soft > 0.0).then_some(open / soft)
}

#[cfg(not(target_os = "linux"))]
fn fd_pressure() -> Option<f64> {
    None
}

pub(crate) fn spawn_overload_monitor(
    state: Arc<OverloadState>,
    listeners: Vec<Arc<ListenerRuntime>>,
    cfg: OverloadConfig,
    metrics: Arc<lb_metrics::Metrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(cfg.check_interval_ms));
        loop {
            ticker.tick().await;
            let connections = connection_pressure(&listeners);
            let memory = cfg
                .max_memory_bytes
                .and_then(|max| resident_bytes().map(|rss| rss as f64 / max as f64));
            let fds = fd_pressure();
            for (resource, value) in [
                ("connections", Some(connections)),
                ("memory", memory),
                ("file_descriptors", fds),
            ] {
                if let Some(value) = value {
                    metrics
                        .overload_pressure
                        .with_label_values(&[resource])
                        .set((value * 1000.0) as i64);
                }
            }
            let pressure = [Some(connections), memory, fds]
                .into_iter()
                .flatten()
                .fold(0.0, f64::max);
            let current = state.level();
            let level = next_level(pressure, current, &cfg);
            if level != current {
                tracing::warn!(
                    from = current,
                    to = level,
                    pressure,
                    "overload level changed"
                );
                state.set_level(level);
            }
            metrics.overload_level.set(level as i64);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OverloadConfig {
        OverloadConfig {
            max_memory_bytes: None,
            shed_keepalive_at: 0.8,
            reject_at: 0.95,
            check_interval_ms: 1_000,
        }
    }

    #[test]
    fn levels_rise_as_soon_as_a_threshold_is_reached() {
        assert_eq!(next_level(0.5, OVERLOAD_NORMAL, &cfg()), OVERLOAD_NORMAL);
        assert_eq!(
            next_level(0.8, OVERLOAD_NORMAL, &cfg()),
            OVERLOAD_SHED_KEEPALIVE
        );
        assert_eq!(next_level(0.97, OVERLOAD_NORMAL, &cfg()), OVERLOAD_REJECT);
    }

    #[test]
    fn levels_fall_only_once_pressure_is_clearly_below_the_threshold() {
        assert_eq!(next_level(0.93, OVERLOAD_REJECT, &cfg()), OVERLOAD_REJECT);
        assert_eq!(
            next_level(0.89, OVERLOAD_REJECT, &cfg()),
            OVERLOAD_SHED_KEEPALIVE
        );
        assert_eq!(next_level(0.2, OVERLOAD_REJECT, &cfg()), OVERLOAD_NORMAL);
        assert_eq!(
            next_level(0.77, OVERLOAD_SHED_KEEPALIVE, &cfg()),
            OVERLOAD_SHED_KEEPALIVE
        );
        assert_eq!(
            next_level(0.74, OVERLOAD_SHED_KEEPALIVE, &cfg()),
            OVERLOAD_NORMAL
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_resource_readings_are_available() {
        assert!(resident_bytes().is_some_and(|rss| rss > 0));
        assert!(fd_pressure().is_some_and(|p| p > 0.0 && p < 1.0));
    }
}
