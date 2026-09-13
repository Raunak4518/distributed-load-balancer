//! Response caching -- see `ProxyContext::cache`.
//!
//! Answers a repeated `GET` straight from memory instead of forwarding it to
//! a backend at all. Deliberately narrow for v1: only a `GET` request, only
//! a `200` response, and only one that declares a `Content-Length` within
//! the configured cap are ever cached. That `Content-Length` precondition is
//! what makes buffering a response safe to do here at all -- without it,
//! deciding to fully collect a body in order to cache it (a chunked or
//! unknown-length response cannot be size-checked before it's been read)
//! would risk draining a response too large to hold, with nothing left to
//! hand the client afterward. A response that fails any of these checks is
//! simply proxied exactly as it always was: streamed, uncached.

use bytes::Bytes;
use dashmap::DashMap;
use hyper::header::{CACHE_CONTROL, CONTENT_LENGTH, HOST};
use hyper::{HeaderMap, Method, StatusCode, Uri};
use lb_core::Clock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// One stored response. Cheap to clone: `Bytes` is a refcounted buffer, and
/// `HeaderMap`/`StatusCode` are small.
#[derive(Clone)]
pub struct CacheEntry {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    expires_at: Instant,
    accounted_size: usize,
}

fn accounted_size(key: &str, headers: &HeaderMap, body_len: usize) -> usize {
    let headers_len: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len())
        .sum();
    key.len() + headers_len + body_len
}

/// Builds the cache key for a request: distinguishes virtual hosts sharing a
/// path (a `[[listeners.routes]]` rule matched by `host`) and query-string
/// variants (`?page=2` vs `?page=3`) -- the two things that would otherwise
/// silently collide if the key were path-only.
pub fn key_for(method: &Method, uri: &Uri, headers: &HeaderMap) -> String {
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    format!("{method}|{host}|{path_and_query}")
}

/// Whether this response may be cached, and for how long -- `None` means
/// "don't cache," `Some(ttl)` means "cache for `ttl`." See the module docs
/// for why each precondition exists.
///
/// `Cache-Control` directives read: `no-store`, `private`, `no-cache`, and
/// `max-age=N`. Everything else (`s-maxage`, `must-revalidate`,
/// `stale-while-revalidate`, `Vary`, `ETag`, conditional requests, ...) is
/// out of scope for v1 -- not because it's harder, but because it's not what
/// was found missing yet.
pub fn cacheable_ttl(
    method: &Method,
    status: StatusCode,
    headers: &HeaderMap,
    max_entry_bytes: usize,
    default_ttl: Duration,
) -> Option<Duration> {
    if *method != Method::GET || status != StatusCode::OK {
        return None;
    }
    let content_length: usize = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())?;
    if content_length > max_entry_bytes {
        return None;
    }
    let Some(cache_control) = headers.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()) else {
        return Some(default_ttl);
    };
    for directive in cache_control.split(',') {
        let directive = directive.trim().to_ascii_lowercase();
        if directive == "no-store" || directive == "private" || directive == "no-cache" {
            return None;
        }
        if let Some(secs) = directive.strip_prefix("max-age=") {
            return match secs.trim().parse::<u64>() {
                Ok(0) | Err(_) => None,
                Ok(secs) => Some(Duration::from_secs(secs)),
            };
        }
    }
    Some(default_ttl)
}

/// A listener-wide response cache. Generic over `Clock` for the same reason
/// `CircuitBreaker<C>` is -- deterministic TTL-expiry tests via `FakeClock`,
/// no real sleeping.
pub struct ResponseCache<C: Clock> {
    entries: DashMap<String, CacheEntry>,
    total_bytes: AtomicUsize,
    max_entry_bytes: usize,
    max_total_bytes: usize,
    default_ttl: Duration,
    clock: C,
}

impl<C: Clock> ResponseCache<C> {
    pub fn new(
        max_entry_bytes: usize,
        max_total_bytes: usize,
        default_ttl: Duration,
        clock: C,
    ) -> Self {
        ResponseCache {
            entries: DashMap::new(),
            total_bytes: AtomicUsize::new(0),
            max_entry_bytes,
            max_total_bytes,
            default_ttl,
            clock,
        }
    }

    pub fn max_entry_bytes(&self) -> usize {
        self.max_entry_bytes
    }

    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// `None` for a miss, an expired entry (removed on the way out rather
    /// than waiting for the next sweep), or an entry that was never there.
    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        let now = self.clock.now();
        {
            let entry = self.entries.get(key)?;
            if entry.expires_at > now {
                return Some(entry.clone());
            }
        }
        // Expired: drop it now instead of waiting for `sweep_expired`, so a
        // request landing between sweeps still sees a correct miss rather
        // than stale content.
        self.remove(key);
        None
    }

    /// Stores `body` under `key` for `ttl`. A no-op (the caller's response
    /// is unaffected either way) if `body` alone exceeds `max_entry_bytes`
    /// or would push the aggregate past `max_total_bytes` -- there is no
    /// eviction algorithm in v1, just "stop admitting new entries until
    /// something already stored expires and is swept."
    pub fn put(
        &self,
        key: String,
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        ttl: Duration,
    ) {
        if body.len() > self.max_entry_bytes {
            return;
        }
        let size = accounted_size(&key, &headers, body.len());
        // A soft cap, not a hard allocator limit: a brief overshoot under
        // concurrent inserts racing this check is acceptable.
        if self.total_bytes.load(Ordering::Relaxed) + size > self.max_total_bytes {
            return;
        }
        let expires_at = self.clock.now() + ttl;
        let entry = CacheEntry {
            status,
            headers,
            body,
            expires_at,
            accounted_size: size,
        };
        if let Some(old) = self.entries.insert(key, entry) {
            self.total_bytes
                .fetch_sub(old.accounted_size, Ordering::Relaxed);
        }
        self.total_bytes.fetch_add(size, Ordering::Relaxed);
    }

    fn remove(&self, key: &str) {
        if let Some((_, removed)) = self.entries.remove(key) {
            self.total_bytes
                .fetch_sub(removed.accounted_size, Ordering::Relaxed);
        }
    }

    /// Removes every expired entry, reclaiming its share of
    /// `max_total_bytes`. Run periodically (`spawn_cache_sweeper`) so a
    /// cache that fills up with short-TTL entries doesn't stay full forever
    /// once traffic for those entries stops -- `get`'s own lazy removal only
    /// reclaims space for keys someone still asks for.
    pub fn sweep_expired(&self) {
        let now = self.clock.now();
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.expires_at <= now)
            .map(|e| e.key().clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }
}

/// Runs `cache.sweep_expired()` on `interval` for as long as the listener
/// lives -- mirrors `lb_ratelimit::spawn_sweeper`'s shape.
pub fn spawn_cache_sweeper<C: Clock + Send + Sync + 'static>(
    cache: std::sync::Arc<ResponseCache<C>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            cache.sweep_expired();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn key_differs_by_method_path_query_and_host() {
        let uri: Uri = "/orders?page=2".parse().unwrap();
        let headers = headers_with(&[("host", "a.example.com")]);
        let key_a = key_for(&Method::GET, &uri, &headers);

        assert_ne!(
            key_a,
            key_for(&Method::POST, &uri, &headers),
            "method must be part of the key"
        );
        let other_page: Uri = "/orders?page=3".parse().unwrap();
        assert_ne!(
            key_a,
            key_for(&Method::GET, &other_page, &headers),
            "query string must be part of the key"
        );
        let other_host = headers_with(&[("host", "b.example.com")]);
        assert_ne!(
            key_a,
            key_for(&Method::GET, &uri, &other_host),
            "host must be part of the key"
        );
    }

    #[test]
    fn non_get_is_never_cacheable() {
        let headers = headers_with(&[("content-length", "10")]);
        assert_eq!(
            cacheable_ttl(
                &Method::POST,
                StatusCode::OK,
                &headers,
                1024,
                Duration::from_secs(60)
            ),
            None
        );
    }

    #[test]
    fn non_200_is_never_cacheable() {
        let headers = headers_with(&[("content-length", "10")]);
        assert_eq!(
            cacheable_ttl(
                &Method::GET,
                StatusCode::NOT_FOUND,
                &headers,
                1024,
                Duration::from_secs(60)
            ),
            None
        );
    }

    #[test]
    fn missing_content_length_is_never_cacheable() {
        let headers = HeaderMap::new();
        assert_eq!(
            cacheable_ttl(
                &Method::GET,
                StatusCode::OK,
                &headers,
                1024,
                Duration::from_secs(60)
            ),
            None
        );
    }

    #[test]
    fn content_length_over_the_cap_is_never_cacheable() {
        let headers = headers_with(&[("content-length", "2000")]);
        assert_eq!(
            cacheable_ttl(
                &Method::GET,
                StatusCode::OK,
                &headers,
                1024,
                Duration::from_secs(60)
            ),
            None
        );
    }

    #[test]
    fn no_store_is_never_cacheable() {
        let headers = headers_with(&[("content-length", "10"), ("cache-control", "no-store")]);
        assert_eq!(
            cacheable_ttl(
                &Method::GET,
                StatusCode::OK,
                &headers,
                1024,
                Duration::from_secs(60)
            ),
            None
        );
    }

    #[test]
    fn max_age_zero_is_never_cacheable() {
        let headers = headers_with(&[("content-length", "10"), ("cache-control", "max-age=0")]);
        assert_eq!(
            cacheable_ttl(
                &Method::GET,
                StatusCode::OK,
                &headers,
                1024,
                Duration::from_secs(60)
            ),
            None
        );
    }

    #[test]
    fn max_age_picks_the_ttl_over_the_default() {
        let headers = headers_with(&[("content-length", "10"), ("cache-control", "max-age=120")]);
        assert_eq!(
            cacheable_ttl(
                &Method::GET,
                StatusCode::OK,
                &headers,
                1024,
                Duration::from_secs(60)
            ),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn no_cache_control_falls_back_to_the_default_ttl() {
        let headers = headers_with(&[("content-length", "10")]);
        assert_eq!(
            cacheable_ttl(
                &Method::GET,
                StatusCode::OK,
                &headers,
                1024,
                Duration::from_secs(60)
            ),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn put_then_get_round_trips() {
        let cache =
            ResponseCache::new(1024, 1024 * 1024, Duration::from_secs(60), FakeClock::new());
        cache.put(
            "k".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"hello"),
            Duration::from_secs(60),
        );
        let entry = cache.get("k").expect("entry should be present");
        assert_eq!(entry.body, Bytes::from_static(b"hello"));
        assert_eq!(entry.status, StatusCode::OK);
    }

    #[test]
    fn an_entry_larger_than_max_entry_bytes_is_never_stored() {
        let cache = ResponseCache::new(4, 1024, Duration::from_secs(60), FakeClock::new());
        cache.put(
            "k".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"too big"),
            Duration::from_secs(60),
        );
        assert!(cache.get("k").is_none());
    }

    #[test]
    fn an_expired_entry_is_a_miss_and_is_removed() {
        let clock = FakeClock::new();
        let cache = ResponseCache::new(1024, 1024, Duration::from_secs(60), clock.clone());
        cache.put(
            "k".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"hello"),
            Duration::from_secs(10),
        );
        assert!(cache.get("k").is_some());
        clock.advance(Duration::from_secs(11));
        assert!(cache.get("k").is_none());
    }

    #[test]
    fn sweep_expired_reclaims_budget_for_a_full_cache() {
        let clock = FakeClock::new();
        // Budget for exactly one entry.
        let cache = ResponseCache::new(5, 11, Duration::from_secs(60), clock.clone());
        cache.put(
            "first".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"hello"),
            Duration::from_secs(10),
        );
        // Budget is full -- a second entry is rejected.
        cache.put(
            "second".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"world"),
            Duration::from_secs(10),
        );
        assert!(cache.get("second").is_none());

        clock.advance(Duration::from_secs(11));
        cache.sweep_expired();

        // The first entry's expiry freed the budget, so this now succeeds.
        cache.put(
            "second".to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"world"),
            Duration::from_secs(10),
        );
        assert!(cache.get("second").is_some());
    }

    #[test]
    fn a_zero_length_body_still_counts_toward_the_total_budget() {
        let cache = ResponseCache::new(1024, 20, Duration::from_secs(60), FakeClock::new());
        for i in 0..1000 {
            cache.put(
                format!("key-{i:016}"),
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::new(),
                Duration::from_secs(60),
            );
        }
        let stored = (0..1000)
            .filter(|i| cache.get(&format!("key-{i:016}")).is_some())
            .count();
        assert!(
            stored < 1000,
            "a zero-length body must not bypass max_total_bytes"
        );
    }
}
