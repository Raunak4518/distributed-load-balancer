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

const ENTRY_OVERHEAD_BYTES: usize = 320;
const PER_HEADER_OVERHEAD_BYTES: usize = 128;

fn accounted_size(key: &str, headers: &HeaderMap, body_len: usize) -> usize {
    let headers_len: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + PER_HEADER_OVERHEAD_BYTES)
        .sum();
    ENTRY_OVERHEAD_BYTES + key.len() + headers_len + body_len
}

/// Builds the cache key for a request: distinguishes virtual hosts sharing a
/// path (a `[[listeners.routes]]` rule matched by `host`) and query-string
/// variants (`?page=2` vs `?page=3`) -- the two things that would otherwise
/// silently collide if the key were path-only.
pub fn key_for(method: &Method, uri: &Uri, headers: &HeaderMap) -> String {
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(|authority| authority.as_str()))
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

    pub fn accounted_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
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
        self.remove_expired(key, now);
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
        self.total_bytes.fetch_add(size, Ordering::Relaxed);
        if let Some(old) = self.entries.insert(key, entry) {
            self.total_bytes
                .fetch_sub(old.accounted_size, Ordering::Relaxed);
        }
    }

    fn remove_expired(&self, key: &str, now: Instant) {
        if let Some((_, removed)) = self
            .entries
            .remove_if(key, |_, entry| entry.expires_at <= now)
        {
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
            self.remove_expired(&key, now);
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
        let cache = ResponseCache::new(5, 340, Duration::from_secs(60), clock.clone());
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
        let cache = ResponseCache::new(1024, 3400, Duration::from_secs(60), FakeClock::new());
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
        assert_eq!(
            stored, 10,
            "a zero-length body must not bypass max_total_bytes"
        );
    }

    fn put_body(cache: &ResponseCache<FakeClock>, key: &str, body_len: usize, ttl_secs: u64) {
        cache.put(
            key.to_string(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from(vec![b'x'; body_len]),
            Duration::from_secs(ttl_secs),
        );
    }

    fn live_entries_sum(cache: &ResponseCache<FakeClock>) -> usize {
        cache.entries.iter().map(|e| e.accounted_size).sum()
    }

    fn assert_accounting_matches_entries(cache: &ResponseCache<FakeClock>) {
        assert_eq!(cache.accounted_bytes(), live_entries_sum(cache));
    }

    #[test]
    fn accounted_size_counts_key_every_header_value_body_and_fixed_overhead() {
        let mut headers = HeaderMap::new();
        headers.append("x-a", "1".parse().unwrap());
        headers.append("set-cookie", "aa".parse().unwrap());
        headers.append("set-cookie", "bbb".parse().unwrap());
        let expected = ENTRY_OVERHEAD_BYTES
            + "key".len()
            + ("x-a".len() + 1 + PER_HEADER_OVERHEAD_BYTES)
            + ("set-cookie".len() + 2 + PER_HEADER_OVERHEAD_BYTES)
            + ("set-cookie".len() + 3 + PER_HEADER_OVERHEAD_BYTES)
            + 7;
        assert_eq!(accounted_size("key", &headers, 7), expected);
    }

    #[test]
    fn total_bytes_equals_the_accounted_size_of_what_was_put() {
        let cache = ResponseCache::new(1024, 1 << 20, Duration::from_secs(60), FakeClock::new());
        assert_eq!(cache.accounted_bytes(), 0);
        put_body(&cache, "k", 100, 60);
        assert_eq!(
            cache.accounted_bytes(),
            accounted_size("k", &HeaderMap::new(), 100)
        );
    }

    #[test]
    fn large_headers_count_toward_the_total_budget_even_with_a_tiny_body() {
        let budget = accounted_size("k", &HeaderMap::new(), 1) + 1000;
        let cache = ResponseCache::new(1024, budget, Duration::from_secs(60), FakeClock::new());
        let mut headers = HeaderMap::new();
        headers.insert("x-big", "v".repeat(5000).parse().unwrap());
        cache.put(
            "k".to_string(),
            StatusCode::OK,
            headers,
            Bytes::from_static(b"x"),
            Duration::from_secs(60),
        );
        assert!(cache.get("k").is_none());
        assert_eq!(cache.accounted_bytes(), 0);
    }

    #[test]
    fn max_entry_bytes_bounds_the_body_alone_and_the_boundary_is_inclusive() {
        let cache = ResponseCache::new(10, 1 << 20, Duration::from_secs(60), FakeClock::new());
        let mut headers = HeaderMap::new();
        headers.insert("x-big", "v".repeat(500).parse().unwrap());
        cache.put(
            "at".to_string(),
            StatusCode::OK,
            headers,
            Bytes::from(vec![b'x'; 10]),
            Duration::from_secs(60),
        );
        assert!(cache.get("at").is_some());
        let before = cache.accounted_bytes();
        put_body(&cache, "over", 11, 60);
        assert!(cache.get("over").is_none());
        assert_eq!(cache.accounted_bytes(), before);
    }

    #[test]
    fn replacing_a_key_swaps_its_accounting_instead_of_adding_to_it() {
        let cache = ResponseCache::new(1024, 1 << 20, Duration::from_secs(60), FakeClock::new());
        put_body(&cache, "k", 100, 60);
        put_body(&cache, "k", 300, 60);
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(
            cache.accounted_bytes(),
            accounted_size("k", &HeaderMap::new(), 300)
        );
        assert_eq!(cache.get("k").unwrap().body.len(), 300);
    }

    #[test]
    fn an_entry_expires_exactly_at_its_ttl_and_not_a_moment_before() {
        let clock = FakeClock::new();
        let cache = ResponseCache::new(1024, 1 << 20, Duration::from_secs(60), clock.clone());
        put_body(&cache, "k", 5, 10);
        clock.advance(Duration::from_millis(9_999));
        assert!(cache.get("k").is_some());
        clock.advance(Duration::from_millis(1));
        assert!(cache.get("k").is_none());
    }

    #[test]
    fn a_lazily_expired_entry_releases_its_accounting() {
        let clock = FakeClock::new();
        let cache = ResponseCache::new(1024, 1 << 20, Duration::from_secs(60), clock.clone());
        put_body(&cache, "k", 50, 5);
        clock.advance(Duration::from_secs(6));
        assert!(cache.get("k").is_none());
        assert_eq!(cache.accounted_bytes(), 0);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn sweep_removes_only_expired_entries_and_keeps_accounting_exact() {
        let clock = FakeClock::new();
        let cache = ResponseCache::new(1024, 1 << 20, Duration::from_secs(60), clock.clone());
        put_body(&cache, "short", 10, 5);
        put_body(&cache, "long", 20, 100);
        clock.advance(Duration::from_secs(6));
        cache.sweep_expired();
        assert!(cache.get("long").is_some());
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(
            cache.accounted_bytes(),
            accounted_size("long", &HeaderMap::new(), 20)
        );
    }

    #[test]
    fn a_full_cache_admits_nothing_new_and_never_evicts_live_entries() {
        let entry = accounted_size("key-0", &HeaderMap::new(), 100);
        let cache = ResponseCache::new(1024, entry * 3, Duration::from_secs(60), FakeClock::new());
        for i in 0..3 {
            put_body(&cache, &format!("key-{i}"), 100, 60);
        }
        assert_eq!(cache.accounted_bytes(), entry * 3);
        for i in 3..10 {
            put_body(&cache, &format!("key-{i}"), 100, 60);
        }
        assert_eq!(cache.entries.len(), 3);
        assert_eq!(cache.accounted_bytes(), entry * 3);
        for i in 0..3 {
            assert!(cache.get(&format!("key-{i}")).is_some());
        }
        for i in 3..10 {
            assert!(cache.get(&format!("key-{i}")).is_none());
        }
    }

    #[test]
    fn headers_status_and_body_round_trip_including_repeated_header_values() {
        let cache = ResponseCache::new(1024, 1 << 20, Duration::from_secs(60), FakeClock::new());
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        headers.append("x-multi", "one".parse().unwrap());
        headers.append("x-multi", "two".parse().unwrap());
        cache.put(
            "k".to_string(),
            StatusCode::OK,
            headers.clone(),
            Bytes::from_static(b"body"),
            Duration::from_secs(60),
        );
        let entry = cache.get("k").unwrap();
        assert_eq!(entry.headers, headers);
        assert_eq!(entry.headers.get_all("x-multi").iter().count(), 2);
        assert_eq!(entry.body, Bytes::from_static(b"body"));
    }

    #[test]
    fn keys_for_different_hosts_on_the_same_path_never_collide() {
        let uri: Uri = "/same".parse().unwrap();
        let a = key_for(&Method::GET, &uri, &headers_with(&[("host", "a.example")]));
        let b = key_for(&Method::GET, &uri, &headers_with(&[("host", "b.example")]));
        assert_ne!(a, b);
    }

    #[test]
    fn keys_for_different_query_strings_never_collide_but_ignore_header_order() {
        let a: Uri = "/p?x=1&y=2".parse().unwrap();
        let b: Uri = "/p?y=2&x=1".parse().unwrap();
        let headers = headers_with(&[("host", "h"), ("accept", "*/*")]);
        assert_ne!(
            key_for(&Method::GET, &a, &headers),
            key_for(&Method::GET, &b, &headers)
        );
        let reordered = headers_with(&[("accept", "*/*"), ("host", "h")]);
        assert_eq!(
            key_for(&Method::GET, &a, &headers),
            key_for(&Method::GET, &a, &reordered)
        );
    }

    #[test]
    fn a_request_without_a_host_header_is_keyed_by_the_uri_authority() {
        let none = HeaderMap::new();
        let a: Uri = "https://a.example/x".parse().unwrap();
        let b: Uri = "https://b.example/x".parse().unwrap();
        assert_ne!(
            key_for(&Method::GET, &a, &none),
            key_for(&Method::GET, &b, &none)
        );
    }

    #[test]
    fn concurrent_puts_to_one_key_keep_the_accounting_consistent() {
        let cache = ResponseCache::new(4096, 1 << 30, Duration::from_secs(60), FakeClock::new());
        std::thread::scope(|scope| {
            for t in 0..8usize {
                let cache = &cache;
                scope.spawn(move || {
                    for i in 0..20_000usize {
                        put_body(cache, "hot", 1 + (i * 37 + t * 101) % 4000, 60);
                    }
                });
            }
        });
        assert_eq!(cache.entries.len(), 1);
        assert_accounting_matches_entries(&cache);
    }

    #[test]
    fn concurrent_puts_of_distinct_keys_are_all_retained_and_fully_accounted() {
        let cache = ResponseCache::new(4096, 1 << 30, Duration::from_secs(60), FakeClock::new());
        std::thread::scope(|scope| {
            for t in 0..8usize {
                let cache = &cache;
                scope.spawn(move || {
                    for i in 0..500usize {
                        put_body(cache, &format!("t{t}-k{i}"), 10 + i % 50, 60);
                    }
                });
            }
        });
        assert_eq!(cache.entries.len(), 8 * 500);
        assert_accounting_matches_entries(&cache);
        for t in 0..8usize {
            for i in 0..500usize {
                assert_eq!(
                    cache.get(&format!("t{t}-k{i}")).unwrap().body.len(),
                    10 + i % 50
                );
            }
        }
    }

    #[test]
    fn concurrent_puts_at_the_cap_overshoot_by_at_most_one_entry_per_thread() {
        let threads = 16usize;
        let entry = accounted_size("t00-k000", &HeaderMap::new(), 200);
        let cap = entry * 10;
        let cache = ResponseCache::new(1024, cap, Duration::from_secs(60), FakeClock::new());
        std::thread::scope(|scope| {
            for t in 0..threads {
                let cache = &cache;
                scope.spawn(move || {
                    for i in 0..50usize {
                        put_body(cache, &format!("t{t:02}-k{i:03}"), 200, 60);
                    }
                });
            }
        });
        assert!(cache.accounted_bytes() > cap - entry);
        assert!(cache.accounted_bytes() <= cap + (threads - 1) * entry);
        assert_accounting_matches_entries(&cache);
    }

    #[test]
    fn concurrent_put_get_and_sweep_never_leave_the_accounting_drifting() {
        let clock = FakeClock::new();
        let cache = ResponseCache::new(4096, 1 << 30, Duration::from_secs(60), clock.clone());
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            let writers: Vec<_> = (0..4usize)
                .map(|t| {
                    let cache = &cache;
                    scope.spawn(move || {
                        for i in 0..5_000usize {
                            put_body(
                                cache,
                                &format!("k{}", (i + t) % 64),
                                1 + i % 300,
                                (i % 3) as u64,
                            );
                            cache.get(&format!("k{}", i % 64));
                        }
                    })
                })
                .collect();
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    clock.advance(Duration::from_millis(1));
                    cache.sweep_expired();
                }
            });
            for writer in writers {
                writer.join().unwrap();
            }
            stop.store(true, Ordering::Relaxed);
        });
        assert_accounting_matches_entries(&cache);
    }

    #[test]
    fn a_fresh_entry_put_while_an_expired_get_is_removing_is_never_evicted() {
        let cache = ResponseCache::new(1024, 1 << 20, Duration::from_secs(60), FakeClock::new());
        let stop = std::sync::atomic::AtomicBool::new(false);
        let mut evicted = 0usize;
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        cache.get("k");
                    }
                });
            }
            for _ in 0..300_000 {
                put_body(&cache, "k", 8, 0);
                put_body(&cache, "k", 8, 60);
                if cache.get("k").is_none() {
                    evicted += 1;
                }
            }
            stop.store(true, Ordering::Relaxed);
        });
        assert_eq!(
            evicted, 0,
            "a fresh entry was evicted by a concurrent expired-entry removal"
        );
        assert_accounting_matches_entries(&cache);
    }

    #[test]
    fn a_fresh_entry_put_while_a_sweep_is_removing_is_never_evicted() {
        let cache = ResponseCache::new(1024, 1 << 20, Duration::from_secs(60), FakeClock::new());
        let stop = std::sync::atomic::AtomicBool::new(false);
        let mut evicted = 0usize;
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        cache.sweep_expired();
                    }
                });
            }
            for _ in 0..300_000 {
                put_body(&cache, "k", 8, 0);
                put_body(&cache, "k", 8, 60);
                if cache.get("k").is_none() {
                    evicted += 1;
                }
            }
            stop.store(true, Ordering::Relaxed);
        });
        assert_eq!(
            evicted, 0,
            "a fresh entry was evicted by a concurrent sweep"
        );
        assert_accounting_matches_entries(&cache);
    }
}
