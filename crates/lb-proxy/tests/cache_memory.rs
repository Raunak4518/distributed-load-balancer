use bytes::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{HeaderMap, StatusCode};
use lb_core::test_util::FakeClock;
use lb_proxy::ResponseCache;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn headers(count: usize, value_len: usize) -> HeaderMap {
    let mut map = HeaderMap::new();
    for i in 0..count {
        map.insert(
            HeaderName::from_bytes(format!("x-custom-header-{i}").as_bytes()).unwrap(),
            HeaderValue::from_str(&"v".repeat(value_len)).unwrap(),
        );
    }
    map
}

fn measure(
    entries: usize,
    header_count: usize,
    value_len: usize,
    body_len: usize,
) -> (usize, usize) {
    let cache = ResponseCache::new(
        usize::MAX / 4,
        usize::MAX / 4,
        Duration::from_secs(60),
        FakeClock::new(),
    );
    let before = LIVE.load(Ordering::Relaxed);
    let mut prepared: Vec<(String, HeaderMap, Bytes)> = (0..entries)
        .map(|i| {
            (
                format!("GET|host.example.com|/resource/{i:08}"),
                headers(header_count, value_len),
                Bytes::from(vec![b'b'; body_len]),
            )
        })
        .collect();
    for (key, h, body) in prepared.drain(..) {
        cache.put(key, StatusCode::OK, h, body, Duration::from_secs(60));
    }
    drop(prepared);
    let after = LIVE.load(Ordering::Relaxed);
    (cache.accounted_bytes(), (after - before).max(0) as usize)
}

#[test]
fn accounted_bytes_track_real_retained_memory_within_a_narrow_band() {
    for (entries, header_count, value_len, body_len) in [
        (20_000, 0, 0, 0),
        (20_000, 5, 20, 100),
        (20_000, 12, 40, 200),
        (500, 50, 1000, 100),
        (200, 1, 60_000, 100),
        (200, 0, 0, 100_000),
    ] {
        let (accounted, real) = measure(entries, header_count, value_len, body_len);
        assert!(
            real * 100 <= accounted * 115,
            "undercount: entries={entries} headers={header_count}x{value_len} body={body_len} accounted={accounted} real={real}"
        );
        assert!(
            accounted * 100 <= real * 125,
            "overcount: entries={entries} headers={header_count}x{value_len} body={body_len} accounted={accounted} real={real}"
        );
    }
}
