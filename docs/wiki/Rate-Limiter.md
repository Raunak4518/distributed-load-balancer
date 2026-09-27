# Rate Limiter

The load balancer uses the **Generic Cell Rate Algorithm (GCRA)** to enforce local rate limits. GCRA provides exact burst shaping without the lock contention and timer requirements of a traditional Token Bucket.

## Why GCRA?

Traditional Token Buckets require background tasks to "refill" tokens over time, or they require storing a timestamp and a token count that must be mutated concurrently.

GCRA removes the concept of tokens entirely. Instead, it tracks a single value for each key: the **Theoretical Arrival Time (TAT)**.

The TAT represents the time when the bucket will be completely full again. 
- If a request arrives *after* the TAT, it is allowed, and the TAT is updated to the current time plus the cost of one request.
- If a request arrives *before* the TAT, the algorithm checks if the arrival time plus the allowed burst window exceeds the TAT. If so, the request is rejected.

This requires only 8 bytes (a 64-bit timestamp) of state per key.

## Implementation Details

The `Gcra` implementation lives in `lb-ratelimit/src/gcra.rs`.

### State Storage
The TATs are stored in a `DashMap<String, AtomicU64>`. 

Because GCRA relies on mutating a shared value based on its current value (Compare-and-Swap), the implementation uses `AtomicU64::fetch_max`. 

```rust
let now = current_time_ns();
let tat = map.get(&key).unwrap();

// Simplified CAS loop
loop {
    let current_tat = tat.load(Ordering::Acquire);
    let new_tat = calculate_new_tat(now, current_tat, limit);
    
    if is_rate_limited(now, current_tat, limit) {
        return false; // Rejected
    }

    if tat.compare_exchange(current_tat, new_tat, Ordering::Release, Ordering::Relaxed).is_ok() {
        return true; // Admitted
    }
}
```

### Memory Bounds and the Overflow Bucket

If a load balancer is deployed at the edge and faces a DDoS attack across millions of unique IPs, storing a TAT for every IP would cause a memory exhaustion crash (OOM).

To prevent this, the `lb-ratelimit` crate implements bounded tracking. 

The state map has a maximum size (e.g., 100,000 keys). If an IP arrives and is not already in the map, and the map is full, the IP is placed into an **Overflow Bucket**.

The Overflow Bucket enforces a highly restrictive, shared rate limit for all unrecognized IPs. This ensures that the system survives the memory pressure while still shaping traffic, without indiscriminately dropping or allowing everything.

Old keys in the `DashMap` are periodically evicted by a background task if their TAT has passed (meaning their bucket is fully replenished and their state is no longer needed).
