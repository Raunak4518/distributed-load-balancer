# Concurrency Model

The load balancer handles tens of thousands of concurrent connections. To achieve this, it relies heavily on the `tokio` async runtime and lock-free (or lock-sharded) data structures.

## Async Execution Model

Every accepted connection spawns a new Tokio task (`tokio::spawn`). 
These tasks run concurrently on the Tokio thread pool. When a task hits an await point (e.g., waiting for network I/O during `stream.read()`), it yields the thread back to the runtime, allowing another connection to execute.

## Shared State and Synchronization

Because thousands of tasks run concurrently, shared state must be managed carefully to avoid lock contention (which ruins throughput).

### 1. DashMap (Sharded Locks)
The rate limiter state (`GCRA TATs`), the CRDT store, and the IP connection limit trackers use `DashMap`.
A `DashMap` is not a single `Mutex<HashMap>`. It is a collection of shards, each protected by its own lock. This allows high concurrent throughput because two requests hitting different keys will likely acquire different shard locks, avoiding contention.

### 2. Atomics (Wait-free)
Health states (`active_healthy`, `circuit_open`) in the `BackendPool` are `AtomicBool`. The Round Robin routing index is an `AtomicUsize`.
These values are read and written using atomic CPU instructions (e.g., Compare-and-Swap). They do not use locks, meaning they never put a Tokio task to sleep.

### 3. ArcSwap (RCU)
The TLS certificates and the routing configuration are stored in `ArcSwap`. This provides Read-Copy-Update semantics. 
Readers (the request path) acquire an `Arc` to the current state instantly without locking. Writers (the background reload tasks) build the new state in private, and then atomically swap the pointer. 

## The TCP Pump (`try_join!`)

The most critical concurrency primitive in the L4 path is `tokio::try_join!`.

When proxying a TCP connection, the system must pump bytes from Client -> Backend AND Backend -> Client simultaneously.

```rust
tokio::try_join!(
    tokio::io::copy(&mut client_read, &mut backend_write),
    tokio::io::copy(&mut backend_read, &mut client_write)
)?;
```

If these were run sequentially, the proxy would deadlock. If they were spawned as separate detached tasks, error handling and half-close logic would be extremely complex. `try_join!` runs both futures concurrently on the *same* task. If either future returns an error, the other is immediately cancelled, and the entire function returns.

## Bottlenecks

While the system is highly concurrent, some bottlenecks are unavoidable:
- **GCRA Hot Keys:** If a massive DDoS attack hits a *single* rate-limit key, thousands of tasks will contend on the single `AtomicU64` for that key's TAT, forcing the CPU to serialize the Compare-and-Swap operations.
- **Global Semaphore:** Every accepted connection acquires a permit from a global Tokio `Semaphore`. Under extreme connection churn, this single synchronization point can become a bottleneck.
