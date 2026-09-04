# Performance Baseline

**Captured:** 2026-09-04, end of Phase 4
**Purpose:** a reference point for Phase 7's optimisation work. Every figure
here should improve; any that regresses is a bug.

Reproduce with:

```bash
cargo build --release -p lb-bench
./target/release/lb-bench
```

## How to read these numbers

**These are relative, not absolute.** They are single-threaded, uncontended
measurements taken on a developer laptop that was simultaneously running the
build toolchain. They tell you the *cost of an operation* and how it *scales
with backend count* — which is exactly what Phase 7 needs. They do **not**
tell you the system's capacity, and no SLA should be derived from them.

The most important limitation: these are **uncontended**. The circuit-breaker
refresh loop takes a `Mutex` per backend, and in production that lock is
shared across every worker thread. A single-threaded measurement cannot show
contention, so the real cost under concurrent load is *higher than measured* —
by how much is unknown until it is tested on production-like hardware with a
separate load-generation host.

## Results

Hardware: Windows 11, developer laptop. 200,000 iterations per measurement,
release profile.

### `BackendPool::eligible_backends()`
Allocates a `Vec` and clones every `BackendId` (each holding a `String`).

| Backends | ns/op | ops/s |
|---:|---:|---:|
| 1 | 171.5 | 5,829,731 |
| 5 | 580.3 | 1,723,374 |
| 20 | 2,477.3 | 403,663 |

### `RoundRobin::pick()`
Dominated by `eligible_backends()` above — the cursor arithmetic itself is
only ~150 ns of the 5-backend figure.

| Backends | ns/op | ops/s |
|---:|---:|---:|
| 1 | 246.7 | 4,053,260 |
| 5 | 733.4 | 1,363,487 |
| 20 | 2,571.4 | 388,900 |

### `Gcra::check()`
One `key.to_string()` allocation plus a `DashMap` operation.

| Case | ns/op | ops/s |
|---|---:|---:|
| single key | 145.4 | 6,875,428 |

### `ListenerCoordinator::try_admit()`
One `format!()` allocation to namespace the key, plus a `DashMap` operation.

| Case | ns/op | ops/s |
|---|---:|---:|
| single key | 482.6 | 2,071,921 |

### Circuit-breaker refresh loop
Two mutex acquisitions per backend, executed once per request.

| Backends | ns/op | ops/s |
|---:|---:|---:|
| 1 | 70.7 | 14,144,472 |
| 5 | 344.4 | 2,903,976 |
| 20 | 1,524.0 | 656,176 |

## What this tells us

**Per-request bookkeeping overhead at 5 backends** (a realistic deployment),
excluding all actual I/O:

| Step | ns |
|---|---:|
| `RoundRobin::pick()` | 733 |
| Circuit-breaker refresh | 344 |
| `Gcra::check()` | 145 |
| `try_admit()` (clustered only) | 483 |
| **Total** | **~1,705 ns ≈ 1.7 µs** |

At 50,000 req/s that is roughly **8.5% of a single core** spent on bookkeeping
before any network work happens. On a multi-core machine that is survivable,
which is the honest headline: the current design is not obviously incapable of
the target. But three caveats matter:

1. **It scales poorly with backend count.** At 20 backends the same bookkeeping
   costs ~4.1 µs/request — roughly 20% of a core at 50k req/s. The dominant
   term is `String` cloning in `eligible_backends()`.
2. **Contention is unmeasured and is the real risk.** The circuit-breaker
   `Mutex` is shared across all worker threads. Under concurrency it
   serialises, and the measured uncontended 344 ns is a floor, not an estimate.
3. **`try_admit()` at 483 ns is disproportionate** for one `format!` and one
   map operation — the allocation dominates.

## Phase 7 targets, in priority order

1. **Replace the per-request circuit-breaker refresh.** Move it off the request
   path (a timer) or replace the `Mutex` with atomics. This is the only item
   with a *contention* risk rather than merely an allocation cost, so it ranks
   first despite not being the largest single number.
2. **Stop allocating in `eligible_backends()`.** Interning `BackendId` as
   `Arc<str>` removes the per-backend `String` clone; returning an iterator or
   reusing a buffer removes the `Vec`.
3. **Remove the `format!` in `try_admit()`** — pre-compute the namespace prefix
   or key on `(listener, key)` without building a new `String`.
4. **Remove `key.to_string()` in `Gcra::check()`** — use a borrowed-key lookup
   before falling back to an owning insert.

## Before any SLA commitment

These figures cannot support a capacity claim. That requires:

- a separate load-generation host (client and server competing for the same
  cores invalidates the measurement),
- production-like hardware,
- concurrent load, to expose the mutex contention this harness cannot see,
- TLS enabled (Phase 6), since handshakes are likely to dominate CPU at the
  edge.
