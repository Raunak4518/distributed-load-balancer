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


## Phase 5 delta (edge hardening)

Re-measured after Phase 5. Run-to-run noise on this machine is roughly ±10%,
so only the GCRA line below is a real signal.

| Operation | Phase 4 | Phase 5 | Note |
|---|---:|---:|---|
| `eligible_backends()` (5 backends) | 580 | 635 | noise |
| `RoundRobin::pick()` (5 backends) | 733 | 704 | noise |
| `Gcra::check()` | 145 | 144 | see below |
| `try_admit()` | 483 | 476 | noise |
| Circuit refresh (5 backends) | 344 | 361 | noise |

Net: Phase 5's connection caps and timeouts cost nothing measurable on the
per-request path, which is expected — they act per *connection*, not per
request, and the two guards are moved into the task rather than checked
repeatedly.

### A 4x regression this harness caught

The first Phase 5 measurement showed `Gcra::check()` at **598 ns, up from
145** — a 4x regression from the new cardinality cap. The cause was an
incorrect assumption in the code's own comment, which claimed the check
"normally only runs a `len()` comparison":

**`DashMap::len()` is not O(1).** It walks every shard and sums them. At the
default shard count that is dozens of locked reads on every single request,
and it dwarfed everything else `check()` does.

The fix is a cached count in an `AtomicUsize`, maintained via an explicit
`Entry::Vacant` match (the only way to know whether a call created a key) and
read with one relaxed load. `sweep()` resyncs it from the real `len()`, which
is fine because sweeping is infrequent. That restored 144 ns — marginally
better than the original baseline.

Worth recording as a lesson rather than just a fix: the comment asserting the
cost was written at the same time as the code, by the same reasoning, and was
simply wrong. Only the measurement caught it. This is the entire argument for
building the harness in Phase 4 before doing any optimisation work in Phase 7.

## Phase 6 delta (TLS)

Re-measured after Phase 6, same machine and method as the Phase 5 delta
above. Run-to-run noise on this machine is real and larger than the ±10%
figure previously quoted: two consecutive runs of the release binary, back
to back, produced `eligible_backends()` at 5 backends of 657 ns and then
776 ns — an 18% swing between two runs of the identical binary with nothing
else changed. Read every number below against that noise floor, not against
a false sense of precision.

| Operation | Phase 5 (5 backends) | Phase 6, run 1 | Phase 6, run 2 | Note |
|---|---:|---:|---:|---|
| `eligible_backends()` | 635 | 657 | 776 | noise |
| `RoundRobin::pick()` | 704 | 689 | 736 | noise |
| `Gcra::check()` | 144 | 149 | 149 | noise |
| `try_admit()` | 476 | 474 | 526 | noise |
| Circuit refresh | 361 | 344 | 345 | noise |

Nothing here regressed outside the noise band, and that is the expected,
correct outcome rather than a clean bill of health worth celebrating: **none
of these five operations are anywhere near the TLS code Phase 6 added.**
`Backend` gained a `server_name: Option<String>` field this phase, which
raised a question worth actually checking rather than assuming away —
`eligible_backends()` clones `BackendId` (a newtype `String`), not the
`Backend` struct itself, so the new field never crosses this path. Confirmed
by reading `BackendPool::eligible_backends()` in
`crates/lb-core/src/pool.rs` before accepting these numbers, in the same
spirit as the `DashMap::len()` finding above: check the code before trusting
that "no change here" is actually true, rather than merely plausible.
Circuit-breaker refresh, GCRA and cluster admission are equally untouched by
Phase 6. This section measures exactly what Phase 4 and Phase 5 measured —
bookkeeping that runs *after* a connection already exists — and Phase 6 did
not touch that bookkeeping, so its cost holding steady is exactly what
should happen.

**What Phase 6 actually added — TLS handshakes, certificate-reload polling,
backend re-encryption — is not on this chart, because this harness does not
measure any of it. That gap is the headline finding here, not a footnote.**
TLS changes what the hot path *is*. Every figure above is nanoseconds of CPU
bookkeeping; a full TLS handshake is milliseconds of CPU (asymmetric-key
signing and verification, an X25519 or similar key exchange) — roughly three
orders of magnitude more expensive than everything this harness currently
measures, combined. A load balancer spending ~1.7 µs on routing and
rate-limiting per request but a couple of milliseconds establishing the
connection that request arrives on is TLS-bound, not bookkeeping-bound — and
this harness would report "all green" the entire time, because it never
looks at the thing that actually dominates.

Phase 7 needs `handshakes/sec` (full handshake, and separately, resumed) as
a first-class harness output before any of the optimisation targets below
are prioritised against it — see target 0.

## Phase 7, target 0: handshake cost (measured 2026-09-06)

`lb-bench` now measures TLS handshake CPU, which is the number every earlier
figure in this file lacked a denominator for.

| Case | ns/op | handshakes/s |
|---|---:|---:|
| Full handshake (ECDSA P-256) | 1,013,109 | 987 |
| Resumed handshake (TLS 1.3 ticket) | 747,654 | 1,338 |

**Method and its limits.** Handshakes are driven in memory between a rustls
`ClientConnection` and `ServerConnection` through byte buffers — no sockets,
so the figure is handshake CPU rather than loopback and syscall overhead.
Two limits matter when reading it:

1. **This is client + server on one thread.** A real server pays only its own
   half, so server-side cost is roughly half the figure above and capacity is
   roughly double. Treat 987/s as a conservative floor, not a capacity claim.
2. **Only P-256 is measured.** RSA would need `rcgen`'s `aws_lc_rs` feature,
   which pulls the C toolchain the `ring` pin exists to avoid.

Both cases assert `handshake_kind()` before measuring, so the "resumed" line
is provably resuming. An earlier version of this benchmark did not, and
reported resumption as only 22% cheaper — because in TLS 1.3 the server sends
`NewSessionTicket` *after* the handshake completes, and a loop that stops at
`is_handshaking() == false` never delivers it. Every "resumed" handshake was
silently a full one. The assertion exists so that cannot recur.

### What this means for Phase 7, bluntly

Per-request bookkeeping at 5 backends totals roughly **2 µs**
(`pick` 755 + circuit refresh 387 + `Gcra::check` 150 + `try_admit` 742).
A full handshake is roughly **1,013 µs** — about **500x** the entire
bookkeeping cost combined.

So for any connection that is not reused, **targets 1–4 below are worth under
0.2% each.** Eliminating all four entirely would not be measurable next to
one handshake. They were ranked before handshake cost was known; that ranking
does not survive the measurement, which is exactly why target 0 said to
measure first.

What actually moves the number, in order:

1. **Connection reuse.** The handshake is amortised across every request on a
   connection, so keep-alive and HTTP/2 (Phase 8) do more for throughput than
   any allocation removal in this file. A connection serving 100 requests
   pays 10 µs of handshake per request; one serving a single request pays
   1,013 µs.
2. **Session resumption** — measured, and worth about 26%. Real, bounded, and
   already implemented; the lever here is operational (cache sizing, and
   noting that per-process ticket keys mean resumption does not carry across
   cluster nodes).
3. **The crypto provider itself.** This project pins `ring` for build-
   environment reasons, not performance ones. `aws-lc-rs` is generally
   reported faster. That pin is now a *measurable* trade rather than a free
   one, and is worth revisiting if handshake CPU ever becomes the binding
   constraint — on a build host that can compile it.

Targets 1–4 remain correct as code hygiene and as protection against
regression at high backend counts (20 backends costs ~5 µs, and that does
scale). They are simply not the throughput story for a TLS-terminating edge,
and Phase 7 should not be planned as though they are.

## Phase 7 targets, in priority order

0. **Add `handshakes/sec` to the harness**, before ranking anything else
   against it — see "Phase 6 delta" above. Every target numbered 1–4 below
   optimises bookkeeping that costs nanoseconds; a handshake costs
   milliseconds, and unmeasured, it might dominate everything else in this
   list combined. Optimising 1–4 first, without this number, risks spending
   real effort on work that cannot move the actual bottleneck.
1. **Replace the per-request circuit-breaker refresh.** Move it off the request
   path (a timer) or replace the `Mutex` with atomics. This is the only item
   with a *contention* risk rather than merely an allocation cost, so it ranks
   first among the bookkeeping targets despite not being the largest single
   number.
2. **Stop allocating in `eligible_backends()`.** Interning `BackendId` as
   `Arc<str>` removes the per-backend `String` clone; returning an iterator or
   reusing a buffer removes the `Vec`.
3. **Remove the `format!` in `try_admit()`** — pre-compute the namespace prefix
   or key on `(listener, key)` without building a new `String`.
4. **Remove `key.to_string()` in `Gcra::check()`** — use a borrowed-key lookup
   before falling back to an owning insert.

## Phase 7, target 1 delta: circuit-breaker mutex removed

`CircuitBreaker` (`crates/lb-healthcheck/src/circuit_breaker.rs`) no longer
holds a `Mutex<CircuitState>`/`Mutex<Option<Instant>>` pair. State is an
`AtomicU8`; `opened_at` is nanoseconds elapsed since the breaker's creation
`Instant` in an `AtomicU64` (`Instant` itself has no atomic form, and
`u64::MAX` nanoseconds is tens of thousands of years, so a sentinel for
"not open" costs nothing realistic). Transitions that must not race —
tripping open, the Open→HalfOpen cooldown flip — go through
`compare_exchange` rather than a lock; a losing CAS means another thread
already made the same transition, so it is not retried. A new stress test
(`concurrent_failures_from_many_threads_trip_exactly_once`) hammers one
breaker from 8 threads at once and asserts no panic and a consistent final
state — the only property a lock-free structure can promise, since there is
no linearization point to assert an exact interleaving against.

**Re-measuring this immediately produced a false alarm worth recording.**
Fresh numbers for the circuit-breaker refresh bench at 5 backends came back
at ~800 ns/op — more than double this file's Phase 5/6 figure of 344–361 ns,
which looked like a regression until checked. Rather than trust that
delta, the old `Mutex`-based file was restored on top of today's code via
`git show HEAD:...` and re-benched *on this same machine, back to back*
with the atomics version, before writing anything down:

| Version | 1 backend | 5 backends | 20 backends |
|---|---:|---:|---:|
| Mutex (restored, pre-change) | ~230–255 ns | ~810–880 ns | ~3,190–3,390 ns |
| Atomics (this change) | ~224–233 ns | ~790–840 ns | ~2,980–3,100 ns |

Statistically indistinguishable — atomics are not measurably faster here,
and that is expected, not a failed optimisation: this bench's closure also
calls `pool.all_backend_ids()` every iteration (it always has, see the
`eligible_backends()` section above for that same allocation's cost), which
dominates the timing at 5+ backends far more than either a mutex or a
handful of atomic loads does. The gap between *this file's* old 344–361 ns
and *today's* ~800–880 ns for the identical Mutex code is real but has
nothing to do with target 1 — it is drift in `all_backend_ids()`'s own cost
(or the machine's noise floor) between when Phase 5/6 were measured and
today, and the A/B above is what proves that rather than assuming it.

The actual point of target 1 was never the uncontended ns/op — it was the
production risk this file already named: "a single-threaded measurement
cannot show contention... the real cost under concurrent load is *higher
than measured*." That risk is now structurally gone (there is no lock left
to contend on), which this single-threaded harness cannot demonstrate by
design. Target 2 (`eligible_backends()`/`all_backend_ids()` allocation) is
the next item on this list, and — per the table above — is now also the
dominant cost left in this specific bench.

## Phase 7, target 2 delta: `BackendId` interned as `Arc<str>`

`BackendId` was `String`; it is now `Arc<str>` (`crates/lb-core/src/backend.rs`).
`PartialEq`/`Eq`/`Hash`/`Ord` on `Arc<str>` all compare the pointed-to string,
not the pointer, so nothing about equality, hashing, or map/set behavior
changed — every existing `.clone()` call site (`eligible_backends()`,
`all_backend_ids()`, every balancer's pick path) got cheaper for free,
without any of those call sites being touched. The only real casualty was
one test double (`lb-healthcheck`'s `StubCall.backend_id: String`) that had
been cloning `.0` directly; that became `.to_string()`. The whole workspace
compiled clean on the first attempt otherwise — good confirmation that this
id was already only ever used through `Clone`/`Hash`/`Eq`/`Display`, never
as a `String` specifically.

Re-measured on the same machine as the target-1 A/B above:

| Operation (5 backends) | Before (String) | After (`Arc<str>`) | Change |
|---|---:|---:|---:|
| `eligible_backends()` | ~730–780 ns | ~382–401 ns | ~2x faster |
| `RoundRobin::pick()` | ~800 ns | ~391–396 ns | ~2x faster |
| Circuit-breaker refresh loop | ~790–840 ns | ~465–512 ns | ~1.7x faster |

| Operation (20 backends) | Before (String) | After (`Arc<str>`) | Change |
|---|---:|---:|---:|
| `eligible_backends()` | ~2,880–3,000 ns | ~1,184–1,260 ns | ~2.3x faster |
| Circuit-breaker refresh loop | ~2,980–3,100 ns | ~1,688–1,690 ns | ~1.8x faster |

This is a real, load-bearing number, not a wash like target 1's — this bench
is single-threaded and uncontended, exactly the case an allocation fix (as
opposed to a lock removal) should show up in.

**Deliberately not done in this pass:** target 2's other half, "returning an
iterator or reusing a buffer removes the `Vec`." `eligible_backends()` still
allocates one `Vec<BackendId>` per call — now a `Vec` of cheap `Arc` clones
rather than heap-backed `String`s, which is most of the win above. Changing
the return type to an iterator would touch every call site that currently
holds the result as an owned `Vec` (indexing, re-iterating, `.len()`, sorting
in `ConsistentHash`) across `lb-core`, every `lb-balancer` strategy, and both
proxy crates — a much larger, riskier change for what the numbers above
suggest is a small remaining slice of this cost, now that the per-element
clone is nearly free. Worth revisiting only if a future measurement shows
the `Vec` allocation itself, not its contents, is the binding cost.

## Phase 7, target 4 delta: `Gcra::check()`'s allocation removed

`Gcra::check()` called `self.state.entry(key.to_string())` unconditionally —
allocating a new `String` on *every* call, even though the overwhelmingly
common case is a key that is already tracked. Fixed with a borrowed lookup
first (`self.state.get_mut(key)`, which `DashMap<String, _>` supports
directly since `String: Borrow<str>` — no new type or dependency needed):
only a genuinely new key falls through to the allocating `entry()` path,
and only once per key's lifetime rather than once per request against it.
The GCRA arithmetic itself was pulled into a shared `admit()` helper so the
two paths can't drift apart.

| | Before | After |
|---|---:|---:|
| `Gcra::check()` | ~145–150 ns | ~100–109 ns |

A clean, full fix — no remaining allocation on the hot (repeat-key) path.

## Phase 7, target 3 delta: `ListenerCoordinator::try_admit()`, partially fixed

This one has two allocations layered on top of each other, and only one of
them is removable without a larger change.

`CounterStore::try_admit()`/`merge()` (`crates/lb-cluster/src/counters.rs`)
were allocating **twice** per call: once for the outer `DashMap<String,
KeyCounts>` entry (`key.to_string()`, where `key` was *already* an owned
`String` handed in by the caller) and again for the inner `per_node`
`HashMap<String, _>` entry (`node_id.to_string()`) — and the second one is
almost pure waste, since `try_admit`'s `node_id` is always this node's own
fixed id. Both got the same borrowed-lookup-first treatment as target 4
(`get_mut` before `entry(...to_string())`), fully contained inside
`counters.rs` with no public signature change.

**Not fixed:** the `format!("{}\u{1}{}", namespace, key)` in
`ListenerCoordinator::namespaced()` that produces the `key: &str` those two
methods receive in the first place. Removing it would mean `CounterStore`
storing `(namespace, key)` as two separate pieces instead of one
concatenated `String` — but looking that up without allocating requires a
type implementing `Borrow<Q>` for some borrowed, non-owning `Q`, and there
is no such `Q` for a two-part *unsized* key (`(str, str)` is not a
constructible Rust type; a wrapper struct hits the same wall, since `Borrow`
must return a reference borrowed *from `self`*, and no field of an owned
`(String, String)` is itself a `(&str, &str)`). Solving this properly needs
either a raw-entry-style API (`hashbrown`'s `Equivalent`, which `DashMap`
does not expose) or a reusable interior-mutable scratch buffer per listener
— both real changes, not proportionate to a cost this file already ranks
last of four, and now smaller still after the fix below.

| (5-backend-scale single key) | Before | After |
|---|---:|---:|
| `ListenerCoordinator::try_admit()` | ~469–483 ns | ~377–404 ns |

## Phase 8 (HTTP/2)

`lb-bench` needs no new benchmark for this phase. HTTP/2 does not add a new
kind of cost to measure — it amortises a cost this harness already measures.
The full-handshake figure from target 0 above (1,013,109 ns/op, ~987
handshakes/s, single-threaded) is paid once per *connection*, not once per
*request*; HTTP/2 multiplexing means one connection now carries many
concurrent requests instead of one. The win from that is a division of the
existing handshake figure by requests-per-connection, not a new number this
harness would need to produce.

**The prediction, stated explicitly:** handshakes per request should fall
roughly in proportion to requests per connection. A connection that serves 1
request still pays the full ~1,013 µs handshake for that request. A
connection that serves 100 requests over HTTP/2 multiplexing pays that same
~1,013 µs once, amortised to ~10 µs/request — the same arithmetic the
"connection reuse" lever in target 1 above already describes for keep-alive,
now available within a single connection rather than only across a pool of
them.

This is a prediction about handshake amortisation, not a benchmark result:
`lb-bench`'s handshake measurement is synthetic (rustls `ClientConnection`/
`ServerConnection` over in-memory byte buffers, no sockets, no real HTTP/2
framing), so it cannot itself show requests multiplexed onto one connection.
**`lb_requests_total{protocol="http2"}`** — the `protocol` label already
present on this counter, with values `http1`/`http2` — is how an operator
confirms the amortisation is actually happening in a running deployment:
a rising `http2` share at a roughly steady TLS-handshake rate
(`lb_tls_handshakes_total{outcome="success"}`) is the multiplexing effect
showing up outside the lab.

## Before any SLA commitment

These figures cannot support a capacity claim. That requires:

- a separate load-generation host (client and server competing for the same
  cores invalidates the measurement),
- production-like hardware,
- concurrent load, to expose the mutex contention this harness cannot see,
- a `handshakes/sec` measurement. TLS is enabled as of Phase 6, but this
  harness still does not measure it, and handshake CPU is likely to
  dominate at the edge — see "Phase 6 delta" above.
