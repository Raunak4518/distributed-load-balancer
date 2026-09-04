# Distributed Load Balancer — Phase 5 Design (Edge Hardening)

**Date:** 2026-09-04
**Status:** Approved for implementation planning
**Builds on:** Phases 1–4, all shipped.
**Scope:** Surviving hostile traffic. No new features — this phase closes the ways the system can be taken down or abused once it faces the public internet.

## 1. The Threat Model

Phases 1–3 assumed cooperative clients. At the edge that assumption is void: anyone on the internet can connect, and some of them are trying to hurt you. Four concrete weaknesses exist in the current code, all verified rather than hypothesised:

| Weakness | Consequence |
|---|---|
| No connection cap (no semaphore anywhere) | Connection flood exhausts file descriptors and memory |
| Size limits but no *time* limits on requests | Slowloris: hold connections open indefinitely |
| Cluster peer port is unauthenticated | Anyone reachable can inject counters and deny service to real users |
| Rate-limit key map is unbounded | Many distinct source IPs balloon memory between sweeps |

Phase 4 made the system observable; this phase makes it survivable. Every control below is metered, because a limit you cannot see being approached is a limit you only learn about during an incident.

## 2. Connection Limits

### 2.1 Global cap, applied as backpressure

Each listener gets a `tokio::sync::Semaphore` sized by `max_connections`. The permit is acquired **before** `accept()`, not after:

```rust
let permit = semaphore.clone().acquire_owned().await;
let (stream, peer) = listener.accept().await?;   // only now
```

The ordering is the whole point. Accepting first and then deciding means we have already spent a file descriptor and a task on a connection we intend to drop. Acquiring first means that at capacity we simply stop calling `accept()`, the kernel's backlog absorbs the next few, and beyond that the OS refuses connections itself — which is exactly the behaviour we want, implemented by the kernel rather than by us.

The permit moves into the connection task and is released on drop, so every exit path — success, error, panic, drain — returns it.

### 2.2 Per-IP cap, because a global cap alone is not enough

A global cap stops the process dying, but one attacker can still consume all of it and starve every legitimate client. So each listener also tracks concurrent connections per source IP against `max_connections_per_ip`.

Unlike the global cap this **must** be checked after `accept()`, because the peer address is not knowable before then. Over-limit connections are dropped immediately, which costs one accept — unavoidable, and far cheaper than servicing them.

**The per-IP map is itself attacker-controlled state, and that is easy to get wrong.** It is keyed by client IP, so if entries were merely decremented and left behind, an attacker cycling through source addresses would grow it without bound — replacing one memory-exhaustion bug with another. Entries are therefore **removed when their count reaches zero**, and a test asserts exactly that.

## 3. Timeouts: Size Limits Are Not Enough

This is the subtlest gap in the current code. `max_request_body_bytes` caps how *much* a client may send; nothing caps how *long* it may take. A client can send 1 MiB at one byte per second and hold a connection for eleven days. Bounding bytes without bounding time is not a defence.

Three timeouts, each covering a distinct phase:

| Setting | Covers | Attack it stops |
|---|---|---|
| `header_read_timeout_ms` | Reading the request head | Classic slowloris (dribbled headers) |
| `body_read_timeout_ms` | Reading the request body | Slow POST |
| `forward_timeout_ms` (existing) | The upstream call | Hung backend |

The header timeout is supplied to hyper's `http1::Builder::header_read_timeout`. The body timeout wraps `read_bounded`, which currently has none.

**A gap that remains, stated rather than glossed over:** a client that reads the *response* slowly still occupies a connection, and hyper's server offers no direct write timeout. TCP backpressure means our write simply blocks. The mitigation is the connection cap from §2 — it bounds the damage rather than preventing the behaviour. A full fix needs write-side deadlines and is deferred.

## 4. Cluster Peer Authentication

Phase 3 shipped the peer port unauthenticated and documented it as a known hole. At the edge that is no longer acceptable: anyone who can reach the port injects counter values, and inflated counters cause legitimate traffic to be rejected — denial of service through the safety mechanism itself.

Each message carries an **HMAC-SHA256 tag** over its payload, keyed by a shared secret:

```
[4-byte big-endian length][32-byte HMAC tag][JSON payload]
```

The receiver recomputes the tag and compares it in **constant time** (`Mac::verify_slice`) before merging anything. A timing-variable comparison would leak the expected tag byte by byte, which is precisely the mistake that makes naive MAC checks useless.

This is a pre-shared key, not mTLS. mTLS needs a PKI and belongs with Phase 6's TLS work; an HMAC closes the hole now at a fraction of the complexity.

**Authentication is mandatory whenever `[cluster]` is configured.** Making it optional would leave an insecure default that nobody turns on. This is a breaking change to Phase 3 cluster configs, taken deliberately.

The secret is supplied by **environment variable** (`shared_secret_env`, naming the variable) so it never lands in a config file in version control. A literal `shared_secret` is also accepted for tests and constrained environments, and the documentation is explicit that the env form is preferred. Exactly one of the two must be present, and an empty secret is rejected at startup.

## 5. Bounding Rate-Limit Cardinality

The GCRA map grows with distinct rate-limit keys and is swept only every 30 seconds. A botnet, or spoofed source addresses, can balloon it in between.

Every available option is bad in a different way, which is why the choice needs stating:

- **Reject new keys** — denies service to legitimate newcomers during an attack.
- **LRU eviction** — lets an attacker evict established, legitimate clients.
- **Stop tracking beyond the cap** — lets the attacker bypass rate limiting entirely.

Phase 5 uses an **overflow bucket**: the map is capped at `max_tracked_keys`, and once full, every new key shares a single budget under a reserved key. Established clients keep their own limits; an attacker spraying thousands of addresses collectively receives one client's worth of throughput. It degrades in the right direction — the people already using the service are the ones protected.

The reserved key is prefixed with a NUL byte, which cannot appear in an IP string or an HTTP header value, so a client cannot craft a key that collides with it.

On the hot path the check short-circuits: normally only a cheap `len()` comparison runs, and the extra `contains_key` lookup happens solely when the map is already at capacity.

## 6. New Metrics

| Metric | Type | Labels |
|---|---|---|
| `lb_connections_rejected_total` | counter | `listener`, `reason` (`max_connections` \| `max_per_ip`) |
| `lb_request_timeouts_total` | counter | `listener`, `phase` (`header` \| `body`) |
| `lb_ratelimit_tracked_keys` | gauge | `listener` |
| `lb_cluster_auth_failures_total` | counter | `peer` |

All labels remain config-derived or from a fixed set — the Phase 4 cardinality rule (§2.3 of that spec) still holds, and its executable test still guards it.

`lb_ratelimit_tracked_keys` matters most: it is the early warning that the overflow bucket is about to engage.

## 7. Configuration

```toml
[[listeners]]
# ...
max_connections        = 10000
max_connections_per_ip = 100
header_read_timeout_ms = 5000
body_read_timeout_ms   = 10000

  [listeners.rate_limit]
  max_tracked_keys = 100000

[cluster]
shared_secret_env = "LB_CLUSTER_SECRET"   # preferred
# shared_secret   = "..."                 # accepted, but keeps secrets in files
```

All listener settings have defaults, so existing configs keep working. The cluster secret does not — it is required when `[cluster]` is present, by design.

Validation, fail-fast as always: positive connection caps, `max_connections_per_ip <= max_connections`, positive timeouts, positive `max_tracked_keys`, exactly one secret source, non-empty secret.

## 8. Testing Strategy

- **Global cap**: open `max_connections` connections and hold them; the next is not served. Releasing one admits the next.
- **Per-IP cap**: one source IP exceeding its limit is refused while the global cap still has room.
- **Per-IP map cleanup**: after connections close, the map holds no entry for that IP — the anti-unbounded-growth guarantee, tested directly.
- **Slowloris**: a connection that dribbles headers is closed within `header_read_timeout`.
- **Slow POST**: a connection that dribbles a body is closed within `body_read_timeout`.
- **HMAC**: a valid tag merges; a wrong tag, a tampered payload, and a truncated tag are each rejected without merging.
- **Missing secret**: a `[cluster]` config with no secret fails startup rather than running insecurely.
- **Cardinality**: filling past `max_tracked_keys` routes new keys to the overflow bucket while existing keys keep their own budgets.
- All 122 existing tests must continue to pass, with changes confined to construction sites and cluster configs that now need a secret.

## 9. Out of Scope

- Write-side (slow-reader) timeouts — see §3; the connection cap is the mitigation for now.
- mTLS on the peer channel — Phase 6.
- SYN-flood and volumetric DDoS defence — these belong upstream of any userspace process, in the network or a scrubbing provider. A load balancer cannot solve them and should not pretend to.
- Per-IP *request* rate limiting beyond the existing GCRA, and IP allow/deny lists.

## 10. Decisions Log

- **Permit acquired before `accept()`**: at capacity we stop accepting and let the kernel refuse, rather than spending an fd and a task to immediately discard a connection.
- **Per-IP cap in addition to a global one**: a global cap alone protects the process but not its users; one attacker could consume the entire budget.
- **Per-IP entries removed at zero**: the map is keyed by attacker-controlled input, so leaving entries behind would recreate the exhaustion bug it exists to prevent.
- **Timeouts alongside size limits**: bytes-without-time is not a bound; 1 MiB at one byte per second is eleven days.
- **HMAC over mTLS for now**: closes the hole immediately without a PKI; mTLS lands with Phase 6's TLS work.
- **Constant-time tag comparison**: a variable-time compare leaks the expected tag byte by byte.
- **Peer auth mandatory when clustering**: an optional security control defaults to off and stays off.
- **Secret via environment variable**: config files end up in version control; secrets should not.
- **Overflow bucket over rejection or LRU**: rejection punishes legitimate newcomers, LRU lets an attacker evict real users; sharing one budget among newcomers protects established clients and blunts a spray attack.
