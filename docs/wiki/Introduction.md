# Introduction

The load balancer was built to handle high-concurrency HTTP and TCP traffic at the edge, protect backends from abusive traffic patterns, and coordinate rate-limiting decisions across a fleet of proxies without introducing external database dependencies.

## Problem Being Solved

Most simple reverse proxies focus purely on backend selection and forwarding. However, operating at the edge requires defending against resource exhaustion (slowloris, HTTP/2 Rapid Reset, connection floods), applying strict burst shaping, and maintaining state across multiple geographic regions or data centers.

While tools like Envoy and HAProxy solve these problems, they often require sidecars, complex control planes, or external Redis instances for cluster-wide rate limiting.

This project solves these problems in a single, statically linked binary. It builds the control plane directly into the data plane, using peer-to-peer gossip to share state.

## Scope and Capabilities

The project provides:
- Edge TLS termination and ALPN negotiation (HTTP/1.1 and HTTP/2).
- Transparent TCP proxying for database or custom protocols.
- Bounded GCRA rate limiting per IP or HTTP header.
- Decentralized, cluster-wide rate limiting via a G-Counter CRDT.
- Active health checking via HTTP or TCP probes using the exact transport configured for real traffic.
- Circuit breaking to quickly sever failing targets from the routing pool.
- Prometheus metrics exposition.

## Non-Goals

The system is strictly an L4/L7 load balancer and traffic shaper. It does **not** aim to provide:
- **Service Mesh Features:** There is no sidecar injection, mTLS between microservices, or complex routing rule evaluation based on URL paths (it routes by listener port).
- **Authentication:** It does not terminate OAuth, JWT, or act as an API gateway for user authentication.
- **Full HTTP Caching Semantics:** `[listeners.cache]` answers a repeated `GET` from memory (see Architecture-Trade-offs), but it is deliberately narrow -- only `GET`+`200`+`Content-Length`-bounded responses, `Cache-Control` max-age/no-store only. There is no `Vary`/`ETag`/conditional-request handling, no purge API, and no shared cache across nodes; that remains a job for a CDN or the backends themselves.

## System Boundaries

The load balancer sits strictly between external clients and internal backends. 

1. **Inbound:** Traffic originates from untrusted clients on the public internet. Connection caps, slowloris timeouts, and HTTP/2 limits apply here.
2. **Outbound:** Traffic is forwarded to trusted backends (or backends verified via `backend_tls` certificates).
3. **Peer-to-Peer:** The load balancer talks to other load balancer instances over a private, HMAC-authenticated TCP gossip port to exchange rate-limit state.

## Terminology

- **Data Plane:** The async tasks that pump bytes from clients to backends (`lb-proxy`, `lb-tcp`).
- **Control Path:** The async tasks that manage cluster state, health checks, and certificate reloads in the background.
- **Listener:** A bound port (e.g., `0.0.0.0:443`) with a specific protocol (`http` or `tcp`) and backend pool.
- **CRDT:** Conflict-free Replicated Data Type. A data structure (here, a G-Counter) that can be merged across network partitions without a central consensus authority.
