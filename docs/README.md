# Documentation

Documentation for the distributed load balancer. Every page is written against the current source code; where a page and the code disagree, the code is authoritative and the page is a bug — please [report it](https://github.com/Raunak4518/distributed-load-balancer/issues/new?template=bug_report.yml).

## Start here

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | Build the binary, balance two local backends, read metrics, watch a backend fail and recover, reload a config. About ten minutes. |
| [Operations](operations.md) | Release artifacts, Docker, systemd, CLI and exit codes, `SIGHUP` reload, graceful shutdown, the admin API, logging and tracing, troubleshooting. |

## Guides

| Page | What it covers |
|---|---|
| [Load balancing](load-balancing.md) | Backend eligibility, the five selection strategies, path/`Host` routes, canary traffic splits, sticky sessions, DNS discovery, retries. |
| [Health checking](health-checking.md) | Active HTTP/TCP probes, passive checks, the circuit breaker, outlier detection and the ejection ceiling, manual drain, state across reloads. |
| [Rate limiting](rate-limiting.md) | The GCRA algorithm, bounded key tracking, the response a limited client receives, the retry budget. |
| [Cluster coordination](cluster-coordination.md) | Cluster-wide rate limiting: the G-Counter CRDT, authenticated gossip, clock-skew bounds, peer mutual TLS, the overshoot bound, failure modes. |
| [TLS](tls.md) | Edge termination, SNI and multiple certificates, ACME, certificate hot reload, backend re-encryption, cluster peer mTLS. |
| [HTTP features](http-features.md) | HTTP/1.1 and HTTP/2, header handling, response caching, compression, WebSocket/`Upgrade` proxying, backend connection pooling. |
| [Edge hardening](edge-hardening.md) | Connection caps, slowloris defenses, body limits, HTTP/2 abuse limits (Rapid Reset), PROXY protocol, the WAF, admin authentication. |

## Reference

| Page | What it covers |
|---|---|
| [Configuration reference](configuration-reference.md) | Every configuration field with type, default and validation rule; cross-field validation; which fields reload live. |
| [Metrics reference](metrics-reference.md) | Every Prometheus metric with type, labels and call sites; cardinality bounds; suggested alert rules. |
| [Request lifecycle](request-lifecycle.md) | The exact ordered path of an HTTP request and a TCP session, and where each can be rejected. |

## Internals

| Page | What it covers |
|---|---|
| [Architecture](architecture.md) | Crate graph and dependency rules, the trait boundaries in `lb-core`, startup wiring, the concurrency model, extension points. |
| [Benchmarks](benchmarks.md) | The benchmark suite, methodology and its limits, and measured results with their sources. |
| [Baseline log](BASELINE.md) | The raw historical micro-benchmark log that the benchmarks page summarizes. |

## Elsewhere in the repository

- [`config.example.toml`](../config.example.toml) — an annotated configuration covering every section.
- [`examples/`](../examples/) — minimal runnable configurations for common deployments.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — development setup, the pre-merge gate and testing standards.
- [`CHANGELOG.md`](../CHANGELOG.md) — notable changes per release.
