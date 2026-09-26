# Contributing

Thank you for your interest in improving this project. This guide covers how to set up a development environment, the checks every change must pass, and what reviewers look for.

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues must **not** be filed as public issues — see [SECURITY.md](SECURITY.md).

## Table of contents

- [Ways to contribute](#ways-to-contribute)
- [Development setup](#development-setup)
- [Repository layout](#repository-layout)
- [The pre-merge gate](#the-pre-merge-gate)
- [Testing standards](#testing-standards)
- [Coding standards](#coding-standards)
- [Commit messages](#commit-messages)
- [Pull request process](#pull-request-process)
- [Licensing of contributions](#licensing-of-contributions)

## Ways to contribute

- **Report a bug** using the [bug report template](https://github.com/Raunak4518/distributed-load-balancer/issues/new?template=bug_report.yml). A minimal config and the exact request sequence that reproduces the problem make a report actionable.
- **Propose a feature** using the [feature request template](https://github.com/Raunak4518/distributed-load-balancer/issues/new?template=feature_request.yml). For anything larger than a small, self-contained change, open an issue to agree on the design before writing code.
- **Improve documentation.** The [docs/](docs/) pages describe behavior that is implemented in code; if you find a page that disagrees with the code, the code is authoritative and the page is the bug.
- **Add benchmarks or experiments** that measure a claim the project makes. See [docs/benchmarks.md](docs/benchmarks.md).

## Development setup

**Requirements**

- A stable Rust toolchain with `rustfmt` and `clippy` (the repository pins the `stable` channel in [`rust-toolchain.toml`](rust-toolchain.toml), so `rustup` installs the right components automatically).
- No C toolchain or CMake is required. TLS uses rustls with the `ring` provider throughout; changes must not pull `aws-lc-rs` into the dependency graph (see [Dependencies](#dependencies)).
- Optional: Go, to run the ACME integration tests locally against [Pebble](https://github.com/letsencrypt/pebble) (see [ACME tests](#acme-tests)).

**Build and run**

```bash
git clone https://github.com/Raunak4518/distributed-load-balancer.git
cd distributed-load-balancer
cargo build --workspace
cargo run -p lb-server -- --check-config examples/http-basic.toml
```

[docs/getting-started.md](docs/getting-started.md) walks through running the binary against local backends.

## Repository layout

| Path | Contents |
|---|---|
| `crates/lb-server` | The `lb-server` binary: configuration loading, listener binding, wiring, reload and shutdown. |
| `crates/lb-core` | Shared traits (`LoadBalancer`, `RateLimiter`, `Clock`, …), core types (`Backend`, `BackendPool`) and configuration parsing/validation. Depends on no other workspace crate. |
| `crates/lb-proxy`, `crates/lb-tcp` | The L7 (HTTP) and L4 (TCP) data planes. |
| `crates/lb-balancer` | Load-balancing strategies. |
| `crates/lb-healthcheck` | Active health checks, circuit breaker, outlier detection. |
| `crates/lb-ratelimit`, `crates/lb-cluster` | Local GCRA rate limiting and gossip-based cluster-wide coordination. |
| `crates/lb-tls` | TLS termination, backend re-encryption, ACME, certificate reload, peer mTLS. |
| `crates/lb-metrics`, `crates/lb-tracing` | Prometheus metrics and admin HTTP server; logging and OpenTelemetry export. |
| `crates/lb-bench` | Micro-benchmarks and real-traffic evaluation harnesses. |
| `docs/` | User and contributor documentation. |
| `examples/` | Minimal, runnable configurations for common deployments. |
| `packaging/`, `scripts/`, `Dockerfile` | Distribution artifacts. |

[docs/architecture.md](docs/architecture.md) explains the crate boundaries and the dependency rules between them.

## The pre-merge gate

CI runs exactly these three commands on every push and pull request. Run them locally before opening a pull request; a change is not ready until all three pass.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings
cargo test --workspace --features lb-core/test-util
```

The `lb-core/test-util` feature enables test-only helpers (such as controllable clocks) used across the workspace's tests. It is never enabled in release builds.

### ACME tests

The ACME integration tests need a running Pebble test CA. Without the `PEBBLE_DIRECTORY_URL` and `PEBBLE_CA_PEM` environment variables they print a skip notice and pass, so the rest of the suite runs without Go installed. CI always runs them; to run them locally, replicate the Pebble setup steps in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

### Resource-constrained machines

The full workspace test suite compiles many integration-test binaries. On machines with limited memory or disk, `cargo test -j 1` reduces peak memory, and running a single crate (`cargo test -p lb-proxy --features lb-core/test-util`) is a fast inner loop. The full gate must still pass before merge.

## Testing standards

A test is only useful if it fails when the behavior it describes is broken. Reviewers check this explicitly.

- **Every bug fix includes a regression test that fails without the fix.** State in the pull request that you confirmed it fails on the unfixed code.
- **Assert the system's behavior, not the test's own setup.** A test that would pass against an empty implementation, or that only checks a value the test itself wrote, is not accepted.
- **Prefer deterministic time.** Use the `Clock` abstraction and fake clocks (or `tokio::time::pause`) instead of real sleeps wherever the logic under test is time-driven.
- **Concurrency claims need concurrency tests.** A change that claims thread safety or race freedom should include a test that exercises the race with real threads or tasks.
- **Integration tests use real sockets.** Tests in `crates/lb-server/tests/` start a real `lb-server` and real backends on loopback. Put new end-to-end tests there, reusing `support.rs`.

## Coding standards

- **Formatting and lints** are enforced by the gate above; `clippy` warnings are errors.
- **Respect the crate boundaries.** New behavior goes behind the existing traits in `lb-core` where one fits. Data-plane crates must not depend on each other or on concrete types that only `lb-server` should know about.
- **No panics on the data path.** Request handling must not `unwrap`/`expect` on anything a client or backend can influence. Return an error response and record a metric instead.
- **Bound everything a client can grow.** Any map, queue or buffer keyed or sized by client input needs an explicit cap and a documented overflow behavior.
- **Observable by default.** A new rejection path, failure mode or state transition should have a metric; see [docs/metrics-reference.md](docs/metrics-reference.md) for naming conventions.
- **Keep changes focused.** Refactors unrelated to the change under review belong in a separate pull request.

### Dependencies

- Prefer crates already present in `Cargo.lock`. Justify any new dependency in the pull request description.
- TLS dependencies must use rustls with the `ring` provider and disable default features that would select `aws-lc-rs`.
- Test-only dependencies go in `[dev-dependencies]`.

## Commit messages

The history uses [Conventional Commits](https://www.conventionalcommits.org/) prefixes:

| Prefix | Use for |
|---|---|
| `feat:` | New user-visible behavior |
| `fix:` | Bug fixes |
| `perf:` | Performance improvements with no behavior change |
| `test:` | Tests only |
| `bench:` | Benchmarks and evaluation harnesses |
| `docs:` | Documentation only |
| `ci:` / `chore:` | Build, CI and repository maintenance |

Keep the subject line short and in the imperative mood (`fix: bound the peer label cardinality`). Put the reasoning a future maintainer needs in the code and the pull request, and keep the commit body to a line or two. Prefer several small, reviewable commits over one large one.

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your change with tests, and run the [pre-merge gate](#the-pre-merge-gate).
3. Update the relevant page under [docs/](docs/) if behavior, configuration or metrics change, and add an entry under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
4. Open a pull request and fill in the template. Link the issue it resolves.
5. A maintainer will review. Expect questions about failure modes, bounds and test discrimination; these are routine, not a sign of rejection.

Pull requests are merged once CI is green and review comments are resolved.

## Licensing of contributions

This project is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
