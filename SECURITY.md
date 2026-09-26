# Security Policy

This project sits on the network edge: it terminates TLS, parses untrusted HTTP/1.1, HTTP/2 and PROXY protocol input, and exchanges authenticated state with cluster peers. Security reports are taken seriously and handled privately.

## Supported versions

Security fixes are applied to the latest release and to `main`.

| Version | Supported |
|---|---|
| Latest release (`0.3.x`) | Yes |
| Older releases | No — upgrade to the latest release |

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/Raunak4518/distributed-load-balancer/security/advisories/new)**

Please include:

- The affected version or commit.
- A description of the issue and its impact (for example: request smuggling, denial of service, authentication bypass, memory exhaustion).
- A minimal configuration and the exact input or request sequence that reproduces it.
- Any known mitigations or workarounds.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | Within 3 business days |
| Initial assessment and severity | Within 10 business days |
| Fix or mitigation for confirmed high-severity issues | As fast as practical, typically within 30 days |

You will be kept informed of progress. Once a fix is released, a GitHub Security Advisory is published and, with your permission, you are credited for the discovery.

## Scope

In scope:

- The `lb-server` binary and all crates in this repository.
- The release artifacts, container image, packages and install script produced by this repository's workflows.

Out of scope:

- Vulnerabilities in third-party dependencies with no demonstrated impact on this project (report those upstream; a report showing how one is reachable here is in scope).
- Denial of service that requires traffic volumes beyond the configured connection and rate limits.
- Findings that depend on a deliberately insecure configuration, such as `danger_accept_invalid_certs = true` or exposing an unauthenticated admin listener to an untrusted network.

## Hardening guidance

Deployment recommendations — binding the admin listener privately and setting an admin token, enabling mutual TLS on the cluster peer channel, supplying secrets through environment variables rather than the config file — are covered in [docs/edge-hardening.md](docs/edge-hardening.md), [docs/tls.md](docs/tls.md) and [docs/operations.md](docs/operations.md).
