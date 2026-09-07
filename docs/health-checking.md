# Health Checking

Active health checks run independently of the request path. They update backend availability, which the router consumes when selecting a target.

## Active Checker

One `spawn_active_checker` task runs per backend per listener. It polls the backend at the configured `interval_ms` and writes a boolean result into the pool's `active_healthy` flag.

## Probes

### HTTP Probe

The HTTP probe issues a GET request to the configured path. A 2xx status code is healthy. Anything else, including timeouts or connection failures, is unhealthy.

The probe uses the exact same `hyper_util::Client` instance as the data plane. They share the same connection pool, trust roots, verification policy, and DNS pinning. 

This shared transport guarantees probe fidelity. If the probe used a separate client, it could successfully verify a backend's certificate that the data plane's client rejects. The probe would mark the backend healthy, but all real traffic would fail.

### TCP Probe

The TCP probe attempts a connection within the configured timeout. 

For a plaintext listener, a successful TCP connect is healthy.

For a re-encrypting listener, a TCP connect is not enough; the backend might accept the connection but present an expired certificate. The probe asks the `OutboundTransport` to wrap the connection in TLS. The backend is healthy only if both the TCP connect and the TLS handshake succeed.

## Circuit Breaker

The circuit breaker maintains a state machine driven by request outcomes, not health probe results. 

### States
- **Closed:** Requests are forwarded normally.
- **Open:** The backend is excluded from load balancing.
- **HalfOpen:** The cooldown has elapsed. A single request is allowed through to test the backend.

### Transitions
When a request fails, `record_failure` increments the failure count. When the count reaches `failure_threshold`, the circuit opens.

The transition from Open to HalfOpen is evaluated lazily. If the time since the circuit opened exceeds `cooldown_ms`, the state is HalfOpen.

If the test request in HalfOpen succeeds, `record_success` closes the circuit. If it fails, the circuit re-opens, and the cooldown timer restarts.

### Integration with the Pool

The pool tracks backend eligibility with an `active_healthy` boolean and a `circuit_open` boolean. A backend is eligible only if `active_healthy` is true and `circuit_open` is false.

The `circuit_open` flag is a cached value for fast routing. The HTTP and TCP request loops refresh this flag once per request by calling `is_open()` on every circuit breaker. 

This refresh is required because the Open to HalfOpen transition relies on time passing. If the loop did not evaluate `is_open()`, an excluded backend would stay excluded forever, as no requests would be routed to it to trigger a state evaluation.
