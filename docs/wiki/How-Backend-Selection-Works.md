# How Backend Selection Works

When a request reaches the router, it does not simply pick the next backend in the list. The router selects a target from the currently eligible backend pool.

## Eligibility

A backend must pass two separate checks to be eligible for routing:
1. **Active Health:** The background health checker must have successfully probed the backend recently.
2. **Circuit State:** The request-path circuit breaker must be `Closed`. 

If the health probe fails, or if a burst of real requests fail and trip the circuit breaker to `Open`, the backend is removed from the eligible set. The router evaluates only the backends that remain.

## The Selection Loop

The router asks the load-balancing strategy (currently Round Robin) to pick an ID from the eligible set. 

If a backend is selected, the proxy attempts to forward the request. If the connection fails (e.g., the backend just died but the health check hasn't run yet), the circuit breaker records the failure immediately. The proxy then retries the request *exactly once*, asking the router for a backend again. Because the failing backend's circuit breaker was updated, it is excluded from the second choice.

## Separation of Concerns

Health checks update availability independently of routing. The router only reads the current state when selecting a target. This prevents routing strategies from having to implement their own health-checking or failure-tracking logic.
