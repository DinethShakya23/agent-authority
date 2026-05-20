# 4. Pre-deducted budget leases

## Context
Budget is shared mutable state across N firewall replicas, but the data plane
must not call the control plane on the request path.

## Decision
The Budget Authority deducts a lease from the remaining budget **before**
returning it. A replica may only authorise spend within its held lease.

## Consequences
- Overspend is impossible under arbitrary crashes and partitions (`S <= B`).
- Budget can be stranded when a replica dies, until lease TTL.
- Lease size becomes a tunable trading p99 latency against utilisation - and
  that trade-off curve is the headline research result.
