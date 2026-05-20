# Formal models

| File | Tool | Property |
|---|---|---|
| `budget.tla` | TLA+ / TLC | `S <= B` under crash, partition, message loss |
| `protocol.spthy` | Tamarin | No passport forgery, no replay, PoP soundness |
| `delegation.spthy` | Tamarin | No chain grants more than its root |

Model the lease protocol **before** implementing `pkg/budget`. A counterexample
found here is a result worth publishing.

Run: `./check.sh`
