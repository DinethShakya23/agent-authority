# Agent Integrator

Execution-scoped, budget-limited, cryptographically verifiable authority for AI
agents at enterprise integration boundaries.

WSO2 Identity Platform answers **who is this agent?**
Agent Integrator answers **may it do this, right now, and how much of its
allowance is left?**

```
Agent -> WSO2 (identity) -> Agent Integrator (authority + budget)
      -> Agent Firewall (verify, meter, decide) -> Enterprise system
```

## Quick start

```bash
make dev-up     # WSO2 + step-ca + control plane + 2 firewall replicas + mock SAP
make demo       # 14 acceptance scenarios
```

## The scenario that explains the project

An agent authorised for "purchase orders up to $10,000" can place four hundred
$9,999 orders. Scopes allow it. Per-request policy allows it. Agent Integrator
does not: authority is a depletable budget scoped to one execution, metered
across every firewall replica with a proven no-overspend bound.

## Layout

See [STRUCTURE.md](STRUCTURE.md). Specification: [spec/](spec/).
Formal models: [formal/](formal/). Benchmarks: [abench/](abench/).

## Division of labour with WSO2

| WSO2 | Agent Integrator |
|---|---|
| Agent identity, lifecycle, authentication | Execution-scoped authority |
| Roles, scopes, consent, `act` claim | Cumulative budgets and metering |
| Token issuance and revocation | Per-request proof and enforcement |

WSO2 issues the identity; Agent Integrator issues and meters the allowance.

## License

Apache 2.0.
