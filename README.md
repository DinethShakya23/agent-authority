# Agent Authority

**Execution-scoped, budget-limited, cryptographically verifiable authority for AI agents at enterprise integration boundaries.**

[![CI](https://github.com/DinethShakya23/agent-authority/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/DinethShakya23/agent-authority/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/DinethShakya23/agent-authority)](https://goreportcard.com/report/github.com/DinethShakya23/agent-authority)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.23-blue.svg)](go.mod)
[![Spec](https://img.shields.io/badge/spec-AIP--1%20v0.1-informational)](spec/AIP-1.md)

---

## The problem

An agent authorised for "purchase orders up to $10,000" can place four hundred $9,999 orders. OAuth scopes allow it. Per-request policy allows it.

Agent Authority does not: authority is a depletable budget scoped to one execution, metered across every firewall replica with a proven no-overspend bound — even under crashes and network partitions.

## How it fits with your IdP

```
Agent ──► IdP (identity)          ──► Agent Authority (authority + budget)
      ──► Agent Firewall (verify, meter, decide) ──► Enterprise system
```

| Your IdP (WSO2, Auth0, Okta, …) | Agent Authority |
|---|---|
| Agent identity, lifecycle, authentication | Execution-scoped authority |
| Roles, scopes, consent, `act` claim | Cumulative budgets and metering |
| Token issuance and revocation | Per-request cryptographic proof and enforcement |

Your IdP answers **who is this agent?**
Agent Authority answers **may it do this right now, and how much of its allowance is left?**

---

## Features

- **Execution-scoped budgets** — authority is a depletable resource (monetary amount, call count, distinct-resource count), not a flag
- **Proven no-overspend** — pre-deducted leases satisfy `spent ≤ budget` under arbitrary replica crashes and partitions (TLA⁺ verified)
- **Cryptographic receipts** — every allow and deny decision emits a signed, tamper-evident audit receipt
- **15-stage firewall pipeline** — stages 1–14 are stateless and side-effect free; stage 15 (budget reservation) is the only mutating step
- **Delegation chains** — agents can mint child passports with monotonically narrowing authority
- **Provider-agnostic identity** — pluggable `Federator` adapter for any OIDC-compliant IdP; WSO2, Auth0, Okta, and Keycloak ship out of the box
- **AIP-1 wire spec** — open, implementation-neutral HTTP header protocol; any conformant firewall interoperates
- **OpenTelemetry native** — per-stage latency spans, budget utilisation metrics, decision counters

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Control Plane (agentd)                                         │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  IdP Adapter │  │   Passport   │  │   Budget Authority   │  │
│  │ (WSO2/OIDC)  │  │  Authority   │  │   + Lease Protocol   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Policy     │  │  Delegation  │  │   Store (BoltDB →    │  │
│  │   Engine     │  │   Engine     │  │    etcd in v0.2)     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                          │ watch / lease sync
┌─────────────────────────────────────────────────────────────────┐
│  Data Plane (agentfw) — stateless, no sync IdP/CP calls        │
│                                                                 │
│  AIP-1 request ──► Stage 01: Headers                           │
│                    Stage 02: Certificate chain                  │
│                    Stage 03: Passport JWS                       │
│                    Stage 04: Cert–passport binding              │
│                    Stage 05: Validity window                    │
│                    Stage 06: Revocation                         │
│                    Stage 07: Timestamp                          │
│                    Stage 08: Nonce (replay prevention)          │
│                    Stage 09: Request signature                  │
│                    Stage 10: Audience                           │
│                    Stage 11: Capability                         │
│                    Stage 12: Payload schema                     │
│                    Stage 13: Per-request constraints (Cedar)    │
│                    Stage 14: Delegation chain                   │
│                    Stage 15: Budget reservation ◄── only write  │
│                             │                                   │
│                    ALLOW / DENY + signed receipt                │
└─────────────────────────────────────────────────────────────────┘
```

**Invariants (AIP-1):**
- **I1** — No synchronous IdP or control-plane call on the request path
- **I2** — Any verification or cache failure → DENY (fail closed)

---

## Quick start

```bash
# Start the full local stack:
# WSO2 IS + step-ca + agentd + 2× agentfw + mock SAP + OpenTelemetry + Jaeger
make dev-up

# Run all 14 acceptance scenarios
make demo

# Tear down
make dev-down
```

The scenario to run first is **scenario 9**: three $9,000 orders against a $25,000 budget — the third is denied even though each order is individually within policy.

---

## Installation

### Helm (Kubernetes)

```bash
helm install agent-authority deploy/helm/agent-authority \
  --set wso2.baseURL=https://your-wso2:9443 \
  --set wso2.audience=agent-authority \
  --set telemetry.otlpEndpoint=http://your-collector:4317
```

Minimum: **2 firewall replicas** — the budget lease protocol requires more than one enforcement point.

Key values:

```yaml
agentd:
  replicas: 1                      # HA with etcd in v0.2

agentfw:
  replicas: 2                      # minimum 2 for the lease protocol
  autoscaling:
    enabled: false

ca:
  provider: cert-manager

telemetry:
  otlpEndpoint: http://otel-collector:4317
```

### Binaries

```bash
make build
# Produces: bin/agentd  bin/agentfw  bin/agentctl
```

---

## Identity providers

Agent Authority ships adapters for any OIDC-compliant provider. Import the adapter and it self-registers:

```go
import _ "github.com/DinethShakya23/agent-authority/pkg/identity/wso2"  // WSO2
import _ "github.com/DinethShakya23/agent-authority/pkg/identity/oidc"  // Auth0, Okta, Keycloak, …
```

Configure via `agentd.yaml`:

```yaml
identity:
  type: oidc    # or "wso2"
  wellKnown: https://your-tenant.auth0.com/.well-known/openid-configuration
  audience: agent-authority
  acceptOnBehalfOf: true
```

Adding a new provider takes one file:

```go
func init() {
    identity.DefaultRegistry.Register("myprovider", Factory)
}
```

---

## Defining policy

```yaml
apiVersion: agentauthority.dev/v1alpha1
kind: AgentPolicy
metadata:
  name: procurement-policy
  namespace: finance
spec:
  agentSelector:
    matchLabels:
      role/procurement-specialist: "true"
  requiredScopes: [purchase_order.create]
  rules:
    - capability: purchase_order.create
      target:
        integration: sap-production
      perRequest:
        vendor: { allowed: [acme, globex] }
        amount: { maximum: 10000, currency: USD }
      budget:
        scope: execution
        amount: { total: 25000, currency: USD }
        calls:  { total: 12 }
      validity:   { duration: 5m }
      delegation: { allowed: true, maxDepth: 2 }
```

```bash
agentctl apply -f procurement-policy.yaml
agentctl get agentpolicy -n finance
```

---

## CLI reference

```
agentctl apply  -f <file>           Apply a resource (YAML or JSON)
agentctl get    <kind> [<name>]     List or get resources
                -n <namespace>
                -A  (all namespaces)

Supported kinds:
  Agent  Capability  AgentPolicy  Integration  AgentExecution  AgentPassport
```

---

## Components

| Binary | Port | Role |
|--------|------|------|
| `agentd` | 8443 | Control plane — policy, passport authority, budget authority, IdP federation |
| `agentfw` | 8080 | Data plane firewall — 15-stage pipeline, no sync CP calls, `/healthz` |
| `agentctl` | — | Operator and developer CLI |

---

## Go SDK

```bash
go get github.com/DinethShakya23/agent-authority/sdk/go
```

The SDK is a separate Go module so agent authors do not pull the control plane into their dependency graph.

---

## Development

```bash
make build       # Build all binaries
make test        # Unit + property tests (-race)
make lint        # golangci-lint
make fmt         # gofmt + goimports
make tidy        # go mod tidy across all modules
make bench       # Benchmark harness
make formal      # TLA⁺ model-check the budget lease protocol
```

### CI jobs

| Job | What it checks |
|-----|---------------|
| `lint` | golangci-lint |
| `build` | Compile all binaries |
| `test` | Unit + property tests with race detector |
| `vet` | go vet |
| `govulncheck` | Known vulnerability scan |
| `license` | Apache 2.0 header on every `.go` file |

---

## Formal verification

The budget lease protocol is model-checked with TLA⁺ (`formal/budget.tla`).

Core safety property: `spent ≤ budget` holds under arbitrary replica crashes and network partitions. Leases are pre-deducted before being granted; a replica may only authorise spend within its held lease.

```bash
make formal
```

---

## Wire specification: AIP-1

[`spec/AIP-1.md`](spec/AIP-1.md) is an open, implementation-neutral HTTP header protocol. Any conformant firewall interoperates with any conformant agent, independent of this implementation.

Eight request headers, a length-prefixed canonical string, and 16 normative verification steps. Steps 1–14 are side-effect free. Step 15 (budget reservation) is the only mutating step.

The spec is versioned independently of the software. Changes to the canonical string, header set, or passport payload require a new spec version and new conformance vectors.

---

## Project status

| Version | Status | Highlights |
|---------|--------|------------|
| **v0.1** | In development | WSO2 + OIDC federation, Cedar policy, passport authority, budget leases, step-ca, HTTP firewall, delegation, receipt chain, agentctl, SDK, 14 acceptance scenarios |
| v0.2 | Planned | MCP adapter, gRPC adapter, credential broker, HITL approval, etcd HA, Envoy ext_authz |
| v0.3 | Planned | Offline delegation, multi-agent authorisation |
| v1.0 | Planned | Stable API, multi-cluster, multiple independent adopters |

See [ROADMAP.md](ROADMAP.md) for the full roadmap.

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md).

Non-negotiable data-plane rules:
1. No synchronous store or IdP call on the request path
2. Any verification, cache, or trust failure → DENY (fail closed)
3. Budget leases are pre-deducted before being granted
4. Ambiguous upstream timeout → HOLD the reservation; never release it
5. Every decision (allow or deny) emits a signed receipt

Commits follow [Conventional Commits](https://www.conventionalcommits.org/). DCO sign-off required (`git commit -s`).

---

## Community

- [Governance](GOVERNANCE.md)
- [Code of Conduct](CODE_OF_CONDUCT.md) — follows the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md)
- [Security Policy](SECURITY.md) — report to `security@agentauthority.dev` or via GitHub private vulnerability reporting

---

## Documentation

| Section | Contents |
|---------|----------|
| [concepts/](docs/concepts/) | Passport, budget, delegation, receipts, integration boundaries |
| [getting-started/](docs/getting-started/) | Agent developer, platform operator, security reviewer paths |
| [reference/](docs/reference/) | API, CLI, error codes, configuration |
| [operations/](docs/operations/) | Deployment, IdP integration, troubleshooting, security hardening |
| [adr/](docs/adr/) | Architecture decision records |
| [spec/](spec/) | AIP-1 wire spec, conformance vectors, JSON schemas |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 The Agent Authority Authors.
