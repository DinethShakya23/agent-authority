# Agent Integrator — CLAUDE.md

## Code style

- **No inline or multiline comments in Go source files.** The only permitted
  comment block is the Apache 2.0 LICENSE header at the top of every `.go`
  file. Remove any `//` line comments or `/* */` blocks you encounter when
  editing a file.
- `internal/` over `pkg/` when in doubt. Everything under `pkg/` is a promise
  to downstream users.
- Three Go modules: root (control + data plane + CLI), `sdk/go` (agent-side
  only), `abench` (benchmark harness). Never collapse them.

## Non-negotiable invariants

These ten invariants must hold after every commit. The PR template carries a
subset as a checklist; skills enforce the rest automatically.

| ID  | Invariant |
|-----|-----------|
| I1  | No synchronous store or IdP call on the firewall request path. |
| I2  | Every failure path fails closed — ambiguous outcomes → DENY. |
| I3  | Passport private key never leaves the agent process. |
| I4  | Total spend never exceeds budget: `S ≤ B` (proven in `formal/budget.tla`). |
| I5  | Budget leases are pre-deducted before being granted, never after. |
| I6  | Delegation chains narrow authority monotonically (never widen). |
| I7  | Every allow and deny decision emits a signed, hash-chained receipt. |
| I8  | `abench/results/` is append-only. Never edit a result file after recording. |
| I9  | `pkg/apierr/codes.go` is append-only. Never renumber an existing code. |
| I10 | `spec/AIP-1.md` is frozen after build week 7. Changes require a version bump and new conformance vectors. |

## Firewall pipeline rules

- Stages are numbered files `01_headers.go` → `15_budget.go`. Numbering
  encodes execution order.
- Stages 01–14 are read-only (no side effects, no mutations).
- Stage 15 (`budget.go`) is the **only** mutating stage.
- Never add a mutating operation to stages 01–14.
- New stages insert between existing ones with a new number; renumber the
  suffix only if the stage is appended at the end.

## Error codes (`pkg/apierr/codes.go`)

Append-only. Rules:
1. Pick the next unused number in the correct range.
2. Add the constant, update `HTTPStatus()` if a new range is introduced.
3. Never delete or renumber an existing constant — downstream callers depend on
   the string value.

Ranges: `AI-11xx` identity · `AI-1xxx` cert · `AI-2xxx` passport ·
`AI-3xxx` sig · `AI-4xxx` replay · `AI-5xxx` authority · `AI-6xxx` budget ·
`AI-7xxx` delegation · `AI-8xxx` approval · `AI-9xxx` internal.

## Wire spec (`spec/AIP-1.md`)

Frozen after build week 7. Before that point, every change must:
- Bump the spec version field.
- Add conformance vectors in `spec/conformance/vectors/`.
- Update `spec/schemas/` if JSON schemas are affected.

## Kubernetes-style project maintenance

This project is maintained like a Kubernetes sub-project:

- **Enhancement proposals** (`docs/enhancements/KEP-NNNN-*.md`) gate
  significant feature work. Use `/kep` to create one.
- **API stability guarantees** mirror Kubernetes: `v1alpha1` may break between
  minor releases; `v1beta1` must not break within a minor; `v1` is frozen.
- **Two firewall replicas** in every dev and CI environment — the lease
  protocol only surfaces bugs under concurrency.
- **ADRs** (`docs/adr/`) are written while deciding, not after.
- **Release branches** (`release-0.1`, `release-0.2`, …) are cut from `main`
  at feature freeze; only fixes merge to a release branch.

## Testing requirements

- A new denial path (new DENY condition) requires a new test in
  `test/adversarial/` in the same PR.
- Adversarial tests are tagged `T1`–`T16` (current). New ones continue the
  sequence.
- `make demo` must pass 14/14 acceptance scenarios before any release tag.

## Durable artefacts

`spec/`, `formal/`, and `abench/` are independently publishable. Treat them as
stable references:
- `formal/` models must be run (`make formal`) before merging changes to
  `pkg/budget/` or `pkg/delegation/`.
- `abench/results/` files are never edited after recording (invariant I8).
