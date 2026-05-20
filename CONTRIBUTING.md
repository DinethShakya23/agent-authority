# Contributing

Thanks for helping. Start with a `good first issue`.

## Development

```bash
make dev-up && make test && make demo
```

## Rules that are not negotiable

These come from the architecture invariants; a PR that breaks one will be
rejected regardless of how good the rest is.

1. The data plane makes **no synchronous store or WSO2 call** on the request path.
2. Any verification, cache or trust failure results in **DENY** (fail closed).
3. Budget leases are **pre-deducted** before being granted.
4. An ambiguous upstream timeout **holds** the reservation; it never releases it.
5. Every decision, allow or deny, emits a **signed receipt**.
6. Changes to `spec/` require a version bump and new conformance vectors.

## Commits and PRs

Conventional commits. One logical change per PR. New behaviour needs a test;
new denial paths need an entry in `test/adversarial`.

## DCO

Sign off every commit: `git commit -s`.
