# /ship-check — Pre-PR Invariant Scan

Run a full automated invariant audit before opening a pull request. Check every
non-negotiable rule from CLAUDE.md and surface any violations with file + line
references.

## Steps

1. **Read CLAUDE.md** to load the current invariant list.

2. **Scan for inline/multiline comments in Go files.**
   Search all `*.go` files for `//` lines that are not the LICENSE header block
   and for any `/* */` blocks. Report each violation as `file:line — comment
   text`. The LICENSE header (lines 1–13, Apache 2.0 boilerplate) is exempt.

3. **Check firewall stage purity (I1, stages 01–14 read-only).**
   Read `pkg/firewall/stages/01_*.go` through `14_*.go`. Flag any function call
   that writes to a store, makes a network call, or mutates shared state. Only
   `pkg/firewall/stages/15_budget.go` may mutate.

4. **Check budget pre-deduction (I5).**
   Read `pkg/budget/lease.go` and `pkg/firewall/stages/15_budget.go`. Verify
   the deduct call precedes the grant call. Flag if the order is reversed.

5. **Check error code append-only rule (I9).**
   Run `git diff main -- pkg/apierr/codes.go`. Flag any deleted or renumbered
   constant. New constants appended at the end are fine.

6. **Check spec freeze (I10).**
   Run `git diff main -- spec/AIP-1.md`. If any lines were deleted or modified
   (not just appended), check whether the spec version field was bumped and
   whether new conformance vectors exist in `spec/conformance/vectors/`. Flag if
   not.

7. **Check adversarial test coverage.**
   For every new `DENY` path added in this diff (grep for `apierr.New` or
   `apierr.Newf` in changed files), verify a corresponding test exists or was
   added in `test/adversarial/`. Flag missing coverage.

8. **Check abench results immutability (I8).**
   Run `git diff main -- abench/results/`. Flag any modified or deleted result
   file. Additions are fine.

9. **Check LICENSE headers.**
   Every `.go` file must start with the Apache 2.0 header block. Report any
   file missing it.

10. **Summarise.**
    Print a table:

    | Check | Status | Issues |
    |-------|--------|--------|
    | No inline comments | ✅/❌ | ... |
    | Stage purity (01–14) | ✅/❌ | ... |
    | Budget pre-deduction | ✅/❌ | ... |
    | Error code append-only | ✅/❌ | ... |
    | Spec freeze | ✅/❌ | ... |
    | Adversarial coverage | ✅/❌ | ... |
    | abench immutability | ✅/❌ | ... |
    | LICENSE headers | ✅/❌ | ... |

    If any row is ❌, do not suggest opening the PR. Fix the violations first.
