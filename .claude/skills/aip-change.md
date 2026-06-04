# /aip-change — Modify the AIP-1 Wire Specification

Guide a safe, backward-compatible change to `spec/AIP-1.md`. Enforces the
freeze rule (invariant I10) and conformance vector discipline.

## Steps

1. **Check freeze status.**
   Read the first commit date from `git log --follow spec/AIP-1.md` to
   determine whether build week 7 has passed. If frozen, warn the user that any
   change requires a spec version bump and backward-compatibility justification.
   Ask for explicit confirmation before proceeding.

2. **Read the current spec.**
   Read `spec/AIP-1.md` and display the current version field and header list.

3. **Ask for the change.**
   Prompt the user for:
   - What is changing (add header / modify header / add verification step /
     modify step / deprecate)
   - Whether the change is backward-compatible (removing a required header is
     not; adding an optional one is)

4. **Apply the change to `spec/AIP-1.md`.**
   Edit only the relevant section. Bump the version field (e.g. `v0.1` →
   `v0.2` or patch-level as appropriate).

5. **Add conformance vectors.**
   In `spec/conformance/vectors/`, create a new YAML or JSON file named after
   the changed feature (e.g. `v02-new-header.yaml`) with at least one valid and
   one invalid example.

6. **Update JSON schemas if applicable.**
   If the change affects request or response shapes, update `spec/schemas/`.

7. **Check for implementation drift.**
   Grep for the changed header name or step number in
   `pkg/firewall/stages/` and `sdk/go/`. List any files that reference the old
   spec and need updating.

8. **Checklist for the user.**
   - [ ] Spec version bumped
   - [ ] Conformance vectors added
   - [ ] JSON schemas updated (if applicable)
   - [ ] Implementation files identified for update
   - [ ] Run `make test` (conformance test suite must pass)
   - [ ] Run `/ship-check`
