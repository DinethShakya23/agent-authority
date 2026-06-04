# /kep — Kubernetes Enhancement Proposal

Create and manage a KEP (Kubernetes Enhancement Proposal) for a significant
feature or API change. KEPs gate feature work the way Kubernetes SIG proposals
do: written before implementation begins, reviewed before code lands.

## When to use

Use `/kep` for any change that:
- Adds or modifies an API type in `api/v1alpha1/`
- Introduces a new protocol capability or AIP-1 header
- Changes the budget lease protocol or formal model
- Adds a new integration adapter
- Promotes an API from alpha to beta or beta to stable

Bug fixes, dependency updates, and test additions do not need a KEP.

## KEP lifecycle stages

`provisional` → `implementable` → `implemented` → `stable` → `deprecated`

A KEP must reach `implementable` (reviewed and approved) before any
implementation code is merged.

## Steps

### Creating a new KEP

1. **Find the next KEP number.**
   List `docs/enhancements/` and take the next integer after the highest
   `KEP-NNNN` prefix.

2. **Ask for KEP metadata.**
   Prompt the user for:
   - Title (short, imperative: "Add Keycloak Federation Provider")
   - Summary (one paragraph)
   - Motivation: what problem does this solve? Why now?
   - Does it change `api/v1alpha1/`? (triggers API review gate)
   - Does it change `spec/AIP-1.md`? (triggers wire spec review)
   - Does it change `pkg/budget/` or `pkg/delegation/`? (triggers formal
     verification)

3. **Create the KEP document.**
   Create `docs/enhancements/KEP-NNNN-<kebab-title>.md` with this structure:

   ```
   # KEP-NNNN: <Title>

   - Stage: provisional
   - Authors: <git user>
   - Created: <today>
   - Target version: <v0.x>

   ## Summary
   <one paragraph>

   ## Motivation
   <why this, why now>

   ## Design

   ### API changes
   <none / describe changes to api/v1alpha1/>

   ### Wire spec changes
   <none / describe AIP-1 changes>

   ### Formal model changes
   <none / describe TLA+/Tamarin impact>

   ### Implementation plan
   <ordered list of subtasks>

   ## Graduation criteria
   ### From provisional to implementable
   - [ ] Design reviewed and approved
   - [ ] API changes reviewed (if applicable)
   - [ ] Formal models updated (if applicable)

   ### From implementable to implemented
   - [ ] All subtasks complete
   - [ ] Acceptance scenarios pass
   - [ ] `/ship-check` passes

   ### From implemented to stable
   - [ ] Deployed to at least one real environment
   - [ ] No regressions in adversarial test suite

   ## Alternatives considered
   <what else was evaluated and why rejected>
   ```

4. **Update the KEP index.**
   If `docs/enhancements/README.md` exists, add a row to the table. If it does
   not exist, create it with a table containing the new KEP.

5. **Gate on API review if needed.**
   If the KEP changes `api/v1alpha1/`, remind the user that the API must be
   reviewed against Kubernetes API conventions before the KEP moves to
   `implementable`:
   - Field names use camelCase in Go, snake_case in YAML
   - New fields must have `omitempty`
   - Status sub-resource is separate from spec
   - No required fields added to existing types without a version bump

### Advancing a KEP stage

If the user runs `/kep` and names an existing KEP:
1. Read the KEP document.
2. Check which graduation criteria are satisfied (read linked code/tests).
3. Report which criteria remain unmet.
4. If all criteria for the next stage are met, update the `Stage:` field and
   note the date.
