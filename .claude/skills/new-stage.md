# /new-stage — Add a Firewall Pipeline Stage

Wizard for safely inserting a new stage into the 15-stage firewall pipeline at
`pkg/firewall/stages/`.

## Steps

1. **Ask for stage details.**
   Prompt the user for:
   - Stage name (e.g. `rate_limit`)
   - Proposed insertion position (which existing stage number it goes after)
   - Whether the stage mutates state (answer must be "no" for any stage other
     than stage 15; if yes, refuse and explain the constraint)

2. **Validate position.**
   Read the current stage files (`pkg/firewall/stages/`) and list them. If the
   user requests insertion before stage 15, confirm the new stage is read-only.
   If after stage 15, refuse — stage 15 must remain last.

3. **Determine the new stage number.**
   If inserting between existing stages, the new file gets the next available
   decimal slot. If appending before stage 15, shift stage 15 to the next
   number (e.g. new stage becomes `15_rate_limit.go`, old budget stage becomes
   `16_budget.go`).

4. **Draft the stage file.**
   Create `pkg/firewall/stages/NN_<name>.go` with:
   - Apache 2.0 LICENSE header (exact same block as existing stage files)
   - Package declaration `package stages`
   - A single exported function `StageNN<Name>(ctx context.Context, req *Request) Result`
   - No inline or multiline comments
   - `TODO` marker where the logic body goes (do not implement logic — that is
     the user's task)

5. **Register the stage in the pipeline.**
   Read `pkg/firewall/pipeline.go`. Find the stage slice. Insert the new stage
   function at the correct position. Write the file. Remove any comments
   introduced in the process.

6. **Add a skeleton adversarial test.**
   Create `test/adversarial/TNN_<name>_test.go` with a failing test stub so CI
   enforces coverage before the stage is considered complete.

7. **Print a checklist for the user.**
   - [ ] Implement stage logic in `pkg/firewall/stages/NN_<name>.go`
   - [ ] Fill in adversarial test `test/adversarial/TNN_<name>_test.go`
   - [ ] Confirm stage is read-only (or, if stage 15 replacement, confirm
         pre-deduction order)
   - [ ] Run `make test` and `make lint`
   - [ ] Run `/ship-check` before opening PR
