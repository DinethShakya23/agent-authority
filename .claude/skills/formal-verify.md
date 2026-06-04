# /formal-verify — Run Formal Verification and Interpret Results

Trigger the TLA+ model checker and Tamarin prover, then interpret the output in
plain language against the invariants.

## Steps

1. **Check tooling.**
   Run `which tlc` and `which tamarin-prover`. If either is missing, print
   installation instructions and stop.

2. **Run TLA+ model check.**
   Run `bash formal/check.sh` (or `make formal` if the Makefile target exists).
   Capture stdout and stderr.

3. **Interpret TLA+ results.**
   - If the model checker reports no violations: confirm invariant I4 (`S ≤ B`)
     holds under the checked state space.
   - If a counterexample is found: print the counterexample trace, identify
     which invariant it violates, and flag it as a blocker on `pkg/budget/`.

4. **Run Tamarin proofs.**
   Run `tamarin-prover formal/protocol.spthy --prove` (and
   `formal/delegation.spthy` if it exists). Capture output.

5. **Interpret Tamarin results.**
   For each lemma, report: proved / falsified / timeout. Falsified lemmas
   block merging to `main`.

6. **Print a summary.**

   | Model | Result | Notes |
   |-------|--------|-------|
   | budget.tla | ✅ verified / ❌ counterexample | ... |
   | protocol.spthy | ✅ all lemmas / ❌ N falsified | ... |
   | delegation.spthy | ✅ / ❌ / ⚠️ missing | ... |

   If all pass: safe to merge changes to `pkg/budget/` or `pkg/delegation/`.
   If any fail: do not merge — fix the implementation to match the model.
