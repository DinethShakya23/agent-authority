# /scenario — Add an Acceptance Test Scenario

Wire up a new end-to-end acceptance scenario, numbered in sequence after the
existing 14 scenarios in `test/e2e/`.

## Steps

1. **Ask for scenario details.**
   Prompt the user for:
   - Scenario name (e.g. `budget_resume_after_epoch_bump`)
   - The happy path or failure condition being tested
   - Which firewall stage(s) or components are exercised
   - Expected outcome: ALLOW or DENY (and if DENY, the expected AI-xxxx code)

2. **Read `test/e2e/README.md`.**
   Find the current highest scenario number. The new scenario gets the next
   number.

3. **Scaffold the test file.**
   Create `test/e2e/scenario_NN_<name>_test.go` with:
   - Apache 2.0 LICENSE header
   - Package `e2e`
   - A single test function `TestScenarioNN<Name>` using Ginkgo
   - A `Describe`/`It` block skeleton with the scenario description
   - No inline or multiline comments

4. **Update `test/e2e/README.md`.**
   Add the new scenario to the table with number, name, and one-line
   description.

5. **Update the success bar in `_.md` and `README.md`.**
   Find the line `14/14 acceptance scenarios pass` and increment both numbers
   to reflect the new total.

6. **Checklist for the user.**
   - [ ] Implement scenario logic in `test/e2e/scenario_NN_<name>_test.go`
   - [ ] Run `make demo` to confirm N/N pass
   - [ ] Run `/ship-check` before opening PR
