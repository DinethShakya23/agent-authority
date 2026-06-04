# /roadmap-sync — What's Next

Read the current roadmap and git state and surface the highest-priority
unstarted item with context on why and what it unblocks.

## Steps

1. **Read the roadmap.**
   Read `ROADMAP.md` and extract all items per version.

2. **Read the 14-week build plan.**
   Read the build plan section in `_.md` (section 25). Extract the week-by-week
   breakdown and identify the current week based on the first commit date in
   `git log`.

3. **Audit current completion.**
   For each v0.1 item, check whether it has a meaningful implementation:
   - `pkg/identity/wso2/` → WSO2 federation
   - `pkg/authority/` → Cedar policy
   - `pkg/passport/` → Passport authority
   - `pkg/budget/` → Budget leases
   - `pkg/firewall/stages/` → HTTP firewall (all 15 stages)
   - `pkg/delegation/` → Delegation
   - `pkg/receipt/` → Receipt chain
   - `cmd/agentctl/` and `sdk/go/` → agentctl + SDK
   - `test/e2e/` → 14 acceptance scenarios
   - `docs/` → Docs site

   For each, report: skeleton only / partial / complete.

4. **Identify the critical path item.**
   The item that is furthest behind schedule or that blocks the most other
   items is the priority. State it explicitly with a one-paragraph explanation
   of why it is the bottleneck.

5. **Print a status table and recommendation.**

   | v0.1 Item | Status | Blocks |
   |-----------|--------|--------|
   | WSO2 federation | ... | ... |
   | ... | ... | ... |

   Then: **Recommended next task:** `<item>` — `<one sentence why>`.
