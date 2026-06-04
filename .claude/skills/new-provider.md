# /new-provider — Add an IdP Federation Provider

Wizard for implementing a new identity provider that satisfies the `Federator`
interface in `pkg/identity/`.

## Steps

1. **Ask for provider details.**
   Prompt the user for:
   - Provider name (e.g. `keycloak`, `okta`, `auth0`)
   - OIDC discovery URL (if known)
   - Whether the provider supports the `act` claim for on-behalf-of flows

2. **Read the existing `Federator` interface.**
   Read `pkg/identity/wso2/federator.go` to extract the current interface
   definition. Display it to the user so they can confirm the new provider must
   implement the same contract.

3. **Scaffold the package.**
   Create `pkg/identity/<name>/federator.go` with:
   - Apache 2.0 LICENSE header
   - Package declaration `package <name>`
   - A struct `Federator` with fields for the OIDC discovery URL and HTTP client
   - Method stubs for every method in the `Federator` interface, each returning
     `nil, errors.New("not implemented")`
   - No inline or multiline comments

4. **Scaffold SCIM sync if applicable.**
   If the provider supports SCIM2, create `pkg/identity/<name>/scimsync.go`
   with the same structure as `pkg/identity/wso2/scimsync.go` (stubbed).

5. **Wire the provider into the controller.**
   Read `internal/controller/wso2sync/` as a reference. Create a parallel
   `internal/controller/<name>sync/` directory with a stubbed controller.

6. **Checklist for the user.**
   - [ ] Implement `Federator` methods in `pkg/identity/<name>/federator.go`
   - [ ] Implement SCIM sync if applicable
   - [ ] Add config fields to `cmd/agentd/main.go` for the new provider
   - [ ] Add an integration test in `test/e2e/` covering autonomous + OBO flows
   - [ ] Confirm the `Federator` interface is unchanged (vendor-neutrality proof)
   - [ ] Run `/ship-check` before opening PR
