// Copyright 2026 Agent Integrator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package identity defines the provider-agnostic IdP federation interface.
// Individual adapters (wso2, oidc) implement Federator and self-register with
// DefaultRegistry via init().
//
// Selecting a provider:
//
//	fed, err := identity.DefaultRegistry.Build(identity.ProviderConfig{
//	    Type:      "oidc",   // or "wso2"
//	    WellKnown: "https://accounts.example.com/.well-known/openid-configuration",
//	    Audience:  "agent-integrator",
//	}, store)
package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/store"
)

// Principal is the provider-agnostic resolved identity after token verification.
// It carries everything downstream (passport issuance, receipt) needs to know
// about who is acting and on whose behalf.
type Principal struct {
	// AgentSubject is the acting agent's subject claim.
	// For autonomous tokens: equal to sub.
	// For OBO tokens (RFC 8693): equal to act.sub.
	AgentSubject string

	// HumanPrincipal is the delegating human's sub when the OBO flow is used.
	// Empty for autonomous (non-delegated) tokens.
	HumanPrincipal string

	// Scopes holds the granted OAuth/OIDC scopes.
	Scopes []string

	// Issuer is the iss claim value, used as part of the store lookup key.
	Issuer string

	// ProviderType is the short identifier of the adapter that produced this
	// principal (e.g. "wso2", "oidc"). Used for logging and metrics.
	ProviderType string

	// JTI is the JWT ID (jti claim), used for replay prevention at issuance.
	JTI string

	ExpiresAt time.Time
}

// SubjectKey returns the canonical store key for agent resolution.
//
// Format: agents-by-subject/{issuer}/{agentSubject}
//
// The issuer URL is globally unique across providers, so the provider type
// is not included in the key. This lets agents be looked up without knowing
// which IdP issued the token.
func (p *Principal) SubjectKey() string {
	return fmt.Sprintf("agents-by-subject/%s/%s", p.Issuer, p.AgentSubject)
}

// Federator verifies IdP tokens and resolves them to registered Agents.
//
// Implementations MUST NOT be called on the data-plane request path (AIP-1 I1).
// Token verification happens only at passport issuance time.
type Federator interface {
	// ProviderType returns the short identifier for this implementation
	// (e.g. "wso2", "oidc"). Used for logging, metrics, and diagnostics.
	ProviderType() string

	// Verify validates the raw bearer token (signature, issuer allow-list,
	// audience, exp/nbf) and returns the resolved Principal on success.
	Verify(ctx context.Context, rawToken string) (*Principal, error)

	// Resolve maps a Principal's AgentSubject+Issuer to a registered Agent.
	// Returns apierr.CodeNoAgentMapping when no Agent is found.
	Resolve(ctx context.Context, p *Principal) (*v1alpha1.Agent, error)
}

// ProviderConfig is the provider-agnostic configuration block used when
// instantiating a Federator via the Registry.
type ProviderConfig struct {
	// Type selects the adapter: "wso2", "oidc".
	Type string

	// WellKnown is the OIDC discovery endpoint URL.
	// The adapter fetches jwks_uri (and optionally issuer) from this document.
	WellKnown string

	// Audience is the expected aud claim value (e.g. "agent-integrator").
	Audience string

	// JWKSRefresh controls how often the JWKS cache is refreshed.
	JWKSRefresh time.Duration

	// AcceptOnBehalfOf enables RFC 8693 act-claim processing (OBO delegation).
	AcceptOnBehalfOf bool

	// Extras holds provider-specific configuration not covered by the generic
	// fields above. Keys are defined by each adapter's package documentation.
	//
	// WSO2 extras: "organization" (string), "introspect" (bool),
	//              "introspect_credentials_ref" (string),
	//              "scim2" (wso2.SCIM2Config-compatible map).
	Extras map[string]any
}

// Factory creates a Federator from a ProviderConfig and a store.
// Each adapter package exposes one Factory and registers it with DefaultRegistry.
type Factory func(cfg ProviderConfig, s store.Store) (Federator, error)
