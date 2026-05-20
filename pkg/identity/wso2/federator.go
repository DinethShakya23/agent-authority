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

// Package wso2 federates identity from the WSO2 Identity Platform.
//
// Two token shapes are accepted:
//
//	autonomous:    sub = agent_id
//	on-behalf-of:  sub = human_id, act.sub = agent_id
//
// Resolution rule (normative per AIP-1 §5.2):
//
//	if token.act.sub exists:
//	    agentSubject   = token.act.sub   // the acting agent
//	    humanPrincipal = token.sub       // recorded in passport + every receipt
//	else:
//	    agentSubject   = token.sub
//	    humanPrincipal = ""
//
// Token verification happens ONLY at passport issuance, never per request (I1).
package wso2

import (
	"context"
	"time"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
)

// Principal is the resolved identity after token verification.
type Principal struct {
	AgentSubject   string    // act.sub if present, else sub
	HumanPrincipal string    // sub when act present, else ""
	Scopes         []string  // OAuth scopes from the token
	Issuer         string
	JTI            string    // JWT ID for replay prevention at issuance
	ExpiresAt      time.Time
}

// Federator verifies WSO2 tokens and resolves them to registered Agents.
type Federator interface {
	// Verify validates the token signature, issuer allow-list, audience, exp/nbf,
	// and optionally calls WSO2 introspection. Returns the resolved Principal.
	// This MUST NOT be called on the data-plane request path.
	Verify(ctx context.Context, rawToken string) (*Principal, error)

	// Resolve maps the Principal's AgentSubject to a registered Agent resource.
	// Returns apierr.CodeNoAgentMapping if no Agent is found.
	Resolve(ctx context.Context, p *Principal) (*v1alpha1.Agent, error)
}

// SCIMSync imports agents from WSO2's SCIM2 endpoint and materialises them
// as Agent resources in the local store. Synced agents carry ManagedBy="wso2".
type SCIMSync interface {
	// Sync performs one synchronisation pass.
	// Returns counts of agents added, updated, and suspended.
	Sync(ctx context.Context) (added, updated, suspended int, err error)
}

// Config holds WSO2 connection parameters (loaded from agentd.yaml §17).
type Config struct {
	BaseURL      string
	Organization string // /t/{org}
	WellKnown    string // OIDC discovery URL
	Audience     string // expected aud claim value, e.g. "agent-integrator"
	JWKSRefresh  time.Duration
	Introspect   bool
	IntrospectCredentialsRef string

	AcceptOnBehalfOf bool // honour the act claim

	SCIM2 SCIM2Config
}

// SCIM2Config holds settings for the optional agent roster sync.
type SCIM2Config struct {
	Enabled        bool
	Endpoint       string
	CredentialsRef string
	SyncInterval   time.Duration
	RoleLabelPrefix string // e.g. "wso2.role/"
}
