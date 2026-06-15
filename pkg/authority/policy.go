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

// Package authority derives grants from AgentPolicy.
//
// Split by design:
//   - perRequest → stateless predicates evaluated by Cedar
//   - budget     → stateful accumulators owned by pkg/budget
//
// An IdP scope is an INPUT to policy derivation, never a grant by itself.
// Both the scope AND a matching AgentPolicy rule are required (§8.3, requiredScopes).
package authority

import (
	"context"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/identity"
)

// ExecutionRequest is the agent's request to create an execution.
type ExecutionRequest struct {
	Capabilities []string
	IntegrationRef v1alpha1.ObjectRef
	BudgetHint   v1alpha1.BudgetLimit
}

// Grant is the derived authority for one execution.
// It is the output of PolicyEngine.Derive and the input to passport.Authority.Issue.
type Grant struct {
	ExecutionID  string
	Agent        *v1alpha1.Agent
	Principal    *identity.Principal
	Policy       *v1alpha1.AgentPolicy
	PolicyRev    int
	Capabilities []string
	Audience     []string
	Resources    []v1alpha1.ResourceSelector
	PerRequest   map[string]v1alpha1.PerRequestConstraint
	Budget       v1alpha1.BudgetLimit
	Validity     v1alpha1.Validity
	Delegation   v1alpha1.DelegationConfig
}

// Verdict is the per-request decision from EvaluateRequest.
type Verdict struct {
	Allow           bool
	RequireApproval bool
	ReasonCode      string // AI-xxxx; empty when Allow=true
	Message         string
}

// CanonicalRequest is the parsed and validated request payload presented to the policy engine.
type CanonicalRequest struct {
	Capability string
	Resource   string
	Audience   string
	Payload    map[string]any
}

// CompiledPolicy is a pre-compiled Cedar policy bundle for fast per-request evaluation.
type CompiledPolicy interface {
	Evaluate(g Grant, r CanonicalRequest) (Verdict, error)
}

// PolicyEngine derives grants and evaluates per-request predicates.
type PolicyEngine interface {
	// Compile pre-compiles the Cedar policy for fast per-request evaluation.
	Compile(p *v1alpha1.AgentPolicy) (CompiledPolicy, error)

	// Derive selects the matching AgentPolicy for the agent + principal,
	// validates required scopes, and returns the Grant.
	// Returns an error with AI-1105 if required scopes are missing.
	Derive(ctx context.Context, a *v1alpha1.Agent, pr *identity.Principal, req ExecutionRequest) (Grant, error)

	// EvaluateRequest evaluates the stateless per-request predicates (Cedar).
	// Called on the data-plane request path; must be deterministic and fast.
	EvaluateRequest(ctx context.Context, g Grant, r CanonicalRequest) (Verdict, error)
}
