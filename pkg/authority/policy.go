// Package authority derives grants from AgentPolicy.
//
// Split by design:
//   - perRequest → stateless predicates evaluated by Cedar
//   - budget     → stateful accumulators owned by pkg/budget
//
// A WSO2 scope is an INPUT to policy derivation, never a grant by itself.
// Both the scope AND a matching AgentPolicy rule are required (§8.3, requiredScopes).
package authority

import (
	"context"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/identity/wso2"
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
	Principal    *wso2.Principal
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
	Resource   string // resource type
	Audience   string
	Payload    map[string]any // parsed request body fields
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
	Derive(ctx context.Context, a *v1alpha1.Agent, pr *wso2.Principal, req ExecutionRequest) (Grant, error)

	// EvaluateRequest evaluates the stateless per-request predicates (Cedar).
	// Called on the data-plane request path; must be deterministic and fast.
	EvaluateRequest(ctx context.Context, g Grant, r CanonicalRequest) (Verdict, error)
}
