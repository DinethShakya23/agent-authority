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

package authority

import (
	"context"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/identity"
)

type ExecutionRequest struct {
	Capabilities   []string
	IntegrationRef v1alpha1.ObjectRef
	BudgetHint     v1alpha1.BudgetLimit
}

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

type Verdict struct {
	Allow           bool
	RequireApproval bool
	ReasonCode      string
	Message         string
}

type CanonicalRequest struct {
	Capability string
	Resource   string
	Audience   string
	Payload    map[string]any
}

type CompiledPolicy interface {
	Evaluate(g Grant, r CanonicalRequest) (Verdict, error)
}

type PolicyEngine interface {
	Compile(p *v1alpha1.AgentPolicy) (CompiledPolicy, error)
	Derive(ctx context.Context, a *v1alpha1.Agent, pr *identity.Principal, req ExecutionRequest) (Grant, error)
	EvaluateRequest(ctx context.Context, g Grant, r CanonicalRequest) (Verdict, error)
}
