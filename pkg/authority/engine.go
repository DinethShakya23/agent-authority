// Copyright 2026 Agent Authority Authors
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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/identity"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

type Engine struct {
	store    store.Store
	mu       sync.RWMutex
	compiled map[string]*compiledPolicy
}

func NewEngine(s store.Store) *Engine {
	return &Engine{
		store:    s,
		compiled: make(map[string]*compiledPolicy),
	}
}

func (e *Engine) Compile(p *v1alpha1.AgentPolicy) (CompiledPolicy, error) {
	raw, err := json.Marshal(p.Spec)
	if err != nil {
		return nil, fmt.Errorf("authority: marshal policy spec: %w", err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(raw))

	cp := &compiledPolicy{
		name:     p.Name,
		revision: p.Status.Revision,
		hash:     hash,
		rules:    p.Spec.Rules,
	}

	key := p.Namespace + "/" + p.Name
	e.mu.Lock()
	e.compiled[key] = cp
	e.mu.Unlock()

	return cp, nil
}

func (e *Engine) Derive(ctx context.Context, a *v1alpha1.Agent, pr *identity.Principal, req ExecutionRequest) (Grant, error) {
	policies, err := e.matchingPolicies(ctx, a)
	if err != nil {
		return Grant{}, err
	}

	if len(policies) == 0 {
		return Grant{}, apierr.Newf(apierr.CodeCapabilityDenied,
			"no AgentPolicy matches agent %s/%s", a.Namespace, a.Name)
	}

	for _, policy := range policies {
		if !scopesSatisfied(pr.Scopes, policy.Spec.RequiredScopes) {
			continue
		}

		grant, err := e.deriveGrant(a, pr, &policy, req)
		if err != nil {
			continue
		}
		return grant, nil
	}

	return Grant{}, apierr.New(apierr.CodeScopeMissing,
		"token scopes do not satisfy any matching AgentPolicy's requiredScopes")
}

func (e *Engine) EvaluateRequest(ctx context.Context, g Grant, r CanonicalRequest) (Verdict, error) {
	key := g.Policy.Namespace + "/" + g.Policy.Name
	e.mu.RLock()
	cp, ok := e.compiled[key]
	e.mu.RUnlock()

	if !ok {
		return Verdict{
			Allow:      false,
			ReasonCode: string(apierr.CodeConstraintFailed),
			Message:    "no compiled policy found for " + key,
		}, nil
	}

	return cp.Evaluate(g, r)
}

func (e *Engine) matchingPolicies(ctx context.Context, a *v1alpha1.Agent) ([]v1alpha1.AgentPolicy, error) {
	var allPolicies []v1alpha1.AgentPolicy
	if err := e.store.List(ctx, "policies/"+a.Namespace+"/", &allPolicies); err != nil {
		return nil, fmt.Errorf("authority: list policies: %w", err)
	}

	var matched []v1alpha1.AgentPolicy
	for _, p := range allPolicies {
		if selectorMatches(p.Spec.AgentSelector, a.Labels) {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

func (e *Engine) deriveGrant(a *v1alpha1.Agent, pr *identity.Principal, policy *v1alpha1.AgentPolicy, req ExecutionRequest) (Grant, error) {
	var matchedRules []v1alpha1.PolicyRule
	for _, rule := range policy.Spec.Rules {
		for _, cap := range req.Capabilities {
			if rule.Capability == cap || rule.Capability == "*" {
				matchedRules = append(matchedRules, rule)
				break
			}
		}
	}

	if len(matchedRules) == 0 {
		return Grant{}, apierr.Newf(apierr.CodeCapabilityDenied,
			"no rules in policy %s match requested capabilities", policy.Name)
	}

	grant := Grant{
		Agent:        a,
		Principal:    pr,
		Policy:       policy,
		PolicyRev:    policy.Status.Revision,
		Capabilities: req.Capabilities,
	}

	for _, rule := range matchedRules {
		for _, rs := range rule.Resources {
			grant.Resources = append(grant.Resources, rs)
		}
		if len(rule.PerRequest) > 0 {
			if grant.PerRequest == nil {
				grant.PerRequest = make(map[string]v1alpha1.PerRequestConstraint)
			}
			for k, v := range rule.PerRequest {
				grant.PerRequest[k] = v
			}
		}
		if rule.Budget.Amount.Value != "" {
			grant.Budget = rule.Budget
		}
		if rule.Validity.Duration != "" {
			grant.Validity = rule.Validity
		}
		grant.Delegation = rule.Delegation
	}

	return grant, nil
}

func selectorMatches(selector v1alpha1.LabelSelector, labels map[string]string) bool {
	if len(selector.MatchLabels) == 0 {
		return true
	}
	for k, v := range selector.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func scopesSatisfied(tokenScopes []string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	have := make(map[string]bool, len(tokenScopes))
	for _, s := range tokenScopes {
		have[s] = true
	}
	for _, r := range required {
		if !have[r] {
			return false
		}
	}
	return true
}

type compiledPolicy struct {
	name     string
	revision int
	hash     string
	rules    []v1alpha1.PolicyRule
}

func (cp *compiledPolicy) Hash() string { return cp.hash }

func (cp *compiledPolicy) Evaluate(g Grant, r CanonicalRequest) (Verdict, error) {
	constraints, ok := g.PerRequest[r.Capability]
	if !ok {
		return Verdict{Allow: true}, nil
	}

	if len(constraints.Allowed) > 0 {
		found := false
		for _, allowed := range constraints.Allowed {
			if allowed == r.Resource {
				found = true
				break
			}
		}
		if !found {
			return Verdict{
				Allow:      false,
				ReasonCode: string(apierr.CodeConstraintFailed),
				Message:    fmt.Sprintf("resource %q not in allowed set for capability %q", r.Resource, r.Capability),
			}, nil
		}
	}

	if constraints.Maximum != "" && r.Payload != nil {
		if amountVal, ok := r.Payload["amount"]; ok {
			if err := checkMaximum(amountVal, constraints.Maximum); err != nil {
				return Verdict{
					Allow:      false,
					ReasonCode: string(apierr.CodeConstraintFailed),
					Message:    err.Error(),
				}, nil
			}
		}
	}

	if constraints.Minimum != "" && r.Payload != nil {
		if amountVal, ok := r.Payload["amount"]; ok {
			if err := checkMinimum(amountVal, constraints.Minimum); err != nil {
				return Verdict{
					Allow:      false,
					ReasonCode: string(apierr.CodeConstraintFailed),
					Message:    err.Error(),
				}, nil
			}
		}
	}

	return Verdict{Allow: true}, nil
}

func checkMaximum(val any, max string) error {
	maxF, err := strconv.ParseFloat(max, 64)
	if err != nil {
		return fmt.Errorf("invalid maximum constraint %q: %w", max, err)
	}
	valF, err := toFloat64(val)
	if err != nil {
		return err
	}
	if valF > maxF {
		return fmt.Errorf("amount %.2f exceeds maximum %.2f", valF, maxF)
	}
	return nil
}

func checkMinimum(val any, min string) error {
	minF, err := strconv.ParseFloat(min, 64)
	if err != nil {
		return fmt.Errorf("invalid minimum constraint %q: %w", min, err)
	}
	valF, err := toFloat64(val)
	if err != nil {
		return err
	}
	if valF < minF {
		return fmt.Errorf("amount %.2f below minimum %.2f", valF, minF)
	}
	return nil
}

func toFloat64(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case string:
		return strconv.ParseFloat(n, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}
