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

package stages

import (
	"context"
	"fmt"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

type ConstraintEvaluator interface {
	Evaluate(
		ctx context.Context,
		policyName string,
		policyRevision int,
		constraints map[string]v1alpha1.PerRequestConstraint,
		reqCtx map[string]string,
	) error
}

type RequestContext interface {
	Extract(r interface{}) map[string]string
}

type Constraints struct {
	evaluator       ConstraintEvaluator
	reqCtxExtractor func(s *integration.State) map[string]string
}

func NewConstraints(evaluator ConstraintEvaluator) *Constraints {
	return &Constraints{evaluator: evaluator}
}

func (c *Constraints) WithContextExtractor(fn func(s *integration.State) map[string]string) *Constraints {
	c.reqCtxExtractor = fn
	return c
}

func (Constraints) Name() string { return "13_constraints" }

func (c Constraints) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}

	constraints := s.Passport.Spec.Authority.PerRequest
	if len(constraints) == 0 {
		return firewall.Continue, nil
	}

	if c.evaluator == nil {
		s.ReasonCode = string(apierr.CodeConstraintFailed)
		s.ReasonMsg = fmt.Sprintf("passport defines %d per-request constraint(s) but no Cedar evaluator is configured", len(constraints))
		return firewall.Deny, nil
	}

	policy := s.Passport.Spec.Policy
	reqCtx := map[string]string{}
	if c.reqCtxExtractor != nil {
		reqCtx = c.reqCtxExtractor(s)
	}

	if err := c.evaluator.Evaluate(ctx, policy.Name, policy.Revision, constraints, reqCtx); err != nil {
		if aerr, ok := err.(*apierr.Error); ok {
			s.ReasonCode = string(aerr.Code)
			s.ReasonMsg = aerr.Message
		} else {
			s.ReasonCode = string(apierr.CodeConstraintFailed)
			s.ReasonMsg = fmt.Sprintf("Cedar constraint evaluation failed: %v", err)
		}
		return firewall.Deny, nil
	}

	return firewall.Continue, nil
}
