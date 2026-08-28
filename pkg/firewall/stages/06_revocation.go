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

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/firewall"
	"github.com/DinethShakya23/agent-authority/pkg/integration"
)

type RevocationChecker interface {
	IsRevoked(ctx context.Context, passportID string) (bool, error)
	CurrentEpoch(ctx context.Context, agentID string) (uint64, error)
}

type Revocation struct {
	checker RevocationChecker
}

func NewRevocation(checker RevocationChecker) *Revocation {
	return &Revocation{checker: checker}
}

func (Revocation) Name() string { return "06_revocation" }

func (r Revocation) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}

	passportID := s.Passport.Spec.PassportID
	agentID := s.Passport.Spec.Agent.ID

	revoked, err := r.checker.IsRevoked(ctx, passportID)
	if err != nil {
		s.ReasonCode = string(apierr.CodeCacheUnavailable)
		s.ReasonMsg = fmt.Sprintf("revocation check failed: %v", err)
		return firewall.Deny, nil
	}
	if revoked {
		s.ReasonCode = string(apierr.CodePassportRevoked)
		s.ReasonMsg = fmt.Sprintf("passport %s is revoked", passportID)
		return firewall.Deny, nil
	}

	if s.Passport.Status.Phase == v1alpha1.PassportPhaseRevoked {
		s.ReasonCode = string(apierr.CodePassportRevoked)
		s.ReasonMsg = fmt.Sprintf("passport %s phase is Revoked", passportID)
		return firewall.Deny, nil
	}

	currentEpoch, err := r.checker.CurrentEpoch(ctx, agentID)
	if err != nil {
		s.ReasonCode = string(apierr.CodeCacheUnavailable)
		s.ReasonMsg = fmt.Sprintf("epoch check failed: %v", err)
		return firewall.Deny, nil
	}
	if s.Passport.Spec.Epoch < currentEpoch {
		s.ReasonCode = string(apierr.CodePassportEpochStale)
		s.ReasonMsg = fmt.Sprintf("passport epoch %d < current epoch %d for agent %s",
			s.Passport.Spec.Epoch, currentEpoch, agentID)
		return firewall.Deny, nil
	}

	return firewall.Continue, nil
}
