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
	"github.com/thev1ndu/agent-integrator/pkg/delegation"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
	"github.com/thev1ndu/agent-integrator/pkg/passport"
)

// Delegation verifies the AI-Chain delegation chain for monotonic attenuation
// (step 14 of §9.4). If no AI-Chain header is present, the stage is a no-op.
//
// When a chain is present:
//  1. Each JWS in ChainJWSs is verified against the trust bundle.
//  2. The full chain (including the leaf passport) is passed to the ChainVerifier.
//  3. s.ChainPassports is populated with the parsed chain (excluding leaf).
type Delegation struct {
	verifier        passport.Verifier
	chainVerifier   delegation.ChainVerifier
	bundle          interface{ Subjects() []string }
	bundlePool      interface{}
	maxDepth        int
}

// NewDelegation creates a Delegation stage.
//   - passportVerifier verifies each JWS in the chain.
//   - chainVerifier checks monotonic attenuation.
//   - bundle is the x509 cert pool used for JWS verification.
//   - maxDepth is the maximum permitted delegation depth (from AgentPolicy).
func NewDelegation(
	passportVerifier passport.Verifier,
	chainVerifier delegation.ChainVerifier,
	maxDepth int,
) *Delegation {
	return &Delegation{
		verifier:      passportVerifier,
		chainVerifier: chainVerifier,
		maxDepth:      maxDepth,
	}
}

type delegationWithBundle struct {
	Delegation
	pool interface{ Subjects() []string }
}

func (Delegation) Name() string { return "14_delegation" }

func (d Delegation) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if len(s.ChainJWSs) == 0 {
		return firewall.Continue, nil
	}

	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}

	chain := make([]*v1alpha1.AgentPassport, 0, len(s.ChainJWSs))
	for i, jws := range s.ChainJWSs {
		p, err := d.verifier.Verify(jws, nil)
		if err != nil {
			s.ReasonCode = string(apierr.CodeBrokenChain)
			s.ReasonMsg = fmt.Sprintf("chain[%d] JWS verification failed: %v", i, err)
			return firewall.Deny, nil
		}
		chain = append(chain, p)
	}

	fullChain := make([]*v1alpha1.AgentPassport, 0, len(chain)+1)
	fullChain = append(fullChain, chain...)
	fullChain = append(fullChain, s.Passport)

	maxDepth := d.maxDepth
	if maxDepth == 0 {
		maxDepth = 8
	}
	if err := d.chainVerifier.Verify(fullChain, s.Passport, maxDepth); err != nil {
		if aerr, ok := err.(*apierr.Error); ok {
			s.ReasonCode = string(aerr.Code)
			s.ReasonMsg = aerr.Message
		} else {
			s.ReasonCode = string(apierr.CodeMonotonicity)
			s.ReasonMsg = fmt.Sprintf("delegation chain verification failed: %v", err)
		}
		return firewall.Deny, nil
	}

	s.ChainPassports = chain
	return firewall.Continue, nil
}
