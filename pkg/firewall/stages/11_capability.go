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

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

type CapabilityChecker interface {
	RequiredCapability(r interface {
		Method() string
		PathPattern() string
	}) string

	ResourceType(r interface {
		Method() string
		PathPattern() string
	}) string
}

type Capability struct {
	requiredCapability   string
	requiredResourceType string
}

func NewCapability(requiredCapability, requiredResourceType string) *Capability {
	return &Capability{
		requiredCapability:   requiredCapability,
		requiredResourceType: requiredResourceType,
	}
}

func (Capability) Name() string { return "11_capability" }

func (c Capability) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}

	auth := s.Passport.Spec.Authority

	if c.requiredCapability != "" {
		found := false
		for _, cap := range auth.Capabilities {
			if cap == c.requiredCapability {
				found = true
				break
			}
		}
		if !found {
			s.ReasonCode = string(apierr.CodeCapabilityDenied)
			s.ReasonMsg = "required capability " + c.requiredCapability + " not present in passport authority"
			return firewall.Deny, nil
		}
	}

	if c.requiredResourceType != "" {
		found := false
		for _, res := range auth.Resources {
			if res.Type == c.requiredResourceType {
				found = true
				break
			}
		}
		if !found {
			s.ReasonCode = string(apierr.CodeResourceDenied)
			s.ReasonMsg = "required resource type " + c.requiredResourceType + " not present in passport authority"
			return firewall.Deny, nil
		}
	}

	return firewall.Continue, nil
}
