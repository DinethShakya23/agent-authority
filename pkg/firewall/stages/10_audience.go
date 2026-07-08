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

type Audience struct{}

func NewAudience() *Audience { return &Audience{} }

func (Audience) Name() string { return "10_audience" }

func (Audience) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}
	if s.Integration == "" {
		s.ReasonCode = string(apierr.CodeMisconfiguration)
		s.ReasonMsg = "integration audience URI not configured"
		return firewall.Deny, nil
	}

	for _, aud := range s.Passport.Spec.Audience {
		if aud == s.Integration {
			return firewall.Continue, nil
		}
	}

	s.ReasonCode = string(apierr.CodeAudienceMismatch)
	s.ReasonMsg = "integration audience " + s.Integration + " not found in passport audience list"
	return firewall.Deny, nil
}
