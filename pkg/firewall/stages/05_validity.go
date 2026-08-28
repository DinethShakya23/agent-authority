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

package stages

import (
	"context"
	"fmt"
	"time"

	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/firewall"
	"github.com/DinethShakya23/agent-authority/pkg/integration"
)

const maxClockSkew = 2 * time.Second

type Validity struct{}

func NewValidity() *Validity { return &Validity{} }

func (Validity) Name() string { return "05_validity" }

func (Validity) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}

	v := s.Passport.Spec.Validity
	now := time.Now().UTC()

	if !v.NotBefore.IsZero() {
		if now.Add(maxClockSkew).Before(v.NotBefore) {
			s.ReasonCode = string(apierr.CodePassportNotYet)
			s.ReasonMsg = fmt.Sprintf("passport not yet valid: notBefore=%s now=%s",
				v.NotBefore.Format(time.RFC3339), now.Format(time.RFC3339))
			return firewall.Deny, nil
		}
	}

	if !v.ExpiresAt.IsZero() {
		if now.After(v.ExpiresAt.Add(maxClockSkew)) {
			s.ReasonCode = string(apierr.CodePassportExpired)
			s.ReasonMsg = fmt.Sprintf("passport expired: expiresAt=%s now=%s",
				v.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
			return firewall.Deny, nil
		}
	}

	return firewall.Continue, nil
}
