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
	"crypto/sha256"
	"encoding/base64"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// Binding verifies that the SHA-256 thumbprint of the leaf certificate matches
// passport.confirmation.x5tS256 (step 4 of §9.4).
// This cryptographically binds the certificate to the passport.
type Binding struct{}

func NewBinding() *Binding { return &Binding{} }

func (Binding) Name() string { return "04_binding" }

func (Binding) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Cert == nil {
		s.ReasonCode = string(apierr.CodeCertChainInvalid)
		s.ReasonMsg = "cert not populated (stage 2 must run first)"
		return firewall.Deny, nil
	}
	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}

	sum := sha256.Sum256(s.Cert.Raw)
	computed := base64.RawURLEncoding.EncodeToString(sum[:])

	expected := s.Passport.Spec.Confirmation.X5tS256
	if computed != expected {
		s.ReasonCode = string(apierr.CodeCertThumbprint)
		s.ReasonMsg = "certificate thumbprint mismatch: passport x5tS256 does not match leaf cert"
		return firewall.Deny, nil
	}

	return firewall.Continue, nil
}
