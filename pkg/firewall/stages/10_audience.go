package stages

import (
	"context"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// Audience verifies that the passport audience list contains this integration's
// audience URI (step 10 of §9.4).
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
