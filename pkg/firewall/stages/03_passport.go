package stages

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
	"github.com/thev1ndu/agent-integrator/pkg/passport"
)

// Passport verifies the AI-Passport JWS against the trust bundle and
// populates s.Passport (step 3 of §9.4).
type Passport struct {
	verifier passport.Verifier
	bundle   *x509.CertPool
}

func NewPassport(verifier passport.Verifier, bundle *x509.CertPool) *Passport {
	return &Passport{verifier: verifier, bundle: bundle}
}

func (Passport) Name() string { return "03_passport" }

func (p Passport) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.PassportJWS == "" {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport JWS is empty (stage 1 must run first)"
		return firewall.Deny, nil
	}

	agentPassport, err := p.verifier.Verify(s.PassportJWS, p.bundle)
	if err != nil {
		// Distinguish unknown kid from other parse/sig errors.
		if aerr, ok := err.(*apierr.Error); ok {
			s.ReasonCode = string(aerr.Code)
			s.ReasonMsg = aerr.Message
		} else {
			s.ReasonCode = string(apierr.CodePassportInvalid)
			s.ReasonMsg = fmt.Sprintf("passport JWS verification failed: %v", err)
		}
		return firewall.Deny, nil
	}

	s.Passport = agentPassport
	return firewall.Continue, nil
}
