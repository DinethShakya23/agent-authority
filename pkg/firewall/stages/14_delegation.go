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
	bundle          interface{ Subjects() []string } // *x509.CertPool — kept as crypto/x509.CertPool
	bundlePool      interface{}                      // holds *x509.CertPool for Verify calls
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

// delegationWithBundle holds a cert pool reference for JWS verification.
type delegationWithBundle struct {
	Delegation
	pool interface{ Subjects() []string } // actually *x509.CertPool
}

func (Delegation) Name() string { return "14_delegation" }

func (d Delegation) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	// No AI-Chain header: delegation check is a no-op.
	if len(s.ChainJWSs) == 0 {
		return firewall.Continue, nil
	}

	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}

	// Parse each JWS in the chain.
	chain := make([]*v1alpha1.AgentPassport, 0, len(s.ChainJWSs))
	for i, jws := range s.ChainJWSs {
		p, err := d.verifier.Verify(jws, nil) // nil bundle: verifier uses its own trust bundle
		if err != nil {
			s.ReasonCode = string(apierr.CodeBrokenChain)
			s.ReasonMsg = fmt.Sprintf("chain[%d] JWS verification failed: %v", i, err)
			return firewall.Deny, nil
		}
		chain = append(chain, p)
	}

	// Full chain = parsed chain passports + leaf passport.
	fullChain := make([]*v1alpha1.AgentPassport, 0, len(chain)+1)
	fullChain = append(fullChain, chain...)
	fullChain = append(fullChain, s.Passport)

	// Verify monotonic attenuation.
	maxDepth := d.maxDepth
	if maxDepth == 0 {
		maxDepth = 8 // default reasonable limit
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

	// Populate chain passports (excluding the leaf which is already in s.Passport).
	s.ChainPassports = chain
	return firewall.Continue, nil
}
