package stages

import (
	"context"
	"fmt"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// RevocationChecker is the read-only interface used by stage 6 to look up
// whether a passport ID is revoked and what the current epoch is for an agent.
// Implementations must be non-blocking (cached local state, no network calls).
type RevocationChecker interface {
	// IsRevoked returns true if passportID has been revoked.
	IsRevoked(ctx context.Context, passportID string) (bool, error)
	// CurrentEpoch returns the current epoch for the given agent ID.
	// Used to enforce passport.epoch >= currentEpoch.
	CurrentEpoch(ctx context.Context, agentID string) (uint64, error)
}

// Revocation checks that the passport is not revoked and that its epoch is
// at least the current epoch for the agent (step 6 of §9.4).
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

	// Also check via phase field if populated.
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
