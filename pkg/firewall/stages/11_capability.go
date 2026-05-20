package stages

import (
	"context"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// CapabilityChecker looks up the resource type for an incoming request and
// checks whether a required capability grants access to that resource type.
// Implementations must be non-blocking (cached control-plane data).
type CapabilityChecker interface {
	// RequiredCapability returns the capability name required for this request.
	// Typically derived from the HTTP method + path pattern.
	RequiredCapability(r interface{ Method() string; PathPattern() string }) string

	// ResourceType returns the resource type for this request.
	ResourceType(r interface{ Method() string; PathPattern() string }) string
}

// Capability verifies that the passport authority grants the capability and
// resource type required for this request (step 11 of §9.4).
type Capability struct {
	// requiredCapability is the capability name that must be present in the passport.
	requiredCapability string
	// requiredResourceType is the resource type that must be listed in passport.authority.resources.
	// Empty means no resource type check.
	requiredResourceType string
}

// NewCapability creates a Capability stage configured with the required
// capability name and resource type for this integration endpoint.
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

	// Check capability presence.
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

	// Check resource type presence.
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
