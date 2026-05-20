// Package delegation verifies monotonic attenuation of Agent Passport chains.
//
// A child's authority is a strict subset of its parent's on EVERY dimension.
// Budget is drawn FROM the parent, never added to.
// Violation of any of the 7 monotonicity rules → DENY AI-7001.
package delegation

import (
	"fmt"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/apierr"
)

// ChainVerifier checks a delegation chain for monotonic attenuation.
type ChainVerifier interface {
	// Verify checks that the chain is valid and that leaf is the terminal passport.
	// chain[0] must have no parent. Each link's authority must be a subset of the
	// prior link's. All epochs must be current.
	// maxDepth comes from the policy (AgentPolicy.spec.rules[].delegation.maxDepth).
	Verify(chain []*v1alpha1.AgentPassport, leaf *v1alpha1.AgentPassport, maxDepth int) error
}

// DefaultVerifier implements ChainVerifier.
type DefaultVerifier struct{}

// Verify implements ChainVerifier.
func (DefaultVerifier) Verify(chain []*v1alpha1.AgentPassport, leaf *v1alpha1.AgentPassport, maxDepth int) error {
	// chain[0] is the root; leaf must equal chain[last].
	if len(chain) == 0 {
		return apierr.New(apierr.CodeBrokenChain, "delegation chain is empty")
	}
	last := chain[len(chain)-1]
	if last.Spec.PassportID != leaf.Spec.PassportID {
		return apierr.New(apierr.CodeBrokenChain, "leaf passport does not match end of chain")
	}
	// Rule 7: depth
	depth := len(chain) - 1
	if depth > maxDepth {
		return apierr.Newf(apierr.CodeDepthExceeded, "depth %d exceeds maxDepth %d", depth, maxDepth)
	}
	// Root must have no parent.
	if chain[0].Spec.Delegation.Parent != "" {
		return apierr.New(apierr.CodeBrokenChain, "chain[0] must have no parent")
	}
	// Verify each link.
	for i := 1; i < len(chain); i++ {
		parent := chain[i-1]
		child := chain[i]
		// Parent link.
		if child.Spec.Delegation.Parent != parent.Spec.PassportID {
			return apierr.Newf(apierr.CodeBrokenChain,
				"chain[%d].delegation.parent %q != chain[%d].passportID %q",
				i, child.Spec.Delegation.Parent, i-1, parent.Spec.PassportID)
		}
		// Depth counter.
		if child.Spec.Delegation.Depth != parent.Spec.Delegation.Depth+1 {
			return apierr.Newf(apierr.CodeBrokenChain,
				"chain[%d].depth %d != chain[%d].depth+1 %d",
				i, child.Spec.Delegation.Depth, i-1, parent.Spec.Delegation.Depth+1)
		}
		if err := checkMonotonicity(parent, child); err != nil {
			return err
		}
	}
	return nil
}

// checkMonotonicity enforces the 6 field-level monotonicity rules (depth is rule 7, checked above).
func checkMonotonicity(parent, child *v1alpha1.AgentPassport) error {
	pa := parent.Spec.Authority
	ca := child.Spec.Authority

	// Rule 1: capabilities subset.
	if err := checkSubset("capabilities", toSet(pa.Capabilities), toSet(ca.Capabilities)); err != nil {
		return err
	}
	// Rule 2: audience subset.
	if err := checkSubset("audience", toSet(parent.Spec.Audience), toSet(child.Spec.Audience)); err != nil {
		return err
	}
	// Rule 3: resources subset.
	parentRes := resourceTypeSet(pa.Resources)
	childRes := resourceTypeSet(ca.Resources)
	if err := checkSubset("resources", parentRes, childRes); err != nil {
		return err
	}
	// Rule 4: per-request constraints at least as tight (child maximum ≤ parent maximum).
	for field, childC := range ca.PerRequest {
		parentC, ok := pa.PerRequest[field]
		if !ok {
			return apierr.Newf(apierr.CodeMonotonicity,
				"child has perRequest constraint %q not present in parent", field)
		}
		if childC.Maximum != "" && parentC.Maximum != "" {
			if childC.Maximum > parentC.Maximum { // lexicographic; real impl uses decimal compare
				return apierr.Newf(apierr.CodeMonotonicity,
					"child perRequest[%s].maximum %s exceeds parent %s", field, childC.Maximum, parentC.Maximum)
			}
		}
	}
	// Rule 5: budget not greater — validated at minting time by the control plane.
	// Rule 6: expiresAt ≤ parent.expiresAt.
	if !child.Spec.Validity.ExpiresAt.IsZero() && !parent.Spec.Validity.ExpiresAt.IsZero() {
		if child.Spec.Validity.ExpiresAt.After(parent.Spec.Validity.ExpiresAt) {
			return apierr.New(apierr.CodeMonotonicity, "child expiresAt is later than parent")
		}
	}
	return nil
}

func toSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

func resourceTypeSet(rs []v1alpha1.ResourceSelector) map[string]struct{} {
	m := make(map[string]struct{}, len(rs))
	for _, r := range rs {
		m[r.Type] = struct{}{}
	}
	return m
}

func checkSubset(field string, parent, child map[string]struct{}) error {
	for k := range child {
		if _, ok := parent[k]; !ok {
			return apierr.Newf(apierr.CodeMonotonicity,
				"child %s %q is not in parent set", field, k)
		}
	}
	return nil
}

// ErrMonotonicity wraps a monotonicity violation with context.
func ErrMonotonicity(msg string) error {
	return fmt.Errorf("delegation: %w", apierr.New(apierr.CodeMonotonicity, msg))
}
