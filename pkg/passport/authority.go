// Package passport mints, verifies, delegates and revokes Agent Passports.
//
// The agent's private key NEVER reaches this package.
// The control plane issues passports; the firewall verifies them.
package passport

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/authority"
)

// DelegationRequest describes what a child passport should contain.
type DelegationRequest struct {
	Capabilities []string
	Audience     []string
	Resources    []v1alpha1.ResourceSelector
	PerRequest   map[string]v1alpha1.PerRequestConstraint
	Budget       v1alpha1.BudgetLimit
	Validity     v1alpha1.Validity
	MaxDepth     int
}

// Signature is a raw Ed25519 signature (64 bytes).
type Signature []byte

// Authority mints and manages Agent Passports (control-plane side).
type Authority interface {
	// Issue mints a new passport for the given grant. The agent's public key
	// and certificate are bound via x5t#S256 (confirmation.x5tS256).
	// Returns the passport and its compact JWS representation.
	Issue(ctx context.Context, g authority.Grant, pub crypto.PublicKey, cert *x509.Certificate) (*v1alpha1.AgentPassport, string, error)

	// Delegate mints a child passport. The request must be signed by the parent
	// key using AIP-1 §9.2 canonical form. All 7 monotonicity rules are verified.
	// The child's budget is atomically deducted from the parent's remaining budget.
	Delegate(ctx context.Context, parentID string, proof Signature, req DelegationRequest) (*v1alpha1.AgentPassport, string, error)

	// Revoke marks the passport as revoked. All in-flight requests carrying it
	// will be denied at the next revocation check (stage 6).
	Revoke(ctx context.Context, passportID, reason string) error
}

// Verifier verifies passport JWSs against the trust bundle (firewall side).
type Verifier interface {
	// Verify parses and validates a compact JWS, checking the signature against
	// the trust bundle and returning the decoded passport.
	Verify(jws string, bundle *x509.CertPool) (*v1alpha1.AgentPassport, error)
}
