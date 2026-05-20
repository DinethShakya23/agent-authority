package stages

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// Certificate parses the DER-encoded leaf certificate, verifies it chains to a
// trusted root, and checks validity period and key usage (step 2 of §9.4).
type Certificate struct {
	roots *x509.CertPool
}

func NewCertificate(roots *x509.CertPool) *Certificate {
	return &Certificate{roots: roots}
}

func (Certificate) Name() string { return "02_certificate" }

func (c Certificate) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if len(s.CertDER) == 0 {
		s.ReasonCode = string(apierr.CodeCertChainInvalid)
		s.ReasonMsg = "certificate DER is empty (stage 1 must run first)"
		return firewall.Deny, nil
	}

	cert, err := x509.ParseCertificate(s.CertDER)
	if err != nil {
		s.ReasonCode = string(apierr.CodeCertChainInvalid)
		s.ReasonMsg = fmt.Sprintf("certificate parse error: %v", err)
		return firewall.Deny, nil
	}

	// Check validity window.
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		s.ReasonCode = string(apierr.CodeCertExpired)
		s.ReasonMsg = fmt.Sprintf("certificate validity [%s, %s] does not cover now %s",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339))
		return firewall.Deny, nil
	}

	// Verify chain to trusted root.
	roots := c.roots
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			s.ReasonCode = string(apierr.CodeMisconfiguration)
			s.ReasonMsg = "cannot load system cert pool: " + err.Error()
			return firewall.Deny, nil
		}
	}
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		s.ReasonCode = string(apierr.CodeCertChainInvalid)
		s.ReasonMsg = "certificate chain verification failed: " + err.Error()
		return firewall.Deny, nil
	}

	s.Cert = cert
	return firewall.Continue, nil
}
