package stages

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// Headers parses and validates the required AIP-1 HTTP headers.
type Headers struct{}

func NewHeaders() *Headers { return &Headers{} }

func (Headers) Name() string { return "01_headers" }

func (Headers) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	r := s.RawRequest
	spec := r.Header.Get("AI-Spec")
	if spec != "AIP-1/v0.1" {
		s.ReasonCode = string(apierr.CodeMisconfiguration)
		s.ReasonMsg = "unsupported or missing AI-Spec: " + spec
		return firewall.Deny, nil
	}
	s.Spec = spec

	s.PassportJWS = r.Header.Get("AI-Passport")
	if s.PassportJWS == "" {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "missing AI-Passport header"
		return firewall.Deny, nil
	}

	certB64 := r.Header.Get("AI-Certificate")
	if certB64 == "" {
		s.ReasonCode = string(apierr.CodeCertChainInvalid)
		s.ReasonMsg = "missing AI-Certificate header"
		return firewall.Deny, nil
	}
	certDER, err := base64.RawURLEncoding.DecodeString(certB64)
	if err != nil {
		s.ReasonCode = string(apierr.CodeCertChainInvalid)
		s.ReasonMsg = "AI-Certificate: invalid base64url"
		return firewall.Deny, nil
	}
	s.CertDER = certDER

	s.ExecutionID = r.Header.Get("AI-Execution")
	if s.ExecutionID == "" {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "missing AI-Execution header"
		return firewall.Deny, nil
	}

	s.Timestamp = r.Header.Get("AI-Timestamp")
	if s.Timestamp == "" {
		s.ReasonCode = string(apierr.CodeTimestampWindow)
		s.ReasonMsg = "missing AI-Timestamp header"
		return firewall.Deny, nil
	}

	s.Nonce = r.Header.Get("AI-Nonce")
	if s.Nonce == "" {
		s.ReasonCode = string(apierr.CodeNonceReused)
		s.ReasonMsg = "missing AI-Nonce header"
		return firewall.Deny, nil
	}

	sigB64 := r.Header.Get("AI-Signature")
	if sigB64 == "" {
		s.ReasonCode = string(apierr.CodeSigInvalid)
		s.ReasonMsg = "missing AI-Signature header"
		return firewall.Deny, nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		s.ReasonCode = string(apierr.CodeSigMalformed)
		s.ReasonMsg = "AI-Signature: invalid base64url"
		return firewall.Deny, nil
	}
	s.Signature = sig

	// Optional chain header: comma-separated base64url JWSs.
	if chain := r.Header.Get("AI-Chain"); chain != "" {
		for _, jws := range strings.Split(chain, ",") {
			s.ChainJWSs = append(s.ChainJWSs, strings.TrimSpace(jws))
		}
	}

	return firewall.Continue, nil
}
