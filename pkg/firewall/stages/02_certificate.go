// Copyright 2026 Agent Authority Authors
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
	"crypto/x509"
	"fmt"
	"time"

	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/firewall"
	"github.com/DinethShakya23/agent-authority/pkg/integration"
)

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

	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		s.ReasonCode = string(apierr.CodeCertExpired)
		s.ReasonMsg = fmt.Sprintf("certificate validity [%s, %s] does not cover now %s",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339))
		return firewall.Deny, nil
	}

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
