// Copyright 2026 Agent Integrator Authors
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
	"crypto"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"

	aipcrypto "github.com/thev1ndu/agent-integrator/pkg/crypto"
)

type Signature struct {
	verifier aipcrypto.SigVerifier
}

func NewSignature(verifier aipcrypto.SigVerifier) *Signature {
	return &Signature{verifier: verifier}
}

func (Signature) Name() string { return "09_signature" }

func (sg Signature) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Cert == nil {
		s.ReasonCode = string(apierr.CodeSigInvalid)
		s.ReasonMsg = "certificate not populated (stage 2 must run first)"
		return firewall.Deny, nil
	}
	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodeSigInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}
	if len(s.Signature) == 0 {
		s.ReasonCode = string(apierr.CodeSigInvalid)
		s.ReasonMsg = "signature bytes empty (stage 1 must run first)"
		return firewall.Deny, nil
	}

	r := s.RawRequest

	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			s.ReasonCode = string(apierr.CodeSigInvalid)
			s.ReasonMsg = "failed to read request body: " + err.Error()
			return firewall.Deny, nil
		}
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	payloadHash := aipcrypto.PayloadSHA256Hex(bodyBytes)
	path := canonicalPath(r)

	canon := aipcrypto.Canonical(aipcrypto.CanonicalRequest{
		Spec:        s.Spec,
		ExecutionID: s.ExecutionID,
		PassportID:  s.Passport.Spec.PassportID,
		Method:      strings.ToUpper(r.Method),
		Audience:    s.Integration,
		Path:        path,
		Timestamp:   s.Timestamp,
		Nonce:       s.Nonce,
		PayloadHash: payloadHash,
	})

	pub := s.Cert.PublicKey
	verifier := sg.verifier
	if verifier == nil {
		verifier = aipcrypto.Ed25519Verifier{}
	}

	if err := verifier.Verify(pub.(crypto.PublicKey), canon, s.Signature); err != nil {
		s.ReasonCode = string(apierr.CodeSigInvalid)
		s.ReasonMsg = fmt.Sprintf("Ed25519 signature verification failed: %v", err)
		return firewall.Deny, nil
	}

	return firewall.Continue, nil
}

func canonicalPath(r *http.Request) string {
	path := r.URL.Path
	q := r.URL.Query()
	if len(q) == 0 {
		return path
	}

	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString(path)
	sb.WriteByte('?')
	first := true
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			if !first {
				sb.WriteByte('&')
			}
			sb.WriteString(k)
			sb.WriteByte('=')
			sb.WriteString(v)
			first = false
		}
	}
	return sb.String()
}
