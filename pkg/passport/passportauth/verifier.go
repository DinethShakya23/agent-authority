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

package passportauth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
)

type JWSVerifier struct {
	publicKey ed25519.PublicKey
}

func NewVerifier(pub ed25519.PublicKey) *JWSVerifier {
	return &JWSVerifier{publicKey: pub}
}

type passportClaims struct {
	jwt.RegisteredClaims
	Spec json.RawMessage `json:"spec"`
}

func (v *JWSVerifier) Verify(jws string, bundle *x509.CertPool) (*v1alpha1.AgentPassport, error) {
	claims := &passportClaims{}
	_, err := jwt.ParseWithClaims(jws, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("passportauth: unexpected signing method: %v", token.Header["alg"])
		}
		return v.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("passportauth: parse jws: %w", err)
	}

	var spec v1alpha1.AgentPassportSpec
	if err := json.Unmarshal(claims.Spec, &spec); err != nil {
		return nil, fmt.Errorf("passportauth: unmarshal spec: %w", err)
	}

	now := time.Now().UTC()

	if now.Before(spec.Validity.NotBefore) {
		return nil, fmt.Errorf("passportauth: passport not yet valid")
	}
	if now.After(spec.Validity.ExpiresAt) {
		return nil, fmt.Errorf("passportauth: passport expired")
	}

	pp := &v1alpha1.AgentPassport{
		TypeMeta: v1alpha1.TypeMeta{
			APIVersion: "agentauthority.dev/v1alpha1",
			Kind:       "AgentPassport",
		},
		ObjectMeta: v1alpha1.ObjectMeta{
			Name: spec.PassportID,
		},
		Spec: spec,
	}

	return pp, nil
}
