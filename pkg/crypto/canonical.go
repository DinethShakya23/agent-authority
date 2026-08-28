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

package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const SpecVersion = "AIP-1/v0.1"

type CanonicalRequest struct {
	Spec        string
	ExecutionID string
	PassportID  string
	Method      string
	Audience    string
	Path        string
	Timestamp   string
	Nonce       string
	PayloadHash string
}

func lp(s string) string {
	b := []byte(s)
	return fmt.Sprintf("%d:%s", len(b), s)
}

func Canonical(r CanonicalRequest) []byte {
	fields := []string{
		r.Spec,
		lp(r.ExecutionID),
		lp(r.PassportID),
		lp(r.Method),
		lp(r.Audience),
		lp(r.Path),
		lp(r.Timestamp),
		lp(r.Nonce),
		lp(r.PayloadHash),
	}
	return []byte(strings.Join(fields, "\n"))
}

func PayloadSHA256Hex(body []byte) string {
	if body == nil {
		body = []byte{}
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type Canonicalizer interface {
	Canonical(r CanonicalRequest) ([]byte, error)
}

type Signer interface {
	Sign(msg []byte) ([]byte, error)
	PublicKey() crypto.PublicKey
}

type SigVerifier interface {
	Verify(pub crypto.PublicKey, msg, sig []byte) error
}

type Ed25519Verifier struct{}

func (Ed25519Verifier) Verify(pub crypto.PublicKey, msg, sig []byte) error {
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("crypto: expected ed25519.PublicKey, got %T", pub)
	}
	if !ed25519.Verify(edPub, msg, sig) {
		return fmt.Errorf("crypto: Ed25519 signature verification failed")
	}
	return nil
}

type Ed25519Signer struct {
	priv ed25519.PrivateKey
}

func NewEd25519Signer(priv ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{priv: priv}
}

func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) {
	sig := ed25519.Sign(s.priv, msg)
	return sig, nil
}

func (s *Ed25519Signer) PublicKey() crypto.PublicKey {
	return s.priv.Public()
}
