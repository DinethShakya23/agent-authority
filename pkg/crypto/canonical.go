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

// Package crypto implements AIP-1 canonicalisation and Ed25519 sign/verify.
//
// The firewall reconstructs the canonical string from what it received and
// NEVER trusts a client-supplied canonical string.
//
// Canonical string format (§9.2 of the AIP-1 spec):
// Length-prefixed fields, newline-separated. LP(s) = decimal byte length + ":" + UTF-8 bytes.
// Order: spec, execution_id, passport_id, method, audience, path, timestamp, nonce, payload_sha256_hex
package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// SpecVersion is the AIP-1 version string that appears as the first field.
const SpecVersion = "AIP-1/v0.1"

// CanonicalRequest holds the fields needed to build the AIP-1 canonical string.
type CanonicalRequest struct {
	Spec        string // always "AIP-1/v0.1"
	ExecutionID string
	PassportID  string
	Method      string // HTTP method, upper-case
	Audience    string // integration audience URI
	Path        string // request path (query params sorted by key then value)
	Timestamp   string // RFC 3339 UTC, millisecond precision
	Nonce       string // 128-bit random, base64url (22 chars)
	PayloadHash string // hex-encoded SHA-256 of exact request body bytes
}

func lp(s string) string {
	b := []byte(s)
	return fmt.Sprintf("%d:%s", len(b), s)
}

// Canonical builds the AIP-1 canonical string for signing.
// The firewall calls this independently from received headers — never from
// a client-supplied value.
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

// PayloadSHA256Hex returns the hex-encoded SHA-256 of body.
// Empty body → SHA-256 of the empty string (not nil-specific).
func PayloadSHA256Hex(body []byte) string {
	if body == nil {
		body = []byte{}
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Canonicalizer builds canonical strings.
type Canonicalizer interface {
	Canonical(r CanonicalRequest) ([]byte, error)
}

// Signer signs messages with an Ed25519 private key.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	PublicKey() crypto.PublicKey
}

// SigVerifier verifies Ed25519 signatures.
type SigVerifier interface {
	Verify(pub crypto.PublicKey, msg, sig []byte) error
}

// Ed25519Verifier implements SigVerifier using stdlib Ed25519.
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

// Ed25519Signer implements Signer using an in-memory private key.
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
