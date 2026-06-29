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

package agentsdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const specVersion = "AIP-1/v0.1"

type Config struct {
	ControlPlane string
	Audience     string
	PrivateKey   ed25519.PrivateKey
	Certificate  *x509.Certificate
	PassportJWS  string
	PassportID   string
	ExecutionID  string
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewClient(cfg Config) *Client {
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{},
	}
}

func lp(s string) string {
	b := []byte(s)
	return fmt.Sprintf("%d:%s", len(b), s)
}

func payloadSHA256Hex(body []byte) string {
	if body == nil {
		body = []byte{}
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func buildCanonical(spec, executionID, passportID, method, audience, path, timestamp, nonce string, body []byte) []byte {
	payloadHash := payloadSHA256Hex(body)
	fields := []string{
		spec,
		lp(executionID),
		lp(passportID),
		lp(method),
		lp(audience),
		lp(path),
		lp(timestamp),
		lp(nonce),
		lp(payloadHash),
	}
	return []byte(strings.Join(fields, "\n"))
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (c *Client) Post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	nonce := generateNonce()

	_, signature, err := c.Sign("POST", path, timestamp, nonce, body)
	if err != nil {
		return nil, fmt.Errorf("agentsdk: sign: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.ControlPlane+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("agentsdk: new request: %w", err)
	}

	certB64 := ""
	if c.cfg.Certificate != nil {
		certB64 = base64.RawURLEncoding.EncodeToString(c.cfg.Certificate.Raw)
	}

	req.Header.Set("AI-Spec", specVersion)
	req.Header.Set("AI-Passport", c.cfg.PassportJWS)
	req.Header.Set("AI-Certificate", certB64)
	req.Header.Set("AI-Execution", c.cfg.ExecutionID)
	req.Header.Set("AI-Timestamp", timestamp)
	req.Header.Set("AI-Nonce", nonce)
	req.Header.Set("AI-Signature", base64.RawURLEncoding.EncodeToString(signature))

	return c.httpClient.Do(req)
}

func (c *Client) Sign(method, path, timestamp, nonce string, body []byte) (canonicalBytes []byte, signature []byte, err error) {
	canonical := buildCanonical(
		specVersion,
		c.cfg.ExecutionID,
		c.cfg.PassportID,
		method,
		c.cfg.Audience,
		path,
		timestamp,
		nonce,
		body,
	)
	sig := ed25519.Sign(c.cfg.PrivateKey, canonical)
	return canonical, sig, nil
}

func (c *Client) Verify(canonicalBytes, signature []byte) error {
	pub := c.cfg.PrivateKey.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, canonicalBytes, signature) {
		return fmt.Errorf("agentsdk: Ed25519 signature verification failed")
	}
	return nil
}
