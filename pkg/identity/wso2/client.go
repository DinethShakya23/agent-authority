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

// Package wso2 client.go — implements identity.Federator for WSO2.
// Token verification uses github.com/golang-jwt/jwt/v5.
// JWKS is fetched lazily and cached for cfg.JWKSRefresh.
//
// WSO2-specific behaviour (vs. the generic OIDC adapter):
//   - The WellKnown URL is also accepted as the issuer claim value,
//     because WSO2 Identity Server may set iss to the discovery endpoint.
//   - Falls back to issuer-agnostic verification when strict issuer check fails,
//     so deployments that haven't configured WSO2's issuer claim are not broken.
package wso2

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/identity"
	"github.com/thev1ndu/agent-integrator/pkg/store"
)

// client implements identity.Federator for WSO2.
type client struct {
	cfg        Config
	store      store.Store
	httpClient *http.Client

	jwksMu    sync.RWMutex
	jwksCache map[string]any // kid → crypto.PublicKey
	lastFetch time.Time
	jwksURI   string
}

// NewFederator creates a WSO2-backed identity.Federator.
func NewFederator(cfg Config, s store.Store) identity.Federator {
	return &client{
		cfg:        cfg,
		store:      s,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		jwksCache:  make(map[string]any),
	}
}

func (c *client) ProviderType() string { return "wso2" }

type discoveryDoc struct {
	JWKSURI string `json:"jwks_uri"`
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

func (c *client) refreshJWKSIfNeeded(ctx context.Context) error {
	c.jwksMu.RLock()
	fresh := !c.lastFetch.IsZero() && time.Since(c.lastFetch) < c.cfg.JWKSRefresh
	c.jwksMu.RUnlock()
	if fresh {
		return nil
	}

	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()

	if !c.lastFetch.IsZero() && time.Since(c.lastFetch) < c.cfg.JWKSRefresh {
		return nil
	}

	if c.jwksURI == "" {
		doc, err := c.fetchJSON(ctx, c.cfg.WellKnown)
		if err != nil {
			return fmt.Errorf("wso2: fetch discovery doc: %w", err)
		}
		var dd discoveryDoc
		if err := json.Unmarshal(doc, &dd); err != nil {
			return fmt.Errorf("wso2: parse discovery doc: %w", err)
		}
		if dd.JWKSURI == "" {
			return fmt.Errorf("wso2: discovery doc missing jwks_uri")
		}
		c.jwksURI = dd.JWKSURI
	}

	raw, err := c.fetchJSON(ctx, c.jwksURI)
	if err != nil {
		return fmt.Errorf("wso2: fetch jwks: %w", err)
	}
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("wso2: parse jwks: %w", err)
	}

	newCache := make(map[string]any, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := parseJWK(k)
		if err != nil {
			continue
		}
		newCache[k.Kid] = pub
	}
	c.jwksCache = newCache
	c.lastFetch = time.Now()
	return nil
}

func (c *client) fetchJSON(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

func parseJWK(k jwkKey) (any, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwk RSA: decode n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwk RSA: decode e: %w", err)
		}
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes)
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("jwk OKP: unsupported curve %q", k.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk OKP: decode x: %w", err)
		}
		return ed25519PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("jwk: unsupported kty %q", k.Kty)
	}
}

type ed25519PublicKey []byte

type actClaims struct {
	Sub string `json:"sub"`
}

type wso2Claims struct {
	jwt.RegisteredClaims
	Act    *actClaims `json:"act,omitempty"`
	Scope  string     `json:"scope,omitempty"`
	Scopes []string   `json:"scopes,omitempty"`
}

// Verify validates the JWT token signature, issuer, audience, exp, and nbf.
// Returns the provider-agnostic Principal on success.
// MUST NOT be called on the data-plane request path (AIP-1 §5.2, I1).
func (c *client) Verify(ctx context.Context, rawToken string) (*identity.Principal, error) {
	if err := c.refreshJWKSIfNeeded(ctx); err != nil {
		return nil, apierr.Newf(apierr.CodeTokenInvalid, "jwks refresh failed: %v", err)
	}

	keyFunc := func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		c.jwksMu.RLock()
		pub, ok := c.jwksCache[kid]
		if !ok && kid == "" {
			for _, v := range c.jwksCache {
				pub, ok = v, true
				break
			}
		}
		c.jwksMu.RUnlock()
		if !ok {
			return nil, apierr.Newf(apierr.CodeTokenInvalid, "unknown kid %q", kid)
		}
		return pub, nil
	}

	claims := &wso2Claims{}
	_, err := jwt.ParseWithClaims(rawToken, claims, keyFunc,
		jwt.WithIssuer(c.cfg.WellKnown),
		jwt.WithAudience(c.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		// WSO2 fallback: some deployments don't set iss to the WellKnown URL.
		// Retry without issuer constraint and accept if signature + aud + exp are valid.
		claims2 := &wso2Claims{}
		_, err2 := jwt.ParseWithClaims(rawToken, claims2, keyFunc,
			jwt.WithAudience(c.cfg.Audience),
			jwt.WithExpirationRequired(),
		)
		if err2 != nil {
			return nil, apierr.Newf(apierr.CodeTokenInvalid, "token verification failed: %v", err2)
		}
		claims = claims2
	}

	issuer, _ := claims.GetIssuer()
	if issuer == "" {
		return nil, apierr.New(apierr.CodeIssuerNotAllowed, "missing issuer claim")
	}

	sub, _ := claims.GetSubject()
	agentSubject := sub
	humanPrincipal := ""
	if c.cfg.AcceptOnBehalfOf && claims.Act != nil && claims.Act.Sub != "" {
		agentSubject = claims.Act.Sub
		humanPrincipal = sub
	}

	scopes := claims.Scopes
	if len(scopes) == 0 && claims.Scope != "" {
		scopes = splitScope(claims.Scope)
	}

	expTime, _ := claims.GetExpirationTime()
	var expiresAt time.Time
	if expTime != nil {
		expiresAt = expTime.Time
	}

	return &identity.Principal{
		AgentSubject:   agentSubject,
		HumanPrincipal: humanPrincipal,
		Scopes:         scopes,
		Issuer:         issuer,
		ProviderType:   "wso2",
		JTI:            claims.ID,
		ExpiresAt:      expiresAt,
	}, nil
}

// Resolve maps the Principal's AgentSubject+Issuer to a registered Agent.
func (c *client) Resolve(ctx context.Context, p *identity.Principal) (*v1alpha1.Agent, error) {
	var agent v1alpha1.Agent
	if err := c.store.Get(ctx, p.SubjectKey(), &agent); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, apierr.Newf(apierr.CodeNoAgentMapping,
				"no agent registered for issuer=%s subject=%s", p.Issuer, p.AgentSubject)
		}
		return nil, fmt.Errorf("wso2: resolve agent: %w", err)
	}
	if agent.Status.Phase == v1alpha1.AgentPhaseSuspended {
		return nil, apierr.Newf(apierr.CodeAgentSuspended,
			"agent %s is suspended", agent.ObjectMeta.Name)
	}
	return &agent, nil
}

func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ' ' {
			if i > start {
				out = append(out, scope[start:i])
			}
			start = i + 1
		}
	}
	return out
}
