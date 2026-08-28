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

package oidc

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
	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/identity"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

func init() {
	identity.DefaultRegistry.Register("oidc", Factory)
}

func Factory(cfg identity.ProviderConfig, s store.Store) (identity.Federator, error) {
	if cfg.WellKnown == "" {
		return nil, fmt.Errorf("oidc: ProviderConfig.WellKnown is required")
	}
	c := &client{
		cfg:        cfg,
		store:      s,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		jwksCache:  make(map[string]any),
	}
	return c, nil
}

type client struct {
	cfg        identity.ProviderConfig
	store      store.Store
	httpClient *http.Client

	mu        sync.RWMutex
	jwksCache map[string]any
	issuer    string
	jwksURI   string
	lastFetch time.Time
}

func (c *client) ProviderType() string { return "oidc" }

type oidcClaims struct {
	jwt.RegisteredClaims
	Act    *actClaims `json:"act,omitempty"`
	Scope  string     `json:"scope,omitempty"`
	Scopes []string   `json:"scopes,omitempty"`
}

type actClaims struct {
	Sub string `json:"sub"`
}

func (c *client) Verify(ctx context.Context, rawToken string) (*identity.Principal, error) {
	if err := c.refreshIfNeeded(ctx); err != nil {
		return nil, apierr.Newf(apierr.CodeTokenInvalid, "oidc: JWKS refresh failed: %v", err)
	}

	claims := &oidcClaims{}
	_, err := jwt.ParseWithClaims(rawToken, claims, c.keyFunc,
		jwt.WithIssuer(c.discoveredIssuer()),
		jwt.WithAudience(c.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil && c.issuerFallbackEnabled() {
		claims = &oidcClaims{}
		_, err = jwt.ParseWithClaims(rawToken, claims, c.keyFunc,
			jwt.WithAudience(c.cfg.Audience),
			jwt.WithExpirationRequired(),
		)
	}
	if err != nil {
		return nil, apierr.Newf(apierr.CodeTokenInvalid, "oidc: token verification failed: %v", err)
	}

	issuer, _ := claims.GetIssuer()
	if issuer == "" {
		return nil, apierr.New(apierr.CodeIssuerNotAllowed, "oidc: missing issuer claim")
	}

	sub, _ := claims.GetSubject()
	agentSubject := sub
	humanPrincipal := ""
	if c.cfg.AcceptOnBehalfOf && claims.Act != nil && claims.Act.Sub != "" {
		agentSubject = claims.Act.Sub
		humanPrincipal = sub
	}

	scopes := c.extractScopes(claims)

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
		ProviderType:   "oidc",
		JTI:            claims.ID,
		ExpiresAt:      expiresAt,
	}, nil
}

func (c *client) Resolve(ctx context.Context, p *identity.Principal) (*v1alpha1.Agent, error) {
	var agent v1alpha1.Agent
	if err := c.store.Get(ctx, p.SubjectKey(), &agent); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, apierr.Newf(apierr.CodeNoAgentMapping,
				"no agent registered for issuer=%s subject=%s", p.Issuer, p.AgentSubject)
		}
		return nil, fmt.Errorf("oidc: resolve agent: %w", err)
	}
	if agent.Status.Phase == v1alpha1.AgentPhaseSuspended {
		return nil, apierr.Newf(apierr.CodeAgentSuspended,
			"agent %s is suspended", agent.ObjectMeta.Name)
	}
	return &agent, nil
}

func (c *client) keyFunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)

	c.mu.RLock()
	pub, ok := c.jwksCache[kid]
	if !ok && kid == "" {
		for _, v := range c.jwksCache {
			pub, ok = v, true
			break
		}
	}
	c.mu.RUnlock()

	if !ok {
		return nil, apierr.Newf(apierr.CodeTokenInvalid, "oidc: unknown kid %q", kid)
	}
	return pub, nil
}

func (c *client) discoveredIssuer() string {
	if override, ok := c.cfg.Extras["issuer_override"].(string); ok && override != "" {
		return override
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.issuer
}

func (c *client) issuerFallbackEnabled() bool {
	v, _ := c.cfg.Extras["issuer_fallback"].(bool)
	return v
}

func (c *client) extractScopes(claims *oidcClaims) []string {
	if len(claims.Scopes) > 0 {
		return claims.Scopes
	}
	return splitScope(claims.Scope)
}

type discoveryDoc struct {
	Issuer  string `json:"issuer"`
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

func (c *client) refreshIfNeeded(ctx context.Context) error {
	c.mu.RLock()
	fresh := !c.lastFetch.IsZero() && time.Since(c.lastFetch) < c.cfg.JWKSRefresh
	c.mu.RUnlock()
	if fresh {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.lastFetch.IsZero() && time.Since(c.lastFetch) < c.cfg.JWKSRefresh {
		return nil
	}

	if c.jwksURI == "" {
		raw, err := c.fetchJSON(ctx, c.cfg.WellKnown)
		if err != nil {
			return fmt.Errorf("fetch discovery doc: %w", err)
		}
		var doc discoveryDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("parse discovery doc: %w", err)
		}
		if doc.JWKSURI == "" {
			return fmt.Errorf("discovery doc missing jwks_uri")
		}
		c.jwksURI = doc.JWKSURI
		if doc.Issuer != "" {
			c.issuer = doc.Issuer
		}
	}

	raw, err := c.fetchJSON(ctx, c.jwksURI)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
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
		n, readErr := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
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
		return ed25519Key(xBytes), nil
	default:
		return nil, fmt.Errorf("jwk: unsupported kty %q", k.Kty)
	}
}

type ed25519Key []byte

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
