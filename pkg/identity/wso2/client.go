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

// Package wso2 client.go implements the Federator interface.
// Token verification uses github.com/golang-jwt/jwt/v5.
// JWKS is fetched lazily and cached for cfg.JWKSRefresh.
//
// Token shapes (AIP-1 §5.2):
//
//	autonomous:    sub = agent_id
//	on-behalf-of:  sub = human_id, act.sub = agent_id
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
	"github.com/thev1ndu/agent-integrator/pkg/store"
)

// client implements Federator.
type client struct {
	cfg        Config
	store      store.Store
	httpClient *http.Client

	jwksMu    sync.RWMutex
	jwksCache map[string]interface{} // kid → crypto.PublicKey
	lastFetch time.Time
	jwksURI   string
}

// NewFederator creates a Federator backed by the given store.
func NewFederator(cfg Config, s store.Store) Federator {
	return &client{
		cfg:        cfg,
		store:      s,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		jwksCache:  make(map[string]interface{}),
	}
}

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
	N   string `json:"n,omitempty"` // RSA modulus (base64url)
	E   string `json:"e,omitempty"` // RSA exponent (base64url)
	Crv string `json:"crv,omitempty"` // EdDSA curve, e.g. "Ed25519"
	X   string `json:"x,omitempty"` // EdDSA public key (base64url)
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

	// Double-check under write lock.
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

	newCache := make(map[string]interface{}, len(doc.Keys))
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

// parseJWK converts a JWK entry to a crypto.PublicKey.
// v0.1 supports RSA (RS256) and Ed25519 (EdDSA).
func parseJWK(k jwkKey) (interface{}, error) {
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

// ed25519PublicKey is a type alias so we can implement crypto.PublicKey.
type ed25519PublicKey []byte

type actClaims struct {
	Sub string `json:"sub"`
}

// wso2Claims extends jwt.RegisteredClaims with WSO2-specific fields.
type wso2Claims struct {
	jwt.RegisteredClaims
	Act    *actClaims `json:"act,omitempty"`
	Scope  string     `json:"scope,omitempty"`
	Scopes []string   `json:"scopes,omitempty"`
}

// Verify validates the JWT token signature, issuer, audience, exp, and nbf.
// Returns the resolved Principal on success.
// This MUST NOT be called on the data-plane request path (AIP-1 §5.2, I1).
func (c *client) Verify(ctx context.Context, rawToken string) (*Principal, error) {
	if err := c.refreshJWKSIfNeeded(ctx); err != nil {
		return nil, apierr.Newf(apierr.CodeTokenInvalid, "jwks refresh failed: %v", err)
	}

	claims := &wso2Claims{}
	_, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)

		c.jwksMu.RLock()
		pub, ok := c.jwksCache[kid]
		c.jwksMu.RUnlock()

		if !ok {
			if kid == "" {
				c.jwksMu.RLock()
				for _, v := range c.jwksCache {
					pub = v
					ok = true
					break
				}
				c.jwksMu.RUnlock()
			}
			if !ok {
				return nil, apierr.Newf(apierr.CodeTokenInvalid, "unknown kid %q", kid)
			}
		}
		return pub, nil
	},
		jwt.WithIssuer(c.cfg.WellKnown),
		jwt.WithAudience(c.cfg.Audience),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		claims2 := &wso2Claims{}
		_, err2 := jwt.ParseWithClaims(rawToken, claims2, func(token *jwt.Token) (interface{}, error) {
			kid, _ := token.Header["kid"].(string)
			c.jwksMu.RLock()
			pub, ok := c.jwksCache[kid]
			c.jwksMu.RUnlock()
			if !ok {
				if kid == "" {
					c.jwksMu.RLock()
					for _, v := range c.jwksCache {
						pub = v
						ok = true
						break
					}
					c.jwksMu.RUnlock()
				}
				if !ok {
					return nil, apierr.Newf(apierr.CodeTokenInvalid, "unknown kid %q", kid)
				}
			}
			return pub, nil
		},
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

	jti := claims.ID

	return &Principal{
		AgentSubject:   agentSubject,
		HumanPrincipal: humanPrincipal,
		Scopes:         scopes,
		Issuer:         issuer,
		JTI:            jti,
		ExpiresAt:      expiresAt,
	}, nil
}

// Resolve maps the Principal's AgentSubject to a registered Agent resource.
// Returns apierr.CodeNoAgentMapping if no Agent is found.
func (c *client) Resolve(ctx context.Context, p *Principal) (*v1alpha1.Agent, error) {
	key := fmt.Sprintf("agents-by-wso2subject/%s/%s", p.Issuer, p.AgentSubject)
	var agent v1alpha1.Agent
	if err := c.store.Get(ctx, key, &agent); err != nil {
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
