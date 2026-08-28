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
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/authority"
	"github.com/DinethShakya23/agent-authority/pkg/delegation"
	"github.com/DinethShakya23/agent-authority/pkg/passport"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

type Authority struct {
	store       store.Store
	signingKey  ed25519.PrivateKey
	signingCert *x509.Certificate
	ttl         time.Duration
}

func New(s store.Store, key ed25519.PrivateKey, cert *x509.Certificate, ttl time.Duration) *Authority {
	return &Authority{
		store:       s,
		signingKey:  key,
		signingCert: cert,
		ttl:         ttl,
	}
}

func newPassportID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("passportauth: generate id: %w", err)
	}
	return "pp-" + hex.EncodeToString(b), nil
}

func x5tS256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (a *Authority) passportKey(namespace, passportID string) string {
	return fmt.Sprintf("passports/%s/%s", namespace, passportID)
}

func (a *Authority) signAndStore(ctx context.Context, pp *v1alpha1.AgentPassport) (string, error) {
	specJSON, err := json.Marshal(pp.Spec)
	if err != nil {
		return "", fmt.Errorf("passportauth: marshal spec: %w", err)
	}

	type passportClaims struct {
		jwt.RegisteredClaims
		Spec json.RawMessage `json:"spec"`
	}

	claims := passportClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: pp.Spec.PassportID,
		},
		Spec: specJSON,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = pp.Spec.PassportID

	compact, err := token.SignedString(a.signingKey)
	if err != nil {
		return "", fmt.Errorf("passportauth: sign passport: %w", err)
	}

	pp.Status.Phase = v1alpha1.PassportPhaseIssued
	pp.Status.JWS = compact

	ns := pp.Namespace
	if ns == "" {
		ns = "default"
	}
	key := a.passportKey(ns, pp.Spec.PassportID)
	if err := a.store.Put(ctx, key, pp); err != nil {
		return "", fmt.Errorf("passportauth: store passport: %w", err)
	}

	return compact, nil
}

func (a *Authority) Issue(ctx context.Context, g authority.Grant, pub crypto.PublicKey, cert *x509.Certificate) (*v1alpha1.AgentPassport, string, error) {
	passportID, err := newPassportID()
	if err != nil {
		return nil, "", err
	}

	thumbprint := x5tS256(cert)

	now := time.Now().UTC()
	expiresAt := now.Add(a.ttl)

	agentName := ""
	agentNS := ""
	if g.Agent != nil {
		agentName = g.Agent.Name
		agentNS = g.Agent.Namespace
	}

	policyName := ""
	policyRev := 0
	if g.Policy != nil {
		policyName = g.Policy.Name
		policyRev = g.PolicyRev
	}

	pp := &v1alpha1.AgentPassport{
		TypeMeta: v1alpha1.TypeMeta{
			APIVersion: "agentauthority.dev/v1alpha1",
			Kind:       "AgentPassport",
		},
		ObjectMeta: v1alpha1.ObjectMeta{
			Name:      passportID,
			Namespace: agentNS,
		},
		Spec: v1alpha1.AgentPassportSpec{
			PassportID: passportID,
			Agent: v1alpha1.PassportAgent{
				ID:      agentName,
				Subject: g.ExecutionID,
			},
			Execution: v1alpha1.PassportExecution{
				ID: g.ExecutionID,
			},
			Audience: g.Audience,
			Authority: v1alpha1.PassportAuthority{
				Capabilities: g.Capabilities,
				Resources:    g.Resources,
				PerRequest:   g.PerRequest,
				Budget:       g.Budget,
			},
			Confirmation: v1alpha1.PassportConfirmation{
				X5tS256: thumbprint,
			},
			Delegation: v1alpha1.PassportDelegation{
				Depth: 0,
			},
			Policy: v1alpha1.PassportPolicy{
				Name:     policyName,
				Revision: policyRev,
			},
			Validity: v1alpha1.Validity{
				NotBefore: now,
				ExpiresAt: expiresAt,
			},
			Epoch: 0,
		},
	}

	compact, err := a.signAndStore(ctx, pp)
	if err != nil {
		return nil, "", err
	}

	return pp, compact, nil
}

const defaultMaxDelegationDepth = 8

func (a *Authority) Delegate(ctx context.Context, parentID string, proof passport.Signature, req passport.DelegationRequest) (*v1alpha1.AgentPassport, string, error) {
	var passports []v1alpha1.AgentPassport
	if err := a.store.List(ctx, "passports/", &passports); err != nil {
		return nil, "", fmt.Errorf("passportauth: list passports: %w", err)
	}

	passportIndex := make(map[string]*v1alpha1.AgentPassport, len(passports))
	for i := range passports {
		passportIndex[passports[i].Spec.PassportID] = &passports[i]
	}

	parent, ok := passportIndex[parentID]
	if !ok {
		return nil, "", fmt.Errorf("passportauth: parent passport %s not found", parentID)
	}

	if parent.Status.Phase == v1alpha1.PassportPhaseRevoked {
		return nil, "", apierr.Newf(apierr.CodeAncestorRevoked, "parent passport %s is revoked", parentID)
	}
	if parent.Status.Phase == v1alpha1.PassportPhaseExpired {
		return nil, "", fmt.Errorf("passportauth: parent passport %s is expired", parentID)
	}

	now := time.Now().UTC()
	if now.After(parent.Spec.Validity.ExpiresAt) {
		return nil, "", fmt.Errorf("passportauth: parent passport %s is expired", parentID)
	}

	cur := parent
	for cur.Spec.Delegation.Parent != "" {
		anc, exists := passportIndex[cur.Spec.Delegation.Parent]
		if !exists {
			return nil, "", apierr.Newf(apierr.CodeBrokenChain, "ancestor passport %s not found", cur.Spec.Delegation.Parent)
		}
		if anc.Status.Phase == v1alpha1.PassportPhaseRevoked {
			return nil, "", apierr.Newf(apierr.CodeAncestorRevoked, "ancestor passport %s is revoked", anc.Spec.PassportID)
		}
		cur = anc
	}

	maxDepth := defaultMaxDelegationDepth
	if req.MaxDepth > 0 {
		maxDepth = req.MaxDepth
	}
	childDepth := parent.Spec.Delegation.Depth + 1
	if childDepth > maxDepth {
		return nil, "", apierr.Newf(apierr.CodeDepthExceeded, "delegation depth %d exceeds maxDepth %d", childDepth, maxDepth)
	}

	passportID, err := newPassportID()
	if err != nil {
		return nil, "", err
	}

	expiresAt := parent.Spec.Validity.ExpiresAt
	if !req.Validity.ExpiresAt.IsZero() && req.Validity.ExpiresAt.Before(expiresAt) {
		expiresAt = req.Validity.ExpiresAt
	}

	parentChainHash := parent.Spec.Delegation.ChainHash
	if parentChainHash == "" {
		parentChainHash = delegation.RootChainHash(parent.Spec.PassportID)
	}
	chainHash := delegation.ComputeChainHash(parentChainHash, passportID)

	child := &v1alpha1.AgentPassport{
		TypeMeta:   parent.TypeMeta,
		ObjectMeta: v1alpha1.ObjectMeta{Name: passportID, Namespace: parent.Namespace},
		Spec: v1alpha1.AgentPassportSpec{
			PassportID: passportID,
			Agent:      parent.Spec.Agent,
			Execution:  parent.Spec.Execution,
			Audience:   req.Audience,
			Authority: v1alpha1.PassportAuthority{
				Capabilities: req.Capabilities,
				Resources:    req.Resources,
				PerRequest:   req.PerRequest,
				Budget:       req.Budget,
			},
			Confirmation: parent.Spec.Confirmation,
			Delegation: v1alpha1.PassportDelegation{
				Depth:     childDepth,
				Parent:    parentID,
				ChainHash: chainHash,
			},
			Policy: parent.Spec.Policy,
			Validity: v1alpha1.Validity{
				NotBefore: now,
				ExpiresAt: expiresAt,
			},
			Epoch: parent.Spec.Epoch,
		},
	}

	if err := delegation.CheckMonotonicity(parent, child); err != nil {
		return nil, "", err
	}

	compact, err := a.signAndStore(ctx, child)
	if err != nil {
		return nil, "", err
	}

	return child, compact, nil
}

func (a *Authority) Revoke(ctx context.Context, passportID, reason string) error {
	var passports []v1alpha1.AgentPassport
	if err := a.store.List(ctx, "passports/", &passports); err != nil {
		return fmt.Errorf("passportauth: list passports: %w", err)
	}

	for i := range passports {
		if passports[i].Spec.PassportID != passportID {
			continue
		}
		pp := passports[i]
		pp.Status.Phase = v1alpha1.PassportPhaseRevoked

		ns := pp.Namespace
		if ns == "" {
			ns = "default"
		}
		key := a.passportKey(ns, passportID)
		if err := a.store.Put(ctx, key, pp); err != nil {
			return fmt.Errorf("passportauth: revoke passport %s: %w", passportID, err)
		}
		return nil
	}

	return errors.New("passportauth: passport not found: " + passportID)
}
