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

package passport

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/authority"
)

type DelegationRequest struct {
	Capabilities []string
	Audience     []string
	Resources    []v1alpha1.ResourceSelector
	PerRequest   map[string]v1alpha1.PerRequestConstraint
	Budget       v1alpha1.BudgetLimit
	Validity     v1alpha1.Validity
	MaxDepth     int
}

type Signature []byte

type Authority interface {
	Issue(ctx context.Context, g authority.Grant, pub crypto.PublicKey, cert *x509.Certificate) (*v1alpha1.AgentPassport, string, error)
	Delegate(ctx context.Context, parentID string, proof Signature, req DelegationRequest) (*v1alpha1.AgentPassport, string, error)
	Revoke(ctx context.Context, passportID, reason string) error
}

type Verifier interface {
	Verify(jws string, bundle *x509.CertPool) (*v1alpha1.AgentPassport, error)
}
