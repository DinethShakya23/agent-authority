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

package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

type Principal struct {
	AgentSubject   string
	HumanPrincipal string
	Scopes         []string
	Issuer         string
	ProviderType   string
	JTI            string
	ExpiresAt      time.Time
}

func (p *Principal) SubjectKey() string {
	return fmt.Sprintf("agents-by-subject/%s/%s", p.Issuer, p.AgentSubject)
}

type Federator interface {
	ProviderType() string
	Verify(ctx context.Context, rawToken string) (*Principal, error)
	Resolve(ctx context.Context, p *Principal) (*v1alpha1.Agent, error)
}

type ProviderConfig struct {
	Type             string
	WellKnown        string
	Audience         string
	JWKSRefresh      time.Duration
	AcceptOnBehalfOf bool
	Extras           map[string]any
}

type Factory func(cfg ProviderConfig, s store.Store) (Federator, error)
