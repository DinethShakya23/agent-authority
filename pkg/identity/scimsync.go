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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/store"
)

type SCIMSync interface {
	Sync(ctx context.Context) (added, updated, suspended int, err error)
}

type SCIM2Config struct {
	Enabled         bool
	Endpoint        string
	CredentialsRef  string
	SyncInterval    time.Duration
	RoleLabelPrefix string
}

type scimSync struct {
	providerType string
	issuer       string
	store        store.Store
	cfg          SCIM2Config
	httpClient   *http.Client
}

func NewSCIMSync(providerType, issuer string, cfg SCIM2Config, s store.Store) SCIMSync {
	return &scimSync{
		providerType: providerType,
		issuer:       issuer,
		store:        s,
		cfg:          cfg,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

type scimListResponse struct {
	TotalResults int        `json:"totalResults"`
	Resources    []scimUser `json:"Resources"`
}

type scimUser struct {
	ID       string     `json:"id"`
	UserName string     `json:"userName"`
	Active   bool       `json:"active"`
	Roles    []scimRole `json:"roles"`
}

type scimRole struct {
	Display string `json:"display"`
}

func (s *scimSync) Sync(ctx context.Context) (added, updated, suspended int, err error) {
	users, err := s.fetchUsers(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("scim2 fetch: %w", err)
	}

	for _, user := range users {
		a, u, su, syncErr := s.syncUser(ctx, user)
		if syncErr != nil {
			err = syncErr
			return
		}
		added += a
		updated += u
		suspended += su
	}
	return
}

func (s *scimSync) fetchUsers(ctx context.Context) ([]scimUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Endpoint+"/Users", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/scim+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scim2: HTTP %d from %s", resp.StatusCode, s.cfg.Endpoint)
	}

	var result scimListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("scim2: decode response: %w", err)
	}
	return result.Resources, nil
}

func (s *scimSync) syncUser(ctx context.Context, user scimUser) (added, updated, suspended int, err error) {
	agentKey := "agents/default/" + user.UserName
	subjectKey := fmt.Sprintf("agents-by-subject/%s/%s", s.issuer, user.UserName)

	var existing v1alpha1.Agent
	existsErr := s.store.Get(ctx, agentKey, &existing)
	exists := existsErr == nil

	if exists && existing.Spec.ManagedBy != s.providerType {
		return 0, 0, 0, nil
	}

	roles := make([]string, 0, len(user.Roles))
	for _, r := range user.Roles {
		roles = append(roles, r.Display)
	}

	if !user.Active && exists {
		if existing.Status.Phase != v1alpha1.AgentPhaseSuspended {
			existing.Status.Phase = v1alpha1.AgentPhaseSuspended
			if err := s.store.Put(ctx, agentKey, existing); err != nil {
				return 0, 0, 0, fmt.Errorf("scim2: suspend %s: %w", user.UserName, err)
			}
			return 0, 0, 1, nil
		}
		return 0, 0, 0, nil
	}

	if !user.Active {
		return 0, 0, 0, nil
	}

	now := time.Now().UTC()
	agent := v1alpha1.Agent{
		TypeMeta: v1alpha1.TypeMeta{
			APIVersion: "agentintegrator.dev/v1alpha1",
			Kind:       "Agent",
		},
		ObjectMeta: v1alpha1.ObjectMeta{
			Name:      user.UserName,
			Namespace: "default",
		},
		Spec: v1alpha1.AgentSpec{
			Identity: v1alpha1.AgentIdentity{
				Provider: s.providerType,
				Issuer:   s.issuer,
				Subject:  user.UserName,
			},
			ManagedBy: s.providerType,
		},
		Status: v1alpha1.AgentStatus{
			Phase:            v1alpha1.AgentPhaseReady,
			IdentityResolved: true,
			Epoch:            1,
			ProviderSync: v1alpha1.ProviderSyncStatus{
				LastSyncedAt: now,
				Roles:        roles,
			},
		},
	}

	if exists {
		agent.ObjectMeta.CreationTimestamp = existing.ObjectMeta.CreationTimestamp
		agent.Status.Epoch = existing.Status.Epoch
		agent.Status.ActivePassports = existing.Status.ActivePassports
	}

	if err := s.store.Put(ctx, agentKey, agent); err != nil {
		return 0, 0, 0, fmt.Errorf("scim2: put agent %s: %w", user.UserName, err)
	}

	if err := s.store.Put(ctx, subjectKey, agent); err != nil {
		return 0, 0, 0, fmt.Errorf("scim2: put subject mapping %s: %w", user.UserName, err)
	}

	if exists {
		return 0, 1, 0, nil
	}
	return 1, 0, 0, nil
}
