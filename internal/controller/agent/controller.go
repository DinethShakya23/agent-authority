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

package agent

import (
	"context"
	"encoding/json"
	"log"

	v1alpha1 "github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

type Controller struct {
	store store.Store
}

func New(s store.Store) *Controller {
	return &Controller{store: s}
}

func (c *Controller) Run(ctx context.Context) error {
	ch, err := c.store.Watch(ctx, "agents/")
	if err != nil {
		return err
	}

	var agents []json.RawMessage
	if err := c.store.List(ctx, "agents/", &agents); err == nil {
		for _, raw := range agents {
			c.reconcile(ctx, raw)
		}
	}

	for ev := range ch {
		if ev.Type == store.EventDeleted {
			continue
		}
		c.reconcile(ctx, ev.Object)
	}
	return nil
}

func (c *Controller) reconcile(ctx context.Context, raw []byte) {
	var agent v1alpha1.Agent
	if err := json.Unmarshal(raw, &agent); err != nil {
		log.Printf("agent controller: unmarshal: %v", err)
		return
	}

	desired := c.desiredStatus(agent)
	if agent.Status.Phase == desired.Phase &&
		agent.Status.IdentityResolved == desired.IdentityResolved {
		return
	}

	agent.Status.Phase = desired.Phase
	agent.Status.IdentityResolved = desired.IdentityResolved
	if agent.Status.Epoch == 0 {
		agent.Status.Epoch = 1
	}

	key := "agents/" + agent.Namespace + "/" + agent.Name
	if err := c.store.Put(ctx, key, agent); err != nil {
		log.Printf("agent controller: put %s: %v", key, err)
	}
}

func (c *Controller) desiredStatus(agent v1alpha1.Agent) v1alpha1.AgentStatus {
	if agent.Spec.Identity.Provider == "" ||
		agent.Spec.Identity.Issuer == "" ||
		agent.Spec.Identity.Subject == "" {
		return v1alpha1.AgentStatus{
			Phase:            v1alpha1.AgentPhaseInvalid,
			IdentityResolved: false,
		}
	}
	return v1alpha1.AgentStatus{
		Phase:            v1alpha1.AgentPhaseReady,
		IdentityResolved: true,
	}
}
