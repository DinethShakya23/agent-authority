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

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/authority"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

type Controller struct {
	store  store.Store
	engine *authority.Engine
}

func New(s store.Store, engine *authority.Engine) *Controller {
	return &Controller{store: s, engine: engine}
}

func (c *Controller) Run(ctx context.Context) error {
	ch, err := c.store.Watch(ctx, "policies/")
	if err != nil {
		return err
	}

	var policies []json.RawMessage
	if err := c.store.List(ctx, "policies/", &policies); err == nil {
		for _, raw := range policies {
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
	var policy v1alpha1.AgentPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		log.Printf("policy controller: unmarshal: %v", err)
		return
	}

	specJSON, _ := json.Marshal(policy.Spec)
	hash := fmt.Sprintf("%x", sha256.Sum256(specJSON))

	if policy.Status.CedarPolicyHash == hash {
		return
	}

	if _, err := c.engine.Compile(&policy); err != nil {
		log.Printf("policy controller: compile %s: %v", policy.Name, err)
		return
	}

	policy.Status.Revision++
	policy.Status.CedarPolicyHash = hash

	key := "policies/" + policy.Namespace + "/" + policy.Name
	if err := c.store.Put(ctx, key, policy); err != nil {
		log.Printf("policy controller: put %s: %v", key, err)
	}
}
