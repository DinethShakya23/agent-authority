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

package capability

import (
	"context"
	"encoding/json"
	"log"

	v1alpha1 "github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/store"
)

type Controller struct {
	store store.Store
}

func New(s store.Store) *Controller {
	return &Controller{store: s}
}

func (c *Controller) Run(ctx context.Context) error {
	ch, err := c.store.Watch(ctx, "capabilities/")
	if err != nil {
		return err
	}

	var caps []json.RawMessage
	if err := c.store.List(ctx, "capabilities/", &caps); err == nil {
		for _, raw := range caps {
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
	var cap v1alpha1.Capability
	if err := json.Unmarshal(raw, &cap); err != nil {
		log.Printf("capability controller: unmarshal: %v", err)
		return
	}

	desired := c.desiredStatus(cap)
	if cap.Status.Phase == desired.Phase &&
		cap.Status.Validated == desired.Validated {
		return
	}

	cap.Status = desired

	key := "capabilities/" + cap.Name
	if err := c.store.Put(ctx, key, cap); err != nil {
		log.Printf("capability controller: put %s: %v", key, err)
	}
}

func (c *Controller) desiredStatus(cap v1alpha1.Capability) v1alpha1.CapabilityStatus {
	if cap.Spec.Name == "" || len(cap.Spec.ResourceTypes) == 0 {
		return v1alpha1.CapabilityStatus{
			Phase:     v1alpha1.CapabilityPhaseInvalid,
			Validated: false,
		}
	}
	return v1alpha1.CapabilityStatus{
		Phase:     v1alpha1.CapabilityPhaseReady,
		Validated: true,
	}
}
