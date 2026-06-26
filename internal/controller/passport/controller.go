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
	"encoding/json"
	"log"
	"time"

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
	ch, err := c.store.Watch(ctx, "passports/")
	if err != nil {
		return err
	}

	var passports []json.RawMessage
	if err := c.store.List(ctx, "passports/", &passports); err == nil {
		for _, raw := range passports {
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
	var pp v1alpha1.AgentPassport
	if err := json.Unmarshal(raw, &pp); err != nil {
		log.Printf("passport controller: unmarshal: %v", err)
		return
	}

	if pp.Status.Phase == v1alpha1.PassportPhaseRevoked ||
		pp.Status.Phase == v1alpha1.PassportPhaseExpired {
		return
	}

	now := time.Now().UTC()
	updated := false

	if !pp.Spec.Validity.ExpiresAt.IsZero() && now.After(pp.Spec.Validity.ExpiresAt) {
		pp.Status.Phase = v1alpha1.PassportPhaseExpired
		updated = true
	} else if (pp.Status.Phase == v1alpha1.PassportPhaseIssued) &&
		!pp.Spec.Validity.NotBefore.IsZero() &&
		!now.Before(pp.Spec.Validity.NotBefore) {
		pp.Status.Phase = v1alpha1.PassportPhaseActive
		updated = true
	}

	if !updated {
		return
	}

	ns := pp.Namespace
	if ns == "" {
		ns = "default"
	}
	key := "passports/" + ns + "/" + pp.Spec.PassportID
	if err := c.store.Put(ctx, key, pp); err != nil {
		log.Printf("passport controller: put %s: %v", key, err)
	}
}
