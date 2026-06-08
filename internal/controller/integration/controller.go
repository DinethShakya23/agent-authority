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

package integration

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	v1alpha1 "github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/store"
)

type Controller struct {
	store  store.Store
	client *http.Client
}

func New(s store.Store) *Controller {
	return &Controller{
		store: s,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *Controller) Run(ctx context.Context) error {
	ch, err := c.store.Watch(ctx, "integrations/")
	if err != nil {
		return err
	}

	var integrations []json.RawMessage
	if err := c.store.List(ctx, "integrations/", &integrations); err == nil {
		for _, raw := range integrations {
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
	var integ v1alpha1.Integration
	if err := json.Unmarshal(raw, &integ); err != nil {
		log.Printf("integration controller: unmarshal: %v", err)
		return
	}

	desired := c.desiredStatus(ctx, integ)
	if integ.Status.Phase == desired.Phase &&
		integ.Status.Reachable == desired.Reachable {
		return
	}

	integ.Status = desired

	key := "integrations/" + integ.Namespace + "/" + integ.Name
	if err := c.store.Put(ctx, key, integ); err != nil {
		log.Printf("integration controller: put %s: %v", key, err)
	}
}

func (c *Controller) desiredStatus(ctx context.Context, integ v1alpha1.Integration) v1alpha1.IntegrationStatus {
	if integ.Spec.Upstream.URL == "" {
		return v1alpha1.IntegrationStatus{
			Phase:     v1alpha1.IntegrationPhasePending,
			Reachable: false,
		}
	}

	reachable := c.probe(ctx, integ.Spec.Upstream.URL)
	phase := v1alpha1.IntegrationPhaseReady
	if !reachable {
		phase = v1alpha1.IntegrationPhaseUnknown
	}
	return v1alpha1.IntegrationStatus{
		Phase:     phase,
		Reachable: reachable,
	}
}

func (c *Controller) probe(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}
