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

package cache

import (
	"context"
	"encoding/json"
	"log"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

type Watcher struct {
	store store.Store
	cache *FirewallCache
}

func NewWatcher(s store.Store, c *FirewallCache) *Watcher {
	return &Watcher{store: s, cache: c}
}

func (w *Watcher) Run(ctx context.Context) error {
	if err := w.initialLoad(ctx); err != nil {
		log.Printf("cache watcher: initial load failed: %v", err)
	}

	passportEvents, err := w.store.Watch(ctx, "passports/")
	if err != nil {
		return err
	}

	agentEvents, err := w.store.Watch(ctx, "agents/")
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-passportEvents:
			if !ok {
				return nil
			}
			if ev.Type == store.EventDeleted {
				continue
			}
			var passport v1alpha1.AgentPassport
			if err := json.Unmarshal(ev.Object, &passport); err != nil {
				continue
			}
			if passport.Status.Phase == v1alpha1.PassportPhaseRevoked {
				w.cache.SetRevoked(passport.Spec.PassportID)
			}
			w.cache.MarkRefreshed()

		case ev, ok := <-agentEvents:
			if !ok {
				return nil
			}
			if ev.Type == store.EventDeleted {
				continue
			}
			var agent v1alpha1.Agent
			if err := json.Unmarshal(ev.Object, &agent); err != nil {
				continue
			}
			w.cache.SetEpoch(agent.ObjectMeta.Name, agent.Status.Epoch)
			w.cache.MarkRefreshed()
		}
	}
}

func (w *Watcher) initialLoad(ctx context.Context) error {
	var passports []v1alpha1.AgentPassport
	if err := w.store.List(ctx, "passports/", &passports); err != nil {
		return err
	}
	for _, p := range passports {
		if p.Status.Phase == v1alpha1.PassportPhaseRevoked {
			w.cache.SetRevoked(p.Spec.PassportID)
		}
	}

	var agents []v1alpha1.Agent
	if err := w.store.List(ctx, "agents/", &agents); err != nil {
		return err
	}
	for _, a := range agents {
		w.cache.SetEpoch(a.ObjectMeta.Name, a.Status.Epoch)
	}

	w.cache.MarkRefreshed()
	return nil
}
