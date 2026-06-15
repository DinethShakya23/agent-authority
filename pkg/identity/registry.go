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
	"fmt"
	"sort"
	"sync"

	"github.com/thev1ndu/agent-integrator/pkg/store"
)

type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

var DefaultRegistry = &Registry{factories: make(map[string]Factory)}

func (r *Registry) Register(providerType string, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[providerType]; exists {
		panic(fmt.Sprintf("identity: provider %q already registered", providerType))
	}
	r.factories[providerType] = f
}

func (r *Registry) Build(cfg ProviderConfig, s store.Store) (Federator, error) {
	r.mu.RLock()
	f, ok := r.factories[cfg.Type]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("identity: unknown provider type %q (registered: %v)",
			cfg.Type, r.knownTypes())
	}
	return f(cfg, s)
}

func (r *Registry) knownTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.factories))
	for t := range r.factories {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}
