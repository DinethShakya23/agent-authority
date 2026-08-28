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

package epochbumper

import (
	"context"
	"errors"
	"fmt"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

type Bumper struct {
	store store.Store
}

func New(s store.Store) *Bumper {
	return &Bumper{store: s}
}

func (b *Bumper) BumpAgentEpoch(ctx context.Context, agentName, namespace string) error {
	key := fmt.Sprintf("agents/%s/%s", namespace, agentName)

	var agent v1alpha1.Agent
	if err := b.store.Get(ctx, key, &agent); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("epochbumper: get agent %s/%s: %w", namespace, agentName, err)
	}

	agent.Status.Epoch++

	if err := b.store.Put(ctx, key, agent); err != nil {
		return fmt.Errorf("epochbumper: put agent %s/%s: %w", namespace, agentName, err)
	}

	return nil
}
