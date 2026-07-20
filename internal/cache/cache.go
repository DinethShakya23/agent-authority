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
	"sync"
	"time"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
)

type FirewallCache struct {
	mu               sync.RWMutex
	revokedPassports map[string]bool
	agentEpochs      map[string]uint64
	lastUpdated      time.Time
	maxStaleness     time.Duration
}

func New(maxStaleness time.Duration) *FirewallCache {
	return &FirewallCache{
		revokedPassports: make(map[string]bool),
		agentEpochs:      make(map[string]uint64),
		maxStaleness:     maxStaleness,
	}
}

func (c *FirewallCache) isStale() bool {
	if c.lastUpdated.IsZero() {
		return true
	}
	return time.Now().After(c.lastUpdated.Add(c.maxStaleness))
}

func (c *FirewallCache) IsRevoked(ctx context.Context, passportID string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.isStale() {
		return false, apierr.Newf(apierr.CodeCacheUnavailable, "firewall cache is stale")
	}

	return c.revokedPassports[passportID], nil
}

func (c *FirewallCache) CurrentEpoch(ctx context.Context, agentID string) (uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.isStale() {
		return 0, apierr.Newf(apierr.CodeCacheUnavailable, "firewall cache is stale")
	}

	epoch, ok := c.agentEpochs[agentID]
	if !ok {
		return 0, nil
	}
	return epoch, nil
}

func (c *FirewallCache) SetRevoked(passportID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revokedPassports[passportID] = true
}

func (c *FirewallCache) SetEpoch(agentID string, epoch uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agentEpochs[agentID] = epoch
}

func (c *FirewallCache) MarkRefreshed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastUpdated = time.Now()
}

