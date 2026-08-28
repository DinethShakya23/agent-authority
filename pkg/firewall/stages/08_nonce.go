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

package stages

import (
	"context"
	"sync"
	"time"

	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/firewall"
	"github.com/DinethShakya23/agent-authority/pkg/integration"
)

const nonceWindow = 30 * time.Second

type nonceEntry struct {
	seenAt time.Time
}

type NonceCache struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
	window  time.Duration
}

func NewNonceCache(window time.Duration) *NonceCache {
	if window == 0 {
		window = nonceWindow
	}
	return &NonceCache{
		entries: make(map[string]nonceEntry),
		window:  window,
	}
}

func (nc *NonceCache) Seen(nonce string) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now()

	for k, e := range nc.entries {
		if now.Sub(e.seenAt) > nc.window {
			delete(nc.entries, k)
		}
	}

	if _, exists := nc.entries[nonce]; exists {
		return true
	}
	nc.entries[nonce] = nonceEntry{seenAt: now}
	return false
}

type NonceCacheIface interface {
	Seen(nonce string) bool
}

type Nonce struct {
	cache NonceCacheIface
}

func NewNonce(cache NonceCacheIface) *Nonce {
	return &Nonce{cache: cache}
}

func (Nonce) Name() string { return "08_nonce" }

func (n Nonce) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Nonce == "" {
		s.ReasonCode = string(apierr.CodeNonceReused)
		s.ReasonMsg = "nonce is empty (stage 1 must run first)"
		return firewall.Deny, nil
	}

	if n.cache.Seen(s.Nonce) {
		s.ReasonCode = string(apierr.CodeNonceReused)
		s.ReasonMsg = "nonce has already been used within the replay window"
		return firewall.Deny, nil
	}

	return firewall.Continue, nil
}
