package stages

import (
	"context"
	"sync"
	"time"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// nonceWindow is the replay window duration (§9.4 step 8).
// Must match the timestamp window so that an expired timestamp cannot be replayed.
const nonceWindow = 30 * time.Second

// nonceEntry holds when a nonce was first seen.
type nonceEntry struct {
	seenAt time.Time
}

// NonceCache is a thread-safe in-memory nonce cache with time-based eviction.
// It satisfies the NonceCacheIface for use in stage 8.
type NonceCache struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
	window  time.Duration
}

// NewNonceCache creates a NonceCache with the given replay window.
// Pass 0 to use the default nonceWindow (30s).
func NewNonceCache(window time.Duration) *NonceCache {
	if window == 0 {
		window = nonceWindow
	}
	return &NonceCache{
		entries: make(map[string]nonceEntry),
		window:  window,
	}
}

// Seen returns true if the nonce has already been seen within the window,
// and inserts it if not. It also evicts expired entries.
func (nc *NonceCache) Seen(nonce string) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	now := time.Now()

	// Evict expired entries.
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

// NonceCacheIface is the interface stage 8 uses to check/record nonces.
// Implementations must be safe for concurrent use.
type NonceCacheIface interface {
	// Seen returns true if the nonce was already seen within the replay window,
	// and records it if not. Must be called at most once per request nonce.
	Seen(nonce string) bool
}

// Nonce checks that the AI-Nonce has not been seen within the replay window
// and records it (step 8 of §9.4). This is the ONLY stage that writes to
// external state before stage 15, but the write is idempotent and in-memory.
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
