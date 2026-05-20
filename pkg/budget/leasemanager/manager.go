// Package leasemanager is the in-process, data-plane implementation of
// budget.LeaseManager. All operations are in-memory against the local Lease;
// no network calls are made. This is by design: the data-plane request path
// must not make synchronous control-plane calls (Invariant I1).
//
// Lifecycle per request:
//
//	Reserve → forward → Commit    (upstream success)
//	Reserve → forward → Release   (clean upstream failure)
//	Reserve → forward → Hold      (AMBIGUOUS timeout — never release)
//
// Ambiguous timeout → HOLD. Stranded budget is recoverable via lease expiry;
// overspend is not.
package leasemanager

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/budget"
)

type reservation struct {
	id     budget.ReservationID
	values budget.Meters
	held   bool // true = HOLD (ambiguous timeout) — never release
}

type manager struct {
	mu           sync.Mutex
	lease        *budget.Lease
	reservations map[budget.ReservationID]*reservation
	nextID       int64
}

// New creates a new LeaseManager seeded with the given Lease.
func New(l *budget.Lease) budget.LeaseManager {
	return &manager{
		lease:        l,
		reservations: make(map[budget.ReservationID]*reservation),
	}
}

// newID returns a unique ReservationID.
func (m *manager) newID() budget.ReservationID {
	n := atomic.AddInt64(&m.nextID, 1)
	return budget.ReservationID(fmt.Sprintf("rsv-%d", n))
}

// parseFloat parses a meter value string; empty → 0.
func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// formatFloat converts a float64 to a meter value string.
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// available computes Available[m] = Granted[m] - Consumed[m] - Reserved[m]
// for meter m. Must be called with m.mu held.
func (m *manager) available(meter string) float64 {
	granted := parseFloat(m.lease.Granted[meter])
	consumed := parseFloat(m.lease.Consumed[meter])
	reserved := 0.0
	for _, r := range m.reservations {
		if r.held {
			// Held reservations are also unavailable.
			reserved += parseFloat(r.values[meter])
		} else {
			reserved += parseFloat(r.values[meter])
		}
	}
	return granted - consumed - reserved
}

// Reserve atomically checks that Available[m] >= values[m] for each meter,
// then records a pending reservation. Returns AI-6001/6002/6003/6004 on failure.
func (m *manager) Reserve(executionID string, values budget.Meters) (budget.ReservationID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lease == nil {
		return "", apierr.New(apierr.CodeLeaseUnavailable, "no active lease")
	}
	if m.lease.ExecutionID != executionID {
		return "", apierr.Newf(apierr.CodeLeaseUnavailable,
			"lease execution mismatch: want %s got %s", executionID, m.lease.ExecutionID)
	}

	// Check all meters before reserving any (all-or-nothing).
	for meter, valStr := range values {
		val := parseFloat(valStr)
		avail := m.available(meter)
		if avail < val {
			// Pick the most specific error code based on the meter name.
			code := apierr.CodeBudgetExhausted
			switch meter {
			case "calls":
				code = apierr.CodeCallLimit
			case "distinctResources", "distinct_resources":
				code = apierr.CodeDistinctLimit
			}
			return "", apierr.Newf(code,
				"meter %s: need %.6f available %.6f", meter, val, avail)
		}
	}

	id := m.newID()
	m.reservations[id] = &reservation{
		id:     id,
		values: values,
		held:   false,
	}
	return id, nil
}

// Commit moves the reserved amount into Consumed. Call on upstream success.
func (m *manager) Commit(id budget.ReservationID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.reservations[id]
	if !ok {
		return fmt.Errorf("leasemanager: reservation %s not found (already committed/held?)", id)
	}
	if r.held {
		return fmt.Errorf("leasemanager: reservation %s is held — cannot commit", id)
	}

	for meter, valStr := range r.values {
		cur := parseFloat(m.lease.Consumed[meter])
		m.lease.Consumed[meter] = formatFloat(cur + parseFloat(valStr))
	}
	delete(m.reservations, id)
	return nil
}

// Release returns the reserved amount to Available. Call on clean upstream failure.
// No-op if the reservation does not exist (already committed or held).
func (m *manager) Release(id budget.ReservationID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.reservations[id]
	if !ok {
		// Already committed or held — idempotent no-op.
		return nil
	}
	if r.held {
		// HOLD means "never release"; respect that.
		return nil
	}
	delete(m.reservations, id)
	return nil
}

// Hold marks the reservation as permanently stranded until the lease TTL
// expires. Call on ambiguous upstream timeout — never release ambiguous spend.
func (m *manager) Hold(id budget.ReservationID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.reservations[id]
	if !ok {
		return fmt.Errorf("leasemanager: reservation %s not found", id)
	}
	r.held = true
	return nil
}

// Stats returns a read-only snapshot of the current lease state.
func (m *manager) Stats() budget.LeaseStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lease == nil {
		return budget.LeaseStats{}
	}

	// Build total Reserved across all pending (including held) reservations.
	reserved := make(budget.Meters)
	for _, r := range m.reservations {
		for meter, valStr := range r.values {
			cur := parseFloat(reserved[meter])
			reserved[meter] = formatFloat(cur + parseFloat(valStr))
		}
	}

	// Build Available = Granted - Consumed - Reserved.
	available := make(budget.Meters)
	for meter, grantedStr := range m.lease.Granted {
		granted := parseFloat(grantedStr)
		consumed := parseFloat(m.lease.Consumed[meter])
		res := parseFloat(reserved[meter])
		avail := granted - consumed - res
		if avail < 0 {
			avail = 0
		}
		available[meter] = formatFloat(avail)
	}

	return budget.LeaseStats{
		LeaseID:   m.lease.ID,
		Granted:   cloneMeters(m.lease.Granted),
		Consumed:  cloneMeters(m.lease.Consumed),
		Reserved:  reserved,
		Available: available,
	}
}

// RefreshLease replaces the current lease with a renewed one.
func (m *manager) RefreshLease(l *budget.Lease) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lease = l
}

// cloneMeters returns a shallow copy of a Meters map.
func cloneMeters(src budget.Meters) budget.Meters {
	if src == nil {
		return nil
	}
	dst := make(budget.Meters, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
