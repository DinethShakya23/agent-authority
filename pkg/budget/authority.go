// Package budget implements execution-scoped cumulative authority.
//
// SAFETY: grants are deducted from the budget BEFORE the lease is returned.
// This ordering is what makes overspend impossible. Do not "optimise" it.
//
// See formal/budget.tla for the machine-checked model (TLC must verify S≤B
// before this implementation is considered correct).
package budget

import (
	"context"
	"time"
)

// Meters maps meter names to their current values (decimal strings).
type Meters map[string]string // e.g. {"amount": "4000", "calls": "1"}

// Budget is the execution-level authoritative record, held only by the control plane.
type Budget struct {
	ExecutionID string
	Epoch       uint64
	Limits      Meters // authoritative total limits
	Remaining   Meters // currently available (Limits - pre-deducted leases)
	Leased      Meters // currently out on active leases (informational)
}

// Lease is a pre-deducted budget slice held by one firewall replica.
// Granted is atomically removed from Budget.Remaining BEFORE the lease is returned.
type Lease struct {
	ID          string
	ExecutionID string
	ReplicaID   string
	Epoch       uint64
	Granted     Meters    // pre-deducted from Budget.Remaining
	Consumed    Meters    // reported consumed so far
	Reserved    Meters    // currently reserved within this lease
	IssuedAt    time.Time
	ExpiresAt   time.Time // default TTL 30s
}

// LeaseRequest parameters for AcquireLease.
type LeaseRequest struct {
	ExecutionID string
	ReplicaID   string
	Hint        Meters // desired amount; actual grant = min(hint, Remaining, maxLeaseFraction×Limit)
	Epoch       uint64
}

// Authority is the control-plane side of the budget protocol.
// All mutations use Store.Txn — never read-modify-write outside a transaction.
type Authority interface {
	// AcquireLease atomically deducts the grant from Budget.Remaining and returns a Lease.
	// Epoch mismatch → error with AI-6005.
	AcquireLease(ctx context.Context, req LeaseRequest) (*Lease, error)

	// RenewLease extends the TTL and optionally tops up the granted amount.
	RenewLease(ctx context.Context, leaseID string, hint Meters) (*Lease, error)

	// ReleaseLease credits back (Granted − Consumed) to Budget.Remaining. Idempotent.
	ReleaseLease(ctx context.Context, leaseID string, consumed Meters) error

	// BumpEpoch invalidates all outstanding leases and passports for the execution.
	BumpEpoch(ctx context.Context, executionID string) (uint64, error)

	// Get returns the current budget status (read-only).
	Get(ctx context.Context, executionID string) (*Budget, error)

	// CreateBudget initialises a budget for a new execution.
	CreateBudget(ctx context.Context, executionID string, limits Meters) (*Budget, error)
}
