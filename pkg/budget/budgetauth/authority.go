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

// Package budgetauth is the control-plane implementation of budget.Authority.
//
// SAFETY PROPERTY: grants are deducted from Budget.Remaining BEFORE the lease
// is returned. This pre-deduction ordering makes overspend (S > B) impossible.
// Do not reorder the deduct-then-write-then-return sequence.
//
// Key layout (_.md §16):
//
//	budgets/{execID}
//	leases/{execID}/{leaseID}
//	epochs/{execID}
package budgetauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/budget"
	"github.com/thev1ndu/agent-integrator/pkg/store"
)

// Config tunes the budget authority behaviour.
type Config struct {
	MaxLeaseFraction float64       // e.g. 0.25 — max fraction of a limit per lease
	LeaseTTL         time.Duration // e.g. 30s
	SweepInterval    time.Duration // e.g. 5s
}

type authority struct {
	store  store.Store
	config Config
}

// New creates a new budget Authority backed by the given store.
func New(s store.Store, cfg Config) budget.Authority {
	return &authority{store: s, config: cfg}
}

func budgetKey(execID string) string { return fmt.Sprintf("budgets/%s", execID) }

func leaseKey(execID, leaseID string) string {
	return fmt.Sprintf("leases/%s/%s", execID, leaseID)
}

func newLeaseID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("lease-%d", time.Now().UnixNano())
	}
	return "lease-" + hex.EncodeToString(b)
}

func parseFloat(s string) (float64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseFloat(s, 64)
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func minFloat3(a, b, c float64) float64 {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// CreateBudget initialises a budget for a new execution.
// All meters are set to their limits; remaining = limits, leased = zero.
func (a *authority) CreateBudget(ctx context.Context, executionID string, limits budget.Meters) (*budget.Budget, error) {
	remaining := make(budget.Meters, len(limits))
	leased := make(budget.Meters, len(limits))
	for k, v := range limits {
		remaining[k] = v
		leased[k] = "0"
	}
	b := &budget.Budget{
		ExecutionID: executionID,
		Epoch:       0,
		Limits:      limits,
		Remaining:   remaining,
		Leased:      leased,
	}
	if err := a.store.Put(ctx, budgetKey(executionID), b); err != nil {
		return nil, fmt.Errorf("budgetauth: create budget %s: %w", executionID, err)
	}
	return b, nil
}

// AcquireLease atomically deducts a grant from Budget.Remaining and returns a
// pre-deducted Lease. The deduction happens inside a Txn, BEFORE the lease is
// returned — this is the invariant that keeps S ≤ B.
func (a *authority) AcquireLease(ctx context.Context, req budget.LeaseRequest) (*budget.Lease, error) {
	var lease *budget.Lease

	err := a.store.Txn(ctx, func(tx store.Tx) error {
		var b budget.Budget
		if err := tx.Get(budgetKey(req.ExecutionID), &b); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return apierr.New(apierr.CodeBudgetExhausted, "budget not found")
			}
			return fmt.Errorf("budgetauth: read budget: %w", err)
		}

		if req.Epoch != 0 && b.Epoch != req.Epoch {
			return apierr.Newf(apierr.CodeEpochBumped,
				"epoch mismatch: want %d got %d", req.Epoch, b.Epoch)
		}

		granted := make(budget.Meters, len(b.Limits))
		newRemaining := make(budget.Meters, len(b.Remaining))
		for k, v := range b.Remaining {
			newRemaining[k] = v
		}

		for m, limitStr := range b.Limits {
			limit, err := parseFloat(limitStr)
			if err != nil {
				return fmt.Errorf("budgetauth: parse limit %q for meter %s: %w", limitStr, m, err)
			}

			remaining, err := parseFloat(b.Remaining[m])
			if err != nil {
				return fmt.Errorf("budgetauth: parse remaining %q for meter %s: %w", b.Remaining[m], m, err)
			}

			if remaining <= 0 {
				return apierr.Newf(apierr.CodeBudgetExhausted,
					"meter %s exhausted (remaining=%.6f)", m, remaining)
			}

			hint := limit
			if hintStr, ok := req.Hint[m]; ok {
				hint, err = parseFloat(hintStr)
				if err != nil {
					return fmt.Errorf("budgetauth: parse hint %q for meter %s: %w", hintStr, m, err)
				}
			}

			maxFraction := a.config.MaxLeaseFraction * limit
			grant := minFloat3(hint, remaining, maxFraction)
			if grant < 0 {
				grant = 0
			}

			granted[m] = formatFloat(grant)
			newRemaining[m] = formatFloat(remaining - grant)
		}

		// Write updated budget with new Remaining (BEFORE returning lease).
		b.Remaining = newRemaining
		if err := tx.Put(budgetKey(req.ExecutionID), &b); err != nil {
			return fmt.Errorf("budgetauth: write budget: %w", err)
		}

		now := time.Now().UTC()
		leaseID := newLeaseID()
		consumed := make(budget.Meters, len(granted))
		reserved := make(budget.Meters, len(granted))
		for m := range granted {
			consumed[m] = "0"
			reserved[m] = "0"
		}

		lease = &budget.Lease{
			ID:          leaseID,
			ExecutionID: req.ExecutionID,
			ReplicaID:   req.ReplicaID,
			Epoch:       b.Epoch,
			Granted:     granted,
			Consumed:    consumed,
			Reserved:    reserved,
			IssuedAt:    now,
			ExpiresAt:   now.Add(a.config.LeaseTTL),
		}

		if err := tx.Put(leaseKey(req.ExecutionID, leaseID), lease); err != nil {
			return fmt.Errorf("budgetauth: write lease: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return lease, nil
}

// RenewLease extends the lease TTL and optionally tops up the granted amount.
func (a *authority) RenewLease(ctx context.Context, leaseID string, hint budget.Meters) (*budget.Lease, error) {
	var updated *budget.Lease

	err := a.store.Txn(ctx, func(tx store.Tx) error {
		// Scan strategy: List all under "leases/" and find by ID.
		// This is acceptable for v0.1 (control plane, not hot path).
		var found budget.Lease
		var foundExecID string

		var rawLeases []budget.Lease
		if err := tx.List("leases/", &rawLeases); err != nil {
			return fmt.Errorf("budgetauth: list leases: %w", err)
		}
		for _, l := range rawLeases {
			if l.ID == leaseID {
				found = l
				foundExecID = l.ExecutionID
				break
			}
		}
		if foundExecID == "" {
			return apierr.Newf(apierr.CodeLeaseUnavailable, "lease %s not found", leaseID)
		}

		now := time.Now().UTC()
		found.ExpiresAt = now.Add(a.config.LeaseTTL)

		if len(hint) > 0 {
			var b budget.Budget
			if err := tx.Get(budgetKey(foundExecID), &b); err != nil {
				return fmt.Errorf("budgetauth: read budget for renew: %w", err)
			}

			newRemaining := make(budget.Meters, len(b.Remaining))
			for k, v := range b.Remaining {
				newRemaining[k] = v
			}

			for m, hintStr := range hint {
				limitStr, ok := b.Limits[m]
				if !ok {
					continue
				}
				limit, err := parseFloat(limitStr)
				if err != nil {
					continue
				}
				remaining, err := parseFloat(b.Remaining[m])
				if err != nil {
					continue
				}
				hintVal, err := parseFloat(hintStr)
				if err != nil {
					continue
				}
				maxFraction := a.config.MaxLeaseFraction * limit
				topUp := minFloat3(hintVal, remaining, maxFraction)
				if topUp > 0 {
					currentGranted, _ := parseFloat(found.Granted[m])
					found.Granted[m] = formatFloat(currentGranted + topUp)
					newRemaining[m] = formatFloat(remaining - topUp)
				}
			}
			b.Remaining = newRemaining
			if err := tx.Put(budgetKey(foundExecID), &b); err != nil {
				return fmt.Errorf("budgetauth: write budget on renew: %w", err)
			}
		}

		if err := tx.Put(leaseKey(foundExecID, leaseID), &found); err != nil {
			return fmt.Errorf("budgetauth: write renewed lease: %w", err)
		}
		updated = &found
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// ReleaseLease credits back (Granted − Consumed) to Budget.Remaining and deletes
// the lease. Idempotent: if the lease is not found, this is a no-op.
func (a *authority) ReleaseLease(ctx context.Context, leaseID string, consumed budget.Meters) error {
	return a.store.Txn(ctx, func(tx store.Tx) error {
		var rawLeases []budget.Lease
		if err := tx.List("leases/", &rawLeases); err != nil {
			return fmt.Errorf("budgetauth: list leases for release: %w", err)
		}

		var found *budget.Lease
		for i := range rawLeases {
			if rawLeases[i].ID == leaseID {
				found = &rawLeases[i]
				break
			}
		}
		if found == nil {
			return nil
		}

		var b budget.Budget
		if err := tx.Get(budgetKey(found.ExecutionID), &b); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return tx.Delete(leaseKey(found.ExecutionID, leaseID))
			}
			return fmt.Errorf("budgetauth: read budget for release: %w", err)
		}

		newRemaining := make(budget.Meters, len(b.Remaining))
		for k, v := range b.Remaining {
			newRemaining[k] = v
		}

		// Credit = Granted − actual consumed (caller-reported).
		for m, grantedStr := range found.Granted {
			granted, err := parseFloat(grantedStr)
			if err != nil {
				continue
			}
			actualConsumed := 0.0
			if consumedStr, ok := consumed[m]; ok {
				actualConsumed, _ = parseFloat(consumedStr)
			}
			credit := granted - actualConsumed
			if credit < 0 {
				credit = 0
			}
			cur, _ := parseFloat(b.Remaining[m])
			newRemaining[m] = formatFloat(cur + credit)
		}

		b.Remaining = newRemaining
		if err := tx.Put(budgetKey(found.ExecutionID), &b); err != nil {
			return fmt.Errorf("budgetauth: write budget on release: %w", err)
		}

		return tx.Delete(leaseKey(found.ExecutionID, leaseID))
	})
}

// BumpEpoch atomically increments Budget.Epoch. Outstanding leases with the
// old epoch will fail their epoch check on the next operation.
func (a *authority) BumpEpoch(ctx context.Context, executionID string) (uint64, error) {
	var newEpoch uint64

	err := a.store.Txn(ctx, func(tx store.Tx) error {
		var b budget.Budget
		if err := tx.Get(budgetKey(executionID), &b); err != nil {
			return fmt.Errorf("budgetauth: read budget for epoch bump: %w", err)
		}
		b.Epoch++
		newEpoch = b.Epoch
		return tx.Put(budgetKey(executionID), &b)
	})
	if err != nil {
		return 0, err
	}
	return newEpoch, nil
}

// Get returns the current budget status (read-only).
func (a *authority) Get(ctx context.Context, executionID string) (*budget.Budget, error) {
	var b budget.Budget
	if err := a.store.Get(ctx, budgetKey(executionID), &b); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, apierr.Newf(apierr.CodeBudgetExhausted, "budget %s not found", executionID)
		}
		return nil, fmt.Errorf("budgetauth: get budget %s: %w", executionID, err)
	}
	return &b, nil
}
