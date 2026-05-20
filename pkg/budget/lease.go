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

package budget

// ReservationID identifies a pending reserve within a local Lease.
type ReservationID string

// LeaseStats is a snapshot of current local lease state.
type LeaseStats struct {
	LeaseID     string
	Granted     Meters
	Consumed    Meters
	Reserved    Meters
	Available   Meters // Granted - Consumed - Reserved
}

// LeaseManager is the in-process, data-plane side of budget accounting.
// No network calls — all operations are in-memory against the local Lease.
//
// Lifecycle per request:
//
//	reserve -> forward -> commit    (upstream success)
//	reserve -> forward -> release   (clean upstream failure)
//	reserve -> forward -> hold      (AMBIGUOUS timeout: strand, never release)
//
// Ambiguous timeout → HOLD, never release. Stranded budget is recoverable;
// overspend is not.
type LeaseManager interface {
	// Reserve atomically checks that Available[m] >= values[m] for each meter,
	// then deducts from Available and records a pending reservation.
	// Returns AI-6001/6002/6003/6004 on exhaustion or unavailability.
	Reserve(executionID string, values Meters) (ReservationID, error)

	// Commit moves the reserved amount into Consumed. Call on upstream success.
	Commit(id ReservationID) error

	// Release returns the reserved amount to Available. Call on clean upstream failure.
	Release(id ReservationID) error

	// Hold leaves the reservation stranded until the lease TTL expires.
	// Call on ambiguous upstream timeout — never release ambiguous spend.
	Hold(id ReservationID) error

	// Stats returns a read-only snapshot of the current lease state.
	Stats() LeaseStats

	// RefreshLease replaces the current lease with a new one (from RenewLease).
	RefreshLease(l *Lease)
}
