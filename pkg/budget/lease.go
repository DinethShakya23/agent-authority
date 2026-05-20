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
