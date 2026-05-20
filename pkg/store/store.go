// Package store is the control-plane persistence interface.
//
// Invariant I1: Store is NEVER called on the data-plane request path.
// Txn is required for budgets and leases — never read-modify-write outside it.
package store

import "context"

// Store is the control-plane persistence interface.
type Store interface {
	// Get retrieves the value at key and JSON-unmarshals it into out.
	Get(ctx context.Context, key string, out any) error

	// List retrieves all values whose keys share the given prefix and
	// JSON-unmarshals them into out (must be a pointer to a slice).
	List(ctx context.Context, prefix string, out any) error

	// Put JSON-marshals obj and stores it at key.
	Put(ctx context.Context, key string, obj any, opts ...PutOption) error

	// Delete removes the key.
	Delete(ctx context.Context, key string) error

	// Watch returns a channel that receives events for keys matching prefix.
	// The channel is closed when ctx is cancelled.
	Watch(ctx context.Context, prefix string) (<-chan Event, error)

	// Txn executes fn inside a serialisable read-write transaction.
	// Required for all budget and lease operations.
	Txn(ctx context.Context, fn func(Tx) error) error

	// Close releases underlying resources.
	Close() error
}

// Tx is a handle to an active transaction.
type Tx interface {
	Get(key string, out any) error
	List(prefix string, out any) error
	Put(key string, obj any) error
	Delete(key string) error
}

// Event is a change notification from Watch.
type Event struct {
	Type   EventType
	Key    string
	Object []byte // raw JSON value; nil for Deleted events
}

// EventType classifies a Watch event.
type EventType string

const (
	EventCreated EventType = "Created"
	EventUpdated EventType = "Updated"
	EventDeleted EventType = "Deleted"
)

// PutOption modifies the behaviour of Put.
type PutOption func(*putOptions)

type putOptions struct {
	ttl      int64 // seconds; 0 = no expiry
	revision int64 // optimistic concurrency; 0 = unconditional
}

// WithTTL asks the backend to expire the key after d seconds (best-effort).
func WithTTL(seconds int64) PutOption {
	return func(o *putOptions) { o.ttl = seconds }
}

// WithRevision makes the Put conditional on the key's current revision.
func WithRevision(rev int64) PutOption {
	return func(o *putOptions) { o.revision = rev }
}

// ErrNotFound is returned by Get when the key does not exist.
var ErrNotFound = &storeError{msg: "not found"}

// ErrConflict is returned by Txn when a conditional Put fails.
var ErrConflict = &storeError{msg: "revision conflict"}

type storeError struct{ msg string }

func (e *storeError) Error() string { return "store: " + e.msg }
