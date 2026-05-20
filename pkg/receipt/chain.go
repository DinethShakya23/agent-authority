// Package receipt emits signed, hash-chained decision records (AIP-1 §12).
//
// Every decision — allow AND deny — produces exactly one receipt.
// Payload bodies are never stored; only requestHash appears.
// Receipt writes are asynchronous and never block a decision.
// Sustained audit write failure raises a critical alert (AI-9003 after threshold).
package receipt

import (
	"context"
	"io"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
)

// Decision is the input to Chain.Append.
type Decision struct {
	ExecutionID     string
	PassportID      string
	Principal       v1alpha1.ReceiptPrincipal
	DelegationChain []string // passportIDs root-first, empty for non-delegated
	Integration     string
	Action          string
	RequestHash     string // hex SHA-256 of exact request body
	Decision        string // "ALLOW" | "DENY" | "REQUIRE_APPROVAL"
	ReasonCode      string // AI-xxxx
	Meters          v1alpha1.Meters
	BudgetAfter     map[string]string
	Policy          string // "policy-name@revision"
	FirewallID      string
}

// Chain manages the signed, hash-chained receipt log for one firewall instance.
// One chain per execution; seq is monotonic.
type Chain interface {
	// Append creates and persists a signed receipt for the given decision.
	// Returns the receipt and any async write error (non-blocking).
	Append(ctx context.Context, d Decision) (*v1alpha1.DecisionReceipt, error)

	// Head returns the current chain head hash and sequence number for an execution.
	Head(executionID string) (hash string, seq int64)

	// Export writes all receipts for an execution as newline-delimited JSON to w.
	Export(ctx context.Context, executionID string, w io.Writer) error
}
