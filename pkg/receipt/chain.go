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
