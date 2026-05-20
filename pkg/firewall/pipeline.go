// Package firewall is the Agent Firewall decision pipeline.
//
// Stages 1-14 are stateless and side-effect free.
// Stage 15 (budget reservation) is the ONLY mutating step and runs last,
// so a denial never needs rollback.
//
// One Stage per step gives per-stage latency attribution for free via OTel spans.
//
// Invariants:
//   I1: no synchronous control-plane or WSO2 call on the request path.
//   I2: any verification failure → DENY (fail closed).
package firewall

import (
	"context"
	"net/http"

	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// Outcome is the result returned by a Stage.Run call.
type Outcome int

const (
	// Continue means this stage passed; proceed to the next stage.
	Continue Outcome = iota
	// Deny means this stage failed; halt and return a DENY decision.
	Deny
	// Approve means this request requires human approval (REQUIRE_APPROVAL).
	Approve
)

// Stage is one step in the firewall decision pipeline.
// Implementing cheapest / most-likely-to-fail checks first maximises early denial.
type Stage interface {
	// Name returns the stage identifier used in OTel span names and logs.
	Name() string

	// Run executes this stage against the shared State.
	// On Deny or Approve, s.ReasonCode and s.ReasonMsg must be set.
	// On Continue, the stage may populate fields in s for downstream stages.
	Run(ctx context.Context, s *integration.State) (Outcome, error)
}

// Pipeline orchestrates the ordered list of Stages and handles the
// commit/release/hold lifecycle after forwarding.
type Pipeline interface {
	// Handle is the http.Handler entry point for the Agent Firewall.
	Handle(ctx context.Context, w http.ResponseWriter, r *http.Request)

	// Stages returns the ordered stage list (for introspection and testing).
	Stages() []Stage
}
