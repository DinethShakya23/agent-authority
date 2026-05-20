// Package integration defines protocol adapters.
// v0.1 ships HTTP only; MCP and gRPC land in v0.2.
package integration

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
)

// State is the shared mutable context threaded through the firewall pipeline.
// Stages read from and write to it; only stage 15 mutates the budget.
type State struct {
	// Request-side inputs (set by stage 1).
	RawRequest *http.Request

	// Parsed AIP-1 headers (populated by stages 1-3).
	Spec        string
	PassportJWS string
	CertDER     []byte
	ChainJWSs   []string
	ExecutionID string
	Timestamp   string
	Nonce       string
	Signature   []byte

	// Parsed and verified artefacts (populated by later stages).
	Passport       *v1alpha1.AgentPassport    // set by stage 3
	Cert           *x509.Certificate          // set by stage 2
	ChainPassports []*v1alpha1.AgentPassport  // set by stage 14

	// Decision (set by the pipeline once all stages complete).
	Decision   string // "ALLOW" | "DENY" | "REQUIRE_APPROVAL"
	ReasonCode string // AI-xxxx
	ReasonMsg  string

	// Budget reservation (set by stage 15, committed/released after upstream).
	ReservationID string

	// Integration reference (set at pipeline init).
	Integration string // audience URI
	Upstream    *http.Request
}

// Adapter prepares and forwards a request to the upstream integration.
// v0.1: HTTP only. The adapter is responsible for protocol translation and
// credential injection (passthrough mode only in v0.1).
type Adapter interface {
	// Audience returns the audience URI for this integration.
	Audience() string

	// Prepare builds the upstream request from the firewall State.
	// Called only after ALLOW — never for DENY or REQUIRE_APPROVAL.
	Prepare(ctx context.Context, s *State) (*http.Request, error)

	// Forward sends the prepared request to the upstream and returns its response.
	Forward(ctx context.Context, req *http.Request) (*http.Response, error)
}
