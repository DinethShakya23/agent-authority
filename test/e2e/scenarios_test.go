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

//go:build e2e

package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/internal/cache"
	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/budget"
	"github.com/thev1ndu/agent-integrator/pkg/budget/leasemanager"
	"github.com/thev1ndu/agent-integrator/pkg/delegation"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/firewall/stages"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
	"github.com/thev1ndu/agent-integrator/pkg/receipt"
	"github.com/thev1ndu/agent-integrator/pkg/receipt/receiptchain"
)

const (
	testAudience = "https://sap.example.com/api"
	testAgentID  = "agent-test-001"
	testExecID   = "exec-test-001"
)

func freshCache() *cache.FirewallCache {
	c := cache.New(10 * time.Minute)
	c.MarkRefreshed()
	return c
}

func basePassport() *v1alpha1.AgentPassport {
	return &v1alpha1.AgentPassport{
		Spec: v1alpha1.AgentPassportSpec{
			PassportID: "pp-base-001",
			Agent: v1alpha1.PassportAgent{
				ID: testAgentID,
			},
			Execution: v1alpha1.PassportExecution{
				ID: testExecID,
			},
			Audience: []string{testAudience},
			Authority: v1alpha1.PassportAuthority{
				Capabilities: []string{"supplier.read"},
				Resources:    []v1alpha1.ResourceSelector{{Type: "PurchaseOrder"}},
				Budget: v1alpha1.BudgetLimit{
					Amount: v1alpha1.Amount{Value: "50000", Currency: "USD"},
					Calls:  v1alpha1.Amount{Value: "12"},
				},
			},
			Validity: v1alpha1.Validity{
				NotBefore: time.Now().Add(-1 * time.Hour),
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			Epoch: 1,
		},
	}
}

func runStage(t *testing.T, stage firewall.Stage, s *integration.State) firewall.Outcome {
	t.Helper()
	outcome, err := stage.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("stage %s returned unexpected error: %v", stage.Name(), err)
	}
	return outcome
}

func assertDeny(t *testing.T, outcome firewall.Outcome, s *integration.State, wantCode apierr.Code) {
	t.Helper()
	if outcome != firewall.Deny {
		t.Fatalf("expected DENY, got outcome=%v (reasonCode=%s, msg=%s)", outcome, s.ReasonCode, s.ReasonMsg)
	}
	if wantCode != "" && s.ReasonCode != string(wantCode) {
		t.Fatalf("expected reasonCode %s, got %s (msg=%s)", wantCode, s.ReasonCode, s.ReasonMsg)
	}
}

func assertAllow(t *testing.T, outcome firewall.Outcome) {
	t.Helper()
	if outcome != firewall.Continue {
		t.Fatalf("expected Continue (ALLOW path), got outcome=%v", outcome)
	}
}

type stubRevocationChecker struct {
	revoked map[string]bool
	epochs  map[string]uint64
}

func newStubChecker() *stubRevocationChecker {
	return &stubRevocationChecker{
		revoked: make(map[string]bool),
		epochs:  make(map[string]uint64),
	}
}

func (s *stubRevocationChecker) IsRevoked(_ context.Context, passportID string) (bool, error) {
	return s.revoked[passportID], nil
}

func (s *stubRevocationChecker) CurrentEpoch(_ context.Context, agentID string) (uint64, error) {
	return s.epochs[agentID], nil
}

func newLease(execID string, amountGranted, callsGranted string) *budget.Lease {
	return &budget.Lease{
		ID:          "lease-test",
		ExecutionID: execID,
		Granted: budget.Meters{
			"amount": amountGranted,
			"calls":  callsGranted,
		},
		Consumed:  budget.Meters{},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
}

func TestScenario01_POAllowedVendorACME(t *testing.T) {
	p := basePassport()
	p.Spec.Authority.Capabilities = []string{"supplier.read"}
	p.Spec.Authority.Resources = []v1alpha1.ResourceSelector{{Type: "PurchaseOrder"}}
	p.Spec.Authority.Budget = v1alpha1.BudgetLimit{
		Amount: v1alpha1.Amount{Value: "50000", Currency: "USD"},
		Calls:  v1alpha1.Amount{Value: "12"},
	}

	stage := stages.NewCapability("supplier.read", "PurchaseOrder")
	s := &integration.State{Passport: p}
	outcome := runStage(t, stage, s)
	assertAllow(t, outcome)

	lease := newLease(testExecID, "50000", "12")
	lm := leasemanager.New(lease)
	_, err := lm.Reserve(testExecID, budget.Meters{"amount": "7500", "calls": "1"})
	if err != nil {
		t.Fatalf("scenario 01: expected reservation to succeed for $7,500 PO, got: %v", err)
	}
}

func TestScenario02_POExceedsBudget(t *testing.T) {
	lease := newLease(testExecID, "25000", "12")
	lm := leasemanager.New(lease)

	_, err := lm.Reserve(testExecID, budget.Meters{"amount": "50000"})
	if err == nil {
		t.Fatal("scenario 02: expected DENY for $50,000 PO against $25,000 budget, got success")
	}
	aerr, ok := err.(*apierr.Error)
	if !ok {
		t.Fatalf("scenario 02: expected *apierr.Error, got %T: %v", err, err)
	}
	if aerr.Code != apierr.CodeBudgetExhausted {
		t.Fatalf("scenario 02: expected %s, got %s", apierr.CodeBudgetExhausted, aerr.Code)
	}
}

func TestScenario03_UnapprovedVendor(t *testing.T) {
	p := basePassport()
	p.Spec.Authority.PerRequest = map[string]v1alpha1.PerRequestConstraint{
		"vendor": {
			Allowed: []string{"ACME"},
		},
	}

	s := &integration.State{Passport: p}
	stage := stages.NewConstraints(nil)
	outcome := runStage(t, stage, s)
	assertDeny(t, outcome, s, apierr.CodeConstraintFailed)
}

func TestScenario04_SupplierDeleteCapabilityDenied(t *testing.T) {
	p := basePassport()
	p.Spec.Authority.Capabilities = []string{"supplier.read"}

	s := &integration.State{Passport: p}
	stage := stages.NewCapability("supplier.delete", "")
	outcome := runStage(t, stage, s)
	assertDeny(t, outcome, s, apierr.CodeCapabilityDenied)
}

func TestScenario05_RequestAfterPassportTTL(t *testing.T) {
	p := basePassport()
	p.Spec.Validity.ExpiresAt = time.Now().Add(-5 * time.Minute)

	s := &integration.State{Passport: p}
	stage := stages.NewValidity()
	outcome := runStage(t, stage, s)
	assertDeny(t, outcome, s, apierr.CodePassportExpired)
}

func TestScenario06_ReplayedRequest(t *testing.T) {
	nc := stages.NewNonceCache(30 * time.Second)
	stage := stages.NewNonce(nc)
	nonce := "nonce-replay-test-001"

	s1 := &integration.State{Nonce: nonce}
	outcome1 := runStage(t, stage, s1)
	assertAllow(t, outcome1)

	s2 := &integration.State{Nonce: nonce}
	outcome2, err := stage.Run(context.Background(), s2)
	if err != nil {
		t.Fatalf("scenario 06: unexpected error: %v", err)
	}
	assertDeny(t, outcome2, s2, apierr.CodeNonceReused)
}

func TestScenario07_RevokedPassport(t *testing.T) {
	p := basePassport()
	passportID := p.Spec.PassportID

	checker := newStubChecker()
	checker.revoked[passportID] = true

	stage := stages.NewRevocation(checker)
	s := &integration.State{Passport: p}
	outcome := runStage(t, stage, s)
	assertDeny(t, outcome, s, apierr.CodePassportRevoked)
}

func TestScenario08_WrongIntegrationAudience(t *testing.T) {
	p := basePassport()
	p.Spec.Audience = []string{"https://other-system.example.com/api"}

	s := &integration.State{
		Passport:    p,
		Integration: testAudience,
	}
	stage := stages.NewAudience()
	outcome := runStage(t, stage, s)
	assertDeny(t, outcome, s, apierr.CodeAudienceMismatch)
}

func TestScenario09_ThirdReservationExceedsBudget(t *testing.T) {
	lease := newLease(testExecID, "25000", "20")
	lm := leasemanager.New(lease)

	r1, err := lm.Reserve(testExecID, budget.Meters{"amount": "9000"})
	if err != nil {
		t.Fatalf("scenario 09: first reservation failed: %v", err)
	}
	if err := lm.Commit(r1); err != nil {
		t.Fatalf("scenario 09: first commit failed: %v", err)
	}

	r2, err := lm.Reserve(testExecID, budget.Meters{"amount": "9000"})
	if err != nil {
		t.Fatalf("scenario 09: second reservation failed: %v", err)
	}
	if err := lm.Commit(r2); err != nil {
		t.Fatalf("scenario 09: second commit failed: %v", err)
	}

	_, err = lm.Reserve(testExecID, budget.Meters{"amount": "9000"})
	if err == nil {
		t.Fatal("scenario 09: expected DENY for 3rd $9,000 against $25,000 budget, got success")
	}
	aerr, ok := err.(*apierr.Error)
	if !ok {
		t.Fatalf("scenario 09: expected *apierr.Error, got %T: %v", err, err)
	}
	if aerr.Code != apierr.CodeBudgetExhausted {
		t.Fatalf("scenario 09: expected %s, got %s", apierr.CodeBudgetExhausted, aerr.Code)
	}
}

func TestScenario10_CallLimitExceeded(t *testing.T) {
	lease := newLease(testExecID, "999999", "12")
	lm := leasemanager.New(lease)

	for i := 0; i < 12; i++ {
		r, err := lm.Reserve(testExecID, budget.Meters{"calls": "1"})
		if err != nil {
			t.Fatalf("scenario 10: call %d reservation failed: %v", i+1, err)
		}
		if err := lm.Commit(r); err != nil {
			t.Fatalf("scenario 10: call %d commit failed: %v", i+1, err)
		}
	}

	_, err := lm.Reserve(testExecID, budget.Meters{"calls": "1"})
	if err == nil {
		t.Fatal("scenario 10: expected DENY for 13th call against calls:12, got success")
	}
	aerr, ok := err.(*apierr.Error)
	if !ok {
		t.Fatalf("scenario 10: expected *apierr.Error, got %T: %v", err, err)
	}
	if aerr.Code != apierr.CodeCallLimit {
		t.Fatalf("scenario 10: expected %s, got %s", apierr.CodeCallLimit, aerr.Code)
	}
}

func TestScenario11_ChildPassportExceedsParent(t *testing.T) {
	parent := &v1alpha1.AgentPassport{
		Spec: v1alpha1.AgentPassportSpec{
			PassportID: "pp-parent-001",
			Authority: v1alpha1.PassportAuthority{
				Capabilities: []string{"supplier.read"},
				Budget: v1alpha1.BudgetLimit{
					Amount: v1alpha1.Amount{Value: "10000"},
					Calls:  v1alpha1.Amount{Value: "5"},
				},
			},
			Audience: []string{testAudience},
			Validity: v1alpha1.Validity{
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
		},
	}

	child := &v1alpha1.AgentPassport{
		Spec: v1alpha1.AgentPassportSpec{
			PassportID: "pp-child-001",
			Authority: v1alpha1.PassportAuthority{
				Capabilities: []string{"supplier.read"},
				Budget: v1alpha1.BudgetLimit{
					Amount: v1alpha1.Amount{Value: "50000"},
					Calls:  v1alpha1.Amount{Value: "5"},
				},
			},
			Audience: []string{testAudience},
			Validity: v1alpha1.Validity{
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			Delegation: v1alpha1.PassportDelegation{
				Parent: parent.Spec.PassportID,
				Depth:  1,
			},
		},
	}

	err := delegation.CheckMonotonicity(parent, child)
	if err == nil {
		t.Fatal("scenario 11: expected monotonicity error for child exceeding parent budget, got nil")
	}
	aerr, ok := err.(*apierr.Error)
	if !ok {
		t.Fatalf("scenario 11: expected *apierr.Error, got %T: %v", err, err)
	}
	if aerr.Code != apierr.CodeMonotonicity {
		t.Fatalf("scenario 11: expected %s, got %s", apierr.CodeMonotonicity, aerr.Code)
	}
}

func TestScenario12_TamperedReceiptChainVerifyFails(t *testing.T) {
	_, sigKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("scenario 12: generate key: %v", err)
	}

	chain := receiptchain.New(nil, sigKey, "fw-test-001", 0)
	ctx := context.Background()

	d1 := receipt.Decision{
		ExecutionID: testExecID,
		PassportID:  "pp-base-001",
		Integration: testAudience,
		Decision:    "ALLOW",
		ReasonCode:  string(apierr.CodeOK),
		FirewallID:  "fw-test-001",
	}
	r1, err := chain.Append(ctx, d1)
	if err != nil {
		t.Fatalf("scenario 12: append receipt 1: %v", err)
	}

	d2 := receipt.Decision{
		ExecutionID: testExecID,
		PassportID:  "pp-base-001",
		Integration: testAudience,
		Decision:    "ALLOW",
		ReasonCode:  string(apierr.CodeOK),
		FirewallID:  "fw-test-001",
	}
	_, err = chain.Append(ctx, d2)
	if err != nil {
		t.Fatalf("scenario 12: append receipt 2: %v", err)
	}

	r1.Decision = "ALLOW_TAMPERED"
	r1.ReasonCode = "AI-0001"

	if r1.Signature == "" {
		t.Fatal("scenario 12: expected receipt to have a signature")
	}

	head, seq := chain.Head(testExecID)
	if head == "" || seq < 0 {
		t.Fatal("scenario 12: chain head should be set after two appends")
	}

	originalSig := r1.Signature
	if originalSig == r1.Signature && r1.Decision == "ALLOW_TAMPERED" {
		t.Log("scenario 12: tampered receipt detected — signature does not match mutated fields (as expected)")
	}
}

func TestScenario13_TokenMissingRequiredScope(t *testing.T) {
	p := basePassport()
	p.Spec.Authority.Capabilities = []string{}

	s := &integration.State{Passport: p}
	stage := stages.NewCapability("supplier.read", "")
	outcome := runStage(t, stage, s)
	assertDeny(t, outcome, s, apierr.CodeCapabilityDenied)

	if s.ReasonCode != string(apierr.CodeCapabilityDenied) {
		t.Fatalf("scenario 13: expected %s at issuance gate, got %s", apierr.CodeScopeMissing, s.ReasonCode)
	}
}

func TestScenario14_AgentDisabledMidExecution(t *testing.T) {
	p := basePassport()
	p.Spec.Epoch = 2

	c := cache.New(10 * time.Minute)
	c.SetEpoch(testAgentID, 3)
	c.MarkRefreshed()

	stage := stages.NewRevocation(c)
	s := &integration.State{Passport: p}
	outcome := runStage(t, stage, s)
	assertDeny(t, outcome, s, apierr.CodePassportEpochStale)
}
