package v1alpha1

import "time"

// DecisionReceipt is emitted by the firewall for every decision.
// It is never authored by an operator. One per execution, seq-ordered, hash-chained.
type DecisionReceipt struct {
	Spec            string            `json:"spec"`      // "AIP-1/v0.1"
	ReceiptID       string            `json:"receiptID"`
	Seq             int64             `json:"seq"`
	Prev            string            `json:"prev"`        // sha256: of previous receipt JCS+sig
	ExecutionID     string            `json:"executionID"`
	PassportID      string            `json:"passportID"`
	Principal       ReceiptPrincipal  `json:"principal"`
	DelegationChain []string          `json:"delegationChain,omitempty"`
	Integration     string            `json:"integration"`
	Action          string            `json:"action"`
	RequestHash     string            `json:"requestHash"` // sha256: of request body
	Decision        string            `json:"decision"`    // ALLOW | DENY | REQUIRE_APPROVAL
	ReasonCode      string            `json:"reasonCode"`  // AI-xxxx
	Meters          Meters            `json:"meters,omitempty"`
	BudgetAfter     map[string]string `json:"budgetAfter,omitempty"`
	Policy          string            `json:"policy"`
	FirewallID      string            `json:"firewallID"`
	Timestamp       time.Time         `json:"timestamp"`
	Signature       string            `json:"signature"` // base64url Ed25519 over JCS(all fields except signature)
}

type ReceiptPrincipal struct {
	Agent string `json:"agent"`
	Human string `json:"human,omitempty"`
}
