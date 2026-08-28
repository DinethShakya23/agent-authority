// Copyright 2026 Agent Authority Authors
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

package v1alpha1

const (
	ExecutionPhasePending   = "Pending"
	ExecutionPhaseActive    = "Active"
	ExecutionPhaseCompleted = "Completed"
	ExecutionPhaseDenied    = "Denied"
	ExecutionPhaseExpired   = "Expired"
)

type AgentExecution struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       AgentExecutionSpec   `json:"spec"`
	Status     AgentExecutionStatus `json:"status,omitempty"`
}

type AgentExecutionList struct {
	TypeMeta `json:",inline"`
	Items    []AgentExecution `json:"items"`
}

type AgentExecutionSpec struct {
	AgentRef  ObjectRef        `json:"agentRef"`
	Intent    ExecutionIntent  `json:"intent,omitempty"`
	Requested ExecutionRequest `json:"requested,omitempty"`
	PublicKey PublicKeySpec    `json:"publicKey"`
}

type ExecutionIntent struct {
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

type ExecutionRequest struct {
	Capabilities []string        `json:"capabilities,omitempty"`
	Target       ExecutionTarget `json:"target,omitempty"`
	BudgetHint   BudgetLimit     `json:"budgetHint,omitempty"`
}

type ExecutionTarget struct {
	IntegrationRef ObjectRef `json:"integrationRef,omitempty"`
}

type PublicKeySpec struct {
	Alg string            `json:"alg"` // "Ed25519"
	JWK map[string]string `json:"jwk,omitempty"`
}

type AgentExecutionStatus struct {
	Phase         string                 `json:"phase,omitempty"`
	ExecutionID   string                 `json:"executionID,omitempty"`
	PassportRef   ObjectRef              `json:"passportRef,omitempty"`
	Principal     ExecutionPrincipal     `json:"principal,omitempty"`
	Authorization ExecutionAuthorization `json:"authorization,omitempty"`
	Budget        ExecutionBudgetStatus  `json:"budget,omitempty"`
	Receipts      ReceiptSummary         `json:"receipts,omitempty"`
}

type ExecutionPrincipal struct {
	Agent string `json:"agent"`
	Human string `json:"human,omitempty"`
}

type ExecutionAuthorization struct {
	Decision string `json:"decision,omitempty"`
	Policy   string `json:"policy,omitempty"`
}

type ExecutionBudgetStatus struct {
	Amount            BudgetStatus `json:"amount,omitempty"`
	Calls             BudgetStatus `json:"calls,omitempty"`
	DistinctResources BudgetStatus `json:"distinctResources,omitempty"`
}

type ReceiptSummary struct {
	Count    int    `json:"count,omitempty"`
	HeadHash string `json:"headHash,omitempty"`
}
