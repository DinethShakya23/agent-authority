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

type AgentPolicy struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       AgentPolicySpec   `json:"spec"`
	Status     AgentPolicyStatus `json:"status,omitempty"`
}

type AgentPolicyList struct {
	TypeMeta `json:",inline"`
	Items    []AgentPolicy `json:"items"`
}

type AgentPolicySpec struct {
	AgentSelector  LabelSelector `json:"agentSelector"`
	RequiredScopes []string      `json:"requiredScopes,omitempty"`
	Rules          []PolicyRule  `json:"rules,omitempty"`
}

type PolicyRule struct {
	Capability string                          `json:"capability"`
	Target     PolicyTarget                    `json:"target"`
	Resources  []ResourceSelector              `json:"resources,omitempty"`
	PerRequest map[string]PerRequestConstraint `json:"perRequest,omitempty"`
	Budget     BudgetLimit                     `json:"budget,omitempty"`
	Approval   ApprovalConfig                  `json:"approval,omitempty"`
	OnBehalfOf OnBehalfOfConfig                `json:"onBehalfOf,omitempty"`
	Validity   Validity                        `json:"validity,omitempty"`
	Delegation DelegationConfig                `json:"delegation,omitempty"`
}

type PolicyTarget struct {
	Integration string `json:"integration,omitempty"`
}

type ResourceSelector struct {
	Type string `json:"type"`
}

type ApprovalConfig struct {
	RequiredAbove map[string]string `json:"requiredAbove,omitempty"`
}

type OnBehalfOfConfig struct {
	Required bool `json:"required,omitempty"`
}

type DelegationConfig struct {
	Allowed  bool `json:"allowed,omitempty"`
	MaxDepth int  `json:"maxDepth,omitempty"`
}

type AgentPolicyStatus struct {
	Revision        int    `json:"revision,omitempty"`
	CedarPolicyHash string `json:"cedarPolicyHash,omitempty"`
}
