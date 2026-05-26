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

package v1alpha1

import "time"

const (
	AgentPhasePending   = "Pending"
	AgentPhaseReady     = "Ready"
	AgentPhaseSuspended = "Suspended"
	AgentPhaseInvalid   = "Invalid"
)

type Agent struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       AgentSpec   `json:"spec"`
	Status     AgentStatus `json:"status,omitempty"`
}

type AgentList struct {
	TypeMeta `json:",inline"`
	Items    []Agent `json:"items"`
}

type AgentSpec struct {
	Identity           AgentIdentity `json:"identity"`
	ManagedBy          string        `json:"managedBy,omitempty"`
	Owner              AgentOwner    `json:"owner,omitempty"`
	Environment        string        `json:"environment,omitempty"`
	MaxDelegationDepth int           `json:"maxDelegationDepth,omitempty"`
}

type AgentIdentity struct {
	Provider        string `json:"provider"`
	Issuer          string `json:"issuer"`
	Subject         string `json:"subject"`
	AllowOnBehalfOf bool   `json:"allowOnBehalfOf,omitempty"`
}

type AgentOwner struct {
	Team    string `json:"team,omitempty"`
	Contact string `json:"contact,omitempty"`
}

type AgentStatus struct {
	Phase            string             `json:"phase,omitempty"`
	IdentityResolved bool               `json:"identityResolved,omitempty"`
	ProviderSync     ProviderSyncStatus `json:"providerSync,omitempty"`
	Epoch            uint64             `json:"epoch,omitempty"`
	ActivePassports  int                `json:"activePassports,omitempty"`
}

// ProviderSyncStatus records the last synchronisation from the identity provider.
// Populated only when ManagedBy is set (e.g. the SCIM2 sync for WSO2).
type ProviderSyncStatus struct {
	LastSyncedAt time.Time `json:"lastSyncedAt,omitempty"`
	Roles        []string  `json:"roles,omitempty"`
}
