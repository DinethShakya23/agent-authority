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

const (
	CapabilityPhaseReady   = "Ready"
	CapabilityPhasePending = "Pending"
	CapabilityPhaseInvalid = "Invalid"
)

type Capability struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       CapabilitySpec   `json:"spec"`
	Status     CapabilityStatus `json:"status,omitempty"`
}

type CapabilityList struct {
	TypeMeta `json:",inline"`
	Items    []Capability `json:"items"`
}

type CapabilitySpec struct {
	Name          string            `json:"name"`
	ResourceTypes []string          `json:"resourceTypes,omitempty"`
	SchemaRef     string            `json:"schemaRef,omitempty"`
	Meters        []CapabilityMeter `json:"meters,omitempty"`
}

type CapabilityMeter struct {
	Name         string `json:"name"`
	JSONPath     string `json:"jsonPath,omitempty"`
	Type         string `json:"type"`
	CurrencyPath string `json:"currencyPath,omitempty"`
}

type CapabilityStatus struct {
	Phase     string `json:"phase,omitempty"`
	Validated bool   `json:"validated,omitempty"`
}
