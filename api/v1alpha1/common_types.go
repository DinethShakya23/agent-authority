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

type TypeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

type ObjectMeta struct {
	Name              string            `json:"name"`
	GenerateName      string            `json:"generateName,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	CreationTimestamp *time.Time        `json:"creationTimestamp,omitempty"`
}

type Amount struct {
	Value    string `json:"value"`
	Currency string `json:"currency,omitempty"`
}

type Meters map[string]Amount

type BudgetLimit struct {
	Scope             string `json:"scope,omitempty"`
	Amount            Amount `json:"amount,omitempty"`
	Calls             Amount `json:"calls,omitempty"`
	DistinctResources Amount `json:"distinctResources,omitempty"`
}

type BudgetStatus struct {
	Total     Amount `json:"total"`
	Spent     Amount `json:"spent"`
	Reserved  Amount `json:"reserved"`
	Remaining Amount `json:"remaining"`
}

type PerRequestConstraint struct {
	Allowed  []string `json:"allowed,omitempty"`
	Maximum  string   `json:"maximum,omitempty"`
	Currency string   `json:"currency,omitempty"`
	Minimum  string   `json:"minimum,omitempty"`
}

type Validity struct {
	NotBefore time.Time `json:"notBefore,omitempty"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	Duration  string    `json:"duration,omitempty"`
}

type ObjectRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}
