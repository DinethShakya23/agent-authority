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

package receipt

import (
	"context"
	"io"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
)

type Decision struct {
	ExecutionID     string
	PassportID      string
	Principal       v1alpha1.ReceiptPrincipal
	DelegationChain []string
	Integration     string
	Action          string
	RequestHash     string
	Decision        string
	ReasonCode      string
	Meters          v1alpha1.Meters
	BudgetAfter     map[string]string
	Policy          string
	FirewallID      string
}

type Chain interface {
	Append(ctx context.Context, d Decision) (*v1alpha1.DecisionReceipt, error)
	Head(executionID string) (hash string, seq int64)
	Export(ctx context.Context, executionID string, w io.Writer) error
}
