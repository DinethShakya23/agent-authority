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

package stages

import (
	"github.com/DinethShakya23/agent-authority/pkg/budget"
	"github.com/DinethShakya23/agent-authority/pkg/integration"
)

type DefaultMeterExtractor struct{}

func NewDefaultMeterExtractor() *DefaultMeterExtractor {
	return &DefaultMeterExtractor{}
}

func (e *DefaultMeterExtractor) Extract(s *integration.State) (budget.Meters, error) {
	meters := budget.Meters{}
	meters["calls"] = "1"
	if s.Passport != nil && s.Passport.Spec.Authority.Budget.Amount.Value != "" {
		meters["amount"] = s.Passport.Spec.Authority.Budget.Amount.Value
	}
	return meters, nil
}
