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
	"context"
	"fmt"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/budget"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

type MeterExtractor interface {
	Extract(s *integration.State) (budget.Meters, error)
}

type Budget struct {
	lease     budget.LeaseManager
	extractor MeterExtractor
}

func NewBudget(lease budget.LeaseManager, extractor MeterExtractor) *Budget {
	return &Budget{lease: lease, extractor: extractor}
}

func (Budget) Name() string { return "15_budget" }

func (b Budget) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Passport == nil {
		s.ReasonCode = string(apierr.CodePassportInvalid)
		s.ReasonMsg = "passport not populated (stage 3 must run first)"
		return firewall.Deny, nil
	}
	if b.lease == nil {
		s.ReasonCode = string(apierr.CodeLeaseUnavailable)
		s.ReasonMsg = "no lease manager configured"
		return firewall.Deny, nil
	}

	meters, err := b.extractor.Extract(s)
	if err != nil {
		s.ReasonCode = string(apierr.CodeLeaseUnavailable)
		s.ReasonMsg = fmt.Sprintf("meter extraction failed: %v", err)
		return firewall.Deny, nil
	}

	reservationID, err := b.lease.Reserve(s.ExecutionID, meters)
	if err != nil {
		if aerr, ok := err.(*apierr.Error); ok {
			s.ReasonCode = string(aerr.Code)
			s.ReasonMsg = aerr.Message
		} else {
			s.ReasonCode = string(apierr.CodeBudgetExhausted)
			s.ReasonMsg = fmt.Sprintf("budget reservation failed: %v", err)
		}
		return firewall.Deny, nil
	}

	s.ReservationID = string(reservationID)
	return firewall.Continue, nil
}
