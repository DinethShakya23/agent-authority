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

// MeterExtractor extracts the meter values to reserve for this request from the
// passport budget limit and/or request payload.
// Implementations may read passport.authority.budget and request-level fields.
type MeterExtractor interface {
	// Extract returns the meters to reserve for this request.
	// The returned Meters map must use the same keys as the LeaseManager expects.
	Extract(s *integration.State) (budget.Meters, error)
}

// Budget is the ONLY mutating stage in the pipeline (§9.4 step 15).
// It atomically reserves the required meters from the local lease.
// On denial, no reservation is made and no rollback is needed.
//
// After a successful ALLOW the pipeline owner must call one of:
//   - LeaseManager.Commit  — upstream success
//   - LeaseManager.Release — clean upstream failure
//   - LeaseManager.Hold    — ambiguous upstream timeout (never release)
type Budget struct {
	lease     budget.LeaseManager
	extractor MeterExtractor
}

// NewBudget creates a Budget stage.
//   - lease is the in-process LeaseManager.
//   - extractor extracts meter values from the pipeline State.
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

	// Reserve atomically. This is the only point in the pipeline that mutates
	// external state before the upstream call; it is last so a denial never
	// needs rollback (I2: fail closed, no prior mutation).
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
