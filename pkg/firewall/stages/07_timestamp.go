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
	"time"

	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/firewall"
	"github.com/DinethShakya23/agent-authority/pkg/integration"
)

const timestampWindow = 30 * time.Second

type Timestamp struct{}

func NewTimestamp() *Timestamp { return &Timestamp{} }

func (Timestamp) Name() string { return "07_timestamp" }

func (Timestamp) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if s.Timestamp == "" {
		s.ReasonCode = string(apierr.CodeTimestampWindow)
		s.ReasonMsg = "timestamp is empty (stage 1 must run first)"
		return firewall.Deny, nil
	}

	ts, err := time.Parse(time.RFC3339Nano, s.Timestamp)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, s.Timestamp)
		if err != nil {
			s.ReasonCode = string(apierr.CodeTimestampWindow)
			s.ReasonMsg = fmt.Sprintf("AI-Timestamp parse error: %v", err)
			return firewall.Deny, nil
		}
	}

	now := time.Now().UTC()
	diff := now.Sub(ts.UTC())
	if diff < 0 {
		diff = -diff
	}
	if diff > timestampWindow {
		s.ReasonCode = string(apierr.CodeTimestampWindow)
		s.ReasonMsg = fmt.Sprintf("AI-Timestamp %s is outside ±%s window (now=%s, diff=%s)",
			s.Timestamp, timestampWindow, now.Format(time.RFC3339), diff)
		return firewall.Deny, nil
	}

	return firewall.Continue, nil
}
