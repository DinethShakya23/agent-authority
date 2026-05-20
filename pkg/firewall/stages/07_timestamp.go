package stages

import (
	"context"
	"fmt"
	"time"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// timestampWindow is the maximum age (or future skew) for AI-Timestamp (§9.4 step 7).
const timestampWindow = 30 * time.Second

// Timestamp checks that |now - AI-Timestamp| <= 30s (step 7 of §9.4).
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
		// Also try RFC3339 without sub-second precision.
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
