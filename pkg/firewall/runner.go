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

package firewall

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/budget"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

type Runner struct {
	stages       []Stage
	adapter      integration.Adapter
	leaseManager budget.LeaseManager
}

func NewRunner(stages []Stage, adapter integration.Adapter, lm budget.LeaseManager) *Runner {
	return &Runner{stages: stages, adapter: adapter, leaseManager: lm}
}

func (r *Runner) Stages() []Stage {
	return r.stages
}

func (r *Runner) Handle(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	state := integration.State{
		RawRequest:  req,
		Integration: r.adapter.Audience(),
	}

	for _, stage := range r.stages {
		outcome, err := stage.Run(ctx, &state)
		if err != nil {
			state.Decision = "DENY"
			state.ReasonCode = string(apierr.CodeMisconfiguration)
			state.ReasonMsg = err.Error()
			break
		}
		switch outcome {
		case Deny:
			state.Decision = "DENY"
		case Approve:
			state.Decision = "REQUIRE_APPROVAL"
		case Continue:
			continue
		default:
			state.Decision = "DENY"
			state.ReasonCode = string(apierr.CodeMisconfiguration)
			state.ReasonMsg = "unexpected stage outcome"
		}
		break
	}

	if state.Decision == "" {
		state.Decision = "ALLOW"
	}

	switch state.Decision {
	case "ALLOW":
		upstreamReq, err := r.adapter.Prepare(ctx, &state)
		if err != nil {
			r.holdReservation(&state)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"decision":   "DENY",
				"reasonCode": string(apierr.CodeMisconfiguration),
				"message":    err.Error(),
			})
			return
		}

		resp, err := r.adapter.Forward(ctx, upstreamReq)
		if err != nil {
			r.holdReservation(&state)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"decision":   "DENY",
				"reasonCode": string(apierr.CodeMisconfiguration),
				"message":    "upstream unreachable",
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			r.commitReservation(&state)
		} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			r.releaseReservation(&state)
		} else {
			r.holdReservation(&state)
		}

		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case "REQUIRE_APPROVAL":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision":   "REQUIRE_APPROVAL",
			"reasonCode": string(apierr.CodeApprovalRequired),
			"message":    state.ReasonMsg,
		})

	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(apierr.HTTPStatus(apierr.Code(state.ReasonCode)))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision":   "DENY",
			"reasonCode": state.ReasonCode,
			"message":    state.ReasonMsg,
		})
	}
}

func (r *Runner) commitReservation(state *integration.State) {
	if r.leaseManager == nil || state.ReservationID == "" {
		return
	}
	_ = r.leaseManager.Commit(budget.ReservationID(state.ReservationID))
}

func (r *Runner) releaseReservation(state *integration.State) {
	if r.leaseManager == nil || state.ReservationID == "" {
		return
	}
	_ = r.leaseManager.Release(budget.ReservationID(state.ReservationID))
}

func (r *Runner) holdReservation(state *integration.State) {
	if r.leaseManager == nil || state.ReservationID == "" {
		return
	}
	_ = r.leaseManager.Hold(budget.ReservationID(state.ReservationID))
}
