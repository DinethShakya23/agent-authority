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
	"fmt"
	"io"
	"net/http"

	"github.com/thev1ndu/agent-integrator/api/v1alpha1"
	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/budget"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
	"github.com/thev1ndu/agent-integrator/pkg/receipt"
)

type Runner struct {
	stages       []Stage
	adapter      integration.Adapter
	leaseManager budget.LeaseManager
	receiptChain receipt.Chain
}

func NewRunner(stages []Stage, adapter integration.Adapter, lm budget.LeaseManager, opts ...RunnerOption) *Runner {
	r := &Runner{stages: stages, adapter: adapter, leaseManager: lm}
	for _, o := range opts {
		o(r)
	}
	return r
}

type RunnerOption func(*Runner)

func WithReceiptChain(c receipt.Chain) RunnerOption {
	return func(r *Runner) { r.receiptChain = c }
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
			state.Decision = "DENY"
			state.ReasonCode = string(apierr.CodeMisconfiguration)
			state.ReasonMsg = err.Error()
			r.emitReceipt(ctx, &state)
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
			state.Decision = "DENY"
			state.ReasonCode = string(apierr.CodeMisconfiguration)
			state.ReasonMsg = "upstream unreachable"
			r.emitReceipt(ctx, &state)
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

		rcpt := r.emitReceipt(ctx, &state)

		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		if rcpt != nil {
			w.Header().Set("AI-Receipt", rcpt.ReceiptID)
			if r.leaseManager != nil {
				stats := r.leaseManager.Stats()
				w.Header().Set("AI-Budget-Remaining", r.budgetRemainingHeader(stats.Available))
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)

	case "REQUIRE_APPROVAL":
		r.emitReceipt(ctx, &state)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision":   "REQUIRE_APPROVAL",
			"reasonCode": string(apierr.CodeApprovalRequired),
			"message":    state.ReasonMsg,
		})

	default:
		r.emitReceipt(ctx, &state)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(apierr.HTTPStatus(apierr.Code(state.ReasonCode)))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision":   "DENY",
			"reasonCode": state.ReasonCode,
			"message":    state.ReasonMsg,
		})
	}
}

func (r *Runner) emitReceipt(ctx context.Context, state *integration.State) *v1alpha1.DecisionReceipt {
	if r.receiptChain == nil {
		return nil
	}
	d := r.buildDecision(state)
	var result *v1alpha1.DecisionReceipt
	ch := make(chan *v1alpha1.DecisionReceipt, 1)
	go func() {
		rec, err := r.receiptChain.Append(ctx, d)
		if err != nil {
			ch <- nil
			return
		}
		ch <- rec
	}()
	result = <-ch
	return result
}

func (r *Runner) buildDecision(state *integration.State) receipt.Decision {
	d := receipt.Decision{
		ExecutionID: state.ExecutionID,
		Integration: state.Integration,
		Decision:    state.Decision,
		ReasonCode:  state.ReasonCode,
		FirewallID:  r.adapter.Audience(),
	}
	if state.Passport != nil {
		d.PassportID = state.Passport.Spec.PassportID
		d.Principal = v1alpha1.ReceiptPrincipal{
			Agent: state.Passport.Spec.Agent.ID,
			Human: state.Passport.Spec.Agent.OnBehalfOf,
		}
		d.Policy = state.Passport.Spec.Policy.Name
	}
	if len(state.ChainPassports) > 0 {
		chain := make([]string, 0, len(state.ChainPassports))
		for _, cp := range state.ChainPassports {
			chain = append(chain, cp.Spec.PassportID)
		}
		d.DelegationChain = chain
	}
	return d
}

func (r *Runner) budgetRemainingHeader(available budget.Meters) string {
	amount := available["amount"]
	calls := available["calls"]
	return fmt.Sprintf("amount=%s;calls=%s", amount, calls)
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
