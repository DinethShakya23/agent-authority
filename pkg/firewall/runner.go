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
	"net/http"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

type Runner struct {
	stages  []Stage
	adapter integration.Adapter
}

func NewRunner(stages []Stage, adapter integration.Adapter) *Runner {
	return &Runner{stages: stages, adapter: adapter}
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

	w.Header().Set("Content-Type", "application/json")

	switch state.Decision {
	case "ALLOW":
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision":   "ALLOW",
			"reasonCode": string(apierr.CodeOK),
		})
	case "REQUIRE_APPROVAL":
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision":   "REQUIRE_APPROVAL",
			"reasonCode": string(apierr.CodeApprovalRequired),
			"message":    state.ReasonMsg,
		})
	default:
		w.WriteHeader(apierr.HTTPStatus(apierr.Code(state.ReasonCode)))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision":   "DENY",
			"reasonCode": state.ReasonCode,
			"message":    state.ReasonMsg,
		})
	}
}
