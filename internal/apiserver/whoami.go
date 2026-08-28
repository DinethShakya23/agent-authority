// Copyright 2026 Agent Authority Authors
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

package apiserver

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/DinethShakya23/agent-authority/pkg/identity"
)

type WhoamiResponse struct {
	Agent     string   `json:"agent"`
	Namespace string   `json:"namespace"`
	Human     string   `json:"human,omitempty"`
	Issuer    string   `json:"issuer"`
	Provider  string   `json:"provider"`
	Scopes    []string `json:"scopes,omitempty"`
	Phase     string   `json:"phase"`
}

func WhoamiHandler(fed identity.Federator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		token := body.Token
		if token == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if token == "" {
			http.Error(w, "token required (JSON body or Authorization header)", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		principal, err := fed.Verify(ctx, token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		agent, err := fed.Resolve(ctx, principal)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		resp := WhoamiResponse{
			Agent:     agent.Name,
			Namespace: agent.Namespace,
			Human:     principal.HumanPrincipal,
			Issuer:    principal.Issuer,
			Provider:  principal.ProviderType,
			Scopes:    principal.Scopes,
			Phase:     agent.Status.Phase,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}
