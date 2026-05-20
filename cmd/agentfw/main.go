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

// Command agentfw is the Agent Integrator data plane: the Agent Firewall.
// It verifies, evaluates, meters, decides, forwards, and emits receipts.
//
// Invariant: no synchronous control-plane or WSO2 call on the request path.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "agentfw",
	Short: "Agent Integrator firewall (data plane)",
	RunE:  run,
}

func run(cmd *cobra.Command, args []string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := ":8080"
	log.Printf("agentfw listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
