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

// Command agentd is the Agent Integrator control plane:
// API server, controllers, WSO2 federation, policy engine,
// passport authority, budget authority, CA client.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"github.com/thev1ndu/agent-integrator/internal/apiserver"
	boltstore "github.com/thev1ndu/agent-integrator/pkg/store/bbolt"
)

var rootCmd = &cobra.Command{
	Use:   "agentd",
	Short: "Agent Integrator control plane",
	RunE:  run,
}

var cfgFile string

func init() {
	rootCmd.Flags().StringVar(&cfgFile, "config", "agentd.yaml", "config file")
}

func run(cmd *cobra.Command, args []string) error {
	dbPath := os.Getenv("AGENTD_DB_PATH")
	if dbPath == "" {
		dbPath = "/var/lib/agentd/state.db"
	}

	st, err := boltstore.Open(dbPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Printf("agentd: store close: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	apiSrv := apiserver.New(st)
	mux.Handle("/apis/", apiSrv.Handler())

	addr := ":8443"
	log.Printf("agentd listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func main() {
	_ = context.Background()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
