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

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/thev1ndu/agent-integrator/internal/apiserver"
	agentctrl "github.com/thev1ndu/agent-integrator/internal/controller/agent"
	capctrl "github.com/thev1ndu/agent-integrator/internal/controller/capability"
	integctrl "github.com/thev1ndu/agent-integrator/internal/controller/integration"
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
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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

	go func() {
		if err := agentctrl.New(st).Run(ctx); err != nil {
			log.Printf("agent controller: %v", err)
		}
	}()
	go func() {
		if err := capctrl.New(st).Run(ctx); err != nil {
			log.Printf("capability controller: %v", err)
		}
	}()
	go func() {
		if err := integctrl.New(st).Run(ctx); err != nil {
			log.Printf("integration controller: %v", err)
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

	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
