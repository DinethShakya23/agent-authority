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
	// Ensure context is available for deferred store close.
	_ = context.Background()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
