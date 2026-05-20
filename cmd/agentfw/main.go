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

	// TODO(v0.2): register the firewall pipeline handler.

	addr := ":8080"
	log.Printf("agentfw listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
