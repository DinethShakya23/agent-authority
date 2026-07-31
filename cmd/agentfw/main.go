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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/thev1ndu/agent-integrator/internal/cache"
	"github.com/thev1ndu/agent-integrator/pkg/budget"
	"github.com/thev1ndu/agent-integrator/pkg/budget/leasemanager"
	"github.com/thev1ndu/agent-integrator/pkg/delegation"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/firewall/stages"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
	"github.com/thev1ndu/agent-integrator/pkg/receipt/receiptchain"
)

var rootCmd = &cobra.Command{
	Use:   "agentfw",
	Short: "Agent Integrator firewall (data plane)",
	RunE:  run,
}

func bootstrapLease() *budget.Lease {
	return &budget.Lease{
		ID:          "dev-lease-001",
		ExecutionID: "dev-exec-001",
		ReplicaID:   "agentfw-0",
		Epoch:       0,
		Granted:     budget.Meters{"amount": "25000", "calls": "100"},
		Consumed:    budget.Meters{"amount": "0", "calls": "0"},
		Reserved:    budget.Meters{"amount": "0", "calls": "0"},
		IssuedAt:    time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(24 * time.Hour),
	}
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	audience := os.Getenv("AGENTFW_AUDIENCE")
	if audience == "" {
		audience = "https://localhost:8443"
	}
	upstreamURL := os.Getenv("AGENTFW_UPSTREAM")
	if upstreamURL == "" {
		upstreamURL = "http://localhost:9090"
	}

	adapter := integration.NewHTTPAdapter(audience, upstreamURL)
	nonceCache := stages.NewNonceCache(0)

	lease := bootstrapLease()
	lm := leasemanager.New(lease)
	extractor := stages.NewDefaultMeterExtractor()

	fwCache := cache.New(24 * time.Hour)
	fwCache.MarkRefreshed()

	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate receipt signing key: %w", err)
	}

	firewallID := os.Getenv("AGENTFW_ID")
	if firewallID == "" {
		firewallID = "agentfw-0"
	}

	rc := receiptchain.New(nil, signingKey, firewallID, 0)

	stageList := []firewall.Stage{
		stages.NewHeaders(),
		stages.NewCertificate(nil),
		stages.NewPassport(nil, nil),
		stages.NewBinding(),
		stages.NewValidity(),
		stages.NewRevocation(fwCache),
		stages.NewTimestamp(),
		stages.NewNonce(nonceCache),
		stages.NewSignature(nil),
		stages.NewAudience(),
		stages.NewCapability("", ""),
		stages.NewSchema(nil, ""),
		stages.NewConstraints(nil),
		stages.NewDelegation(nil, delegation.DefaultVerifier{}, 8),
		stages.NewBudget(lm, extractor),
	}

	pipeline := firewall.NewRunner(stageList, adapter, lm, firewall.WithReceiptChain(rc))

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pipeline.Handle(r.Context(), w, r)
	})

	addr := ":8080"
	log.Printf("agentfw listening on %s", addr)

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
