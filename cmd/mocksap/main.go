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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

type purchaseOrder struct {
	ID          string    `json:"id"`
	Vendor      string    `json:"vendor"`
	Amount      float64   `json:"amount"`
	Currency    string    `json:"currency"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
}

type createPORequest struct {
	Vendor      string  `json:"vendor"`
	Amount      float64 `json:"amount"`
	Currency    string  `json:"currency"`
	Description string  `json:"description"`
}

var (
	mu      sync.RWMutex
	poStore = map[string]*purchaseOrder{}
	poSeq   int
)

var rootCmd = &cobra.Command{
	Use:   "mocksap",
	Short: "Mock SAP backend for Agent Authority demo",
	RunE:  run,
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/api/purchase-orders", handlePurchaseOrders)
	mux.HandleFunc("/api/purchase-orders/", handlePurchaseOrderByID)

	addr := ":9090"
	log.Printf("mocksap listening on %s", addr)

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

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func handlePurchaseOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req createPORequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Currency == "" {
		req.Currency = "USD"
	}
	if req.Vendor == "" {
		http.Error(w, "vendor is required", http.StatusBadRequest)
		return
	}

	mu.Lock()
	poSeq++
	id := fmt.Sprintf("PO-%06d", poSeq)
	po := &purchaseOrder{
		ID:          id,
		Vendor:      req.Vendor,
		Amount:      req.Amount,
		Currency:    req.Currency,
		Description: req.Description,
		Status:      "OPEN",
		CreatedAt:   time.Now().UTC(),
	}
	poStore[id] = po
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(po)
}

func handlePurchaseOrderByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/purchase-orders/")
	if id == "" {
		http.Error(w, "missing purchase order id", http.StatusBadRequest)
		return
	}

	mu.RLock()
	po, ok := poStore[id]
	mu.RUnlock()

	if !ok {
		http.Error(w, "purchase order not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(po)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
