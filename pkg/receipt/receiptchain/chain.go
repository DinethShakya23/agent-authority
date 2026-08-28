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

package receiptchain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/receipt"
	"github.com/DinethShakya23/agent-authority/pkg/store"
)

type headEntry struct {
	hash string
	seq  int64
}

type ReceiptChain struct {
	store      store.Store
	signingKey ed25519.PrivateKey
	firewallID string
	seqStart   int64
	mu         sync.Mutex
	heads      map[string]*headEntry
}

func New(s store.Store, signingKey ed25519.PrivateKey, firewallID string, seqStart int64) *ReceiptChain {
	return &ReceiptChain{
		store:      s,
		signingKey: signingKey,
		firewallID: firewallID,
		seqStart:   seqStart,
		heads:      make(map[string]*headEntry),
	}
}

func generateReceiptID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "rcpt_" + hex.EncodeToString(b), nil
}

func initialPrev(executionID string) string {
	sum := sha256.Sum256([]byte(executionID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashReceipt(r *v1alpha1.DecisionReceipt) (string, error) {
	type receiptForHash struct {
		Spec            string                   `json:"spec"`
		ReceiptID       string                   `json:"receiptID"`
		Seq             int64                    `json:"seq"`
		Prev            string                   `json:"prev"`
		ExecutionID     string                   `json:"executionID"`
		PassportID      string                   `json:"passportID"`
		Principal       v1alpha1.ReceiptPrincipal `json:"principal"`
		DelegationChain []string                 `json:"delegationChain,omitempty"`
		Integration     string                   `json:"integration"`
		Action          string                   `json:"action"`
		RequestHash     string                   `json:"requestHash"`
		Decision        string                   `json:"decision"`
		ReasonCode      string                   `json:"reasonCode"`
		Meters          v1alpha1.Meters          `json:"meters,omitempty"`
		BudgetAfter     map[string]string        `json:"budgetAfter,omitempty"`
		Policy          string                   `json:"policy"`
		FirewallID      string                   `json:"firewallID"`
		Timestamp       time.Time                `json:"timestamp"`
		Signature       string                   `json:"signature"`
	}
	h := receiptForHash{
		Spec:            r.Spec,
		ReceiptID:       r.ReceiptID,
		Seq:             r.Seq,
		Prev:            r.Prev,
		ExecutionID:     r.ExecutionID,
		PassportID:      r.PassportID,
		Principal:       r.Principal,
		DelegationChain: r.DelegationChain,
		Integration:     r.Integration,
		Action:          r.Action,
		RequestHash:     r.RequestHash,
		Decision:        r.Decision,
		ReasonCode:      r.ReasonCode,
		Meters:          r.Meters,
		BudgetAfter:     r.BudgetAfter,
		Policy:          r.Policy,
		FirewallID:      r.FirewallID,
		Timestamp:       r.Timestamp,
		Signature:       r.Signature,
	}
	data, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func signReceipt(r *v1alpha1.DecisionReceipt, key ed25519.PrivateKey) (string, error) {
	type receiptPayload struct {
		Spec            string                   `json:"spec"`
		ReceiptID       string                   `json:"receiptID"`
		Seq             int64                    `json:"seq"`
		Prev            string                   `json:"prev"`
		ExecutionID     string                   `json:"executionID"`
		PassportID      string                   `json:"passportID"`
		Principal       v1alpha1.ReceiptPrincipal `json:"principal"`
		DelegationChain []string                 `json:"delegationChain,omitempty"`
		Integration     string                   `json:"integration"`
		Action          string                   `json:"action"`
		RequestHash     string                   `json:"requestHash"`
		Decision        string                   `json:"decision"`
		ReasonCode      string                   `json:"reasonCode"`
		Meters          v1alpha1.Meters          `json:"meters,omitempty"`
		BudgetAfter     map[string]string        `json:"budgetAfter,omitempty"`
		Policy          string                   `json:"policy"`
		FirewallID      string                   `json:"firewallID"`
		Timestamp       time.Time                `json:"timestamp"`
	}
	payload := receiptPayload{
		Spec:            r.Spec,
		ReceiptID:       r.ReceiptID,
		Seq:             r.Seq,
		Prev:            r.Prev,
		ExecutionID:     r.ExecutionID,
		PassportID:      r.PassportID,
		Principal:       r.Principal,
		DelegationChain: r.DelegationChain,
		Integration:     r.Integration,
		Action:          r.Action,
		RequestHash:     r.RequestHash,
		Decision:        r.Decision,
		ReasonCode:      r.ReasonCode,
		Meters:          r.Meters,
		BudgetAfter:     r.BudgetAfter,
		Policy:          r.Policy,
		FirewallID:      r.FirewallID,
		Timestamp:       r.Timestamp,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	sig := ed25519.Sign(key, sum[:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *ReceiptChain) Append(ctx context.Context, d receipt.Decision) (*v1alpha1.DecisionReceipt, error) {
	receiptID, err := generateReceiptID()
	if err != nil {
		return nil, fmt.Errorf("receiptchain: generate receipt ID: %w", err)
	}

	c.mu.Lock()
	entry, ok := c.heads[d.ExecutionID]
	var prevHash string
	var seq int64
	if !ok {
		prevHash = initialPrev(d.ExecutionID)
		seq = c.seqStart
	} else {
		prevHash = entry.hash
		seq = entry.seq + 1
	}
	c.mu.Unlock()

	r := &v1alpha1.DecisionReceipt{
		Spec:            "AIP-1/v0.1",
		ReceiptID:       receiptID,
		Seq:             seq,
		Prev:            prevHash,
		ExecutionID:     d.ExecutionID,
		PassportID:      d.PassportID,
		Principal:       d.Principal,
		DelegationChain: d.DelegationChain,
		Integration:     d.Integration,
		Action:          d.Action,
		RequestHash:     d.RequestHash,
		Decision:        d.Decision,
		ReasonCode:      d.ReasonCode,
		Meters:          d.Meters,
		BudgetAfter:     d.BudgetAfter,
		Policy:          d.Policy,
		FirewallID:      d.FirewallID,
		Timestamp:       time.Now().UTC(),
	}

	sig, err := signReceipt(r, c.signingKey)
	if err != nil {
		return nil, fmt.Errorf("receiptchain: sign receipt: %w", err)
	}
	r.Signature = sig

	newHash, err := hashReceipt(r)
	if err != nil {
		return nil, fmt.Errorf("receiptchain: hash receipt: %w", err)
	}

	storeKey := fmt.Sprintf("receipts/%s/%d", d.ExecutionID, seq)
	if c.store != nil {
		if err := c.store.Put(ctx, storeKey, r); err != nil {
			return nil, fmt.Errorf("receiptchain: store receipt: %w", err)
		}
	}

	c.mu.Lock()
	c.heads[d.ExecutionID] = &headEntry{hash: newHash, seq: seq}
	c.mu.Unlock()

	return r, nil
}

func (c *ReceiptChain) Head(executionID string) (string, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.heads[executionID]
	if !ok {
		return "", -1
	}
	return entry.hash, entry.seq
}

func (c *ReceiptChain) Export(ctx context.Context, executionID string, w io.Writer) error {
	if c.store == nil {
		return nil
	}
	prefix := fmt.Sprintf("receipts/%s/", executionID)
	var receipts []*v1alpha1.DecisionReceipt
	if err := c.store.List(ctx, prefix, &receipts); err != nil {
		return fmt.Errorf("receiptchain: list receipts: %w", err)
	}
	enc := json.NewEncoder(w)
	for _, r := range receipts {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("receiptchain: encode receipt: %w", err)
		}
	}
	return nil
}
