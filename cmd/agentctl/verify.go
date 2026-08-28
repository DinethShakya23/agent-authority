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
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
)

var (
	verifyFile   string
	verifyPubKey string
)

var verifyReceiptsCmd = &cobra.Command{
	Use:   "verify-receipts",
	Short: "Verify a JSONL receipt chain file",
	RunE:  runVerifyReceipts,
}

func runVerifyReceipts(cmd *cobra.Command, args []string) error {
	if verifyFile == "" {
		return fmt.Errorf("specify a receipts file with -f")
	}

	f, err := os.Open(verifyFile)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	var pubKey ed25519.PublicKey
	if verifyPubKey != "" {
		raw, err := base64.RawURLEncoding.DecodeString(verifyPubKey)
		if err != nil {
			return fmt.Errorf("decode public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid ed25519 public key length: got %d want %d", len(raw), ed25519.PublicKeySize)
		}
		pubKey = ed25519.PublicKey(raw)
	}

	var receipts []*v1alpha1.DecisionReceipt
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r v1alpha1.DecisionReceipt
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("parse receipt: %w", err)
		}
		receipts = append(receipts, &r)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	if len(receipts) == 0 {
		fmt.Println("no receipts found")
		return nil
	}

	errors := 0
	for i, r := range receipts {
		label := fmt.Sprintf("[%d] %s seq=%d", i, r.ReceiptID, r.Seq)

		if i > 0 {
			prev := receipts[i-1]
			if r.Seq != prev.Seq+1 {
				fmt.Printf("FAIL %s: seq not monotonic (prev=%d)\n", label, prev.Seq)
				errors++
			}
			expectedPrev, err := hashReceiptForChain(prev)
			if err != nil {
				fmt.Printf("FAIL %s: hash prev receipt: %v\n", label, err)
				errors++
			} else if r.Prev != expectedPrev {
				fmt.Printf("FAIL %s: prev hash mismatch\n  want: %s\n  got:  %s\n", label, expectedPrev, r.Prev)
				errors++
			}
		}

		if pubKey != nil {
			if err := verifyReceiptSig(r, pubKey); err != nil {
				fmt.Printf("FAIL %s: signature invalid: %v\n", label, err)
				errors++
			} else {
				fmt.Printf("OK   %s: signature valid\n", label)
			}
		} else {
			fmt.Printf("OK   %s: chain ok (no pubkey, sig not verified)\n", label)
		}
	}

	fmt.Printf("\n%d receipts checked, %d errors\n", len(receipts), errors)
	if errors > 0 {
		return fmt.Errorf("verification failed with %d error(s)", errors)
	}
	return nil
}

func hashReceiptForChain(r *v1alpha1.DecisionReceipt) (string, error) {
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

func verifyReceiptSig(r *v1alpha1.DecisionReceipt, pubKey ed25519.PublicKey) error {
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
		return fmt.Errorf("marshal payload: %w", err)
	}
	sum := sha256.Sum256(data)
	sigBytes, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pubKey, sum[:], sigBytes) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func init() {
	verifyReceiptsCmd.Flags().StringVarP(&verifyFile, "filename", "f", "", "JSONL receipts file to verify")
	verifyReceiptsCmd.Flags().StringVar(&verifyPubKey, "pubkey", "", "base64url-encoded ed25519 public key for signature verification")
	rootCmd.AddCommand(verifyReceiptsCmd)
}
