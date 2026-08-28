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

package delegation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
	"github.com/DinethShakya23/agent-authority/pkg/apierr"
)

type ChainVerifier interface {
	Verify(chain []*v1alpha1.AgentPassport, leaf *v1alpha1.AgentPassport, maxDepth int) error
}

type DefaultVerifier struct{}

func (DefaultVerifier) Verify(chain []*v1alpha1.AgentPassport, leaf *v1alpha1.AgentPassport, maxDepth int) error {
	if len(chain) == 0 {
		return apierr.New(apierr.CodeBrokenChain, "delegation chain is empty")
	}
	last := chain[len(chain)-1]
	if last.Spec.PassportID != leaf.Spec.PassportID {
		return apierr.New(apierr.CodeBrokenChain, "leaf passport does not match end of chain")
	}
	depth := len(chain) - 1
	if depth > maxDepth {
		return apierr.Newf(apierr.CodeDepthExceeded, "depth %d exceeds maxDepth %d", depth, maxDepth)
	}
	if chain[0].Spec.Delegation.Parent != "" {
		return apierr.New(apierr.CodeBrokenChain, "chain[0] must have no parent")
	}
	for i := 1; i < len(chain); i++ {
		parent := chain[i-1]
		child := chain[i]
		if child.Spec.Delegation.Parent != parent.Spec.PassportID {
			return apierr.Newf(apierr.CodeBrokenChain,
				"chain[%d].delegation.parent %q != chain[%d].passportID %q",
				i, child.Spec.Delegation.Parent, i-1, parent.Spec.PassportID)
		}
		if child.Spec.Delegation.Depth != parent.Spec.Delegation.Depth+1 {
			return apierr.Newf(apierr.CodeBrokenChain,
				"chain[%d].depth %d != chain[%d].depth+1 %d",
				i, child.Spec.Delegation.Depth, i-1, parent.Spec.Delegation.Depth+1)
		}
		if err := checkMonotonicity(parent, child); err != nil {
			return err
		}
	}
	return nil
}

func CheckMonotonicity(parent, child *v1alpha1.AgentPassport) error {
	return checkMonotonicity(parent, child)
}

func checkMonotonicity(parent, child *v1alpha1.AgentPassport) error {
	pa := parent.Spec.Authority
	ca := child.Spec.Authority

	if err := checkSubset("capabilities", toSet(pa.Capabilities), toSet(ca.Capabilities)); err != nil {
		return err
	}
	if err := checkSubset("audience", toSet(parent.Spec.Audience), toSet(child.Spec.Audience)); err != nil {
		return err
	}
	parentRes := resourceTypeSet(pa.Resources)
	childRes := resourceTypeSet(ca.Resources)
	if err := checkSubset("resources", parentRes, childRes); err != nil {
		return err
	}
	for field, childC := range ca.PerRequest {
		parentC, ok := pa.PerRequest[field]
		if !ok {
			return apierr.Newf(apierr.CodeMonotonicity,
				"child has perRequest constraint %q not present in parent", field)
		}
		if childC.Maximum != "" && parentC.Maximum != "" {
			if childC.Maximum > parentC.Maximum {
				return apierr.Newf(apierr.CodeMonotonicity,
					"child perRequest[%s].maximum %s exceeds parent %s", field, childC.Maximum, parentC.Maximum)
			}
		}
	}
	if err := checkBudgetSubset(pa.Budget, ca.Budget); err != nil {
		return err
	}
	if !child.Spec.Validity.ExpiresAt.IsZero() && !parent.Spec.Validity.ExpiresAt.IsZero() {
		if child.Spec.Validity.ExpiresAt.After(parent.Spec.Validity.ExpiresAt) {
			return apierr.New(apierr.CodeMonotonicity, "child expiresAt is later than parent")
		}
	}
	return nil
}

func checkBudgetSubset(parent, child v1alpha1.BudgetLimit) error {
	if child.Amount.Value != "" && parent.Amount.Value != "" {
		cv, err := strconv.ParseFloat(child.Amount.Value, 64)
		if err != nil {
			return apierr.Newf(apierr.CodeMonotonicity, "child budget amount value unparseable: %s", child.Amount.Value)
		}
		pv, err := strconv.ParseFloat(parent.Amount.Value, 64)
		if err != nil {
			return apierr.Newf(apierr.CodeMonotonicity, "parent budget amount value unparseable: %s", parent.Amount.Value)
		}
		if cv > pv {
			return apierr.Newf(apierr.CodeMonotonicity, "child budget amount %s exceeds parent %s", child.Amount.Value, parent.Amount.Value)
		}
	}
	if child.Calls.Value != "" && parent.Calls.Value != "" {
		cv, err := strconv.ParseFloat(child.Calls.Value, 64)
		if err != nil {
			return apierr.Newf(apierr.CodeMonotonicity, "child budget calls value unparseable: %s", child.Calls.Value)
		}
		pv, err := strconv.ParseFloat(parent.Calls.Value, 64)
		if err != nil {
			return apierr.Newf(apierr.CodeMonotonicity, "parent budget calls value unparseable: %s", parent.Calls.Value)
		}
		if cv > pv {
			return apierr.Newf(apierr.CodeMonotonicity, "child budget calls %s exceeds parent %s", child.Calls.Value, parent.Calls.Value)
		}
	}
	return nil
}

func ComputeChainHash(parentChainHash, childPassportID string) string {
	h := sha256.Sum256([]byte(parentChainHash + childPassportID))
	return hex.EncodeToString(h[:])
}

func RootChainHash(passportID string) string {
	h := sha256.Sum256([]byte(passportID))
	return hex.EncodeToString(h[:])
}

func toSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

func resourceTypeSet(rs []v1alpha1.ResourceSelector) map[string]struct{} {
	m := make(map[string]struct{}, len(rs))
	for _, r := range rs {
		m[r.Type] = struct{}{}
	}
	return m
}

func checkSubset(field string, parent, child map[string]struct{}) error {
	for k := range child {
		if _, ok := parent[k]; !ok {
			return apierr.Newf(apierr.CodeMonotonicity,
				"child %s %q is not in parent set", field, k)
		}
	}
	return nil
}

func ErrMonotonicity(msg string) error {
	return fmt.Errorf("delegation: %w", apierr.New(apierr.CodeMonotonicity, msg))
}
