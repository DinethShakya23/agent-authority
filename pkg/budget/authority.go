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

package budget

import (
	"context"
	"time"
)

type Meters map[string]string

type Budget struct {
	ExecutionID string
	Epoch       uint64
	Limits      Meters
	Remaining   Meters
	Leased      Meters
}

type Lease struct {
	ID          string
	ExecutionID string
	ReplicaID   string
	Epoch       uint64
	Granted     Meters
	Consumed    Meters
	Reserved    Meters
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

type LeaseRequest struct {
	ExecutionID string
	ReplicaID   string
	Hint        Meters
	Epoch       uint64
}

type Authority interface {
	AcquireLease(ctx context.Context, req LeaseRequest) (*Lease, error)
	RenewLease(ctx context.Context, leaseID string, hint Meters) (*Lease, error)
	ReleaseLease(ctx context.Context, leaseID string, consumed Meters) error
	BumpEpoch(ctx context.Context, executionID string) (uint64, error)
	Get(ctx context.Context, executionID string) (*Budget, error)
	CreateBudget(ctx context.Context, executionID string, limits Meters) (*Budget, error)
}
