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

package leasemanager

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/budget"
)

type reservation struct {
	id     budget.ReservationID
	values budget.Meters
	held   bool
}

type manager struct {
	mu           sync.Mutex
	lease        *budget.Lease
	reservations map[budget.ReservationID]*reservation
	nextID       int64
}

func New(l *budget.Lease) budget.LeaseManager {
	return &manager{
		lease:        l,
		reservations: make(map[budget.ReservationID]*reservation),
	}
}

func (m *manager) newID() budget.ReservationID {
	n := atomic.AddInt64(&m.nextID, 1)
	return budget.ReservationID(fmt.Sprintf("rsv-%d", n))
}

func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func (m *manager) available(meter string) float64 {
	granted := parseFloat(m.lease.Granted[meter])
	consumed := parseFloat(m.lease.Consumed[meter])
	reserved := 0.0
	for _, r := range m.reservations {
		reserved += parseFloat(r.values[meter])
	}
	return granted - consumed - reserved
}

func (m *manager) Reserve(executionID string, values budget.Meters) (budget.ReservationID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lease == nil {
		return "", apierr.New(apierr.CodeLeaseUnavailable, "no active lease")
	}
	if m.lease.ExecutionID != executionID {
		return "", apierr.Newf(apierr.CodeLeaseUnavailable,
			"lease execution mismatch: want %s got %s", executionID, m.lease.ExecutionID)
	}

	for meter, valStr := range values {
		val := parseFloat(valStr)
		avail := m.available(meter)
		if avail < val {
			code := apierr.CodeBudgetExhausted
			switch meter {
			case "calls":
				code = apierr.CodeCallLimit
			case "distinctResources", "distinct_resources":
				code = apierr.CodeDistinctLimit
			}
			return "", apierr.Newf(code,
				"meter %s: need %.6f available %.6f", meter, val, avail)
		}
	}

	id := m.newID()
	m.reservations[id] = &reservation{
		id:     id,
		values: values,
		held:   false,
	}
	return id, nil
}

func (m *manager) Commit(id budget.ReservationID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.reservations[id]
	if !ok {
		return fmt.Errorf("leasemanager: reservation %s not found (already committed/held?)", id)
	}
	if r.held {
		return fmt.Errorf("leasemanager: reservation %s is held — cannot commit", id)
	}

	for meter, valStr := range r.values {
		cur := parseFloat(m.lease.Consumed[meter])
		m.lease.Consumed[meter] = formatFloat(cur + parseFloat(valStr))
	}
	delete(m.reservations, id)
	return nil
}

func (m *manager) Release(id budget.ReservationID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.reservations[id]
	if !ok {
		return nil
	}
	if r.held {
		return nil
	}
	delete(m.reservations, id)
	return nil
}

func (m *manager) Hold(id budget.ReservationID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.reservations[id]
	if !ok {
		return fmt.Errorf("leasemanager: reservation %s not found", id)
	}
	r.held = true
	return nil
}

func (m *manager) Stats() budget.LeaseStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lease == nil {
		return budget.LeaseStats{}
	}

	reserved := make(budget.Meters)
	for _, r := range m.reservations {
		for meter, valStr := range r.values {
			cur := parseFloat(reserved[meter])
			reserved[meter] = formatFloat(cur + parseFloat(valStr))
		}
	}

	available := make(budget.Meters)
	for meter, grantedStr := range m.lease.Granted {
		granted := parseFloat(grantedStr)
		consumed := parseFloat(m.lease.Consumed[meter])
		res := parseFloat(reserved[meter])
		avail := granted - consumed - res
		if avail < 0 {
			avail = 0
		}
		available[meter] = formatFloat(avail)
	}

	return budget.LeaseStats{
		LeaseID:   m.lease.ID,
		Granted:   cloneMeters(m.lease.Granted),
		Consumed:  cloneMeters(m.lease.Consumed),
		Reserved:  reserved,
		Available: available,
	}
}

func (m *manager) RefreshLease(l *budget.Lease) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lease = l
}

func cloneMeters(src budget.Meters) budget.Meters {
	if src == nil {
		return nil
	}
	dst := make(budget.Meters, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
