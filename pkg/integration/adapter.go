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

package integration

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/DinethShakya23/agent-authority/api/v1alpha1"
)

type State struct {
	RawRequest *http.Request

	Spec        string
	PassportJWS string
	CertDER     []byte
	ChainJWSs   []string
	ExecutionID string
	Timestamp   string
	Nonce       string
	Signature   []byte

	Passport       *v1alpha1.AgentPassport
	Cert           *x509.Certificate
	ChainPassports []*v1alpha1.AgentPassport

	Decision   string
	ReasonCode string
	ReasonMsg  string

	ReservationID string

	Integration string
	Upstream    *http.Request
}

type Adapter interface {
	Audience() string
	Prepare(ctx context.Context, s *State) (*http.Request, error)
	Forward(ctx context.Context, req *http.Request) (*http.Response, error)
}
