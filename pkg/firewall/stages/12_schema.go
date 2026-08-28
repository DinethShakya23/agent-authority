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

package stages

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/DinethShakya23/agent-authority/pkg/apierr"
	"github.com/DinethShakya23/agent-authority/pkg/firewall"
	"github.com/DinethShakya23/agent-authority/pkg/integration"
)

type SchemaValidator interface {
	Validate(schemaRef string, payload []byte) error
}

type Schema struct {
	validator SchemaValidator
	schemaRef string
}

func NewSchema(validator SchemaValidator, schemaRef string) *Schema {
	return &Schema{validator: validator, schemaRef: schemaRef}
}

func (Schema) Name() string { return "12_schema" }

func (sc Schema) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	if sc.schemaRef == "" || sc.validator == nil {
		return firewall.Continue, nil
	}

	r := s.RawRequest
	if r == nil {
		s.ReasonCode = string(apierr.CodeSchemaInvalid)
		s.ReasonMsg = "raw request not set"
		return firewall.Deny, nil
	}

	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			s.ReasonCode = string(apierr.CodeSchemaInvalid)
			s.ReasonMsg = fmt.Sprintf("failed to read request body for schema validation: %v", err)
			return firewall.Deny, nil
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	if err := sc.validator.Validate(sc.schemaRef, body); err != nil {
		s.ReasonCode = string(apierr.CodeSchemaInvalid)
		s.ReasonMsg = fmt.Sprintf("payload schema validation failed (%s): %v", sc.schemaRef, err)
		return firewall.Deny, nil
	}

	return firewall.Continue, nil
}
