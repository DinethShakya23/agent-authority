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

package cache

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/DinethShakya23/agent-authority/pkg/apierr"
)

type CachedSchemaValidator struct {
	mu      sync.RWMutex
	schemas map[string]json.RawMessage
}

func NewSchemaValidator() *CachedSchemaValidator {
	return &CachedSchemaValidator{
		schemas: make(map[string]json.RawMessage),
	}
}

func (v *CachedSchemaValidator) Validate(schemaRef string, payload []byte) error {
	v.mu.RLock()
	_, ok := v.schemas[schemaRef]
	v.mu.RUnlock()

	if !ok {
		return apierr.Newf(apierr.CodeSchemaInvalid, "schema %q not found", schemaRef)
	}

	if len(payload) == 0 {
		return nil
	}

	if !json.Valid(payload) {
		return fmt.Errorf("payload is not valid JSON")
	}

	return nil
}

func (v *CachedSchemaValidator) LoadSchema(schemaRef string, schema json.RawMessage) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.schemas[schemaRef] = schema
}
