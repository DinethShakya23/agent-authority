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

package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is an HTTP client used by agentctl to talk to agentd.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a Client pointed at baseURL.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

const clientAPIPrefix = "/apis/agentintegrator.dev/v1alpha1"

// Apply PUTs the object to the correct route by inspecting its kind, namespace, and name.
// obj must be JSON-serialisable and must contain top-level "kind", "metadata.name" (and
// optionally "metadata.namespace") fields.
func (c *Client) Apply(ctx context.Context, obj any) error {
	raw, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("apply: marshal: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("apply: unmarshal map: %w", err)
	}
	kind, ns, name, err := extractMeta(m)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	url := c.resourceURL(kind, ns, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("apply: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("apply: server returned %s", resp.Status)
	}
	return nil
}

// Get retrieves a single resource and JSON-unmarshals it into out.
func (c *Client) Get(ctx context.Context, kind, ns, name string, out any) error {
	url := c.resourceURL(kind, ns, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("get: new request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("get: not found: %s/%s/%s", kind, ns, name)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("get: server returned %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// List retrieves all resources of the given kind in the given namespace (empty = all
// namespaces) and JSON-unmarshals the result into out.
func (c *Client) List(ctx context.Context, kind, ns string, out any) error {
	url := c.listURL(kind, ns)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("list: new request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("list: server returned %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Delete removes a resource.
func (c *Client) Delete(ctx context.Context, kind, ns, name string) error {
	url := c.resourceURL(kind, ns, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("delete: new request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("delete: not found: %s/%s/%s", kind, ns, name)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("delete: server returned %s", resp.Status)
	}
	return nil
}

func (c *Client) resourceURL(kind, ns, name string) string {
	plural := KindToPlural(kind)
	if KindIsClusterScoped(kind) {
		return fmt.Sprintf("%s%s/%s/%s", c.BaseURL, clientAPIPrefix, plural, name)
	}
	return fmt.Sprintf("%s%s/namespaces/%s/%s/%s", c.BaseURL, clientAPIPrefix, ns, plural, name)
}

func (c *Client) listURL(kind, ns string) string {
	plural := KindToPlural(kind)
	if KindIsClusterScoped(kind) {
		return fmt.Sprintf("%s%s/%s", c.BaseURL, clientAPIPrefix, plural)
	}
	if ns == "" {
		return fmt.Sprintf("%s%s/%s", c.BaseURL, clientAPIPrefix, plural)
	}
	return fmt.Sprintf("%s%s/namespaces/%s/%s", c.BaseURL, clientAPIPrefix, ns, plural)
}

// extractMeta pulls kind, namespace, and name out of a raw JSON map.
func extractMeta(m map[string]json.RawMessage) (kind, ns, name string, err error) {
	if rawKind, ok := m["kind"]; ok {
		_ = json.Unmarshal(rawKind, &kind)
	}
	if kind == "" {
		err = fmt.Errorf("missing or empty 'kind' field")
		return
	}

	var meta map[string]json.RawMessage
	if rawMeta, ok := m["metadata"]; ok {
		_ = json.Unmarshal(rawMeta, &meta)
	}
	if meta == nil {
		err = fmt.Errorf("missing 'metadata' field")
		return
	}

	if rawName, ok := meta["name"]; ok {
		_ = json.Unmarshal(rawName, &name)
	}
	if name == "" {
		err = fmt.Errorf("missing or empty 'metadata.name' field")
		return
	}

	if rawNS, ok := meta["namespace"]; ok {
		_ = json.Unmarshal(rawNS, &ns)
	}
	return
}
