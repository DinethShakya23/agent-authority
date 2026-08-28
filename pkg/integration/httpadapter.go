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

package integration

import (
	"context"
	"net/http"
)

type HTTPAdapter struct {
	audience    string
	upstreamURL string
	client      *http.Client
}

func NewHTTPAdapter(audience, upstreamURL string) *HTTPAdapter {
	return &HTTPAdapter{
		audience:    audience,
		upstreamURL: upstreamURL,
		client:      &http.Client{},
	}
}

func (a *HTTPAdapter) Audience() string {
	return a.audience
}

func (a *HTTPAdapter) Prepare(ctx context.Context, s *State) (*http.Request, error) {
	upstream, err := http.NewRequestWithContext(ctx, s.RawRequest.Method, a.upstreamURL+s.RawRequest.URL.RequestURI(), s.RawRequest.Body)
	if err != nil {
		return nil, err
	}
	for k, vals := range s.RawRequest.Header {
		for _, v := range vals {
			upstream.Header.Add(k, v)
		}
	}
	return upstream, nil
}

func (a *HTTPAdapter) Forward(ctx context.Context, req *http.Request) (*http.Response, error) {
	return a.client.Do(req)
}
