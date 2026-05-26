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

// Package wso2 provides an identity adapter for the WSO2 Identity Platform.
//
// It implements identity.Federator and self-registers as provider type "wso2".
// Import this package (blank import) to activate WSO2 support:
//
//	import _ "github.com/thev1ndu/agent-integrator/pkg/identity/wso2"
//
// Two token shapes are accepted (AIP-1 §5.2):
//
//	autonomous:    sub = agent_id
//	on-behalf-of:  sub = human_id, act.sub = agent_id
//
// ProviderConfig.Extras keys recognised by this adapter:
//
//	"organization"               (string) – WSO2 tenant path segment (/t/{org})
//	"introspect"                 (bool)   – enable token introspection
//	"introspect_credentials_ref" (string) – secret reference for introspection credentials
package wso2

import (
	"context"
	"fmt"
	"time"

	"github.com/thev1ndu/agent-integrator/pkg/identity"
	"github.com/thev1ndu/agent-integrator/pkg/store"
)

func init() {
	identity.DefaultRegistry.Register("wso2", Factory)
}

// Factory creates a WSO2-backed identity.Federator from a ProviderConfig.
// Called by identity.DefaultRegistry.Build when Type == "wso2".
func Factory(cfg identity.ProviderConfig, s store.Store) (identity.Federator, error) {
	if cfg.WellKnown == "" {
		return nil, fmt.Errorf("wso2: ProviderConfig.WellKnown is required")
	}
	wCfg := Config{
		WellKnown:        cfg.WellKnown,
		Audience:         cfg.Audience,
		JWKSRefresh:      cfg.JWKSRefresh,
		AcceptOnBehalfOf: cfg.AcceptOnBehalfOf,
	}
	if org, ok := cfg.Extras["organization"].(string); ok {
		wCfg.Organization = org
	}
	if v, ok := cfg.Extras["introspect"].(bool); ok {
		wCfg.Introspect = v
	}
	if ref, ok := cfg.Extras["introspect_credentials_ref"].(string); ok {
		wCfg.IntrospectCredentialsRef = ref
	}
	return NewFederator(wCfg, s), nil
}

// SCIMSync imports agents from WSO2's SCIM2 endpoint and materialises them
// as Agent resources in the local store. Synced agents carry ManagedBy="wso2".
type SCIMSync interface {
	// Sync performs one synchronisation pass.
	// Returns counts of agents added, updated, and suspended.
	Sync(ctx context.Context) (added, updated, suspended int, err error)
}

// Config holds WSO2-specific connection parameters (loaded from agentd.yaml §17).
// Generic fields (WellKnown, Audience, JWKSRefresh, AcceptOnBehalfOf) are
// populated from ProviderConfig by Factory.
type Config struct {
	Organization             string        // /t/{org} tenant path
	WellKnown                string        // OIDC discovery URL (also used as issuer in WSO2)
	Audience                 string        // expected aud claim value
	JWKSRefresh              time.Duration
	Introspect               bool
	IntrospectCredentialsRef string
	AcceptOnBehalfOf         bool
	SCIM2                    SCIM2Config
}

// SCIM2Config holds settings for the optional agent roster sync.
type SCIM2Config struct {
	Enabled         bool
	Endpoint        string
	CredentialsRef  string
	SyncInterval    time.Duration
	RoleLabelPrefix string // e.g. "wso2.role/"
}
