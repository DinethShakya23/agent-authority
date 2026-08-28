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

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/DinethShakya23/agent-authority/internal/apiserver"
	"github.com/DinethShakya23/agent-authority/internal/cache"
	agentctrl "github.com/DinethShakya23/agent-authority/internal/controller/agent"
	capctrl "github.com/DinethShakya23/agent-authority/internal/controller/capability"
	idsyncctrl "github.com/DinethShakya23/agent-authority/internal/controller/identitysync"
	integctrl "github.com/DinethShakya23/agent-authority/internal/controller/integration"
	passportctrl "github.com/DinethShakya23/agent-authority/internal/controller/passport"
	policectrl "github.com/DinethShakya23/agent-authority/internal/controller/policy"
	"github.com/DinethShakya23/agent-authority/internal/epochbumper"
	"github.com/DinethShakya23/agent-authority/pkg/authority"
	"github.com/DinethShakya23/agent-authority/pkg/budget/budgetauth"
	"github.com/DinethShakya23/agent-authority/pkg/identity"
	_ "github.com/DinethShakya23/agent-authority/pkg/identity/oidc"
	boltstore "github.com/DinethShakya23/agent-authority/pkg/store/bbolt"
)

var rootCmd = &cobra.Command{
	Use:   "agentd",
	Short: "Agent Integrator control plane",
	RunE:  run,
}

var cfgFile string

func init() {
	rootCmd.Flags().StringVar(&cfgFile, "config", "agentd.yaml", "config file")
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dbPath := os.Getenv("AGENTD_DB_PATH")
	if dbPath == "" {
		dbPath = "/var/lib/agentd/state.db"
	}

	st, err := boltstore.Open(dbPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Printf("agentd: store close: %v", err)
		}
	}()

	go func() {
		if err := agentctrl.New(st).Run(ctx); err != nil {
			log.Printf("agent controller: %v", err)
		}
	}()
	go func() {
		if err := capctrl.New(st).Run(ctx); err != nil {
			log.Printf("capability controller: %v", err)
		}
	}()
	go func() {
		if err := integctrl.New(st).Run(ctx); err != nil {
			log.Printf("integration controller: %v", err)
		}
	}()
	go func() {
		if err := passportctrl.New(st).Run(ctx); err != nil {
			log.Printf("passport controller: %v", err)
		}
	}()

	engine := authority.NewEngine(st)
	go func() {
		if err := policectrl.New(st, engine).Run(ctx); err != nil {
			log.Printf("policy controller: %v", err)
		}
	}()

	budgetAuth := budgetauth.New(st, budgetauth.Config{
		MaxLeaseFraction: 0.25,
		LeaseTTL:         30 * time.Second,
		SweepInterval:    5 * time.Second,
	})
	go func() {
		if err := budgetAuth.Run(ctx); err != nil {
			log.Printf("budget sweeper: %v", err)
		}
	}()

	fwCache := cache.New(10 * time.Second)
	watcher := cache.NewWatcher(st, fwCache)
	go func() {
		if err := watcher.Run(ctx); err != nil {
			log.Printf("cache watcher: %v", err)
		}
	}()

	providerCfg := loadProviderConfig()
	var fed identity.Federator
	if providerCfg.WellKnown != "" {
		fed, err = identity.DefaultRegistry.Build(providerCfg, st)
		if err != nil {
			return err
		}

		scimCfg := loadSCIM2Config()
		if scimCfg.Enabled {
			bumper := epochbumper.New(st)
			syncer := identity.NewSCIMSync(providerCfg.Type, providerCfg.WellKnown, scimCfg, st, bumper)
			go func() {
				if err := idsyncctrl.New(syncer, scimCfg.SyncInterval).Run(ctx); err != nil {
					log.Printf("identitysync controller: %v", err)
				}
			}()
		}
		log.Printf("agentd: identity federation enabled (type=%s issuer=%s)", providerCfg.Type, providerCfg.WellKnown)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	apiSrv := apiserver.New(st)
	mux.Handle("/apis/", apiSrv.Handler())

	if fed != nil {
		mux.HandleFunc("/apis/agentintegrator.dev/v1alpha1/whoami", apiserver.WhoamiHandler(fed))
	}

	addr := ":8443"
	log.Printf("agentd listening on %s", addr)

	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func loadProviderConfig() identity.ProviderConfig {
	wellKnown := os.Getenv("IDP_WELL_KNOWN")
	if wellKnown == "" {
		return identity.ProviderConfig{}
	}

	providerType := os.Getenv("IDP_TYPE")
	if providerType == "" {
		providerType = "oidc"
	}

	refresh := 5 * time.Minute
	if v := os.Getenv("IDP_JWKS_REFRESH"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			refresh = d
		}
	}

	obo := os.Getenv("IDP_ACCEPT_OBO") == "true" || os.Getenv("IDP_ACCEPT_OBO") == "1"

	extras := map[string]any{}
	if v := os.Getenv("IDP_ISSUER_OVERRIDE"); v != "" {
		extras["issuer_override"] = v
	}
	if os.Getenv("IDP_ISSUER_FALLBACK") == "true" || os.Getenv("IDP_ISSUER_FALLBACK") == "1" {
		extras["issuer_fallback"] = true
	}

	return identity.ProviderConfig{
		Type:             providerType,
		WellKnown:        wellKnown,
		Audience:         os.Getenv("IDP_AUDIENCE"),
		JWKSRefresh:      refresh,
		AcceptOnBehalfOf: obo,
		Extras:           extras,
	}
}

func loadSCIM2Config() identity.SCIM2Config {
	enabled := os.Getenv("SCIM2_ENABLED") == "true" || os.Getenv("SCIM2_ENABLED") == "1"

	interval := 5 * time.Minute
	if v := os.Getenv("SCIM2_SYNC_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}

	return identity.SCIM2Config{
		Enabled:         enabled,
		Endpoint:        os.Getenv("SCIM2_ENDPOINT"),
		CredentialsRef:  os.Getenv("SCIM2_CREDENTIALS_REF"),
		SyncInterval:    interval,
		RoleLabelPrefix: os.Getenv("SCIM2_ROLE_LABEL_PREFIX"),
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
