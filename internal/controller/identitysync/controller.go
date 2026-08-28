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

package identitysync

import (
	"context"
	"log"
	"time"

	"github.com/DinethShakya23/agent-authority/pkg/identity"
)

type Controller struct {
	syncer   identity.SCIMSync
	interval time.Duration
}

func New(syncer identity.SCIMSync, interval time.Duration) *Controller {
	if interval == 0 {
		interval = 5 * time.Minute
	}
	return &Controller{
		syncer:   syncer,
		interval: interval,
	}
}

func (c *Controller) Run(ctx context.Context) error {
	added, updated, suspended, err := c.syncer.Sync(ctx)
	if err != nil {
		log.Printf("identitysync: initial sync failed: %v", err)
	} else {
		log.Printf("identitysync: initial sync: added=%d updated=%d suspended=%d", added, updated, suspended)
	}

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			added, updated, suspended, err := c.syncer.Sync(ctx)
			if err != nil {
				log.Printf("identitysync: sync failed: %v", err)
				continue
			}
			log.Printf("identitysync: sync: added=%d updated=%d suspended=%d", added, updated, suspended)
		}
	}
}
