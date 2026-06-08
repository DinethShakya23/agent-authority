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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/thev1ndu/agent-integrator/pkg/store"
)

type Server struct {
	store store.Store
	mux   *http.ServeMux
}

func New(s store.Store) *Server {
	srv := &Server{store: s, mux: http.NewServeMux()}
	srv.registerRoutes()
	return srv
}

func (s *Server) Handler() http.Handler { return s.mux }

type resourceInfo struct {
	plural       string
	clusterScope bool
	storePrefix  string
}

var resources = map[string]resourceInfo{
	"Agent":          {plural: "agents", storePrefix: "agents"},
	"Capability":     {plural: "capabilities", clusterScope: true, storePrefix: "capabilities"},
	"AgentPolicy":    {plural: "policies", storePrefix: "policies"},
	"Integration":    {plural: "integrations", storePrefix: "integrations"},
	"AgentExecution": {plural: "executions", storePrefix: "executions"},
	"AgentPassport":  {plural: "passports", storePrefix: "passports"},
}

const apiPrefix = "/apis/agentintegrator.dev/v1alpha1"

var pluralToResource map[string]resourceInfo

func init() {
	pluralToResource = make(map[string]resourceInfo, len(resources))
	for _, ri := range resources {
		pluralToResource[ri.plural] = ri
	}
}

func (s *Server) registerRoutes() {
	for _, ri := range resources {
		if !ri.clusterScope {
			continue
		}
		s.mux.HandleFunc(apiPrefix+"/"+ri.plural, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if r.URL.Query().Get("watch") == "true" {
				s.watchStream(w, r, ri.storePrefix+"/")
				return
			}
			s.listCluster(w, r, ri)
		})
		s.mux.HandleFunc(apiPrefix+"/"+ri.plural+"/", func(w http.ResponseWriter, r *http.Request) {
			name := strings.TrimPrefix(r.URL.Path, apiPrefix+"/"+ri.plural+"/")
			name = strings.Trim(name, "/")
			if name == "" {
				http.NotFound(w, r)
				return
			}
			switch r.Method {
			case http.MethodGet:
				s.getCluster(w, r, ri, name)
			case http.MethodPut:
				s.applyCluster(w, r, ri, name)
			case http.MethodDelete:
				s.deleteCluster(w, r, ri, name)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		})
	}

	for _, ri := range resources {
		if ri.clusterScope {
			continue
		}
		s.mux.HandleFunc(apiPrefix+"/"+ri.plural, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			ns := r.URL.Query().Get("namespace")
			if r.URL.Query().Get("watch") == "true" {
				prefix := ri.storePrefix + "/"
				if ns != "" {
					prefix = ri.storePrefix + "/" + ns + "/"
				}
				s.watchStream(w, r, prefix)
				return
			}
			s.listNamespaced(w, r, ri, ns)
		})
	}

	s.mux.HandleFunc(apiPrefix+"/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, apiPrefix+"/namespaces/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			http.NotFound(w, r)
			return
		}
		ns := parts[0]
		plural := parts[1]
		ri, ok := pluralToResource[plural]
		if !ok || ri.clusterScope {
			http.NotFound(w, r)
			return
		}
		if len(parts) == 2 || parts[2] == "" {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if r.URL.Query().Get("watch") == "true" {
				s.watchStream(w, r, ri.storePrefix+"/"+ns+"/")
				return
			}
			s.listNamespaced(w, r, ri, ns)
			return
		}
		name := parts[2]
		switch r.Method {
		case http.MethodGet:
			s.getNamespaced(w, r, ri, ns, name)
		case http.MethodPut:
			s.applyNamespaced(w, r, ri, ns, name)
		case http.MethodDelete:
			s.deleteNamespaced(w, r, ri, ns, name)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func (s *Server) listCluster(w http.ResponseWriter, r *http.Request, ri resourceInfo) {
	var items []json.RawMessage
	if err := s.store.List(r.Context(), ri.storePrefix+"/", &items); err != nil {
		if isNotFound(err) {
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getCluster(w http.ResponseWriter, r *http.Request, ri resourceInfo, name string) {
	var obj json.RawMessage
	key := ri.storePrefix + "/" + name
	if err := s.store.Get(r.Context(), key, &obj); err != nil {
		if isNotFound(err) {
			http.NotFound(w, r)
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, obj)
}

func (s *Server) applyCluster(w http.ResponseWriter, r *http.Request, ri resourceInfo, name string) {
	var obj json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	obj = stampCreationTimestamp(r.Context(), s.store, ri.storePrefix+"/"+name, obj)
	key := ri.storePrefix + "/" + name
	if err := s.store.Put(r.Context(), key, obj); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, obj)
}

func (s *Server) deleteCluster(w http.ResponseWriter, r *http.Request, ri resourceInfo, name string) {
	key := ri.storePrefix + "/" + name
	if err := s.store.Delete(r.Context(), key); err != nil {
		if isNotFound(err) {
			http.NotFound(w, r)
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listNamespaced(w http.ResponseWriter, r *http.Request, ri resourceInfo, ns string) {
	prefix := ri.storePrefix + "/"
	if ns != "" {
		prefix = ri.storePrefix + "/" + ns + "/"
	}
	var items []json.RawMessage
	if err := s.store.List(r.Context(), prefix, &items); err != nil {
		if isNotFound(err) {
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
			return
		}
		writeError(w, err)
		return
	}
	if items == nil {
		items = []json.RawMessage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getNamespaced(w http.ResponseWriter, r *http.Request, ri resourceInfo, ns, name string) {
	key := ri.storePrefix + "/" + ns + "/" + name
	var obj json.RawMessage
	if err := s.store.Get(r.Context(), key, &obj); err != nil {
		if isNotFound(err) {
			http.NotFound(w, r)
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, obj)
}

func (s *Server) applyNamespaced(w http.ResponseWriter, r *http.Request, ri resourceInfo, ns, name string) {
	var obj json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	key := ri.storePrefix + "/" + ns + "/" + name
	obj = stampCreationTimestamp(r.Context(), s.store, key, obj)
	if err := s.store.Put(r.Context(), key, obj); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, obj)
}

func (s *Server) deleteNamespaced(w http.ResponseWriter, r *http.Request, ri resourceInfo, ns, name string) {
	key := ri.storePrefix + "/" + ns + "/" + name
	if err := s.store.Delete(r.Context(), key); err != nil {
		if isNotFound(err) {
			http.NotFound(w, r)
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) watchStream(w http.ResponseWriter, r *http.Request, prefix string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	ch, err := s.store.Watch(ctx, prefix)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	for ev := range ch {
		data, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}
}

func stampCreationTimestamp(_ context.Context, _ store.Store, _ string, obj json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(obj, &m); err != nil {
		return obj
	}
	meta, ok := m["metadata"]
	if !ok {
		return obj
	}
	var metaMap map[string]json.RawMessage
	if err := json.Unmarshal(meta, &metaMap); err != nil {
		return obj
	}
	if _, exists := metaMap["creationTimestamp"]; exists {
		return obj
	}
	ts, _ := json.Marshal(time.Now().UTC())
	metaMap["creationTimestamp"] = ts
	newMeta, err := json.Marshal(metaMap)
	if err != nil {
		return obj
	}
	m["metadata"] = newMeta
	newObj, err := json.Marshal(m)
	if err != nil {
		return obj
	}
	return newObj
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func isNotFound(err error) bool {
	return err != nil && err.Error() == "store: not found"
}

func KindToPlural(kind string) string {
	for k, ri := range resources {
		if k == kind {
			return ri.plural
		}
	}
	return strings.ToLower(kind) + "s"
}

func KindIsClusterScoped(kind string) bool {
	if ri, ok := resources[kind]; ok {
		return ri.clusterScope
	}
	return false
}
