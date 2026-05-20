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

// Command agentctl is the operator and developer CLI.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/thev1ndu/agent-integrator/internal/apiserver"
	"github.com/thev1ndu/agent-integrator/internal/version"
)

var serverAddr string

var rootCmd = &cobra.Command{
	Use:   "agentctl",
	Short: "Agent Integrator operator CLI",
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the agentctl version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("agentctl %s\n", version.Version)
	},
}

var applyFile string

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a resource from a YAML or JSON file",
	RunE:  runApply,
}

func runApply(cmd *cobra.Command, args []string) error {
	if applyFile == "" {
		return fmt.Errorf("specify a file with -f")
	}

	data, err := os.ReadFile(applyFile)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse file: %w", err)
	}

	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	kind, _ := raw["kind"].(string)
	var name string
	if meta, ok := raw["metadata"].(map[string]any); ok {
		name, _ = meta["name"].(string)
	}
	if kind == "" {
		return fmt.Errorf("'kind' field missing in resource file")
	}
	if name == "" {
		return fmt.Errorf("'metadata.name' field missing in resource file")
	}

	var obj json.RawMessage = jsonBytes

	client := apiserver.NewClient(serverAddr)
	if err := client.Apply(context.Background(), obj); err != nil {
		return err
	}
	fmt.Printf("applied %s/%s\n", strings.ToLower(kind), name)
	return nil
}

var (
	getNamespace string
	getAllNs      bool
)

var getCmd = &cobra.Command{
	Use:   "get <kind> [<name>]",
	Short: "List or get resources",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runGet,
}

func runGet(cmd *cobra.Command, args []string) error {
	kind := normaliseKind(args[0])
	name := ""
	if len(args) == 2 {
		name = args[1]
	}

	ns := getNamespace
	if getAllNs {
		ns = ""
	}

	client := apiserver.NewClient(serverAddr)
	ctx := context.Background()

	if name != "" {
		var obj map[string]json.RawMessage
		if err := client.Get(ctx, kind, ns, name, &obj); err != nil {
			return err
		}
		printTable([]map[string]json.RawMessage{obj})
		return nil
	}

	var result struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := client.List(ctx, kind, ns, &result); err != nil {
		return err
	}
	printTable(result.Items)
	return nil
}

// normaliseKind converts plural/lowercase inputs to canonical Kind strings.
func normaliseKind(s string) string {
	switch strings.ToLower(strings.TrimRight(s, "s")) {
	case "agent":
		return "Agent"
	case "capability", "capabilit":
		return "Capability"
	case "agentpolicy", "policy", "policie":
		return "AgentPolicy"
	case "integration":
		return "Integration"
	case "agentexecution", "execution":
		return "AgentExecution"
	case "agentpassport", "passport":
		return "AgentPassport"
	}
	if len(s) > 0 {
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// printTable prints a fixed-width table of resources.
func printTable(items []map[string]json.RawMessage) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tNAMESPACE\tPHASE\tAGE")
	for _, item := range items {
		name := jsonStr(item, "metadata", "name")
		ns := jsonStr(item, "metadata", "namespace")
		phase := jsonStrStatus(item)
		age := jsonAge(item)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, ns, phase, age)
	}
	w.Flush()
}

// jsonStr extracts a nested string field via successive keys.
func jsonStr(m map[string]json.RawMessage, keys ...string) string {
	if len(keys) == 0 {
		return ""
	}
	raw, ok := m[keys[0]]
	if !ok {
		return ""
	}
	if len(keys) == 1 {
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil {
		return ""
	}
	return jsonStr(nested, keys[1:]...)
}

// jsonStrStatus extracts .status.phase from a resource map.
func jsonStrStatus(m map[string]json.RawMessage) string {
	raw, ok := m["status"]
	if !ok {
		return ""
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(raw, &status); err != nil {
		return ""
	}
	phaseRaw, ok := status["phase"]
	if !ok {
		return ""
	}
	var phase string
	_ = json.Unmarshal(phaseRaw, &phase)
	return phase
}

// jsonAge extracts a creation timestamp and returns a human-readable age.
func jsonAge(m map[string]json.RawMessage) string {
	raw, ok := m["metadata"]
	if !ok {
		return "<unknown>"
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "<unknown>"
	}
	tsRaw, ok := meta["creationTimestamp"]
	if !ok {
		return "<unknown>"
	}
	var ts time.Time
	if err := json.Unmarshal(tsRaw, &ts); err != nil {
		return "<unknown>"
	}
	d := time.Since(ts)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "http://localhost:8443", "agentd API server address")

	applyCmd.Flags().StringVarP(&applyFile, "filename", "f", "", "file to apply (YAML or JSON)")
	getCmd.Flags().StringVarP(&getNamespace, "namespace", "n", "default", "namespace to query")
	getCmd.Flags().BoolVarP(&getAllNs, "all-namespaces", "A", false, "list across all namespaces")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(getCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
