module github.com/DinethShakya23/agent-authority

go 1.25

// Direct dependencies are added as packages land. Pinned in go.sum.
// Planned: cedar-policy/cedar-go, go.etcd.io/bbolt, coreos/go-oidc,
// go.opentelemetry.io/otel, spf13/cobra, onsi/ginkgo, pgregory.net/rapid

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/spf13/cobra v1.10.2
	go.etcd.io/bbolt v1.3.10
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.4.0 // indirect
)
