package stages

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/thev1ndu/agent-integrator/pkg/apierr"
	"github.com/thev1ndu/agent-integrator/pkg/firewall"
	"github.com/thev1ndu/agent-integrator/pkg/integration"
)

// SchemaValidator validates a request payload against a named resource schema.
// Implementations must be non-blocking (use pre-compiled, cached schemas).
type SchemaValidator interface {
	// Validate checks payload against the schema identified by schemaRef.
	// Returns nil if valid, or a descriptive error on failure.
	Validate(schemaRef string, payload []byte) error
}

// Schema validates the request payload against the resource schema specified
// in the passport authority's capability (step 12 of §9.4).
type Schema struct {
	validator SchemaValidator
	// schemaRef identifies which schema to validate against.
	// If empty, the stage skips validation (no-op for integrations without
	// a fixed schema — per-capability schema lookup should be preferred).
	schemaRef string
}

// NewSchema creates a Schema stage with the given validator and schema reference.
// Pass an empty schemaRef to skip payload validation for this integration.
func NewSchema(validator SchemaValidator, schemaRef string) *Schema {
	return &Schema{validator: validator, schemaRef: schemaRef}
}

func (Schema) Name() string { return "12_schema" }

func (sc Schema) Run(ctx context.Context, s *integration.State) (firewall.Outcome, error) {
	// If no schema reference or no validator is configured, skip.
	if sc.schemaRef == "" || sc.validator == nil {
		return firewall.Continue, nil
	}

	r := s.RawRequest
	if r == nil {
		s.ReasonCode = string(apierr.CodeSchemaInvalid)
		s.ReasonMsg = "raw request not set"
		return firewall.Deny, nil
	}

	// Read body (it was already restored by stage 9 if that ran first).
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			s.ReasonCode = string(apierr.CodeSchemaInvalid)
			s.ReasonMsg = fmt.Sprintf("failed to read request body for schema validation: %v", err)
			return firewall.Deny, nil
		}
		// Restore body for downstream handlers.
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	if err := sc.validator.Validate(sc.schemaRef, body); err != nil {
		s.ReasonCode = string(apierr.CodeSchemaInvalid)
		s.ReasonMsg = fmt.Sprintf("payload schema validation failed (%s): %v", sc.schemaRef, err)
		return firewall.Deny, nil
	}

	return firewall.Continue, nil
}
