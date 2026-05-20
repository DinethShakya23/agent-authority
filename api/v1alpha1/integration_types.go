package v1alpha1

const (
	IntegrationPhaseReady   = "Ready"
	IntegrationPhasePending = "Pending"
	IntegrationPhaseUnknown = "Unknown"
)

type Integration struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       IntegrationSpec   `json:"spec"`
	Status     IntegrationStatus `json:"status,omitempty"`
}

type IntegrationList struct {
	TypeMeta `json:",inline"`
	Items    []Integration `json:"items"`
}

type IntegrationSpec struct {
	Audience    string              `json:"audience"`
	Protocol    string              `json:"protocol"` // "http"
	Upstream    IntegrationUpstream `json:"upstream"`
	Credentials IntegrationCreds    `json:"credentials,omitempty"`
	Schemas     []IntegrationSchema `json:"schemas,omitempty"`
	RateLimit   RateLimitConfig     `json:"rateLimit,omitempty"`
}

type IntegrationUpstream struct {
	URL string `json:"url"`
}

type IntegrationCreds struct {
	Mode string `json:"mode,omitempty"` // "passthrough" | "broker" (v0.2)
}

type IntegrationSchema struct {
	ResourceType string `json:"resourceType"`
	Ref          string `json:"ref"`
}

type RateLimitConfig struct {
	RequestsPerSecond int `json:"requestsPerSecond,omitempty"`
	Burst             int `json:"burst,omitempty"`
}

type IntegrationStatus struct {
	Phase     string `json:"phase,omitempty"`
	Reachable bool   `json:"reachable,omitempty"`
}
