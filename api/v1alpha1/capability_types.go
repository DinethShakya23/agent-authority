package v1alpha1

type Capability struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       CapabilitySpec `json:"spec"`
}

type CapabilityList struct {
	TypeMeta `json:",inline"`
	Items    []Capability `json:"items"`
}

type CapabilitySpec struct {
	Name          string            `json:"name"`
	ResourceTypes []string          `json:"resourceTypes,omitempty"`
	SchemaRef     string            `json:"schemaRef,omitempty"`
	Meters        []CapabilityMeter `json:"meters,omitempty"`
}

type CapabilityMeter struct {
	Name         string `json:"name"`
	JSONPath     string `json:"jsonPath,omitempty"`
	Type         string `json:"type"` // "decimal" | "counter" | "distinct"
	CurrencyPath string `json:"currencyPath,omitempty"`
}
