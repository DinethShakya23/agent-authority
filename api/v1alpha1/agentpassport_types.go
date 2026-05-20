package v1alpha1

const (
	PassportPhaseIssued  = "Issued"
	PassportPhaseActive  = "Active"
	PassportPhaseExpired = "Expired"
	PassportPhaseRevoked = "Revoked"
)

type AgentPassport struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       AgentPassportSpec   `json:"spec"`
	Status     AgentPassportStatus `json:"status,omitempty"`
}

type AgentPassportList struct {
	TypeMeta `json:",inline"`
	Items    []AgentPassport `json:"items"`
}

type AgentPassportSpec struct {
	PassportID   string               `json:"passportID"`
	Agent        PassportAgent        `json:"agent"`
	Execution    PassportExecution    `json:"execution"`
	Audience     []string             `json:"audience"`
	Authority    PassportAuthority    `json:"authority"`
	Confirmation PassportConfirmation `json:"confirmation"`
	Delegation   PassportDelegation   `json:"delegation"`
	Policy       PassportPolicy       `json:"policy"`
	Validity     Validity             `json:"validity"`
	Epoch        uint64               `json:"epoch"`
}

type PassportAgent struct {
	ID          string `json:"id"`
	WSO2Subject string `json:"wso2Subject,omitempty"`
	OnBehalfOf  string `json:"onBehalfOf,omitempty"`
}

type PassportExecution struct {
	ID string `json:"id"`
}

type PassportAuthority struct {
	Capabilities []string                        `json:"capabilities,omitempty"`
	Resources    []ResourceSelector              `json:"resources,omitempty"`
	PerRequest   map[string]PerRequestConstraint `json:"perRequest,omitempty"`
	Budget       BudgetLimit                     `json:"budget,omitempty"`
}

type PassportConfirmation struct {
	X5tS256 string `json:"x5tS256"` // SHA-256 thumbprint of the agent leaf cert
}

type PassportDelegation struct {
	Depth     int    `json:"depth"`
	Parent    string `json:"parent,omitempty"`    // parent passportID
	ChainHash string `json:"chainHash,omitempty"` // SHA-256 of full chain
}

type PassportPolicy struct {
	Name     string `json:"name"`
	Revision int    `json:"revision,omitempty"`
}

type AgentPassportStatus struct {
	Phase string `json:"phase,omitempty"`
	JWS   string `json:"jws,omitempty"` // compact JWS serialisation
}
