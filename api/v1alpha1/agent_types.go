package v1alpha1

import "time"

const (
	AgentPhasePending   = "Pending"
	AgentPhaseReady     = "Ready"
	AgentPhaseSuspended = "Suspended"
	AgentPhaseInvalid   = "Invalid"
)

type Agent struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       AgentSpec   `json:"spec"`
	Status     AgentStatus `json:"status,omitempty"`
}

type AgentList struct {
	TypeMeta `json:",inline"`
	Items    []Agent `json:"items"`
}

type AgentSpec struct {
	Identity           AgentIdentity `json:"identity"`
	ManagedBy          string        `json:"managedBy,omitempty"` // "manual" | "wso2"
	Owner              AgentOwner    `json:"owner,omitempty"`
	Environment        string        `json:"environment,omitempty"`
	MaxDelegationDepth int           `json:"maxDelegationDepth,omitempty"`
}

type AgentIdentity struct {
	Provider        string `json:"provider"`           // "wso2"
	Issuer          string `json:"issuer"`
	Subject         string `json:"subject"`            // WSO2 Agent ID
	AllowOnBehalfOf bool   `json:"allowOnBehalfOf,omitempty"`
}

type AgentOwner struct {
	Team    string `json:"team,omitempty"`
	Contact string `json:"contact,omitempty"`
}

type AgentStatus struct {
	Phase            string          `json:"phase,omitempty"`
	IdentityResolved bool            `json:"identityResolved,omitempty"`
	WSO2             AgentWSO2Status `json:"wso2,omitempty"`
	Epoch            uint64          `json:"epoch,omitempty"`
	ActivePassports  int             `json:"activePassports,omitempty"`
}

type AgentWSO2Status struct {
	LastSyncedAt time.Time `json:"lastSyncedAt,omitempty"`
	Roles        []string  `json:"roles,omitempty"`
}
