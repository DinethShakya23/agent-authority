package v1alpha1

type AgentPolicy struct {
	TypeMeta   `json:",inline"`
	ObjectMeta `json:"metadata"`
	Spec       AgentPolicySpec   `json:"spec"`
	Status     AgentPolicyStatus `json:"status,omitempty"`
}

type AgentPolicyList struct {
	TypeMeta `json:",inline"`
	Items    []AgentPolicy `json:"items"`
}

type AgentPolicySpec struct {
	AgentSelector  LabelSelector `json:"agentSelector"`
	RequiredScopes []string      `json:"requiredScopes,omitempty"`
	Rules          []PolicyRule  `json:"rules,omitempty"`
}

type PolicyRule struct {
	Capability string                          `json:"capability"`
	Target     PolicyTarget                    `json:"target"`
	Resources  []ResourceSelector              `json:"resources,omitempty"`
	PerRequest map[string]PerRequestConstraint `json:"perRequest,omitempty"`
	Budget     BudgetLimit                     `json:"budget,omitempty"`
	Approval   ApprovalConfig                  `json:"approval,omitempty"`
	OnBehalfOf OnBehalfOfConfig                `json:"onBehalfOf,omitempty"`
	Validity   Validity                        `json:"validity,omitempty"`
	Delegation DelegationConfig                `json:"delegation,omitempty"`
}

type PolicyTarget struct {
	Integration string `json:"integration,omitempty"`
}

type ResourceSelector struct {
	Type string `json:"type"`
}

type ApprovalConfig struct {
	RequiredAbove map[string]string `json:"requiredAbove,omitempty"` // e.g. amount: "15000"
}

type OnBehalfOfConfig struct {
	Required bool `json:"required,omitempty"`
}

type DelegationConfig struct {
	Allowed  bool `json:"allowed,omitempty"`
	MaxDepth int  `json:"maxDepth,omitempty"`
}

type AgentPolicyStatus struct {
	Revision        int    `json:"revision,omitempty"`
	CedarPolicyHash string `json:"cedarPolicyHash,omitempty"`
}
