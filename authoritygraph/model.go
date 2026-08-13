// Package authoritygraph implements deterministic counterfactual evaluation of
// one authority-changing action — MCP capability delegation — against a
// declared principal/capability graph and a mandate.
package authoritygraph

// ActionTypeMCPCapabilityDelegation is the only supported action type.
const ActionTypeMCPCapabilityDelegation = "mcp_capability_delegation"

// ProofProperty names the enforced property reported in every receipt.
const ProofProperty = "reachable_authority_after_subset_of_mandate"

// CapabilityPair is a single authorized authority pair (principal, capability).
type CapabilityPair struct {
	Principal  string `json:"principal"`
	Capability string `json:"capability"`
}

// DelegationEdge is a declared delegation edge (from, to, capability).
type DelegationEdge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Capability string `json:"capability"`
}

// ProposedAction is the single authority-changing operation to evaluate.
type ProposedAction struct {
	Type       string `json:"type"`
	From       string `json:"from"`
	To         string `json:"to"`
	Capability string `json:"capability"`
}

// Request is the strict-JSON input contract for one evaluation.
type Request struct {
	Principals                []string         `json:"principals"`
	Capabilities              []string         `json:"capabilities"`
	DirectGrants              []CapabilityPair `json:"direct_grants"`
	Delegations               []DelegationEdge `json:"delegations"`
	Mandate                   []CapabilityPair `json:"mandate"`
	ProposedAction            ProposedAction   `json:"proposed_action"`
	DirectOperationAuthorized bool             `json:"direct_operation_authorized"`
}

// Proof reports whether the enforced property was established.
type Proof struct {
	Property string `json:"property"`
	Valid    bool   `json:"valid"`
}

// Receipt is the deterministic output of one evaluation.
type Receipt struct {
	Decision                  string           `json:"decision"`
	ReasonCode                string           `json:"reason_code"`
	ActionType                string           `json:"action_type"`
	DirectOperationAuthorized bool             `json:"direct_operation_authorized"`
	AuthorityBefore           []CapabilityPair `json:"authority_before"`
	AuthorityAfter            []CapabilityPair `json:"authority_after"`
	AuthorityDelta            []CapabilityPair `json:"authority_delta"`
	Violations                []CapabilityPair `json:"violations"`
	Proof                     Proof            `json:"proof"`
}
