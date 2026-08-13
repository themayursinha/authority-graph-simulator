package authoritygraph

import "sort"

// Evaluate evaluates one proposed delegation edge against the declared graph.
//
// The decision is ALLOW iff DirectOperationAuthorized AND
// Reach(G_after) ⊆ Mandate, with Reach(G_before) ⊆ Mandate enforced as a
// fail-closed precondition. Every failure path returns a deny receipt with a
// stable reason code; validation failures never fabricate authority results.
func Evaluate(req Request) Receipt {
	r := newReceipt(req)
	if reason, ok := validate(req); !ok {
		r.ReasonCode = reason
		return r
	}

	before := reachable(req.DirectGrants, req.Delegations)
	r.AuthorityBefore = before

	mandate := pairSet(req.Mandate)
	if !subsetOf(before, mandate) {
		r.ReasonCode = "baseline_exceeds_mandate"
		return r
	}
	if !req.DirectOperationAuthorized {
		r.ReasonCode = "direct_operation_unauthorized"
		return r
	}
	if !hasPair(before, req.ProposedAction.From, req.ProposedAction.Capability) {
		r.ReasonCode = "grantor_lacks_capability"
		return r
	}

	afterEdges := append(append([]DelegationEdge{}, req.Delegations...), proposedEdge(req.ProposedAction))
	after := reachable(req.DirectGrants, afterEdges)
	r.AuthorityAfter = after
	r.AuthorityDelta = difference(after, before)
	r.Violations = difference(after, sortedPairs(mandate))

	if len(r.Violations) == 0 {
		r.Decision = "allow"
		r.ReasonCode = "within_mandate"
		r.Proof.Valid = true
	} else {
		r.ReasonCode = "authority_exceeds_mandate"
	}
	return r
}

func newReceipt(req Request) Receipt {
	actionType := ""
	if req.ProposedAction.Type == ActionTypeMCPCapabilityDelegation {
		actionType = req.ProposedAction.Type
	}
	return Receipt{
		Decision:                  "deny",
		ReasonCode:                "",
		ActionType:                actionType,
		DirectOperationAuthorized: req.DirectOperationAuthorized,
		AuthorityBefore:           []CapabilityPair{},
		AuthorityAfter:            []CapabilityPair{},
		AuthorityDelta:            []CapabilityPair{},
		Violations:                []CapabilityPair{},
		Proof:                     Proof{Property: ProofProperty, Valid: false},
	}
}

// validate checks that every declared and proposed identifier is present,
// non-empty, and declared. It returns a stable deny reason code and ok=false
// on the first violation.
func validate(req Request) (string, bool) {
	if len(req.Principals) == 0 || len(req.Capabilities) == 0 {
		return "invalid_request", false
	}
	principals := stringSet(req.Principals)
	capabilities := stringSet(req.Capabilities)
	if containsEmpty(req.Principals) || containsEmpty(req.Capabilities) {
		return "invalid_request", false
	}
	for _, g := range req.DirectGrants {
		if g.Principal == "" || g.Capability == "" {
			return "invalid_request", false
		}
		if !hasString(principals, g.Principal) {
			return "unknown_principal", false
		}
		if !hasString(capabilities, g.Capability) {
			return "unknown_capability", false
		}
	}
	for _, e := range req.Delegations {
		if e.From == "" || e.To == "" || e.Capability == "" {
			return "invalid_request", false
		}
		if !hasString(principals, e.From) || !hasString(principals, e.To) {
			return "unknown_principal", false
		}
		if !hasString(capabilities, e.Capability) {
			return "unknown_capability", false
		}
	}
	for _, m := range req.Mandate {
		if m.Principal == "" || m.Capability == "" {
			return "invalid_request", false
		}
		if !hasString(principals, m.Principal) {
			return "unknown_principal", false
		}
		if !hasString(capabilities, m.Capability) {
			return "unknown_capability", false
		}
	}
	pa := req.ProposedAction
	if pa.Type == "" {
		return "invalid_request", false
	}
	if pa.Type != ActionTypeMCPCapabilityDelegation {
		return "unknown_action_type", false
	}
	if pa.From == "" || pa.To == "" || pa.Capability == "" {
		return "invalid_request", false
	}
	if !hasString(principals, pa.From) || !hasString(principals, pa.To) {
		return "unknown_principal", false
	}
	if !hasString(capabilities, pa.Capability) {
		return "unknown_capability", false
	}
	return "", true
}

type principalCap struct {
	principal  string
	capability string
}

// reachable computes the least fixed point Reach(G): the direct grants plus
// every (to, capability) made reachable by a delegation edge whose from holds
// the capability. The result is sorted lexicographically.
func reachable(grants []CapabilityPair, edges []DelegationEdge) []CapabilityPair {
	seen := make(map[principalCap]struct{})
	var queue []principalCap
	add := func(pc principalCap) {
		if _, ok := seen[pc]; ok {
			return
		}
		seen[pc] = struct{}{}
		queue = append(queue, pc)
	}
	for _, g := range grants {
		add(principalCap{principal: g.Principal, capability: g.Capability})
	}
	for len(queue) > 0 {
		pc := queue[0]
		queue = queue[1:]
		for _, e := range edges {
			if e.From == pc.principal && e.Capability == pc.capability {
				add(principalCap{principal: e.To, capability: e.Capability})
			}
		}
	}
	return sortedPairs(seen)
}

func sortedPairs(seen map[principalCap]struct{}) []CapabilityPair {
	out := make([]CapabilityPair, 0, len(seen))
	for pc := range seen {
		out = append(out, CapabilityPair{Principal: pc.principal, Capability: pc.capability})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Principal != out[j].Principal {
			return out[i].Principal < out[j].Principal
		}
		return out[i].Capability < out[j].Capability
	})
	return out
}

func pairSet(pairs []CapabilityPair) map[principalCap]struct{} {
	out := make(map[principalCap]struct{}, len(pairs))
	for _, p := range pairs {
		out[principalCap{principal: p.Principal, capability: p.Capability}] = struct{}{}
	}
	return out
}

func subsetOf(pairs []CapabilityPair, set map[principalCap]struct{}) bool {
	for _, p := range pairs {
		if _, ok := set[principalCap{principal: p.Principal, capability: p.Capability}]; !ok {
			return false
		}
	}
	return true
}

func hasPair(pairs []CapabilityPair, principal, capability string) bool {
	want := CapabilityPair{Principal: principal, Capability: capability}
	for _, p := range pairs {
		if p == want {
			return true
		}
	}
	return false
}

// difference returns the pairs of a that are not in b, preserving a's order.
// The result is always non-nil so an empty difference encodes as [] not null.
func difference(a, b []CapabilityPair) []CapabilityPair {
	set := pairSet(b)
	out := []CapabilityPair{}
	for _, p := range a {
		if _, ok := set[principalCap{principal: p.Principal, capability: p.Capability}]; !ok {
			out = append(out, p)
		}
	}
	return out
}

func proposedEdge(a ProposedAction) DelegationEdge {
	return DelegationEdge{From: a.From, To: a.To, Capability: a.Capability}
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

func hasString(set map[string]struct{}, v string) bool {
	_, ok := set[v]
	return ok
}

func containsEmpty(values []string) bool {
	for _, v := range values {
		if v == "" {
			return true
		}
	}
	return false
}
