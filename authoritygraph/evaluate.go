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

// validate checks every declared and proposed identifier. Reason codes follow
// a fixed precedence independent of declaration order — unknown_principal >
// unknown_capability > unknown_action_type > invalid_request — so reordering
// grants, delegations, or mandate declarations can never flip the receipt's
// reason_code. Missing or empty principal/capability collections are
// order-independent structural preconditions reported as invalid_request
// before any reference check.
func validate(req Request) (string, bool) {
	if len(req.Principals) == 0 || len(req.Capabilities) == 0 {
		return "invalid_request", false
	}
	if containsEmpty(req.Principals) || containsEmpty(req.Capabilities) {
		return "invalid_request", false
	}
	principals := stringSet(req.Principals)
	capabilities := stringSet(req.Capabilities)

	reason := ""
	for _, g := range req.DirectGrants {
		reason = worst(reason, pairReason(principals, capabilities, g))
	}
	for _, e := range req.Delegations {
		reason = worst(reason, edgeReason(principals, capabilities, e))
	}
	for _, m := range req.Mandate {
		reason = worst(reason, pairReason(principals, capabilities, m))
	}
	reason = worst(reason, actionReason(principals, capabilities, req.ProposedAction))
	if reason != "" {
		return reason, false
	}
	return "", true
}

// reasonPriority ranks validation failures so the highest-priority reason wins
// no matter how the declarations were ordered in the request.
func reasonPriority(reason string) int {
	switch reason {
	case "unknown_principal":
		return 4
	case "unknown_capability":
		return 3
	case "unknown_action_type":
		return 2
	case "invalid_request":
		return 1
	}
	return 0
}

// worst returns the higher-priority of two reason codes ("" means no failure).
func worst(a, b string) string {
	if reasonPriority(b) > reasonPriority(a) {
		return b
	}
	return a
}

// pairReason validates one principal/capability pair declaration. Each field
// is checked independently and combined with worst so the documented
// reason-code precedence holds within a single declaration, not just across
// declarations. Empty fields report invalid_request and are not double-reported
// as unknown.
func pairReason(principals, capabilities map[string]struct{}, p CapabilityPair) string {
	reason := ""
	if p.Principal == "" || p.Capability == "" {
		reason = worst(reason, "invalid_request")
	}
	if p.Principal != "" && !hasString(principals, p.Principal) {
		reason = worst(reason, "unknown_principal")
	}
	if p.Capability != "" && !hasString(capabilities, p.Capability) {
		reason = worst(reason, "unknown_capability")
	}
	return reason
}

// edgeReason validates one delegation edge declaration.
func edgeReason(principals, capabilities map[string]struct{}, e DelegationEdge) string {
	reason := ""
	if e.From == "" || e.To == "" || e.Capability == "" {
		reason = worst(reason, "invalid_request")
	}
	if e.From != "" && !hasString(principals, e.From) {
		reason = worst(reason, "unknown_principal")
	}
	if e.To != "" && !hasString(principals, e.To) {
		reason = worst(reason, "unknown_principal")
	}
	if e.Capability != "" && !hasString(capabilities, e.Capability) {
		reason = worst(reason, "unknown_capability")
	}
	return reason
}

// actionReason validates the proposed action.
func actionReason(principals, capabilities map[string]struct{}, pa ProposedAction) string {
	reason := ""
	if pa.Type == "" {
		reason = worst(reason, "invalid_request")
	}
	if pa.Type != "" && pa.Type != ActionTypeMCPCapabilityDelegation {
		reason = worst(reason, "unknown_action_type")
	}
	if pa.From == "" || pa.To == "" || pa.Capability == "" {
		reason = worst(reason, "invalid_request")
	}
	if pa.From != "" && !hasString(principals, pa.From) {
		reason = worst(reason, "unknown_principal")
	}
	if pa.To != "" && !hasString(principals, pa.To) {
		reason = worst(reason, "unknown_principal")
	}
	if pa.Capability != "" && !hasString(capabilities, pa.Capability) {
		reason = worst(reason, "unknown_capability")
	}
	return reason
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
