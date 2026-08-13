package authoritygraph

import "testing"

func mustPair(principal, capability string) CapabilityPair {
	return CapabilityPair{Principal: principal, Capability: capability}
}

func containsPair(pairs []CapabilityPair, want CapabilityPair) bool {
	for _, p := range pairs {
		if p == want {
			return true
		}
	}
	return false
}

// TestEvaluateDeniesDirectAuthorityAmplification proves the direct case: A
// holds the capability, A proposes to delegate to B, and the mandate
// authorizes A only. The after-state exceeds the mandate, so the action must
// deny before any side effect.
func TestEvaluateDeniesDirectAuthorityAmplification(t *testing.T) {
	req := Request{
		Principals:   []string{"agent-a", "agent-b"},
		Capabilities: []string{"mcp:payments:refund"},
		DirectGrants: []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		Mandate:      []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-a",
			To:         "agent-b",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: true,
	}

	got := Evaluate(req)
	if got.Decision != "deny" {
		t.Fatalf("Decision = %q, want %q", got.Decision, "deny")
	}
	if got.ReasonCode != "authority_exceeds_mandate" {
		t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, "authority_exceeds_mandate")
	}
	if !containsPair(got.AuthorityDelta, mustPair("agent-b", "mcp:payments:refund")) {
		t.Fatalf("AuthorityDelta = %v, want agent-b present", got.AuthorityDelta)
	}
	if !containsPair(got.Violations, mustPair("agent-b", "mcp:payments:refund")) {
		t.Fatalf("Violations = %v, want agent-b present", got.Violations)
	}
	if got.Proof.Valid {
		t.Fatal("Proof.Valid = true, want false")
	}
}

// TestEvaluateAllowsMandatedDelegation proves the legitimate case: the same
// graph transition is allowed when the mandate authorizes both A and B.
func TestEvaluateAllowsMandatedDelegation(t *testing.T) {
	req := Request{
		Principals:   []string{"agent-a", "agent-b"},
		Capabilities: []string{"mcp:payments:refund"},
		DirectGrants: []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		Mandate: []CapabilityPair{
			mustPair("agent-a", "mcp:payments:refund"),
			mustPair("agent-b", "mcp:payments:refund"),
		},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-a",
			To:         "agent-b",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: true,
	}

	got := Evaluate(req)
	if got.Decision != "allow" {
		t.Fatalf("Decision = %q, want %q", got.Decision, "allow")
	}
	if got.ReasonCode != "within_mandate" {
		t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, "within_mandate")
	}
	if !containsPair(got.AuthorityDelta, mustPair("agent-b", "mcp:payments:refund")) {
		t.Fatalf("AuthorityDelta = %v, want agent-b present", got.AuthorityDelta)
	}
	if len(got.Violations) != 0 {
		t.Fatalf("Violations = %v, want empty", got.Violations)
	}
	if !got.Proof.Valid {
		t.Fatal("Proof.Valid = false, want true")
	}
}

// TestEvaluateRejectsInvalidBaseline proves the fail-closed precondition: a
// before-state whose reachable authority already exceeds the mandate is
// invalid input, not an allow.
func TestEvaluateRejectsInvalidBaseline(t *testing.T) {
	req := Request{
		Principals:   []string{"agent-a", "agent-b"},
		Capabilities: []string{"mcp:payments:refund"},
		DirectGrants: []CapabilityPair{
			mustPair("agent-a", "mcp:payments:refund"),
			mustPair("agent-b", "mcp:payments:refund"),
		},
		Mandate: []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-a",
			To:         "agent-b",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: true,
	}

	got := Evaluate(req)
	if got.Decision != "deny" {
		t.Fatalf("Decision = %q, want %q", got.Decision, "deny")
	}
	if got.ReasonCode != "baseline_exceeds_mandate" {
		t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, "baseline_exceeds_mandate")
	}
	if got.Proof.Valid {
		t.Fatal("Proof.Valid = true, want false")
	}
}

// TestEvaluateDeniesWhenDirectOperationUnauthorized proves that a graph
// transition that would otherwise remain within the mandate is still denied
// when the request declares the direct operation unauthorized.
func TestEvaluateDeniesWhenDirectOperationUnauthorized(t *testing.T) {
	req := Request{
		Principals:   []string{"agent-a", "agent-b"},
		Capabilities: []string{"mcp:payments:refund"},
		DirectGrants: []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		Mandate: []CapabilityPair{
			mustPair("agent-a", "mcp:payments:refund"),
			mustPair("agent-b", "mcp:payments:refund"),
		},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-a",
			To:         "agent-b",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: false,
	}

	got := Evaluate(req)
	if got.Decision != "deny" {
		t.Fatalf("Decision = %q, want %q", got.Decision, "deny")
	}
	if got.ReasonCode != "direct_operation_unauthorized" {
		t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, "direct_operation_unauthorized")
	}
	if got.Proof.Valid {
		t.Fatal("Proof.Valid = true, want false")
	}
}

// TestEvaluateRejectsUnknownNodeOrCapability proves every unknown-reference
// failure mode denies deterministically with its stable reason code and no
// fabricated authority result.
func TestEvaluateRejectsUnknownNodeOrCapability(t *testing.T) {
	base := Request{
		Principals:   []string{"agent-a", "agent-b"},
		Capabilities: []string{"mcp:payments:refund"},
		DirectGrants: []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		Mandate:      []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-a",
			To:         "agent-b",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: true,
	}

	cases := []struct {
		name       string
		mutate     func(*Request)
		wantReason string
	}{
		{"unknown grantor", func(r *Request) { r.ProposedAction.From = "agent-ghost" }, "unknown_principal"},
		{"unknown grantee", func(r *Request) { r.ProposedAction.To = "agent-ghost" }, "unknown_principal"},
		{"unknown proposed capability", func(r *Request) { r.ProposedAction.Capability = "mcp:unknown:cap" }, "unknown_capability"},
		{"unknown action type", func(r *Request) { r.ProposedAction.Type = "iam_pass_role" }, "unknown_action_type"},
		{"unknown grant principal", func(r *Request) {
			r.DirectGrants = append(r.DirectGrants, mustPair("agent-ghost", "mcp:payments:refund"))
		}, "unknown_principal"},
		{"unknown grant capability", func(r *Request) { r.DirectGrants = append(r.DirectGrants, mustPair("agent-a", "mcp:unknown:cap")) }, "unknown_capability"},
		{"unknown delegation principal", func(r *Request) {
			r.Delegations = append(r.Delegations, DelegationEdge{From: "agent-a", To: "agent-ghost", Capability: "mcp:payments:refund"})
		}, "unknown_principal"},
		{"unknown mandate principal", func(r *Request) { r.Mandate = append(r.Mandate, mustPair("agent-ghost", "mcp:payments:refund")) }, "unknown_principal"},
		{"empty identifier", func(r *Request) { r.Principals = append(r.Principals, "") }, "invalid_request"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			got := Evaluate(req)
			if got.Decision != "deny" {
				t.Fatalf("Decision = %q, want %q", got.Decision, "deny")
			}
			if got.ReasonCode != tc.wantReason {
				t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, tc.wantReason)
			}
			if len(got.AuthorityBefore) != 0 || len(got.AuthorityAfter) != 0 ||
				len(got.AuthorityDelta) != 0 || len(got.Violations) != 0 {
				t.Fatalf("validation failure fabricated authority result: %+v", got)
			}
		})
	}
}

// TestEvaluateRejectsGrantorWithoutCapability proves the grantor must hold the
// delegated capability in the before-closure.
func TestEvaluateRejectsGrantorWithoutCapability(t *testing.T) {
	req := Request{
		Principals:   []string{"agent-a", "agent-b", "agent-c"},
		Capabilities: []string{"mcp:payments:refund"},
		DirectGrants: []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		Mandate: []CapabilityPair{
			mustPair("agent-a", "mcp:payments:refund"),
			mustPair("agent-c", "mcp:payments:refund"),
		},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-b",
			To:         "agent-c",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: true,
	}

	got := Evaluate(req)
	if got.Decision != "deny" {
		t.Fatalf("Decision = %q, want %q", got.Decision, "deny")
	}
	if got.ReasonCode != "grantor_lacks_capability" {
		t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, "grantor_lacks_capability")
	}
	if !containsPair(got.AuthorityBefore, mustPair("agent-a", "mcp:payments:refund")) {
		t.Fatalf("AuthorityBefore = %v, want agent-a present", got.AuthorityBefore)
	}
	if len(got.AuthorityAfter) != 0 || len(got.AuthorityDelta) != 0 || len(got.Violations) != 0 {
		t.Fatalf("after-state computed without a valid transition: %+v", got)
	}
	if got.Proof.Valid {
		t.Fatal("Proof.Valid = true, want false")
	}
}

// TestReachabilityTerminatesOnCycle proves the fixed-point closure terminates
// on a delegation cycle and yields each reachable pair exactly once.
func TestReachabilityTerminatesOnCycle(t *testing.T) {
	grants := []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")}
	edges := []DelegationEdge{
		{From: "agent-a", To: "agent-b", Capability: "mcp:payments:refund"},
		{From: "agent-b", To: "agent-a", Capability: "mcp:payments:refund"},
	}

	got := reachable(grants, edges)
	want := []CapabilityPair{
		mustPair("agent-a", "mcp:payments:refund"),
		mustPair("agent-b", "mcp:payments:refund"),
	}
	if len(got) != len(want) {
		t.Fatalf("reachable = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reachable[%d] = %v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}
}

// TestReceiptOrderingIsDeterministic proves identical declarations supplied in
// different orders produce byte-identical encoded receipts.
func TestReceiptOrderingIsDeterministic(t *testing.T) {
	build := func(principals []string, capabilities []string, grants []CapabilityPair, delegations []DelegationEdge, mandate []CapabilityPair) Request {
		return Request{
			Principals:   principals,
			Capabilities: capabilities,
			DirectGrants: grants,
			Delegations:  delegations,
			Mandate:      mandate,
			ProposedAction: ProposedAction{
				Type:       ActionTypeMCPCapabilityDelegation,
				From:       "agent-a",
				To:         "agent-b",
				Capability: "mcp:payments:refund",
			},
			DirectOperationAuthorized: true,
		}
	}

	a := build(
		[]string{"agent-a", "agent-b", "agent-c"},
		[]string{"mcp:payments:refund", "mcp:storage:read"},
		[]CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		[]DelegationEdge{{From: "agent-b", To: "agent-c", Capability: "mcp:payments:refund"}},
		[]CapabilityPair{
			mustPair("agent-a", "mcp:payments:refund"),
			mustPair("agent-b", "mcp:payments:refund"),
			mustPair("agent-c", "mcp:payments:refund"),
		},
	)
	b := build(
		[]string{"agent-c", "agent-a", "agent-b"},
		[]string{"mcp:storage:read", "mcp:payments:refund"},
		[]CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		[]DelegationEdge{{From: "agent-b", To: "agent-c", Capability: "mcp:payments:refund"}},
		[]CapabilityPair{
			mustPair("agent-c", "mcp:payments:refund"),
			mustPair("agent-a", "mcp:payments:refund"),
			mustPair("agent-b", "mcp:payments:refund"),
		},
	)

	ra, rb := Evaluate(a), Evaluate(b)
	ea, err := ra.Encode()
	if err != nil {
		t.Fatalf("Encode(a): %v", err)
	}
	eb, err := rb.Encode()
	if err != nil {
		t.Fatalf("Encode(b): %v", err)
	}
	if string(ea) != string(eb) {
		t.Fatalf("receipts differ for reordered declarations:\nA: %s\nB: %s", ea, eb)
	}
}

// TestEvaluateDeniesTransitiveActivation proves the transitive case: a dormant
// B→C delegation edge exists, and the proposed A→B edge activates both B and
// C outside the mandate.
func TestEvaluateDeniesTransitiveActivation(t *testing.T) {
	req := Request{
		Principals:   []string{"agent-a", "agent-b", "agent-c"},
		Capabilities: []string{"mcp:payments:refund"},
		DirectGrants: []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		Delegations: []DelegationEdge{
			{From: "agent-b", To: "agent-c", Capability: "mcp:payments:refund"},
		},
		Mandate: []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-a",
			To:         "agent-b",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: true,
	}

	got := Evaluate(req)
	if got.Decision != "deny" {
		t.Fatalf("Decision = %q, want %q", got.Decision, "deny")
	}
	if got.ReasonCode != "authority_exceeds_mandate" {
		t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, "authority_exceeds_mandate")
	}
	for _, principal := range []string{"agent-b", "agent-c"} {
		pair := mustPair(principal, "mcp:payments:refund")
		if !containsPair(got.AuthorityDelta, pair) {
			t.Fatalf("AuthorityDelta = %v, want %s present", got.AuthorityDelta, principal)
		}
		if !containsPair(got.Violations, pair) {
			t.Fatalf("Violations = %v, want %s present", got.Violations, principal)
		}
	}
	if got.Proof.Valid {
		t.Fatal("Proof.Valid = true, want false")
	}
}

// TestEvaluateValidationPrecedenceIsOrderIndependent proves invalid-request
// receipts are byte-stable: reordering two invalid direct grants cannot flip
// the reason code between unknown_principal and unknown_capability.
func TestEvaluateValidationPrecedenceIsOrderIndependent(t *testing.T) {
	build := func(grants []CapabilityPair) Request {
		return Request{
			Principals:   []string{"agent-a", "agent-b"},
			Capabilities: []string{"mcp:payments:refund"},
			DirectGrants: grants,
			Mandate:      []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
			ProposedAction: ProposedAction{
				Type:       ActionTypeMCPCapabilityDelegation,
				From:       "agent-a",
				To:         "agent-b",
				Capability: "mcp:payments:refund",
			},
			DirectOperationAuthorized: true,
		}
	}

	badPrincipal := mustPair("agent-ghost", "mcp:payments:refund")
	badCapability := mustPair("agent-a", "mcp:unknown:cap")

	ra := Evaluate(build([]CapabilityPair{badPrincipal, badCapability}))
	rb := Evaluate(build([]CapabilityPair{badCapability, badPrincipal}))

	if ra.ReasonCode != "unknown_principal" {
		t.Fatalf("ReasonCode = %q, want %q", ra.ReasonCode, "unknown_principal")
	}
	if rb.ReasonCode != ra.ReasonCode {
		t.Fatalf("reordered grants changed reason code: got %q, want %q", rb.ReasonCode, ra.ReasonCode)
	}
	ea, err := ra.Encode()
	if err != nil {
		t.Fatalf("Encode(a): %v", err)
	}
	eb, err := rb.Encode()
	if err != nil {
		t.Fatalf("Encode(b): %v", err)
	}
	if string(ea) != string(eb) {
		t.Fatalf("receipts differ for reordered invalid grants:\nA: %s\nB: %s", ea, eb)
	}
}

// TestEvaluateValidationReasonPrecedence proves the deterministic reason-code
// precedence (unknown_principal > unknown_capability > invalid_request) holds
// over mixed declarations and is independent of declaration order.
func TestEvaluateValidationReasonPrecedence(t *testing.T) {
	base := Request{
		Principals:   []string{"agent-a", "agent-b"},
		Capabilities: []string{"mcp:payments:refund"},
		Mandate:      []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-a",
			To:         "agent-b",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: true,
	}
	build := func(grants []CapabilityPair, delegations []DelegationEdge) Request {
		r := base
		r.DirectGrants = grants
		r.Delegations = delegations
		return r
	}
	reversePairs := func(pairs []CapabilityPair) []CapabilityPair {
		out := make([]CapabilityPair, len(pairs))
		for i := range pairs {
			out[i] = pairs[len(pairs)-1-i]
		}
		return out
	}
	reverseEdges := func(edges []DelegationEdge) []DelegationEdge {
		out := make([]DelegationEdge, len(edges))
		for i := range edges {
			out[i] = edges[len(edges)-1-i]
		}
		return out
	}

	cases := []struct {
		name        string
		grants      []CapabilityPair
		delegations []DelegationEdge
		want        string
	}{
		{
			name: "unknown_principal beats unknown_capability",
			grants: []CapabilityPair{
				mustPair("agent-ghost", "mcp:payments:refund"),
				mustPair("agent-a", "mcp:unknown:cap"),
			},
			want: "unknown_principal",
		},
		{
			name: "unknown_capability beats invalid_request",
			grants: []CapabilityPair{
				mustPair("agent-a", ""),
				mustPair("agent-a", "mcp:unknown:cap"),
			},
			want: "unknown_capability",
		},
		{
			name: "unknown_principal beats invalid_request",
			grants: []CapabilityPair{
				mustPair("", "mcp:payments:refund"),
				mustPair("agent-ghost", "mcp:payments:refund"),
			},
			want: "unknown_principal",
		},
		{
			name: "unknown_principal beats unknown_capability across sections",
			grants: []CapabilityPair{
				mustPair("agent-a", "mcp:unknown:cap"),
			},
			delegations: []DelegationEdge{
				{From: "agent-ghost", To: "agent-b", Capability: "mcp:payments:refund"},
			},
			want: "unknown_principal",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := Evaluate(build(tc.grants, tc.delegations))
			b := Evaluate(build(reversePairs(tc.grants), reverseEdges(tc.delegations)))
			if a.ReasonCode != tc.want {
				t.Fatalf("ReasonCode = %q, want %q", a.ReasonCode, tc.want)
			}
			if b.ReasonCode != a.ReasonCode {
				t.Fatalf("reordered declarations changed reason code: got %q, want %q", b.ReasonCode, a.ReasonCode)
			}
			ea, err := a.Encode()
			if err != nil {
				t.Fatalf("Encode(a): %v", err)
			}
			eb, err := b.Encode()
			if err != nil {
				t.Fatalf("Encode(b): %v", err)
			}
			if string(ea) != string(eb) {
				t.Fatalf("receipts differ for reordered declarations:\nA: %s\nB: %s", ea, eb)
			}
		})
	}
}

// TestEvaluateValidationReasonPrecedenceWithinDeclaration proves the documented
// reason-code precedence also holds within a single declaration: a record
// carrying both an empty field and an unknown reference reports the
// higher-priority reason instead of short-circuiting to invalid_request
// (Codex P2, fix on 14a2db7).
func TestEvaluateValidationReasonPrecedenceWithinDeclaration(t *testing.T) {
	base := Request{
		Principals:   []string{"agent-a", "agent-b"},
		Capabilities: []string{"mcp:payments:refund"},
		Mandate:      []CapabilityPair{mustPair("agent-a", "mcp:payments:refund")},
		ProposedAction: ProposedAction{
			Type:       ActionTypeMCPCapabilityDelegation,
			From:       "agent-a",
			To:         "agent-b",
			Capability: "mcp:payments:refund",
		},
		DirectOperationAuthorized: true,
	}

	cases := []struct {
		name   string
		mutate func(*Request)
		want   string
	}{
		{
			name: "empty principal plus unknown capability",
			mutate: func(r *Request) {
				r.DirectGrants = []CapabilityPair{mustPair("", "mcp:unknown:cap")}
			},
			want: "unknown_capability",
		},
		{
			name: "unknown principal plus empty capability",
			mutate: func(r *Request) {
				r.DirectGrants = []CapabilityPair{mustPair("agent-ghost", "")}
			},
			want: "unknown_principal",
		},
		{
			name: "empty from plus unknown to on a delegation edge",
			mutate: func(r *Request) {
				r.Delegations = []DelegationEdge{{From: "", To: "agent-ghost", Capability: "mcp:payments:refund"}}
			},
			want: "unknown_principal",
		},
		{
			name: "unknown action type plus unknown grantee",
			mutate: func(r *Request) {
				r.ProposedAction.Type = "iam_pass_role"
				r.ProposedAction.To = "agent-ghost"
			},
			want: "unknown_principal",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			got := Evaluate(req)
			if got.Decision != "deny" {
				t.Fatalf("Decision = %q, want deny", got.Decision)
			}
			if got.ReasonCode != tc.want {
				t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, tc.want)
			}
		})
	}
}
