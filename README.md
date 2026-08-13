# Authority Graph Simulator

Deterministic counterfactual authorization for a single authority-changing
action: MCP capability delegation.

An agent can be individually authorized to perform a delegation while that
operation activates authority for another principal — or a transitive chain of
principals — outside the originating mandate. This prototype evaluates one
proposed `mcp_capability_delegation(grantor, grantee, capability)` edge against
a declared principal/capability graph and denies it when the resulting declared
authority exceeds the mandate.

## Model

- `P` — finite declared set of principals.
- `C` — finite declared set of MCP capabilities.
- `D ⊆ P × C` — direct authority grants.
- `E ⊆ P × P × C` — delegation edges.
- `M ⊆ P × C` — the mandate's authorized authority pairs.
- `Reach(G)` — least fixed point initialized with `D`; every edge
  `(u, v, c) ∈ E` makes `(v, c)` reachable when `(u, c)` is reachable.
  Iteration terminates because `P × C` is finite.

## Enforced property

```text
Precondition (fail-closed):  Reach(G_before) ⊆ M
Authorization property:      DirectOperationAuthorized
                             AND Reach(G_after) ⊆ M
Violations = Reach(G_after) \ M
ALLOW iff DirectOperationAuthorized AND Violations = ∅
```

A baseline that already exceeds the mandate is invalid input, not an allow.
Unknown principals, unknown capabilities, malformed action types, and grantors
that do not hold the delegated capability in the before-closure all fail
closed with stable reason codes. The receipt also reports
`AuthorityDelta = Reach(G_after) \ Reach(G_before)`.

## Quick start

Requires Go 1.26+. Standard library only.

```bash
go test ./... -count=1

go run ./cmd/authority-graph-simulator testdata/deny-transitive.json
# decision: deny, reason_code: authority_exceeds_mandate
# B and C become reachable; both exceed the mandate

go run ./cmd/authority-graph-simulator testdata/allow-legitimate.json
# decision: allow, reason_code: within_mandate
```

The CLI takes exactly one JSON request file and prints one deterministic JSON
receipt. Strict JSON decoding rejects unknown fields, top-level non-objects,
and trailing JSON with a non-zero exit and no partial receipt on stdout. A
deny is an authorization result, not a process failure.

### Example request

```json
{
  "principals": ["agent-a", "agent-b", "agent-c"],
  "capabilities": ["mcp:payments:refund"],
  "direct_grants": [
    {"principal": "agent-a", "capability": "mcp:payments:refund"}
  ],
  "delegations": [
    {"from": "agent-b", "to": "agent-c", "capability": "mcp:payments:refund"}
  ],
  "mandate": [
    {"principal": "agent-a", "capability": "mcp:payments:refund"}
  ],
  "proposed_action": {
    "type": "mcp_capability_delegation",
    "from": "agent-a",
    "to": "agent-b",
    "capability": "mcp:payments:refund"
  },
  "direct_operation_authorized": true
}
```

The dormant `B → C` edge makes the proposed `A → B` edge activate both B and C
outside the mandate. The simulator denies before any side effect.

## Boundary

This is a declared-graph proof, not a cloud IAM simulator. It is sound
relative to the supplied graph and mandate, and makes no claim of complete
real-world IAM discovery. It is not integrated into any MCP proxy, and it does
not model Azure/AWS/GCP provider semantics, conditions, deny precedence,
expiry, revocation, or budgets.

## Roadmap (not implemented)

- Additional edge types (for example capability activation or role assignment).
- A concrete MCP adapter contract for pre-relay enforcement.
- Any cloud IAM ingestion.

## License

MIT — see [LICENSE](LICENSE).
