# Authority Graph Simulator — Project Contract

A standalone, deterministic Go prototype that counterfactually evaluates one
authority-changing action — MCP capability delegation — against a declared
principal/capability graph and a mandate.

## Boundary

- One edge type only: `mcp_capability_delegation(grantor, grantee, capability)`.
- Standard library only. No network access, server, database, UI, policy
  language, telemetry, or third-party Go dependencies.
- Not a cloud IAM simulator. No Azure/AWS/GCP ingestion or provider semantics.
- Not integrated into any MCP proxy. This is a declared-graph proof only: it is
  sound relative to the supplied graph and mandate, not a claim of complete
  real-world IAM discovery.

## Declared model

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

The receipt also reports `AuthorityDelta = Reach(G_after) \ Reach(G_before)`.

## CLI contract

- One positional argument: path to a single JSON request object.
- Strict JSON decoding: unknown fields and trailing JSON are rejected as
  process errors (non-zero exit, no receipt on stdout).
- A deny is an authorization result, not a process failure (exit 0).
- Exit non-zero only for unreadable/malformed/invalid request structure.
- Output is one deterministic JSON receipt with lexicographically sorted
  authority-pair arrays.
