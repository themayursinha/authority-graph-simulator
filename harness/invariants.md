# Authority Graph Simulator — Invariants

## AG1 — Direct operation authorization

The proposed action is allowed only when the request declares
`direct_operation_authorized: true`. Otherwise the decision is `deny` with
reason code `direct_operation_unauthorized`.

## AG2 — Baseline within mandate (fail-closed precondition)

`Reach(G_before) ⊆ Mandate` must hold. A baseline that already exceeds the
mandate is invalid input and denies with reason code `baseline_exceeds_mandate`,
not an allow.

## AG3 — After-state within mandate

`Reach(G_after) ⊆ Mandate` must hold for an allow. Otherwise the decision is
`deny` with reason code `authority_exceeds_mandate`, and the receipt lists the
violations `Reach(G_after) \ Mandate` plus the authority delta
`Reach(G_after) \ Reach(G_before)`.

## AG4 — Deterministic fail-closed validation

- Unknown principals, unknown capabilities, unknown or missing action types,
  and empty identifiers deny with stable reason codes and no fabricated
  authority result.
- Validation failures follow a fixed reason-code precedence independent of
  declaration order: `unknown_principal` > `unknown_capability` >
  `unknown_action_type` > `invalid_request`. Reordering grants, delegations,
  or mandate declarations never flips the emitted reason code. Missing or
  empty principal/capability collections are reported as `invalid_request`
  before any reference check.
- The proposed grantor must hold the delegated capability in `Reach(G_before)`;
  otherwise deny with reason code `grantor_lacks_capability`.
- Duplicate declarations and duplicate grants/edges are normalized as sets;
  behavior remains deterministic.
- Receipts are deterministic: all authority-pair arrays are sorted
  lexicographically by principal then capability; identical declarations in
  different order produce byte-identical encoded receipts.
- Malformed request JSON (syntax error, unknown field, duplicate key,
  case-variant field name, null collection or required field, trailing JSON)
  is a process error: non-zero exit and no partial JSON receipt on stdout.

## Required reason codes

| Reason code | Meaning |
|---|---|
| `within_mandate` | Allow; after-state is a subset of the mandate |
| `authority_exceeds_mandate` | After-state exceeds the mandate; violations listed |
| `baseline_exceeds_mandate` | Before-state already exceeds the mandate |
| `direct_operation_unauthorized` | Request declares the direct operation unauthorized |
| `grantor_lacks_capability` | Grantor does not hold the capability in the before-closure |
| `unknown_action_type` | Action type is present but not recognized |
| `unknown_principal` | A declared or proposed ID is not a declared principal |
| `unknown_capability` | A declared or proposed ID is not a declared capability |
| `invalid_request` | Empty identifiers, missing action type, or otherwise malformed request |
