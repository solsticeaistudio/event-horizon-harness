# Minimum Compromise Sets (v0.7)

The smallest set of independently trusted principals that must be compromised
(or fail) to falsify each major certificate property. Derived from the trust
dependencies declared in `docs/TRUST_ARCHITECTURE_V0_6.md` and enforced by
`trust_manifest.py`, `witness.py`, `effect_gateway.py`, and
`verification_bundle.py`.

| Certificate property | Depends on | Minimum compromise set |
|---|---|---|
| Signature validity of certificate | certificate signer + deployment root (for manifest authorization) | cert signer key |
| Manifest role authorization | deployment root | root key |
| Namespace integrity (run/session binding) | recorder + coordinator | coordinator alone can write foreign-namespace events, but builder rejects mixed sessions → recorder + coordinator |
| Evidence completeness | recorder + all statement signers | recorder host (suppress events) — detected as incomplete, not forged as complete |
| Guardian quorum approval | k authorized guardians | k guardian keys (one key = one slot) |
| Witnessed history | recorder + external witness | recorder + witness (same-host dev witness collapses this to 1 account; documented) |
| Historically trusted statement | signer + manifest chain + pre-revocation observation | signer key + (recorder ∧ witness at observation time) |
| Effect mediated & reconciled | executor receipt + gateway statements | gateway key (+ executor for conflicting claim → surfaced as conflicted) |
| Exclusive effect mediation | deployment enforcement (signed policy) | whoever can flip signed policy to true without enforcement reality: deployment root |
| Provider-authenticated receipts | provider signing identity | provider credential |
| Quorum approval property | k-of-n approver keys | k approver keys |
| Assurance profile itself | conjunction above | smallest set across required facts |

Reading examples:
* A single malicious coordinator cannot produce a clean witnessed certificate:
  it lacks the witness key and the certificate signer.
* Same-host development witnessing reduces "witnessed history" from a
  two-principal guarantee to one OS account; certificates state this honestly
  via `witness_administratively_independent = false` and never derive an
  independent-control-plane profile from it.
