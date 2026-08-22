# Deployment Trust Boundaries (v0.8)

What each isolation property means, what enforces it today, and how it is
reflected in certificates.

## Property classes

| Class | Meaning | Enforced by |
|---|---|---|
| Protocol-enforced | Cryptographic/state invariants independent of deployment | signatures, hash chains, lifecycle FSM, gateway identity/fingerprint split |
| Process-enforced | Separate OS processes per role (harness default) | `ProcessSeparatedHarness` — 8 roles, unique PIDs asserted |
| Credential-enforced | Secret ownership verified against a binding table | `deployment.verify_credential_inventory` |
| Network-enforced | Declared connectivity matches observed reachability probes | `deployment.summarize_network_policy` (`declared`/`observed`/`enforced` distinct) |
| Manifest-enforced | Caller key+role+purpose checked at every protected ingress | purpose-bound authorization schema v2 on all protected RPCs |
| Externally witnessed | Independent principal acknowledges history; independence flags are *signed declarations*, honestly false for same-host dev witnesses | witness service + acks |

## Production profile: PRODUCTION_INDEPENDENT

Granted only when ALL observed facts are true (never declarable):

- role-specific keys; coordinator lacks actor private keys
- root private key offline (runtime verifies via root public key only;
  delegated intermediate signs manifests within grant constraints)
- end-to-end manifest enforcement at every service ingress
- persistent replay; dedicated Effect Gateway service
- executor holds no provider credential and its provider route is probe-verified blocked
- provider credential exists only at the gateway; reconciliation carries
  `provider_authenticated_receipt` evidence
- off-control-plane witness with storage/administrative independence declared+verified
- witnessed recorder AND trust-state history; zero unresolved effects
- complete offline verification bundle

## Updated minimum compromise sets (v0.8 topology)

| Falsify… | Minimum set |
|---|---|
| Provider effect outcome | gateway key ∧ (provider credential OR receipt-verification bypass) |
| Witnessed history | recorder + independent witness (2 accounts under reference separation) |
| Exclusive mediation | executor-isolation boundary ∨ network-policy authority ∨ policy-statement key |
| Any certificate | certificate signer + required corroborating principals per claim |

Compromise classes are distinct: cryptographic ≠ host ≠ credential ≠
network-policy ≠ provider compromise. See `MINIMUM_COMPROMISE_SETS.md`.

## Honest limits

Container image digests, kernel-level namespace proofs, and hardware
measurement remain outside current attestation; the attestation is
**configuration/runtime evidence**, explicitly not hardware measurement.
