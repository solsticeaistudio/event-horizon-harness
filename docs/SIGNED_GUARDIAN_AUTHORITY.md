# Independent guardian signatures: signer-side proof contract

EHH now has an **opt-in cryptographic decision interface** for use when
the capability signer operates in a *separate protected trust domain*
from the agent, coordinator and guardian private keys.

The new `event_horizon.signed_guardian_authority` module contains:

- `GuardianSigningKey`: an Ed25519 identity held by **one** required guardian
- `SignedGuardianApproval`: versioned, domain-separated signature over
  guardian name, signer-issued single-use challenge, exact request digest,
  policy digest, decision, evidence and pinned key ID
- `PinnedGuardianVerifier`: signer-owned public-key pinset requiring
  **four distinct** guardian keys; every approval must be present and valid
- `PinnedGuardianCapabilityIssuer`: signer facade that consumes the
  one-use challenge, verifies signed unanimity, independently evaluates the
  exact request against its own immutable static policy, validates the
  coordinator-provided compiled ceiling against that policy, binds signed
  attestation evidence, and then calls the capability broker

There is **no silent fallback** from this facade to unsigned coordinator
approval. Missing/duplicate votes, bad signature, impersonation, stale or
swapped challenge, policy mismatch, invalid attestation binding and an
enlarged compiled ceiling fail closed. The four private keys cannot be the
same key reused under different names.

### Scope: what has and has not been accomplished

**Established and CI-tested:** a coordinator that possesses only requests,
public keys and signed approvals cannot manufacture an additional guardian's
signature or mutate a previously signed approval. The signer independently
enforces its static policy before issuing an otherwise valid, signed
capability. The test proves a valid control can still issue a real,
verifiable capability, then refuses replay.

**Not yet established:** physically independent guardians or a hardened
network/HSM signer service. This module is a cryptographic contract and
in-process proof of logic, **not an independently deployed trust boundary**.
No operating system permissions or remote peer-authenticated RPC for
guardian services are installed by this PR. Existing local unsiged
`GuardianQuorum` and `CapabilityBroker` callers are untouched for
compatibility and are **not magically protected** against compromise of the
trusted coordinator process. In an actual deployment, the signer must be
the **exclusive holder** of the capability private key; a coordinator
must never retain a reference to a raw `CapabilityBroker.issue` method,
or to any guardian private keys.

An attestation guardian signature establishes the identity of that
guardian's attestation decision; it does **not** itself verify a physical
TPM quote or establish hardware enrollment. Real quote verification and
independently provisioned guardian identities are separate requirements.

### Next deployment/assurance milestones

1. Provision independent per-guardian signing keys, pinned out-of-band on
   the signer host; no coordinator-generated key material.
2. Expose the signer facade behind mutually authenticated RPC with strict
   admission/rate limits, challenges and replay state outside the coordinator.
3. Physically or at least OS-process isolate the guardian workers and
   protected signer; prove via forced coordinator compromise/fault injection
   that it cannot issue valid capabilities.
4. Bind the actual attestation guardian to a separately pinned real TPM
   verifier and audit signed outcomes independently.
5. Upgrade the deployed default issuance path only after equivalent positive,
   failure and recovery tests pass; do not erase existing research modules.

The relevant regression entrypoint is:

```bash
python -m unittest tests.test_signed_guardian_authority -v
```

Tests use freshly generated synthetic Ed25519 identities and no production
secrets, external services or Docker. This contract is a foundation for
coordinator-compromise resistance, not the final proof of that property.
