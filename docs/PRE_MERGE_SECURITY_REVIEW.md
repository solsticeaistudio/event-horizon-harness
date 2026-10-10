# Pre-merge security review — October 2026

**Scope:** stacked PRs #1–#6 and the revocation/doc hardening increment.
This is a project-maintainer engineering review, **not** an independent
security audit or production readiness assessment.

| Area | Verified safeguard | Explicit limitation |
| --- | --- | --- |
| Canonical protocol | Signed exact digest and strict framing | No proof against compromised issuer |
| Capability broker | Exact Ed25519 request/argument/session/attestation bindings | Trusted signing boundary must survive compromise |
| Signed replay | etcd CAS for capabilities, nonces, authorizations and checkpoint history; three-member cluster CI | Client high-water files and keys remain locally administered in CI |
| Gateway | Host-owned effect handler with pre-effect authorization/recording | Effect and etcd transaction are separate; ambiguous effects remain possible |
| Seven-process integration | Live etcd requests; no etcd client credentials in executor config | Same-user process topology is not host/KVM isolation |
| Evidence | Ed25519 receipts, hash chain and independent software validator | Issuer identity needs an out-of-band pinned public key; no host-kernel proof |
| Guardian | Static ceiling and unanimous veto | Not validated against an open-ended hostile model |
| Revocation CRL | Deterministic insertion order, signature-linked entries, rollback on signer failure, tests for multi-record corruption | No externally pinned CRL high-water, so deleting an intact suffix is not detected |
| HSM | Configured HSM fails closed | Hardware lifecycle/rotation still unverified |
| Attestation | TypeScript TPM quote parser; Python legacy is enrolled signed claims | Production hardware endorsement and enrollment not established |
| Raft | Unsafe prototype explicitly denies authority use; operational quorum via etcd | Research custom Raft is not production |
| Formal model | Narrow capability lifecycle properties | Definitional invariants and no distributed rollback/partition proof |

## Release gates

1. Confirm all Python unit tests, lint, Node build/typecheck/tests,
   public demo, signed evidence and certificate verification green at the
   *exact hardening commit*.
2. Confirm three-node etcd quorum integration green for the reviewed stack.
3. Inspect revocation signing, correct chained storage and corruption denial;
   separately track host/KVM containment evidence as not yet completed.
4. Merge the stacked branches with merge commits in dependency order,
   retargeting each next PR to `main`.
5. Verify `main` CI after merging the final hardening commit.

## Remaining security work

Independent review of issuer/broker, protocol, attestation binding, protected
mutation paths, replay checkpoint persistence and effect gateway; formal
rollback/crash specification; KVM guest-root containment with independent
host effect oracles; independently provisioned signing/attestation identities.

Merging promotes a tested **research development baseline**, not a
certification of secure production isolation.
