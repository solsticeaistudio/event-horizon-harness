# Trust architecture v0.6 — independent trust, effect integrity, compromise-resistant provenance

v0.6 extends the v0.5 foundation (typed signed statements, derived
certificates, namespace-bound evidence, lifecycle state machine, recorder
checkpoints) so that **compromise of one logical component does not
automatically compromise every trust claim**. See
`SECURITY_ASSURANCE_MATRIX.md` for the deployment-mode matrix.

## What changed in v0.6

1. **Trust Root Manifest** (`trust_manifest.py`) — a signed, hash-chained
   registry of authorized actors. A signature being cryptographically valid is
   no longer sufficient: the signer must hold the correct *role* and *purpose*
   under the manifest version applicable at issuance. One key holds exactly
   one role; cross-role substitution fails closed at issuance.
2. **Key lifecycle** — active → retired → revoked with sequence-ordered
   revocations. Revocation never silently reinterprets history: statements are
   validated against the manifest that was authoritative when they were issued.
3. **Effect Gateway** (`effect_gateway.py`) — governed mediation of
   externally meaningful effects: durable intent before dispatch, immutable
   content-derived idempotency keys, provider adapter contract with explicit
   outcome vocabulary (`committed` / `provider-failed` /
   `confirmed-not-executed` / `unknown` / `provider-cannot-answer`), and
   independently signed intent/receipt/reconciliation statements.
4. **External witness** (`witness.py`) — a separate trust principal that
   verifies recorder checkpoints and acknowledges them under its own key.
   Rollback (`recorder-behind-witness`), forks, foreign deployments, and
   unrecognized witness keys are first-class verdicts.
5. **Evidence provenance graph** (`provenance.py`) — namespace-safe DAG of
   statement nodes with a deterministic Merkle evidence root and inclusion
   proofs. Nodes from another run/session/deployment cannot attach.
6. **Certificate v0.6** — binds `deployment_id`, the trust-root manifest
   digest, witnessed checkpoint state, effect reconciliation summary,
   unresolved-state counts, and a machine-readable assurance lattice
   (`local < authenticated < witnessed < mediated-effects < independent-trust`).
7. **Quorum hooks** (`quorum.py`) — k-of-n approvals from distinct,
   manifest-authorized approver keys for high-value transitions (certificate
   issuance, manifest rotation, emergency revocation). Multiple verified
   signatures only; no custom threshold cryptography.
8. **Key provider abstraction** (`key_providers.py`) — role-bound signing
   identities behind an interface that local files satisfy today and KMS/HSM/
   TPM backends can implement without touching service code.

## The five claims buckets

### Cryptographically proven
Signature validity over canonical bytes; hash-chain integrity; namespace
membership of every consumed event; idempotency-key immutability; lifecycle
transition legality; manifest chaining and signature validity; deterministic
evidence-root computation.

### Independently corroborated
Witnessed recorder history (recorder + witness agree); mediated effects
(executor receipt + gateway receipt + gateway reconciliation); quorum
approvals (k distinct manifest-authorized keys); guardian quorum over
independently signed decisions.

### Deployment-enforced
That externally meaningful effects actually traverse the Effect Gateway;
network/process isolation between roles; independent administration of role
keys (the interfaces accept it; a single-host dev box only provides logical
separation).

### Assumed
Honesty of each individual trust principal within its domain (one compromised
component is tolerated; colluding majorities are not); host integrity of the
machine running the trusted control plane; the deployment root key's custody.

### Not proven
Unrestricted semantic truth; Byzantine-fault-tolerant consensus; hardware
attestation of any actor; protection against a malicious deployment root;
that unmediated legacy code paths cannot touch external systems when deployed
without governance enabled.
