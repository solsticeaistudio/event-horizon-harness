# Trust architecture v0.5 — derived claims and independent provenance

This document describes the security architecture introduced by the v0.5
hardening program. It distinguishes what Event Horizon **proves**, what it
**assumes**, and what it **cannot yet prove**.

## The layered distinction

Cryptographic authenticity alone is never treated as proof that an assertion
is true. The architecture now separates:

1. **Message authenticity** — Ed25519 signatures over canonical bytes.
2. **Source authenticity** — each trusted actor independently signs its own
   statements; the coordinator is not a transitive root of trust.
3. **Semantic truth** — certificate claims are *derived* from verified
   evidence, never accepted from callers.
4. **Execution provenance** — an explicit lifecycle state machine records
   every capability execution transition durably.
5. **Evidence completeness** — required evidence classes must be present for
   a "complete" certificate; otherwise status is `incomplete`.
6. **State continuity** — signed recorder checkpoints anchored outside the
   events file detect rollback or replacement.
7. **History continuity** — replay clients persist their latest accepted
   checkpoint so service rollback is detectable across restarts.
8. **Authority containment** — one-use capabilities cannot re-enter
   authority-granting states; unresolved executions block certification.

## Signed statement envelopes

Every independently trusted actor produces typed statements with explicit
domain separation (`EVENT_HORIZON/<TYPE>/v<N>`):

| Statement type | Signer | Consumed by |
|---|---|---|
| `verifier-attestation` | verifier service | certificate builder |
| `guardian-decision` | guardians service | capability signer, certificate builder |
| `execution-receipt` | executor service | coordinator/recorder evidence |
| `teardown-attestation` | watchdog (separate key) | certificate builder |
| `recorder-checkpoint` | recorder key | external anchor + certificate |

A signature over one statement class can never be interpreted as another
class: the domain string is part of the signed payload and the type/version
must match the domain exactly.

## Certificate derivation

`ContainainmentCertificateBuilder.build(run_id)`:

1. takes **only** a run selector from the caller;
2. reads one atomic `VerifiedRecorderSnapshot` (verify and event collection
   are the same scan);
3. filters to events whose payload carries that `run_id`;
4. derives the session identity from evidence (multi-session runs are
   rejected);
5. verifies embedded source statements against pinned trust anchors;
6. mechanically derives every claim as `satisfied` / `violated` / `unknown`;
7. binds the anchored recorder checkpoint and a Merkle root over consumed
   event hashes;
8. refuses unknown run namespaces entirely (fail closed).

Caller-supplied booleans ("assertions") are rejected at the protocol
envelope before any signing occurs.

## Effect-state honesty

Operations declare purity (`PURE_OPERATIONS`). Past the dispatch boundary:

- declared-pure failures are provably `not_committed`;
- any potentially effectful failure becomes `possibly_committed` /
  `indeterminate` — never `not_committed`;
- reconciliation may resolve uncertainty only with positive evidence; the
  lifecycle state machine rejects `confirmed_not_committed` after dispatch
  unless purity carries that proof by construction.

RPC response loss after consumption is recorded as indeterminate, not denied.

## Recorder checkpoints

The recorder signs checkpoints binding sequence, chain tip, previous
checkpoint digest, and issuance time. Checkpoints are stored via a
`CheckpointAnchor` abstraction (local file journal in development; control
plane, transparency log, witness, or consensus backends are future work).
Certificate generation requires checkpoint continuity against the anchor.

## Key identity scheme

One scheme everywhere: `ed25519:<sha256(raw public key)[:32]>`. Earlier
remote-replay DER-based derivation was retired; replay protocol schemas were
bumped to `.v2`. Old pinned registrations fail closed rather than silently
reinterpreting key identities.
