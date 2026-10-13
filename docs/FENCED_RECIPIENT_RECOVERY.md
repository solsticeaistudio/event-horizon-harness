# Fenced recipient recovery — first opt-in protocol implementation

The six archived Firecracker windows establish why **negative observation is
not authority to release an uncertain reservation**. This PR adds a separate
prototype that demonstrates **safe progress** for a narrower cooperating
recipient contract, without changing the existing conservative gateway, the
Firecracker guest protocol, or historic evidence verifiers.

## Safety contract

The recipient is a trusted, local SQLite transactional effect executor:
**the business effect IS the insertion of the durable row with the effect
result**. A unique logical effect key, request digest and pinned output
digest are committed in the same SQLite FULL-synchronous transaction.
Concurrent processes or a late original request may race a newly authorized
recovery attempt. The recipient deduplicates all but the first commit,
returning the identical immutable result and stable receipt.

The recovery gateway:

1. Verifies signature, attestation, scoped request/policy and **consumes a
   newly signed capability** via the existing authority verifier.
2. Requires recorder authorization evidence and trusted output preflight.
3. Reserves the effect once; for recovery, **reads but never releases** the
   original durable reservation, ensuring identical request digest.
4. Calls the pinned cooperating transactional recipient. A **positive
   receipt** is corroborated by a second durable read of its ledger.
5. Confirms the original journal row using original capability/claim binding;
   this does not reassign original provenance to the new recovery token.
6. Only acknowledges completion after durable evidence is appended. A
   recorder, journal or recipient outage returns an indeterminate result,
   not a fabricated success.

## Scope and limitations

- This is a **portable opt-in protocol prototype**, not a new actual KVM
  crash campaign or hardware attestation claim.
- It proves **at most one durable effect row** for a cooperating atomic
  SQLite recipient and safe resumption when a new authorization is issued.
- It does **not** make email, payment, web API, or other effects exactly once
  unless the external recipient also participates in an equivalent atomic,
  persistent idempotency/fencing contract. An arbitrary callback cannot be
  safely wrapped by this component.
- Both the journal and the cooperating recipient need durable trusted
  storage. Loss/corruption of that storage fails closed.
- This implementation does not grant automatic negative reconciliation,
  does not delete reservations, and does not let untrusted guests choose
  an output, recipient identity, storage path, or protocol mode.
- Receipt digests here are internal bindings, **not independently signed
  external acknowledgements**. Independent trust anchors remain future work.

## Test evidence

The Python suite includes real cryptographically signed capabilities,
durable authority replay state, a cooperating SQLite recipient reopened
after lost acknowledgement, pre-commit failure, the late-original/
newly authorized writer races, concurrent recipient instances, corrupt
stored receipts, mismatched output, unavailable recorder/journal,
and explicit no-side-effect preflight denials.

The six original real KVM windows and their strict evidence checks remain
untouched. The **next lab step** after this protocol is reviewed is to build
a separate real process, then Firecracker, crash/partition matrix for the
opt-in fenced recipient—not re-label portable checks as hardware evidence.
