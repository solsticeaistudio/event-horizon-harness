# Durable effect outcome journal (opt-in)

The trusted host gateway can now use `DurableEffectJournal` to atomically
reserve a capability **before** effect handler dispatch. The reservation lives
on disk (SQLite, `synchronous=FULL`) in a trusted, non-group-writable,
non-world-writable directory. A new gateway instance refuses to run an effect
whose capability **or logical effect identity** was already reserved. The identity
is derived from session ID plus request ID, so another freshly issued capability
cannot silently retry the same action after a lost acknowledgment.

**Safety is conservative:** a reserved capability is treated as
`possibly-committed`, even if the process died before calling its handler.
The journal does not prove that an external effect ran. It does not implement
exactly-once effects or permit retry with a different capability.

## Scope and trust

- The gateway and journal run in a trusted host process; the guest, coordinator,
  and compromised worker must not read, delete, alter, replace, or select the
  journal file or its parent directory.
- `outcome_journal=DurableEffectJournal("/trusted/private/effects.sqlite")`
  is explicitly opt-in. Existing package/KVM experiments are unchanged.
- A capability is already verified and consumed before the journal reservation.
  The journal is an **additional** defense against accidental re-dispatch,
  not a replacement for distributed one-use authority.
- Each reservation binds tenant, environment, logical effect key
  (session ID + request ID), capability ID, exact request digest and signed
  claims digest. An alternate capability for the same logical effect fails
  closed as `possibly-committed`. A caller intentionally inventing a new
  request ID is outside this protection; trusted request identity is required.
- The optional `pre_dispatch_rules` are host-installed callables keyed to
  registered operations, never supplied by a guest. They may reject known
  oversized operations **before** the effect callback, but output measurement
  still occurs after dispatch and cannot undo a remote effect.
- The reservation stays uncertain after the handler returns. The host must
  obtain and validate a recipient-side receipt independently and call
  `confirm_from_trusted_recipient` with the bound receipt digest. A callback
  return value is **not** independently witnessed external state.
- Journal or pre-dispatch-rule failures cause no effect dispatch. Journal
  directory permissions and file privacy are checked at initialization.
- Do not recreate/erase the journal to get a retry. No global revocation,
  automatic reconciliation, or cross-host consensus guarantee is implied.

## Recovery model

| Phase | Journal state | Safe next action |
|---|---|---|
| Before reservation | Missing | New approved effect can be attempted |
| Reserved, before dispatch | Possibly committed | No automatic retry; ask recipient |
| Effect committed, reply lost | Possibly committed | No automatic retry; ask recipient |
| Trusted recipient receipt verified | Recipient confirmed | Retain immutable receipt binding; no re-dispatch |
| Host disk unavailable | Indeterminate/denied | Fail closed; do not execute |

The portable suite covers durable re-open, changed binding, conflicting
recipient receipt, handler-commit-then-lost-reply, duplicate request with a fresh
verifier, a new capability for the same logical request, known pre-dispatch
denial and journal outage. **Actual process SIGKILL,
power loss, Firecracker guest interruption and a real independent recipient
oracle are not yet exercised.** Those require a separate privileged experiment,
new report and explicit operator review under
[Issue #34](https://github.com/solsticeaistudio/event-horizon-harness/issues/34).

Historical signed v1-v4 evidence and the original October 12 report remain
unaltered. Do not append these new software checks to the old report or claim
they were performed in the original KVM execution.
