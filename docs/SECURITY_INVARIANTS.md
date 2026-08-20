# Security invariants

These are implementation targets under the trust assumptions in `THREAT_MODEL.md` and `KNOWN_LIMITATIONS.md`, not universal containment proofs.

- **EH-1 — signing-key separation.** Executor configuration contains only public verification keys. The process harness places capability, recorder, and certificate private seeds in separate trusted service paths.
- **EH-2 — provider-derived trust.** Trust is reconstructed from verified attestation output. Caller-requested trust is advisory and cannot raise effective trust.
- **EH-3 — capability exactness.** Signed claims bind subject, workload, task/fingerprint, exact request/action/resource/arguments, audience, tenant/environment, trust, policy/compiler/synthesizer versions, compiled ceiling, guardian state, decay profile, lifetime, one use, and output scope.
- **EH-4 — at-most-once committed effect.** One-use consumption uses atomic SQLite or in-memory transitions before effect dispatch. Multi-host consensus and atomic commit with arbitrary external effects are not implemented.
- **EH-5 — evidence integrity.** Recorder records are ordered, hash-linked, signed by receipts, and checked on restart. Denial certificates distinguish denied, committed-response-lost, indeterminate, and reconciliation-required states.
- **EH-6 — guardian subtract-only authority.** Dynamic outputs are represented as `AuthorityReduction`; the deterministic compiler intersects them with static policy.
- **EH-7 — adaptive-policy non-authority.** The synthesizer emits an untrusted candidate. Only the deterministic compiler emits broker-consumable ceilings; neither synthesizer nor optional model holds signing material.
- **EH-8 — monotonic decay.** Within a capability identity, decay scope can remain constant or decrease. The live capabilities are one-use; session-scoped behavioral accumulation is a separate guardian control, and session/lineage accumulation in `DecayEngine` is not implemented.
- **EH-9 — canary non-effect.** The disjoint canary type is checked before normal execution, always denied, and emits a security event.
- **EH-10 — verifiable denial evidence.** A certificate signs one exact denial and its evidence link without generalizing to untested variations or claiming no effect in ambiguous states.
- **EH-11 — hardware fail-safe independence.** This is not yet implemented or demonstrated with physical hardware. It remains a required future subsystem and claim boundary.
