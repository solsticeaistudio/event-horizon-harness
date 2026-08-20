# Event Horizon technical report

## Summary

Agents are commonly over-provisioned relative to their tasks. Adaptive policy can reduce exposure, but a learned policy must not be the final enforcement boundary. Event Horizon separates policy sizing from authority enforcement: a task-specific candidate ceiling is proposed, a deterministic trusted compiler intersects it with hard limits, and cryptographically bound, provider-attested capabilities enforce the result.

## Enforcement model

The broker consumes only the compiler output. Effective authority is the intersection of global maximum, task ceiling, requested and signed authority, provider-attested authority, guardian reductions, current policy, and current decay. Guardians, behavioral scoring, canaries, recovery, and human approvals can only preserve or subtract authority. One-use durable consumption and evidence recording make retries and ambiguous outcomes explicit.

## Evidence and evaluation

Canaries detect authority-layer probing without producing effects. Signed denial certificates provide portable evidence for a specific denied attempt. Behavioral rules persistently detect boundary-probing sequences within a session. Redemption-time decay is monotonic within each fresh one-use capability identity; the live decay engine does not accumulate counters across a session or lineage. Property, concurrency, chaos, and positive-control tests attack the state transitions. A reviewed literature-feed adapter imports metadata only; it never executes downloaded material. The hardware-failsafe simulator models an independently verified heartbeat and safe-state transition.

## Boundaries

These results are project-authored synthetic evidence, not an external audit or a claim about frontier models. Production Firecracker deployment, physical TPM provenance, multi-host consensus, physically independent evidence, hardware-in-the-loop testing, and complete TLC checking remain future work.
