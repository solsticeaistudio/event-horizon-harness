# Containment invariants

## EH-1 — No ambient authority

No reusable credential, cloud workload identity, cluster token, signing key, or production secret exists inside the agent process, guest, or sacrificial host.

**Failure:** hostile code retrieves any credential that can authorize an external operation without a new decision by the external capability broker.

## EH-2 — No direct causal path

The hostile world has no direct route to the internet, package registries, metadata services, control planes, neighboring workers, production storage, or management networks.

**Failure:** hostile code transmits an unauthorized byte or initiates an unauthorized request outside the synthetic range.

## EH-3 — Every effect is exact and one-use

Every external effect is bound to the exact session, agent, executor measurement, operation, resource, argument digest, policy digest, expiry, output envelope, and invocation count.

**Failure:** a capability is replayed, widened, transferred, used from another session/executor, or used after expiration.

## EH-4 — Compromise cannot propagate or persist

Workload or host compromise may occur, but it cannot create another identity, reach another machine, or survive verified teardown.

**Failure:** cross-cell influence, lateral movement, or durable state remains after reset.

## EH-5 — Authoritative observation survives compromise

The authoritative event chain and certificate are stored outside every environment the agent can modify.

**Failure:** the hostile environment can delete, rewrite, reorder, or suppress authoritative evidence without detection.

## EH-6 — Guardians only subtract authority

No guardian, model, human approval, or anomaly detector may grant an operation beyond the static experiment policy. Any guardian may veto. Sensitive authorization requires independent agreement.

**Failure:** compromise of one guardian creates a new authority edge.

## EH-7 — Adaptive policy is non-authoritative

The synthesizer may propose less authority but cannot mint, sign, or widen a capability. The trusted compiler rejects unknown fields and intersects every proposal with hard policy.

## EH-8 — Trust and decay are monotonic

Without a new authorization and attestation event, provider trust and current decay authority cannot increase. Trust upgrades never revive a consumed capability.

In the live harness, each new authorization creates a fresh one-use capability and decay identity. Persistent session behavior is handled by the Behavioral Transition Guardian; `DecayEngine` does not carry counters across those identities.

## EH-9 — Canaries have no effect path

Canary discovery, mutation, transfer, inspection, and redemption generate trusted security events and deny before effect execution.

## EH-10 — Denial evidence is scoped

A denial certificate proves evaluation and denial of one request under named policy, trust, build, and evidence state. It does not generalize to untested attacks and cannot claim no effect when state is ambiguous.

## EH-11 — Hardware safe state is fail-closed

The simulator enters its configured safe state on timeout, invalid or replayed heartbeat, policy/evidence mismatch, restart, or explicit kill, and requires explicit trusted re-arm.
