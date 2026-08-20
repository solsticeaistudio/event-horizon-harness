# Behavioral subtract-only guardian

The behavioral guardian detects request-sequence patterns that can indicate boundary probing. It does not infer intent. Its state is tenant/session scoped and can be held atomically in memory or in SQLite for process and worker restart continuity.

Deterministic signals include one-field-at-a-time mutation, resource enumeration, workload mutation, repeated denials, rapid retries, slow probing, parallel-worker distribution, canary interaction, nonce/capability guessing, stale evidence, parser probing, scope/trust expansion, and evidence-suppression attempts. Rule, optional anomaly-scoring, shadow, and evaluation modes are supported. A model outage fails closed outside shadow/evaluation mode.

Every result is converted to `AuthorityReduction` and passes the same deterministic validator. That type can remove tools, actions, resources, and destinations; lower budgets, parallelism, and duration; require approval or re-attestation; revoke; or quarantine. It has no additive fields. A malformed or additive model response is a veto.

The process harness persists state in `trusted-control/behavioral-state.sqlite3`. Trusted re-attestation or human-approved recovery starts a new explicit recovery transition; state is never silently restored by retries or restart. Current tests report detection and false-positive metrics over deterministic fixtures. Those fixture rates are not estimates of real-world model behavior.

This session-scoped history is distinct from redemption-time `DecayEngine` state. The live decay engine is keyed by fresh one-use capability IDs and does not accumulate behavioral counters across a session or lineage.
