# Known limitations

Event Horizon is a research harness, not a production containment system.

## v0.6 additions

- The Effect Gateway mediation path exists at the executor/library level (durable intent, immutable idempotency, signed receipts/reconciliations) but is not yet plumbed through the process-separated RPC topology as its own service role; deployments that do not enable governed effects keep `effect_mediation_consistent = unknown` and never receive mediated-effects assurance.
- Provider idempotency is modeled by deterministic simulators and an in-process local adapter contract; real provider integrations with signed reconciliation answers are not implemented.
- The external checkpoint witness runs as its own service role with its own key, but in development it executes on the same host under the same account; independent administration remains a deployment property. The witness journal is append-only by convention, not tamper-resistant storage.
- The Trust Root Manifest authorizes roles/purposes and supports rotation/revocation with historical verification, but end-to-end enforcement currently lives in the statement-verifier layer; not every service role yet refuses statements from manifest-unauthorized keys at its RPC boundary. Manifest rotation itself is operator-driven tooling, not an automated quorum transition.
- Quorum approval hooks (k-of-n distinct manifest-authorized approvers) are implemented for certificate issuance policy but disabled by default in development deployments.
- Key providers are role-bound abstractions over local restricted files today; KMS/HSM/TPM backends remain future work.

## Standing limitations

- The execution cell is not yet a production Firecracker deployment. The process-separated path is the reproducible default; Linux/KVM integration remains a development target with host kernel, KVM, Firecracker, image, and watchdog assumptions.
- TPM quote generation and independent verification remain incomplete for a production deployment. Synthetic fixtures and `swtpm` exercise code paths but do not establish physical hardware provenance, endorsement, fleet enrollment, or production measurement policy.
- The Executor Attestation simulator does not constitute hardware attestation and can produce only development trust.
- The capability signer, evidence recorder, and certificate signer require authenticated mutation requests and use separate restricted key files, but the development harness provisions them under one host account. They are not independently administered, HSM-backed, physically one-way, or independently hosted. A same-user or host-kernel compromise remains inside the trusted computing base.
- SQLite-backed nonce and capability consumption is durable and atomic across cooperating processes on one host. The signed remote replay protocol adds authenticated clients, response binding, checkpoints, explicit epochs, rollback detection relative to client-retained state, and a single-writer reference service. It does not provide consensus, old-leader fencing, rollback-resistant client storage, automatic safe failover, or a deployed multi-host guarantee. Database deletion before a client retains a newer checkpoint, filesystem compromise, namespace/partition misconfiguration, and unbounded record/checkpoint retention remain limitations. In the portable same-user process fallback, keeping the authority path out of executor configuration is logical separation rather than enforced filesystem isolation.
- The reference replay HTTP binding is for conformance and controlled deployment work. It has message authentication and bounded bodies/timeouts but no TLS termination, mutual TLS, rate limiting, admission control, production observability, or denial-of-service hardening.
- Tests are currently authored by the project creator and automated tooling. They are not independent validation.
- No claim is made that a frontier model has been contained. The demonstrations use deterministic synthetic actions and a harmless scripted adversary.
- No external security audit has occurred.
- The current certificate derives every claim from run-namespaced evidence, verifies independently signed source statements, and fails closed on unknown namespaces — but it does not make false evidence impossible when the recorder host or a statement-signing boundary is compromised. A dishonest coordinator that also controls a statement signer can still feed the builder fabricated-but-signed statements; independent administration of those keys is a deployment property, not an implementation guarantee.
- Recorder checkpoints bind chain history to an anchor outside the events file and detect rollback/replacement against that anchor, but the development `FileCheckpointAnchor` lives on the same host as the recorder. An attacker who controls both files can rebuild a consistent (events, checkpoint) pair; production rollback resistance requires an externally administered witness, transparency log, or consensus backend.
- Replay clients persist their latest accepted checkpoint (`FileReplayClientContinuityStore`), so restarts recover real continuity instead of genesis; this local file is still host-trusted and is not tamper-resistant hardware monotonic state.
- The capability/execution lifecycle state machine records transitions durably and blocks certification while executions are unresolved, but reconciliation of ambiguous external effects currently accepts locally recorded evidence only; provider-side idempotency receipts are not yet integrated.
- Statement signing keys (verifier, guardians, watchdog) are provisioned by the same harness that provisions all other development seeds under one host account; they are logically separate roles, not independently administered parties.
- Protected request authentication identifies the configured coordinator client; it does not make an authorized but dishonest coordinator or evidence source truthful. Per-source independently administered recorder credentials are not implemented.
- Availability is intentionally sacrificed on verifier, signer, recorder, static-policy, guardian, or infrastructure failure.
- Behavioral detection thresholds and reported rates come from deterministic synthetic fixtures; they are not validated estimates for adaptive real-world adversaries.
- Canary seeding is test-only and disabled by default. Automatic denial-certificate emission is not yet wired into every canary event path.
- Live authority decay is redemption-time and keyed by each fresh one-use capability ID. It does not accumulate denial/risk/canary/environment/restart counters across a session or lineage; persistent session behavior is enforced separately by the Behavioral Transition Guardian. Its SQLite state is not a distributed monotonic clock, consensus protocol, or atomic transaction with arbitrary external side effects.
- No independent hardware fail-safe switch or hardware-in-the-loop test has yet been implemented.
- Protocol numbers are integer-only across Python and TypeScript; persisted recorder files written by pre-v0.5 versions embed floating-point timestamps and fail verification (fail closed) rather than being silently migrated.
- CI pins third-party actions to immutable commit SHAs with minimal permissions; GitHub-hosted runner images and npm registry availability remain external trust assumptions.

These limitations are security-relevant. Results should not be generalized beyond the tested topology and explicit trust assumptions. See `docs/TRUST_ARCHITECTURE_V0_5.md` for the current proof/assumption/cannot-prove distinction.
