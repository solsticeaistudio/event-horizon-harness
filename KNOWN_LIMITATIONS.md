# Known limitations

Event Horizon is a research harness, not a production containment system.

- The execution cell is not yet a production Firecracker deployment. The process-separated path is the reproducible default; Linux/KVM integration remains a development target with host kernel, KVM, Firecracker, image, and watchdog assumptions.
- TPM quote generation and independent verification remain incomplete for a production deployment. Synthetic fixtures and `swtpm` exercise code paths but do not establish physical hardware provenance, endorsement, fleet enrollment, or production measurement policy.
- The Executor Attestation simulator does not constitute hardware attestation and can produce only development trust.
- The capability signer, evidence recorder, and certificate signer require authenticated mutation requests and use separate restricted key files, but the development harness provisions them under one host account. They are not independently administered, HSM-backed, physically one-way, or independently hosted. A same-user or host-kernel compromise remains inside the trusted computing base.
- SQLite-backed nonce and capability consumption is durable and atomic across cooperating processes on one host. The signed remote replay protocol adds authenticated clients, response binding, checkpoints, explicit epochs, rollback detection relative to client-retained state, and a single-writer reference service. It does not provide consensus, old-leader fencing, rollback-resistant client storage, automatic safe failover, or a deployed multi-host guarantee. Database deletion before a client retains a newer checkpoint, filesystem compromise, namespace/partition misconfiguration, and unbounded record/checkpoint retention remain limitations. In the portable same-user process fallback, keeping the authority path out of executor configuration is logical separation rather than enforced filesystem isolation.
- The reference replay HTTP binding is for conformance and controlled deployment work. It has message authentication and bounded bodies/timeouts but no TLS termination, mutual TLS, rate limiting, admission control, production observability, or denial-of-service hardening.
- Tests are currently authored by the project creator and automated tooling. They are not independent validation.
- No claim is made that a frontier model has been contained. The demonstrations use deterministic synthetic actions and a harmless scripted adversary.
- No external security audit has occurred.
- The current certificate verifies claims over the recorder's evidence and configured teardown path; it does not make false evidence impossible when the recorder host or signing boundary is compromised.
- Protected request authentication identifies the configured coordinator client; it does not make an authorized but dishonest coordinator or evidence source truthful. Per-source independently administered recorder credentials are not implemented.
- Availability is intentionally sacrificed on verifier, signer, recorder, static-policy, guardian, or infrastructure failure.
- Behavioral detection thresholds and reported rates come from deterministic synthetic fixtures; they are not validated estimates for adaptive real-world adversaries.
- Canary seeding is test-only and disabled by default. Automatic denial-certificate emission is not yet wired into every canary event path.
- Live authority decay is redemption-time and keyed by each fresh one-use capability ID. It does not accumulate denial/risk/canary/environment/restart counters across a session or lineage; persistent session behavior is enforced separately by the Behavioral Transition Guardian. Its SQLite state is not a distributed monotonic clock, consensus protocol, or atomic transaction with arbitrary external side effects.
- No independent hardware fail-safe switch or hardware-in-the-loop test has yet been implemented.

These limitations are security-relevant. Results should not be generalized beyond the tested topology and explicit trust assumptions.
