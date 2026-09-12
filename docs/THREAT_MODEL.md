# Threat model

The [owned package-service experiment](PACKAGE_ISOLATION.md) adds a scoped compromised-service configuration: the package worker is untrusted at host UID 60001, while the retrieval gate, artifact recipient, root-owned replay/decay/evidence, supervisor, and watchdog remain trusted. Paired synthetic effects and useful work were observed with actual guest-root VMs. This does not cover host-root/gate compromise, concurrent tenant VMs, real package installation, or arbitrary service vulnerabilities.

## Security claim

The target property is that root or total compromise inside the hostile execution cell cannot create transferable authority outside it. Portable tests exercise capability replay/widening, session/executor substitution, expiry checks, evidence integrity, guardian vetoes, and service unavailability through intended interfaces. The separate [Linux/KVM lab](LINUX_ISOLATION.md) additionally exercises real guest root with jailed Firecracker, host-side dataset enforcement, protected replay/decay/evidence, no NIC/MMDS, and external teardown. This is a bounded static experiment; auxiliary-service compromise, arbitrary workloads, concurrent sessions, and unknown isolation bypasses remain untested.

The portable development demo runs services under one host account. Separate processes and authenticated requests do not prevent that account from reading keys or mutating databases. The Linux lab uses distinct VM/effect UIDs and root-owned authoritative observation, but still trusts host kernel, hypervisor, firmware, administrators, supervisor, recorder, and effect-service integrity.

## Adversary

Assume the workload can inspect all guest inputs and local files, execute arbitrary code, deliberately obtain guest root, steal every secret in the cell, modify local logs, pressure parsers and output channels, replay observations across time, coordinate child sessions, and fully understand the architecture. Tests also inject a permissive guardian, unavailable signer/verifier, a tampered recorder file, fake credentials/services, and session/executor substitution.

## Protected assets

- External network and production service access.
- Cloud, cluster, CI, registry, package, source-control, database, metadata, and signing identities.
- Capability signing and redemption authority.
- Other executors, devices, sessions, and workloads.
- Persistent state and later runs.
- Authoritative evidence and teardown proof.

## Trust and compromise assumptions

- Compromise begins inside the hostile cell, not inside every independent TCB process simultaneously.
- One guardian may be compromised; static policy and the remaining vetoes are not all compromised together.
- Capability signer, verifier, recorder, certificate, and protected-client keys are provisioned outside executor configuration. The portable harness uses restricted development files and in-memory client keys; production requires distinct principals and external provisioning.
- Recorder mutation requests are client-authenticated and its storage/private key are logically outside the cell. The same-host demo does not enforce this against same-user filesystem or process-memory access; production requires separate administration/storage.
- In hardware mode, the verifier has an authentic pre-registered AK public key and qualified name, and the configured PCR policy represents the intended image.
- In Firecracker mode, host kernel/KVM/Firecracker/watchdog integrity is part of the TCB. No VM-isolation claim is made by the process fallback.
- The certificate consumer independently provisions a trusted certificate-signer public key or key ID and verifies the certificate signature, recorder chain/receipts, configuration digests, and claim-mode label. A key embedded in the certificate is not a trust anchor.

## Fail-closed transitions

The table below describes the portable process path. The separate Linux lab's enforced boundaries and evidence coverage are specified in [Linux isolation](LINUX_ISOLATION.md); its results do not upgrade the portable path's guarantees.

| Threat | Implemented/tested behavior | Remaining boundary |
|---|---|---|
| Replay | Atomic one-use broker/executor consumption and nonce/proof stores | Databases are accessible to the host account; no distributed guarantee |
| Scope/argument widening | Exact canonical request digest and claim comparison | Guest-root-resistant external effect enforcement is planned |
| Session/executor transfer | Session, executor, device, measurement, and attestation bindings | Protocol rejection does not establish cross-session filesystem isolation |
| Expiry bypass | Signer/executor deadlines and fresh verification | Trusted clocks and state remain assumptions |
| Ambient credentials | Sanitized child environment and bounded root probes | Probes do not exclude host file/process access or undiscovered secrets |
| Egress/lateral movement | Static policy rejects unsupported network operations; Firecracker target omits NIC/MMDS | Process fallback has no enforced network isolation; service-mediated egress is unproven |
| Persistence | Configured process stop and scratch/config teardown checks | Hostile descendant cleanup, revocation, and later-session isolation need external validation |
| Evidence mutation/loss/reordering | Hash chain, sequences, signed receipts, restart checks | Missing observations, rollback, and trusted-source dishonesty are not eliminated |
| Forged protected-service request | Exact-envelope Ed25519 authorization and durable nonce | Role-scoped independent credentials and protected storage are deployment work |
| One guardian compromise | Veto quorum and static ceiling | Signer/static policy and remaining vetoes stay trusted |
| Signer/verifier outage | No permissive issuance fallback | Previously started effects are not undone |
| Parser/output pressure | Framing and byte/depth/request/output limits | Output remains untrusted; byte limits are not secret filtering |
| Failure after operation dispatch | Indeterminate outcome, retained consumption, no automatic retry | No rollback, exactly-once effect, or automatic reconciliation guarantee |

See [Execution outcomes and the external-effect contract](EXECUTION_OUTCOMES.md) for failure semantics and independent synthetic effect tests.

## Non-goals and residual risk

- Resistance to unknown KVM, Firecracker, Linux kernel, TPM firmware, or physical side-channel vulnerabilities.
- Securely exposing arbitrary shell, HTTP, package installation, dynamic plugins, or unrestricted connectors.
- Treating `swtpm`, synthetic TPM fixtures, Windows process isolation, or the explicit process fallback as hardware attestation/isolation.
- Availability when a trusted service is down. Denial of service is accepted; authority is not granted to recover availability.
- Proving a raw platform event log correct when no normalized event log is supplied. Production policy should require one when the platform makes it available.
