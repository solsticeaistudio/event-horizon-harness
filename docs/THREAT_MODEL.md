# Threat model

## Security claim

Root or total compromise inside the hostile execution cell must not create transferable authority outside it. The harness fails closed against capability replay or widening, session/executor substitution, expiry bypass, ambient credentials, unrestricted egress, persistence after teardown, lateral movement, evidence tampering, one compromised guardian, and signer/verifier unavailability.

This is an authority-containment claim under the topology and assumptions below, not a claim that all hypervisors, kernels, firmware, or physical systems are invulnerable.

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

| Threat | Enforced boundary |
|---|---|
| Replay | One-use external broker redemption plus nonce/proof replay stores |
| Scope/argument widening | Exact canonical request digest and claim comparison |
| Session/executor transfer | Session, executor, device, measurement, and attestation bindings |
| Expiry bypass | Signer and executor deadlines using fresh verification |
| Ambient credentials | Sanitized child environment, no mounted identities, root probe |
| Egress/lateral movement | Static policy veto; Firecracker has no NIC/MMDS |
| Persistence | External watchdog and scratch/config destruction evidence |
| Evidence mutation/loss/reordering | Hash chain, source/global sequence, signed receipts, restart validation |
| Forged protected-service request | Exact-envelope Ed25519 client authorization plus durable one-use nonce |
| One guardian compromise | Veto quorum; guardians only subtract authority |
| Signer/verifier outage | No local key or cached authorization fallback |
| Parser/output pressure | Fixed framing and byte/depth/request/output limits |

## Non-goals and residual risk

- Resistance to unknown KVM, Firecracker, Linux kernel, TPM firmware, or physical side-channel vulnerabilities.
- Securely exposing arbitrary shell, HTTP, package installation, dynamic plugins, or unrestricted connectors.
- Treating `swtpm`, synthetic TPM fixtures, Windows process isolation, or the explicit process fallback as hardware attestation/isolation.
- Availability when a trusted service is down. Denial of service is accepted; authority is not granted to recover availability.
- Proving a raw platform event log correct when no normalized event log is supplied. Production policy should require one when the platform makes it available.
