# Implementation-level design defense

This document describes the v0.4.0 implementation, including its current trust assumptions. It does not describe a stronger future system.

## 1. Why can guardians only subtract authority?

The Static Policy Guardian evaluates the immutable canonical `ActionRequest` against an allowlist of agents, executors, operations, resources, argument keys, and output limits. The coordinator requires one well-formed approval from every required guardian and treats every denial, absence, timeout, exception, malformed response, duplicate identity, request-digest mismatch, or policy-version mismatch as a veto. Dynamic decisions are never used to construct operation scope. After unanimity, the broker signs the same request and the output limit returned by the static policy. Consequently, a dynamic approval contributes no authority; it can only avoid exercising that guardian's veto.

This invariant assumes the deterministic policy and the code that evaluates and binds it are trusted. Compromise of the static policy configuration is compromise of the ceiling, not a case the dynamic-guardian theorem covers.

## 2. What signs a capability?

`CapabilityBroker` signs canonical `CapabilityClaims` with an Ed25519 private key. In the process-separated harness the seed is loaded by the signer service from a separate restricted development file; it is not embedded in JSON configuration. The executor is configured with only the corresponding public key and derived key ID. Capability issue and consume calls also require a fresh Ed25519 client authorization bound to the exact RPC request. There is no production HSM, managed key service, separately administered principal, or remote authenticated transport in this artifact.

## 3. What exactly is bound into a capability?

The signed claims bind a random capability ID; integer issuance and exclusive-expiration times; session, agent, executor, and device IDs; executor measurement; verified attestation-result, complete-bundle, and verifier-policy digests; operation and resource; canonical arguments digest; canonical whole-request digest; maximum output bytes; invocation limit of one; deterministic static-policy digest; and signer key ID. The whole-request digest covers request ID, session ID, agent ID, operation, resource ID, executor ID, arguments, and purpose.

The executor reconstructs the request and arguments digests independently and compares every runtime binding before dispatch. It also checks the attestation result digest, executor measurement, configured policy digest, configured verifier-policy digest, configured device identity, signing key identity, Ed25519 signature, and time window.

## 4. Why can it be used only once?

Every capability has `invocation_limit = 1` and a unique `capability_id`. After signature, time, request, executor, attestation, policy, and key checks succeed, `verify_and_consume` hashes the complete signed claims and asks its configured consumption store to insert the capability ID once. The default process-separated path uses SQLite transactions. A second or concurrent redemption is denied. It consumes in the authority-side broker domain and again in a distinct executor domain; failure after the first transition burns the capability rather than restoring it.

The committed multi-process test races 16 spawned broker verifiers and requires exactly one success. Consumption survives signer and executor process restarts. `RemoteCapabilityConsumptionStore` can instead use the authenticated replay state-machine interface. Its reference service signs exact-request decisions and serializes transitions through one SQLite writer; a 48-way remote-interface race also requires exactly one success. This validates the interface but does not supply consensus or old-leader fencing for multi-host deployment.

## 5. How is nonce replay prevented?

The verifier accepts only a canonical 32-byte nonce that its `NonceAuthority` issued or explicitly registered. The authority record binds device ID, executor ID, session ID, purpose, issuance time, expiration time, and an immutable context digest. Only after provider-specific proof verification succeeds does the authority perform one atomic `issued -> consumed` transition. Unknown, malformed, expired, already consumed, and wrong-context nonces fail closed; simultaneous verification attempts can produce at most one accepted transition.

The default verifier bridge uses `SqliteNoncePersistence`, whose conditional `UPDATE` is atomic across cooperating local verifier processes and durable across their restarts. A committed test races 24 separate Node processes and requires exactly one successful verification. The awaitable `RemoteNoncePersistence` uses signed canonical requests against the same remote replay interface. Its client pins service key, epoch, and checkpoint continuity; invalid signatures, stale epochs, rollback, malformed results, and outages fail closed. A Python-service/Node-client test verifies actual cross-language signatures and records. The in-memory implementation remains available for isolated unit tests. The reference remote service is not a consensus backend, and protected checkpoint storage plus old-leader fencing remain deployment requirements.

## 6. How does the verifier distinguish simulator trust from hardware trust?

The outer verifier parses a strict bundle, rejects unknown methods, and dispatches the complete signed bundle and challenge context to the verifier registered for that method. It derives trust only from a strict successful provider result. The simulator verifier can return only `simulated` trust with `development` assurance. A simulator result cannot satisfy a hardware-only minimum.

Only `Tpm2AttestationVerifier` may return `hardware` trust, after checking freshness, nonce and device context, registered attestation-key identity, parsed TPM quote type and safe clock, quote nonce, qualified signer, PCR selection and composite digest, optional event-log reconstruction, quote signature, whole-bundle signature, and measurement policy. A method or trust-level string inside the bundle does not itself grant trust. Missing providers, exceptions, malformed results, invalid TPM data, and unimplemented methods fail closed.

## 7. What happens if a guardian is compromised?

A compromised dynamic guardian that approves everything cannot widen the request because scope comes only from the static policy and exact canonical request. A guardian that denies, stalls, crashes, swaps request digests, replays a decision bound to a different request, or emits malformed data causes denial. Thus one dynamic guardian can cause loss of availability but not additive authority under the implemented coordinator. Guardian decisions do not currently carry their own timestamp; freshness comes from invoking each guardian for the current digest rather than accepting detached approvals.

The Static Policy Guardian, coordinator, broker, and their configuration are trusted computing base components. A compromise that changes the static policy and its expected digest can change the ceiling; that is not prevented by quorum approvals.

## Adaptive governance, canaries, decay, and evidence

The task-policy synthesizer accepts untrusted natural language, templates, traces, and optional model output. `TaskPolicyCompiler` validates the strict candidate, rejects unknown fields, intersects it with global/tenant/environment/trust constraints, and emits the only ceiling shape accepted by the broker. The synthesizer has no signer and cannot mint capabilities. Shadow and evaluation modes compute proposals without changing enforcement.

The broker's effective authority is the intersection of global maximum, compiled task ceiling, request, signed claims, provider-attested trust, guardian reductions, current policy, and current decay. The behavioral guardian and decay engine return reductions only; malformed or unavailable state denies. The behavioral guardian persists session-scoped history, while the live decay engine records redemption-time state under each fresh one-use capability ID and does not accumulate its optional behavioral counters across capabilities. A canary is a disjoint signed artifact checked before normal effect execution and can never reach an effect path.

Denial certificates are scoped receipts. They bind request, policy-ceiling, compiler, trust, guardian, decay, build, signer, and evidence-chain digests. Only pre-effect or post-validation denial states can make a definitive no-effect statement; crashes, lost responses, and reconciliation states remain indeterminate. The hardware-failsafe implementation is a simulator with an independent verification-key model and explicit re-arm; no physical isolation is claimed.

## 8. What happens if the static policy guardian fails?

Issuance is denied. The static guardian is required exactly once, must approve the same request digest, and must report the coordinator's expected policy digest and a valid output envelope. Absence, timeout, exception, malformed output, denial, or inconsistent version is a veto. There is no cached approval or dynamic fallback.

## 9. What is the highest-value trusted-computing-base attack?

Stealing or controlling the capability-signing key or authorized signer-client key is the most direct authority attack: a forger that also knows the executor's configured bindings could target capability issuance. The signer independently revalidates guardian and attestation bindings, but its configured client remains trusted. Closely related targets are the executor's trusted public-key/policy configuration, the static-policy evaluator, and deletion or rollback of authoritative replay state. Production deployment therefore needs hardware-backed or separately administered signing, distinct authenticated principals, protected configuration rollout, least-privilege signer APIs, rollback-resistant replay storage, rotation/revocation, and independent monitoring. None of those deployment controls is claimed here.

For evidence rather than authority, compromise of the recorder/certificate signing boundary is comparably decisive because it could create apparently authoritative false evidence.

## 10. How could parser disagreement widen authority?

If the signer read one operation or argument set while the executor acted on another, a correctly signed narrow request could become a wider action. Duplicate JSON keys, unknown fields, Unicode variants, floats and large integers, negative zero, alternative signature encodings, reordered nested objects, trailing data, or mutation after approval are representative ambiguity sources.

The implementation uses exact field sets, duplicate-key rejection at protocol parsing, bounded NFC canonical JSON, interoperable integers, no floating-point request values, immutable request arguments, canonical digests, canonical signature encoding, and independent digest reconstruction at signing and execution. The fixed adversarial vectors exercise these boundaries. Cross-language conformance is still a high-value review target.

## 11. What is currently simulated?

The default demo uses a process-separated sacrificial executor, synthetic objects and actions, a deterministic static policy, the development Executor Attestation simulator, locally generated restricted service-key files, ephemeral protected-client keys, and a harmless scripted adversary in declared synthetic ranges. The evidence recorder is an authenticated separate logical process on the same host. The reference comparison is scripted synthetic data and explicitly leaves teardown persistence, authoritative evidence verification, and certificate signing unmeasured.

An optional Firecracker development runner and `swtpm` fixtures exist, but neither changes the default public claim. Simulator verification is not hardware attestation, and the scripted adversary is not a real offensive campaign or frontier model.

## 12. What would be required for a real Firecracker deployment?

A production target needs a pinned and reproducibly built Firecracker/VMM, kernel, and minimal immutable root filesystem; native Linux/KVM; the Firecracker jailer or equivalent namespaces, cgroups, uid/gid isolation, seccomp, resource quotas, and host hardening; authenticated image and configuration rollout; a fixed bounded vsock protocol; no guest NIC or ambient host mounts; isolated scratch lifecycle; enforced watchdog teardown; replay state that the guest cannot access or roll back; and evidence exported to a separately administered recorder. It also needs tests against kernel, VMM, device-model, vsock, teardown, and host-control failure modes.

The repository currently has a route-less, read-only-rootfs development configuration and watchdog, plus one nested-WSL2 development fixture. It does not provide a production jailer deployment or claim resistance to host-kernel compromise.

## 13. What would be required for real TPM attestation?

The current verifier parses and verifies a constrained RSA/SHA-256 TPM quote path, but production hardware trust additionally requires real device enrollment; endorsement and attestation-key provenance; protected key lifecycle and rotation; manufacturer or organizational trust anchors; quote generation on the target hardware; an approved PCR-selection and measurement policy tied to reproducible boot artifacts; validated measured-boot event logs; secure freshness and a linearizable multi-host nonce authority; revocation; downgrade handling; and an independently operated verifier and device registry. Those pieces need conformance testing against deployed TPMs. `swtpm` and synthetic fixtures do not establish physical hardware provenance.

## 14. How is authoritative evidence protected?

The recorder appends fixed-size canonical events with global sequence, per-source sequence, previous hash, and event hash. It rescans before append and on recovery, detects modification, partial-record truncation, reordering, gaps, and linkage failure, and returns Ed25519-signed receipts. Append and certificate-build requests require exact-envelope Ed25519 client authorization and durable one-use nonces. Recorder and certificate keys are distinct restricted development files and survive service restart. The containment certificate binds the verified chain tip and count plus attestation, capability, policy, image, teardown, egress, and assertion domains, then signs the canonical certificate with a separate Ed25519 key. Verification can pin the expected public key and key ID. Removal of a complete trailing suffix after recorder state loss requires an externally retained receipt or certificate checkpoint to detect; the local file alone cannot prove that its last valid event was globally final.

In the demo this is authenticated logical separation, not physical independence or one-way storage. The coordinator is an authorized mutation client, so authentication does not prove its submitted events are true. A compromised same-user host, authorized client, recorder process/key, or certificate process/key remains capable of suppressing or fabricating evidence. Separately administered principals, per-source identities, append-only storage, and HSM/KMS-backed signing are future work.

## 15. Which claims are not yet externally validated?

There has been no independent audit, third-party parser review, production TPM validation, production Firecracker assessment, separately administered signer/evidence test, separately hosted evidence test, consensus-backed multi-host replay deployment, Windows ACL assessment, independent rollback-resistance assessment, or frontier-model containment experiment. Tests are authored by the project creator and automated tooling. The artifact demonstrates deterministic synthetic security regressions in its documented topology; it does not establish production readiness or general frontier-model containment.
