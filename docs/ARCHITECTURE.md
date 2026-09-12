# Architecture and trusted computing base

## Process topology

This is the portable development topology. All services, development keys, and databases run under one host account. The logical separation described below is not an enforced filesystem or process-memory boundary against compromise of that account. A separate opt-in [Linux/KVM dataset lab](LINUX_ISOLATION.md) now demonstrates jailed guest root and a host-side effect service under distinct host UIDs; it uses a synthetic issuer and does not replace this seven-process flow.

```text
hostile request
      |
      v
Intent Canonicalizer ----> Executor Attestation verifier
      |                              |
      +--> Task Policy Synthesizer   |
      |             |                |
      |      untrusted candidate     |
      |             v                |
      +--> deterministic compiler <--+
      |             |
      +--------> guardian quorum <---+
                         |
              authenticated request
                         v
              Capability Signer / broker
                         |
                  exact capability
                         v
                sacrificial executor

Every transition ----> authenticated evidence append
                                      |
                         independent logical evidence recorder
                                      |
                                      v
                         Evidence Chain Verification
```

Each named box is a separate OS process in `ProcessSeparatedHarness`. Processes communicate over stdin/stdout pipes using the same minimal protocol: four-byte big-endian length followed by canonical UTF-8 JSON. The protocol rejects duplicate keys, noncanonical encodings, unknown message types or fields, excessive bytes, strings, collections or nesting, expired deadlines, and excess requests. Signer, recorder, and certificate mutations additionally require an audience-bound Ed25519 client authorization over the exact RPC envelope and a durable one-use authorization nonce.

## Authority flow

1. The Intent Canonicalizer parses and canonicalizes a typed request. It has no tool registry, signing key, network client, or execution authority.
2. Executor Attestation verifies a verifier-issued one-time nonce, registered device/AK identity, signed measurement evidence, freshness, PCR selection, and policy. It returns evidence, never authorization.
3. The Task Policy Synthesizer proposes a task-specific ceiling. The deterministic compiler rejects unknown authority and intersects the candidate with static policy, provider trust, tenant/environment policy, approvals, and guardian reductions. The synthesizer cannot sign or mint authority.
4. The Static Policy Guardian, Executor Attestation Guardian, Lineage Budget Guardian, and Behavioral Transition Guardian each evaluate the same request. One permissive guardian cannot override another veto or widen static policy.
5. The broker presents a fresh authenticated request to the isolated signer, which independently revalidates the guardian aggregate and attestation binding before minting a short-lived capability for the exact canonical request digest and compiled ceiling.
6. The authority-side broker atomically burns each capability before dispatch. The executor receives the public verification key, expected bindings, and a separate defense-in-depth replay database—never the signing key or authoritative replay database—and rechecks every binding before one pre-registered operation.
7. Redemption reconstructs the signed decay profile, applies the live per-capability inputs before authorization, atomically records the one-use capability's decay state, and intersects that state with all preceding authority. Session-scoped behavioral history is enforced separately by the Behavioral Transition Guardian; the live broker does not accumulate `DecayEngine` counters across fresh capability IDs.
8. Canary artifacts follow a disjoint signed schema. The executor checks them before the ordinary capability path, records the tripwire event, and cannot route them to an effect.
9. The independent logical evidence recorder returns a signed receipt for every fixed-size event envelope. Evidence Chain Verification signs a certificate only after recorder verification and verified teardown. Denial certificates provide a separate exact-attempt receipt and preserve ambiguous effect states.

Operation dispatch is tracked separately from successful response delivery. Failures after dispatch are indeterminate and never refund consumption; see [Execution outcomes](EXECUTION_OUTCOMES.md). The process executor's local recorder is a null implementation, so authoritative logical execution evidence is appended by the coordinator after a response, and missing responses remain unknown.

## Capability bindings

The capability commits to request ID and digest, session and subject, operation/resource/arguments, workload and device identity, image/measurement digest, task ID and fingerprint, tenant/environment/audience, requested/provider/effective/signed trust, Executor Attestation method/key/bundle/result digests, verifier-policy digest, static-policy digest, the complete compiled ceiling and digest, guardian state, decay profile/version/profile digest/initial-authority digest/refresh requirements, signer key ID, expiry, one-use invocation count, and maximum output bytes.

Guardian combination is unanimity with mandatory identities, not majority voting. Response schemas, guardian identity, request digest, and policy version are checked independently of response order. Any missing, duplicate, stale, malformed, timed-out, crashed, or inconsistent response is a veto. See [GUARDIAN_QUORUM.md](GUARDIAN_QUORUM.md).

## Trusted computing base inventory

| Component | Trusted for | Explicitly lacks |
|---|---|---|
| Protocol codec/schema | Canonical parsing and bounds | Policy, keys, execution |
| Executor Attestation verifier | Identity and measurement decision | Authorization and capability key |
| Static Policy Guardian and quorum coordinator | Subtractive policy and veto combination | Execution and signing key |
| Signer/broker and client authenticator | Exact capability minting, caller identity, and redemption state | Workload code and arbitrary connectors |
| Executor verifier/dispatcher | Binding checks and fixed operations | Capability private key and ambient credentials |
| Independent logical evidence recorder | Authenticated append, ordered evidence, and receipts | Workload execution authority or source truthfulness |
| Evidence Chain Verification | Authenticated construction, final evidence-domain validation, and signature | Capability minting and workload access |
| Firecracker, host kernel, KVM, guest image, watchdog | Hardware cell isolation and teardown in KVM mode | External service credentials |
| TPM, AK, `tpm2-tools`, Executor Attestation parser | Hardware identity/measurement evidence in TPM mode | Action authorization |

The default local topology stores authoritative nonce, protected-request, and broker consumption state in SQLite outside the executor and executor consumption in a separate SQLite database. Conditional transitions are durable across cooperating process restarts on one host. Capability, recorder, and certificate seeds are loaded from distinct non-inline files. The files, authorized-client keys, WALs, namespace/domain configuration, rollback protection, and host filesystem remain trusted; see [REPLAY_STATE.md](REPLAY_STATE.md) and [PROTECTED_BOUNDARIES.md](PROTECTED_BOUNDARIES.md).

The model, hostile executor contents, synthetic services, local audit decoy, model-based guardian, and human-facing output are untrusted. Development deployments currently run the seven trusted processes on one host; distinct processes reduce key exposure and confused-deputy paths but do not make a compromised host kernel trustworthy.

## Firecracker cell

The Linux/KVM target has a read-only minimal rootfs, a per-run scratch image, no package manager, no host mounts, no NIC, no MMDS/metadata endpoint, and one fixed vsock protocol. An external watchdog terminates the VM and invalidates then deletes scratch/configuration. If KVM or required artifacts are missing, the default behavior is denial. The explicit process fallback writes `hardware_isolation_claimed: false`.

## Evidence and certificate

Events carry global and per-source sequence numbers and a previous-hash link. Recorder receipts are Ed25519 signed. Startup validates the persisted chain before accepting another event; loss, reordering, mutation, and source gaps deny further recording. The certificate contains or hashes all seven required evidence domains. Authenticity verification requires a signer public key or key ID obtained independently of the certificate; the embedded public key is metadata and cannot establish its own trust root.
