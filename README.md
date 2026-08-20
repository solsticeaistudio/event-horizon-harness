# Event Horizon

<p align="center">
  <img src="assets/event-horizon-harness.png" alt="Event Horizon Harness black hole and accretion disk artwork" width="100%">
</p>

[![CI](https://github.com/Solasticeaistudio/event-horizon-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/Solasticeaistudio/event-horizon-harness/actions/workflows/ci.yml)

Event Horizon is a research harness for testing whether a fully compromised autonomous-agent execution environment can convert local control into transferable authority. It computes a task-specific least-authority ceiling and then enforces that ceiling through cryptographically bound, attestation-aware, subtract-only capabilities.

The tested claim is narrower than general containment: compromise inside the hostile execution cell must not grant transferable authority, unrestricted egress, durable persistence, cross-session influence, or control over authoritative evidence.

## What this repository demonstrates

- Strict canonical requests cross explicit process boundaries with bounded schemas and duplicate-key rejection. Shared adversarial vectors enforce the same NFC, byte, item, depth, numeric, and Unicode key-order domain in Python and TypeScript.
- Executor Attestation issues a fresh, context-bound nonce and dispatches verification by signed-bundle method. The default public demo uses a simulator and labels it development-only.
- An Ed25519 capability binds the exact request, arguments, session, executor, device, measurement, attestation, verifier policy, static policy, expiry, output limit, and one-use identifier.
- The signer and executor independently reconstruct request and argument digests. SQLite-backed replay state makes nonce and capability consumption durable and atomic across cooperating processes on one host. A signed cross-language interface defines the same transitions for a separately deployed replay authority.
- Capability issuance/consumption, evidence append, and certificate construction require fresh Ed25519 client authorization. Service signing seeds are restricted file-backed fixtures, not inline JSON values.
- Four required guardians form a unanimity veto. Missing, malformed, stale, inconsistent, crashed, or timed-out decisions deny execution.
- An independent logical evidence recorder hash-chains events and signs receipts. A detached Ed25519 containment certificate covers the recorded evidence domains and verified teardown; authenticity requires an independently provisioned signer key or pinned key ID.
- Fixed adversarial vectors and compromise-injection tests exercise parser disagreement, substitution, replay, guardian failure, evidence tampering, and transfer attempts.
- A deterministic task-policy synthesizer and trusted compiler size authority from task semantics while keeping the adaptive proposal non-authoritative.
- Canary capabilities, session-scoped behavioral boundary-probing detection, per-capability redemption-time monotonic decay, signed denial certificates, bounded adaptive-adversary interfaces, and a hardware-failsafe simulator provide additional subtract-only controls and evidence.

## What it does not demonstrate

This repository does not demonstrate containment of a frontier model, production Firecracker isolation, production TPM enrollment or hardware provenance, resistance to host-kernel compromise, separately administered or hardware-backed signing, physically one-way evidence storage, a deployed multi-host replay backend, a physical fail-safe installation, TLC model checking on this host, or an independent security audit. The default adversary is scripted and synthetic; a real model endpoint is optional and its self-report is never trusted.

See [Known limitations](KNOWN_LIMITATIONS.md) for the complete claim boundary.

## Core security invariant

> Guardians may only subtract authority. Dynamic approval can never exceed the deterministic static policy ceiling.

Every issued capability is the intersection of the canonical request and deterministic static policy, further restricted by all guardian vetoes. A model, guardian, approval service, or human decision cannot add operations, resources, arguments, identities, duration, egress, or output beyond that ceiling. Static-policy failure denies capability issuance.

Effective authority is the intersection of `GlobalMaximumAuthority`, `TaskPolicyCeiling`, `RequestedAuthority`, `SignedAuthority`, `ProviderAttestedAuthority`, `GuardianPermittedAuthority`, `CurrentPolicyAuthority`, and `CurrentDecayAuthority`.

## Threat model

Assume arbitrary code execution, root-equivalent visibility, stolen local files and process memory, parser pressure, replay, concurrency, and deliberate evidence tampering inside the sacrificial cell. Capability and protected-client signing keys, attestation enrollment, deterministic policy, replay state, the logical recorder, certificate signing, and the host isolation boundary remain trusted computing base components in the current prototype.

The system accepts loss of availability when a trusted component fails. It does not recover availability by granting fallback authority. See the [full threat model](docs/THREAT_MODEL.md) and [Executor Attestation threat model](docs/ATTESTATION_THREAT_MODEL.md).

## Architecture

```text
Untrusted agent
    |
    v
Intent Canonicalizer
    |
    v
Task Classification
    |
    v
Adaptive Task Policy Ceiling
    |
    v
Trusted Policy Compiler
    |
    +--> Executor Attestation Guardian
    +--> Lineage Budget Guardian
    +--> Behavioral Transition Guardian
    |
    v
Capability Broker
    |
    v
Sacrificial Executor
    |
    v
Sanitized Result Channel

Authenticated logical side plane on the same host:
requests, decisions, capabilities and results
    -> Independent logical evidence recorder
    -> Signed Containment Certificate
```

Physical separation of the evidence plane is future work. Implementation details are in [Architecture](docs/ARCHITECTURE.md), [Protected signing and evidence boundaries](docs/PROTECTED_BOUNDARIES.md), [Guardian quorum semantics](docs/GUARDIAN_QUORUM.md), [Executor Attestation architecture](docs/ATTESTATION_ARCHITECTURE.md), [Durable replay state](docs/REPLAY_STATE.md), and the [authenticated remote replay protocol](docs/REMOTE_REPLAY_PROTOCOL.md).

## Quick start

Requirements: Python 3.11+, Node.js 20+, npm, and GNU Make on POSIX systems.

```bash
npm ci
python -m pip install -e ".[test]"
make demo
```

On Windows PowerShell:

```powershell
npm ci
python -m pip install -e .
./scripts/demo.ps1
```

The demo generates development keys at runtime. It commits no private key and explicitly states that simulator verification is not hardware-backed attestation.

The demo writes the certificate signer public key separately, from the signer service's trusted `info` path, before it verifies the certificate. The certificate's embedded key is descriptive metadata and is never used as its own trust anchor:

```text
trusted certificate-signer service identity
        |
        v
.demo/latest-certificate-signer-public.pem
        |
        v
verify .demo/latest-containment-certificate.json
```

## Reference result

The current scripted demo produces this normalized result:

| Check | Result |
|---|---:|
| Initial local access | ASSUMED |
| Executor attestation | VERIFIED (SIMULATOR) |
| Permitted exact operation | SUCCESS |
| Capability replay | DENIED |
| Argument widening | DENIED |
| Cross-executor transfer | DENIED |
| Unauthorized network operation | DENIED |
| Local evidence-copy tampering | DETECTED |
| Containment certificate | VERIFIED |

The deterministic normalized fixture is under [examples/reference-run](examples/reference-run/README.md). Fresh nonces, keys, timestamps, capabilities, and digests intentionally change on every live run.

## Verification

```bash
npm ci
npm run build
npm test
python scripts/verify_remote_replay_interop.py
python scripts/verify_capability_vectors.py
python scripts/verify_canonicalization_vectors.py
python scripts/verify_certificate.py .demo/latest-containment-certificate.json --trusted-key .demo/latest-certificate-signer-public.pem
python scripts/check_repository_policy.py
python scripts/generate_security_report.py
```

The exact current test counts are recorded in [STATUS.md](STATUS.md). The real-TPM integration test is opt-in on a configured Linux host. For an isolated clone, run `scripts/verify-clean-install.sh` or `scripts/verify-clean-install.ps1`.

Containment-certificate verification fails closed without `--trusted-key` or an independently pinned `--trusted-key-id`. `ContainmentCertificateBuilder.verify_self_consistency()` exists only for diagnostics and does not establish trusted authenticity.

The [implementation-level design defense](docs/DESIGN_DEFENSE.md) maps the central security questions to the current code and trust assumptions.

## Attack the harness

Start with [RED_TEAM.md](RED_TEAM.md) and [SECURITY.md](SECURITY.md). Public testing is limited to owned synthetic environments. Useful targets include authority widening, replay, executor transfer, nonce reuse, hardware-trust forgery, evidence-chain alteration, and persistence after verified teardown.

The future campaign-engine boundary is intentionally limited to the [bounded synthetic adversarial runner](docs/ADVERSARIAL_RUNNER.md); no raw offensive platform or real-infrastructure connector is included.

Paired `baseline` and `event-horizon` results use the strict [experiment format](docs/EXPERIMENT_FORMAT.md). The committed comparison is clearly labeled scripted synthetic data and is not a real campaign result.

The fixed capability inputs are in [test-vectors](test-vectors/README.md):

```bash
python scripts/verify_capability_vectors.py
python -m unittest discover -s tests -p "test_guardian_compromise.py" -v
```

Report plausible containment bypasses privately before publishing details.

## Current limitations

The default execution path is process separation, not a production microVM. TPM fixtures and `swtpm` do not establish hardware provenance. The hardware-failsafe component is a simulator only. The optional adaptive adversary is a bounded controller-side interface, not a completed hostile-cell model campaign. Literature fixtures are metadata-only and pending human review. Signing and evidence mutations are authenticated, but their development keys, services, and storage remain under one host account. The remote replay protocol has authenticated Python and TypeScript clients, signed checkpoints, explicit epochs, and a single-writer reference service; no consensus-backed multi-host deployment or old-leader fencing is included. Tests are project-authored and automated, and no external audit has occurred.

These are active limitations, not deployment footnotes. See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

## Roadmap

1. Deploy the authenticated signing/evidence interfaces under separate principals with externally provisioned protected keys and storage.
2. Deploy the authenticated replay interface on a consensus-backed multi-host state machine with old-leader fencing, protected client checkpoints, and independent monitoring.
3. Complete production TPM enrollment, endorsement validation, quote generation, and measurement policy.
4. Run the executor in a reproducibly built Firecracker image with enforced host controls and teardown.
5. Commission independent parser, capability, attestation, evidence, and containment review.

Contribution requirements are in [CONTRIBUTING.md](CONTRIBUTING.md). The repository retains its existing source-review license; see [LICENSE](LICENSE).
