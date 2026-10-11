# Firecracker + etcd containment - operator-run evidence (2026-10-11)

**Status: original operator-run report and checksum published; paired observations and three signed chains verified against embedded keys. Synthetic attestation and internal signatures are not independently witnessed hardware attestation.**

This records three real Firecracker/KVM guest-root sessions executed by the operator on an owned Ubuntu/WSL2 machine: one deliberately vulnerable package-service fixture and two protected fixtures, with an etcd-backed one-use capability authority. The experiment was not run in GitHub Actions. Publication copied the original [JSON report](artifacts/2026-10-11/package-etcd-20261011T203017Z-10867.json) and [checksum sidecar](artifacts/2026-10-11/package-etcd-20261011T203017Z-10867.json.sha256) byte-for-byte; it did not rerun the experiment or change source code.

**This run did not integrate the separately isolated four-guardian signer system. That integration remains separate work.**

## Experiment identity and provenance

| Item | Value / evidence source |
|---|---|
| Experiment source revision | [`f74e31537512dc5885596a6f50a3d8d43bd90127`](https://github.com/solsticeaistudio/event-horizon-harness/commit/f74e31537512dc5885596a6f50a3d8d43bd90127), supplied by the operator and matching the checkout at publication inspection |
| Environment | Operator's Ubuntu on WSL2, x86_64; report host kernel `6.6.87.2-microsoft-standard-WSL2` |
| Firecracker / jailer | v1.15.1; pinned binary hashes in `build_manifest.artifacts` and `build_manifest.asset_lock` |
| Guest kernel | Pinned Linux 6.1.155 image in `build_manifest.asset_lock.kernel_url` |
| Worker toolchain | GCC 13.3.0, Ubuntu 24.04 build; `worker_build` records source and binary digests |
| Report schema / result | `event-horizon.package-isolation.v2` / `PASS` |
| Attestation | `synthetic-fixture`; `tpm2_enabled: false`; guest diagnostic reports TPM2 not enabled |
| Authority | `etcd`, pinned cluster ID **`15411549680087618151`** |
| Cluster topology / version | Three disposable etcd v3.6.0 Docker nodes forming a real Raft quorum, reported by the operator; launcher at the source revision configures three members and defaults to `quay.io/coreos/etcd:v3.6.0` |
| Original report | `artifacts/reports/package-etcd-20261011T203017Z-10867.json` |
| Original and published SHA-256 | `0d9b62922e187d7d00c50dc115f877ccfbfa6c2ab590d3aa2a425d0b7bc7a32d` |
| Independent external witness | None |

The source revision is operator-supplied provenance, not a Git commit field cryptographically bound inside this JSON. The report binds build/configuration digests and the cluster ID in signed context. Its per-session etcd oracle records corroborate use of that cluster; it does not embed a full three-member status transcript or etcd image digest. The launcher checks three endpoints using linearizable reads and requires their cluster IDs to agree. Its default image tag can be overridden, so the version above also relies on the operator's account of this run.

## Terminal result supplied by the operator

```text
PASS: three disposable etcd nodes agree on cluster 15411549680087618151

Package-service isolation: PASS (vulnerable control + two protected guest-root sessions; pinned distributed etcd authority)

Package isolation evidence: VERIFIED (paired oracle and 3 signed chains; embedded keys, integrity only)

package-etcd-20261011T203017Z-10867.json: OK
```

## Verified observations

The same worker binary and approved inert artifact digest appear in all three rounds. The guest-root diagnostic reports UID 0; host observations report VM UID 60000 and package-service UID 60001, verified chroots, separate network namespaces, VM seccomp, resource limits, and no configured guest network interfaces. These are host-reported observations of real KVM execution, not hardware-attested statements.

| Observation | Vulnerable control, round 0 | Protected, round 1 | Protected, round 2 |
|---|---|---|---|
| Approved retrieval and trusted recipient digest check | Succeeded | Succeeded | Succeeded |
| Synthetic relay / fake credential reuse | Both observed | Neither observed | Neither observed |
| Cross-session fixture message / durable shared marker | Both observed | Neither observed | Neither observed |
| Synthetic evidence-canary tamper | Observed | Not observed | Not observed |
| Actual authoritative evidence outside service root | Yes | Yes | Yes |
| Missing capability, forged signature, argument substitution, unauthorized operation | Denied | Denied | Denied |
| URL/budget widening and substituted success response | Denied/rejected | Denied/rejected | Denied/rejected |
| Prior-session capability | No prior round | Denied | Denied |
| Capability consumption / replay | Exactly one / denied | Exactly one / denied | Exactly one / denied |
| etcd oracle revision / Raft term | 2 / 2 | 3 / 2 | 4 / 2 |
| Signed event receipts | 13 | 14 | 14 |
| Requested-stop teardown, empty process groups, scratch and endpoints removed | Verified | Verified | Verified |

Evidence paths within the JSON are `rounds[*].observations.package`, `rounds[*].observations.denied_cases`, `rounds[*].observations.authority_oracle`, `rounds[*].events`, `rounds[*].receipts`, and `rounds[*].teardown`. The five `package.forbidden_effects` flags are all true in the vulnerable control and all false in each protected round. Target receipts record relay and credential reuse only in the vulnerable round. No ambiguous outcomes are recorded.

Each round has exactly one `execution.authorized` and one successful `execution.completed` event for its capability ID. The host supervisor's separate linearizable etcd read records one consumption entry with the matching capability ID, claims digest, expiry, pinned cluster ID, positive revision and Raft term, and `record_integrity_checked: true`. This oracle is separate from the compromised worker but remains inside the trusted host boundary.

## Publication verification and content review

The original sidecar passed `sha256sum -c`. The existing `scripts/verify_package_isolation.py` passed on the original and published JSON, checking paired outcomes, signed context, authority-oracle consistency, teardown, chained event hashes and Ed25519 receipts against public keys embedded in the report. Additional direct inspection checked the vulnerable/protected effect flags, authorization and replay outcomes, cluster ID, oracle revisions, receipt counts, and requested-stop cleanup.

Original and copied JSON bytes, and original and copied sidecar bytes, were compared exactly. The published checksum is:

```text
0d9b62922e187d7d00c50dc115f877ccfbfa6c2ab590d3aa2a425d0b7bc7a32d  package-etcd-20261011T203017Z-10867.json
```

Review of report fields, event payloads, receipts, key material and host/build metadata found no private signing keys, real credentials, access tokens, personal home paths or personal contact information. The PEM keys are public keys. Capability identifiers, signatures, hashes, synthetic effect labels and ephemeral `/var/tmp/ehk-*` paths remain as original evidence. The credential-reuse observations describe a fake fixture credential, not publication of a real credential. This review is not an independent security audit.

## Verify the published artifact without running the experiment

From a repository checkout with the project's Python dependencies available:

```bash
(cd docs/evidence/artifacts/2026-10-11 && \
  sha256sum -c package-etcd-20261011T203017Z-10867.json.sha256)
PYTHONDONTWRITEBYTECODE=1 /var/tmp/event-horizon-isolation-venv/bin/python \
  scripts/verify_package_isolation.py \
  docs/evidence/artifacts/2026-10-11/package-etcd-20261011T203017Z-10867.json
```

Use a dependency-equipped `python` instead if the operator's venv path is unavailable. SHA-256 verifies byte identity against the published fingerprint. Embedded-key signature verification establishes internal integrity, not independently trusted signer identity, truthful host observations, or complete observation of all effects.

## Reproduce separately on an owned host

These instructions are for a future independent run; they were **not executed during publication**. Use a separate checkout at the exact experiment revision so existing reports remain untouched:

```bash
git clone https://github.com/solsticeaistudio/event-horizon-harness.git ehh-package-etcd-reproduction
cd ehh-package-etcd-reproduction
git switch --detach f74e31537512dc5885596a6f50a3d8d43bd90127
# Complete docs/LINUX_ISOLATION.md preparation in this checkout first.
# Requires Ubuntu x86_64, working KVM/cgroup v2, pinned Firecracker assets,
# the prepared Python environment, and operator access to a Docker daemon.
docker info >/dev/null
EHH_LAB_ETCD_IMAGE=quay.io/coreos/etcd:v3.6.0 bash scripts/run_package_etcd_lab.sh
```

Follow [Linux/KVM preparation](../LINUX_ISOLATION.md) and the [package-isolation procedure](../PACKAGE_ISOLATION.md). The launcher checks loopback ports 2379/3379/4379, creates its own disposable cluster, discovers and pins that new cluster's actual ID, runs three serialized sessions, verifies the new report, and writes a timestamped checksum. Do not reuse this report's cluster ID for a new cluster. Fresh run IDs, signatures, timings and report hashes will differ. Do not use production etcd, real credentials, or third-party targets.

## Limitations and untested threats

- Synthetic attestation and internally signed evidence only: no TPM2 quote, independently witnessed hardware attestation, externally pinned signer, trusted timestamp, or independent operator reproduction.
- The isolated four-guardian signer system was **not integrated into this experiment**; this report does not establish coordinator-compromise resistance through that system.
- Host kernel/hypervisor, supervisor, trusted gate, recorder and etcd infrastructure remain trusted. Host-root compromise, VM escape resistance and malicious host observations are not established by these results.
- Three disposable nodes share the operator's machine/environment; this is not physical or administrative trust-domain separation. This run does not test quorum loss, network partitions, rollback/recovery, interrupted effects or distributed revocation. Shutdown retires the local effect endpoint.
- Deterministic, bounded, already-compromised native worker and serialized guest-root sessions; zero model-selected probes. No unrestricted adaptive guest agent, concurrent tenant VM containment, real registry or package installation, or comprehensive covert-channel coverage.
- Automatic attack detection is false and detection latency is null in all rounds. Teardown was controller-requested. The three timing samples are not a statistical performance benchmark; retained host fixtures are not a secure-erasure claim.
- The service worker has no additional seccomp policy; the build toolchain is not hermetic. These results do not establish general production readiness or complete observation of all possible effects.

The original reports remain unchanged. This publication adds reviewable evidence for this scoped integration run, without changing EHH's implementation or strengthening its trust assumptions.
