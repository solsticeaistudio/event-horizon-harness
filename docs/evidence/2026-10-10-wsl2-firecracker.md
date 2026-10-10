# Firecracker/KVM isolation — operator-run evidence (2026-10-10)

**Status: local PASS reported; signed report has not yet been published here.**

This page records a reproducible, *scoped* result from an operator's Ubuntu 24.04.5 LTS installation under WSL2 on an x86_64 laptop. The original experiment executed on the operator's machine, **not** in GitHub Actions. The text below reflects terminal output supplied by the operator. It is **not** a substitute for publicly downloadable report bytes and an independently pinned hash. The report and its checksum will be published only after local inspection for sensitive data.

## Experiment identity

| Item | Value |
|---|---|
| Source commit used for successful run | [`238ec72a610eae188491e924ee1bdeec9c7b3f64`](https://github.com/solsticeaistudio/event-horizon-harness/commit/238ec72a610eae188491e924ee1bdeec9c7b3f64) |
| OS | Ubuntu 24.04.5 LTS on WSL2, x86_64 |
| WSL2 host kernel reported during preflight | `6.6.87.2-microsoft-standard-WSL2` |
| KVM functional probe | KVM API 12; `KVM_CREATE_VM` succeeded |
| Firecracker and jailer | v1.15.1, pinned release archive and extracted SHA-256 binaries |
| Guest kernel | Linux 6.1.155 (pinned test kernel) |
| Attestation | **Synthetic fixture; no TPM2 quote or independent hardware provenance** |
| Isolation mechanism | Real Firecracker/KVM guest + jailer, host UID and cgroup boundaries, trusted host-side dataset effect service |
| Intended report file | `artifacts/reports/linux-isolation.json` (local, not committed) |
| Original report SHA-256 | **Not yet supplied/published — do not infer one from source or CI** |
| External independent witness | **None** |

The Firecracker build is pinned through [`firecracker/linux-kvm.lock.json`](../../firecracker/linux-kvm.lock.json), and its generated local manifest records the installed toolchain and guest image digests. The host-specific build manifest is included in the experiment's JSON report.

## Terminal result supplied by the operator

```text
Linux/KVM isolation experiment: PASS (3 guest-root sessions)
Teardown: requested stop, deadline, and supervisor control-channel loss verified
Evidence report: .../artifacts/reports/linux-isolation.json
Linux isolation evidence: VERIFIED (3 chains and signed receipts; embedded keys, integrity only)
```

This result indicates the standalone SQLite-backed dataset boundary completed three synthetic guest-root sessions with independent supervisor/host-service observations, denial and replay checks, three distinct teardown triggers, and an internally consistent Ed25519-signed evidence chain. It **does not** establish independent evidence-signer trust, comprehensive VM escape resistance, frontier-agent safety, or production readiness.

## Preserve and validate original evidence before publication

On the same Ubuntu host, from the checked-out experiment commit:

```bash
cd ~/event-horizon-harness
git rev-parse HEAD
/var/tmp/event-horizon-isolation-venv/bin/python scripts/verify_linux_isolation.py \
  artifacts/reports/linux-isolation.json
sha256sum artifacts/reports/linux-isolation.json | tee artifacts/reports/linux-isolation.json.sha256
```

Make an immutable backup of the **unmodified** JSON and checksum outside the checkout. Inspect the full report before making it public, including `rounds[*].observations`, `rounds[*].events[*].payload`, `rounds[*].receipts`, and build/host metadata. Never publish a private signing key, real credential, unexpected hostname/user directory, or non-synthetic dataset. If the report needs redaction, preserve the original privately and produce a **separately labelled summary**; do not silently edit the signed report or present a redacted copy as signature-equivalent.

After inspection and consent, publish the unmodified `linux-isolation.json` and matching `linux-isolation.json.sha256` as GitHub Release **assets** for an experiment-specific tag pointed at `238ec72a610eae188491e924ee1bdeec9c7b3f64`. This avoids putting large generated evidence or environment metadata in Git history. Link the release here and in the root README when it exists. No upload has been performed by this documentation change.

## Verify a published report

With a repository checkout providing `scripts/verify_linux_isolation.py` and its pinned Python dependencies:

```bash
sha256sum -c linux-isolation.json.sha256
python scripts/verify_linux_isolation.py linux-isolation.json
```

The SHA-256 check detects post-publication byte changes relative to the **published hash**. The Python verifier validates event ordering, chained hashes, receipt signatures against public keys **embedded in the report**, and its specific experiment assertions. Neither check independently proves who operated the machine or whether all possible malicious effects were observed. A separate trustworthy signing or timestamp witness would strengthen provenance.

## Follow-on security work

1. Independently witness the exact report checksum and source-commit identity.
2. Reproduce the same experiment on a second owned x86_64 Linux KVM host; record its independent SHA-256 and verification output.
3. Perform the **separate** Firecracker-to-distributed-etcd authority integration and test its failures under partition/rollback and interrupted-effect conditions.
4. Expand the threat model and report limitations before making general claims.

For the experiment's full security boundaries, see [Linux/KVM isolation](../LINUX_ISOLATION.md).
