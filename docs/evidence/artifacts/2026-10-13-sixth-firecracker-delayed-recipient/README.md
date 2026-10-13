# Sixth real Firecracker/KVM window — in-flight recipient commits after gateway death

Status: **PASS, verified**, original operator-run evidence from 2026-10-13 UTC.

## Provenance

- Experiment source commit: `236976a378d7b356b62852851c51443a3221cd8e` (preserved on `main` through merge commit `86861704aad275b64c2394164ed705c678a93787`, PR #62).
- Mode: `real-kvm-guardian-etcd-inflight-recipient-gateway-sigkill`.
- Schema: `event-horizon.firecracker-inflight-recipient-sigkill.v1`.
- Host: Linux kernel `6.6.87.2-microsoft-standard-WSL2`.
- Original report filename: `package-etcd-20261013T033722Z-34693-kvm-delayed-commit.json`.
- Original report size: **647,500 bytes**.
- SHA-256: `9b0939668d5725f98ef67668c52c6a77e74e287cde403c1e7daaf7eb363bbedd`.
- Exact original Git blob SHA-1: `1af438e6202ec0ec0457d7eed96c98666ed60418`.
- Recipients/authority: distinct recipient PID 34999, killed gateway PID 35001, recovery PID 35078, three disposable local etcd members and four isolated guardian approvals.
- Standalone verifier: `scripts/verify_integrated_kvm_delayed_commit.py`; user command reported `VERIFIED`, checksum `OK`.
- Independent review of uploaded raw evidence: SHA-256 sidecar matches; all **30/30** Ed25519 receipts independently verified with embedded public key; all 30 event hashes and chain linkage verified.

## Pre-registered prediction and observed result

A real Firecracker guest submitted the signed effect; the independent recipient accepted it and paused just before commit. Supervisor observed recipient commit counts **0 before**, **0 paused**, and **0 after gateway SIGKILL (-9)**. A restarted gateway denied the original consumed capability (`authority-denied`) and a *newly signed* capability for the same logical effect (`prior-effect-unknown`), while commits were still **0**. Only after those denials did the supervisor release the old in-flight recipient; the independent durable recipient ledger recorded **1** commit. Exactly one `execution.dispatch`, zero `execution.completed`, no duplicate effect, and signed cgroup teardown all passed strict report verification.

This closes a **test-specific delayed in-flight commit race** that the previous five KVM windows did not exercise. It does **not** establish general-purpose exactly-once recovery for arbitrary recipients or safe automatic release of ambiguous effect reservations.

## Assurance boundary

- Keys used to verify event receipts are embedded in the report. This verifies internal cryptographic integrity, **not externally anchored provenance** or independent witnessing.
- Guest attestation is explicitly **synthetic**; TPM2 hardware attestation was not enabled.
- Three disposable etcd members and separate guardian/recipient processes ran under one WSL2 host, **not physically independent machines**.
- Actual gateway process `SIGKILL` does **not** simulate physical power loss.
- This is **one synthetic effect**, no concurrent multi-tenant gateway proof.
- Preserve the report **byte for byte**, together with its sidecar. Do not rewrite JSON or regenerate signatures.

## Verification

```bash
cd docs/evidence/artifacts/2026-10-13-sixth-firecracker-delayed-recipient
sha256sum -c package-etcd-20261013T033722Z-34693-kvm-delayed-commit.json.sha256
python ../../../../scripts/verify_integrated_kvm_delayed_commit.py package-etcd-20261013T033722Z-34693-kvm-delayed-commit.json
git hash-object package-etcd-20261013T033722Z-34693-kvm-delayed-commit.json
```

Expected blob SHA-1: `1af438e6202ec0ec0457d7eed96c98666ed60418`.

The archive accompanies code in PR #62 and is separate from the original five-window artifact.
