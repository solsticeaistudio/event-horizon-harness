# Original bridged-KVM evidence — October 12, 2026

**Publication status:** JSON awaiting exact-byte transfer from the operator's Ubuntu checkout. Do not merge the evidence branch without the original JSON.

- Report: `package-etcd-20261012T205802Z-29724-bridged-authority.json` (1,916 KB)
- Original SHA-256: `cda4a51a10b87e90d017563df6228999722fbca8ed28401eeb3678a74cf5e99c`
- Original Git blob SHA-1: `ae2563d82afe46d58232b14a8064b047d0a62964`
- Source revision: `8be130eb584dfd90d514b754244e26b4434ccda3`
- Report status: `PASS`; verifier status: `VERIFIED`
- Test: 3 paired Firecracker KVM rounds, 3-node disposable etcd, four guardian approvals, separate gateway subprocess per round, signed local receipts and replay denials.
- Limits: synthetic attestation; internal signing keys; not a power-loss or five-window gateway SIGKILL recovery experiment.

## Required before merge

Transfer **the unchanged original JSON** from `artifacts/reports/` to this directory and verify that both the Git blob SHA and SHA-256 match. Keep the report and the published sidecar byte-identical to the originals. The SHA-256 sidecar is already committed. Do not edit or reserialize the signed report.

The source archive must be preserved even if later test campaigns fail.
