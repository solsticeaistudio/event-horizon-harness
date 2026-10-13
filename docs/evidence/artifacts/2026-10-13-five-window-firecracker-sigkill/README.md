# Evidence: five real Firecracker KVM guest-triggered gateway SIGKILL windows

**Archived original evidence.** The 3,215,615-byte JSON was copied byte-for-byte from the operator's Ubuntu report, the original SHA-256 sidecar passed, the Git blob SHA-1 matched, and the standalone five-window verifier reported `VERIFIED`.

## Provenance

- UTC experiment date: 2026-10-13 (local time 2026-10-12)
- Original report filename: `package-etcd-20261013T013107Z-32978-kvm-crash.json`
- Source commit **used during the hardware run**: `b7e21994ae6066f6973b626ad59e3f13edfe74b2`
- Verification implementation on successful subsequent standalone command: `02c6d424dde6ca1d21ea1b102f193d2a9957ae2f`
- Report schema: `event-horizon.firecracker-gateway-sigkill.v1`
- Experiment mode: `real-kvm-guardian-etcd-recipient-gateway-sigkill`
- Report status: `PASS`
- Host kernel: `6.6.87.2-microsoft-standard-WSL2`
- Original report size: **3,215,615 bytes**
- Original SHA-256: `a7b49126869b49b25b07f63f4fdcaa36c06c8278e54383ccc76e934566bd3b9c`
- Original Git blob SHA-1: `7efbb12a9224a0b88b02b02547c708d471d4517b`

This evidence was originally produced by the experimental branch. Its implemented runner and standalone verifier were merged as [PR #58](https://github.com/solsticeaistudio/event-horizon-harness/pull/58) at merge commit `6e7936974e6c3d28bdc2a42e14c738e1b64603df`. The later verifier-only import/parser corrections did **not** rewrite, transform, or rerun the original experiment.

## Observed real KVM rounds

| Window | Trusted crash checkpoint | SIGKILL exit | Killed gateway PID | Recovery PID | Recipient PID | Durable commits | Dispatch events | Signed completion events |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | `before_reservation` | -9 | 33282 | 33355 | 33279 | 0 | 0 | 0 |
| 2 | `after_reservation_before_dispatch` | -9 | 33426 | 33501 | 33423 | 0 | 0 | 0 |
| 3 | `after_recipient_commit_before_gateway_ack` | -9 | 33574 | 33647 | 33571 | 1 | 1 | 0 |
| 4 | `after_handler_return_before_completion` | -9 | 33721 | 33795 | 33718 | 1 | 1 | 0 |
| 5 | `after_completion_before_client_ack` | -9 | 33867 | 33943 | 33864 | 1 | 1 | 1 |

All five rounds use a genuine jailed Firecracker guest/vsock request path, four separately isolated guardian processes and a signer, a disposable owned three-member etcd cluster, an independent durable recipient and real host-supervised `SIGKILL`. A new gateway process uses the same durable journal after each kill. Consumed original capability replay is denied; in windows 2–5, a distinct newly signed capability is also denied rather than causing a second recipient commit. The recorded external recipient counts remain `[0, 0, 1, 1, 1]` after restart.

## Verified evidence integrity and protocol checks

The original Ubuntu command completed with:

```text
package-etcd-20261013T013107Z-32978-kvm-crash.json: OK
VERIFIED: 5 guest/vsock KVM SIGKILL phases, four guardian approvals, three-node etcd and independent recipients; embedded keys only
```

The 147 event records across the five rounds have 147 matching Ed25519 receipt signatures, verified against their **embedded** public keys. Five recorded hash chains and their tips are internally consistent, and the exact original SHA-256 checksum matches the sidecar. The verifier checks ordered signed supervisor crash/recovery observations, child process separation within each round, recipient ledger digests and counts, consumed-capability denials, trusted guardian approvals, etcd authority, and resource teardown.

## Assurance boundaries

- Signature keys and verifier public keys are embedded in this report; they establish **internal integrity**, not externally anchored provenance or independent witness.
- Executor/guest attestation is synthetic; **no hardware TPM attestation** is claimed.
- The experiment used a single WSL2/Linux host with an owned three-node etcd cluster, not three physically independent machines.
- Linux process `SIGKILL` is not equivalent to physical power loss or network partition recovery under all conditions.
- A missing recipient commit does **not** allow automatic retry of an uncertain reservation without a trusted fencing/non-commit protocol.
- Evidence publication is distinct from experimental success. Publishing this report does not establish independent third-party replication.

## Publication verification

The original JSON is included in this directory without reserialization. Operator-side checks passed before pushing: `sha256sum -c`, Git blob ID `7efbb12a9224a0b88b02b02547c708d471d4517b`, and `scripts/verify_integrated_kvm_crash.py` against the staged JSON. GitHub file retrieval of the pushed artifact returns that exact blob ID. These results support original-byte archival; they do not constitute third-party witnessing or hardware attestation.
