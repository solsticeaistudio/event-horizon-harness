# Evidence: real KVM, four guardians, etcd, independent gateway and durable recipient

**Draft provenance only. The original 1,956,708-byte JSON must be copied without reserialization and hash-verified before this branch can merge.**

- Date (UTC): 2026-10-12
- Original file: `package-etcd-20261012T213923Z-31278-bridged-recipient.json`
- Source commit: `ea79595db5a659c6ae543c42e66618edfcd770ba`
- Schema: `event-horizon.package-isolation.v4`
- Mode: `isolated-authority-firecracker-etcd-bridged-recipient`
- Result: `PASS` (three rounds)
- SHA-256: `b870943d5379f2a03444a378687a5730de1e8e62390288efa7e4814d92edd267`
- Git blob SHA-1: `cccd2f8a5dff350355e18c4c078fa83003ad1bde`

## Observed per-round evidence

| Round | Gateway PID | Recipient PID | Observed recipient commits | Journal state | Recorded authorized dispatch |
| --- | ---: | ---: | ---: | --- | ---: |
| 1 | 31589 | 31586 | 1 | possibly-committed | 1 |
| 2 | 31734 | 31731 | 1 | possibly-committed | 1 |
| 3 | 31874 | 31871 | 1 | possibly-committed | 1 |

Supervisor PID was 31522. The report binds each recipient request digest to the guardian-authorized guest request; the etcd consumption oracle and replay-denied observations passed. Independent offline recomputation of the 98 event hashes and verification of 98 embedded-key Ed25519 receipt signatures succeeded, and each signed observation matches its report summary. Thirty-six guardian approvals are recorded across nine issuance messages; the original verifier checks their signatures.

## Scope limits

Embedded/public keys establish internal integrity, not outside authentication of the operator. Attestation is synthetic. **This report does not prove** an intentionally SIGKILLed gateway, post-commit recovery, suppression of a newly signed duplicate capability in the real KVM run, or the five crash windows. It also does not test physical multi-host independence.

## Before merging

Copy the original exact JSON bytes from the user's Ubuntu `artifacts/reports` into this directory. Verify both the SHA-256 sidecar and Git blob SHA-1. Run `scripts/verify_package_isolation.py` against the newly staged JSON before marking the PR ready. Do not overwrite or reserialize the evidence.
