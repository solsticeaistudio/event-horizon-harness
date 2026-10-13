# PR #67 — Real Firecracker recipient SIGKILL / atomic recovery

**Status: source implementation + portable CI; KVM evidence NOT YET collected.**

PR #66 verified **gateway** death, not recipient death. This opt-in mode
keeps the real trusted gateway alive and deliberately kills the separately
supervised recipient on the host after the actual guest's signed request.
A restart uses the *same* private SQLite recipient identity, same durable
effect ledger, same pinned HMAC key, and requires new signed authority.

It does NOT extend at-most-once guarantees to arbitrary external HTTP/APIs,
non-atomic effects, multi-host failover, physical power loss or malicious
host/kernel compromise. TPM attestation is still synthetic in this fixture.

## Workload and fault matrix

- `before_commit`: kill the exact recipient child at its checkpoint before
  its SQLite BEGIN/INSERT; expected durable rows immediately after kill = 0;
  fresh capability then makes the one authorized commit.
- `after_commit_before_reply`: kill after SQLite COMMIT but before IPC ACK;
  expected durable rows immediately after kill = 1; fresh capability must
  positively return the same original receipt without inserting another row.

Both windows use **different** Firecracker guests, signed sessions, independent
recipient stores and disposable three-member etcd clusters. Each tests
negative guest controls, consumed-original denial, and fresh signed recovery.
The supervisor will not remove a stale socket without exact child SIGKILL,
original socket inode and private owner-only path.

## Operator commands (ONLY after portable CI passes)

On the existing, owned Ubuntu 24.04 x86_64 KVM lab:

```bash
cd ~/event-horizon-harness
git fetch origin
git switch --track origin/feature/firecracker-recipient-faults
PYTHONPATH=src:. /var/tmp/event-horizon-isolation-venv/bin/python \
  -m unittest tests.test_fenced_recipient_restart \
  tests.test_kvm_recipient_crash_evidence_contract \
  tests.test_kvm_recipient_crash_bridge_portable -v

# Actual KVM hardware execution — not a simulated process fallback
bash scripts/run_package_etcd_lab.sh --kvm-recipient-crash
```

Do not use this command on production etcd. The shell runner checks that the
three dedicated ports are unoccupied, creates disposable owned Docker etcd
members, and cleans them on exit. It writes an **exclusive-create original**
JSON under `artifacts/reports/*-kvm-recipient-crash.json` with a SHA-256
sidecar, including INCOMPLETE failure reports.

A PASS requires the standalone new hardware verifier:

```bash
PYTHONPATH=src:. /var/tmp/event-horizon-isolation-venv/bin/python \
  scripts/verify_integrated_kvm_recipient_crash.py \
  artifacts/reports/<EXACT-KVM-RECIPIENT-CRASH-REPORT>.json
```

The verifier independently checks the KVM jail, chroot/seccomp, source/asset
hashes, isolated four-guardian signer, real etcd authority consumption,
the signed per-event chain, real SIGKILL/restart PID differences,
host-observed socket-inode cleanup, original reservation identity, expected
crash-phase durable counts, the single atomic recipient receipt, fresh signed
recovery, guest responses, negative controls, and host teardown.

This is **not** a portable CI proof of genuine KVM recovery. PR stays draft
until real host results are present, reviewed, verified and immutable.

Further separate campaigns: recipient IPC partition/lost ACK without death,
two truly competing *gateway* processes on the KVM path, and durability under
power interruption. Portable Linux tests from prior work do not establish
those hardware cases.
