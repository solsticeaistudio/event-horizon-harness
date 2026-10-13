# Independently supervised fenced recipient — portable assurance stage

Implemented after PR #64 (d6a6b275). This is a separate opt-in
service for the existing atomic-sqlite-v1 effect, not a change to
TrustedEffectGateway, arbitrary APIs or the six preserved KVM archives.

## Authority and process boundaries

- Trusted gateway verifies and durably consumes a NEW signed capability for
  EVERY attempt. It records authorization, preflights output and reserves or
  reads the original journal binding before making any recipient RPC.
- Host-selected FencedRecipientClient uses an independent process running
  scripts.fenced_recipient_service over an absolute Unix socket in a trusted
  directory. Only the recipient service opens its own SQLite ledger.
- Linux SO_PEERCRED verifies peer UID; socket mode is 0600. A private 256-bit
  key authenticates both request/response HMACs; fresh per-request nonce
  prevents substitution across calls. Framed messages have strict limits.
- Only the synthetic apply and observe operations are supported; a guest
  cannot supply recipient paths, IPC keys or callback implementations.
- BEGIN IMMEDIATE, unique effect key, immutable output and receipt digest
  are committed in the same synchronous SQLite transaction. Replays require
  byte-for-byte matching result and request binding.
- Gateway independently re-reads the positive durable receipt before it
  confirms the ORIGINAL journal record, never replacing original capability
  provenance with the recovery token.
- Timeout, disconnect, missing row, wrong key, malformed output, corrupted
  receipt or mismatched recipient are NOT authority to release the fence.

## Trust limits

Both processes and their private configuration belong to the trusted host.
Same-UID peer credentials and the shared secret authenticate this configured
service channel, not an attacker-compromised host. A malicious process with
the same UID that can read private config/memory is out of scope. Distinct
UID isolation, independent signed receipts and witness separation remain
future security work. Socket/config parent paths must be trusted.

This synthetic SQLite row represents the ENTIRE business effect. It does not
make HTTP, email, payments or other arbitrary external side effects exactly
once. Host-process crash survival does not prove arbitrary power-loss
durability, availability under partitions, or Firecracker guarantees.

## Run the real process test suite on Linux

    python -m pip install -e ".[test]"
    python -m unittest tests.test_independent_fenced_recipient -v
    python -m unittest discover -s tests -v
    python scripts/lint_python.py

Tests launch separate Linux gateway and recipient subprocesses. Supervisor
observes child checkpoints then sends SIGKILL, independently reads durable
SQLite effect count/journal, and recovers using a distinct signed capability.
After a killed recipient, the supervisor REAPS its known child PID and checks
the leftover socket inode owner/type/mode before unlinking and restarting.
Production supervision must enforce equivalent restrictions.

| Fault | Required result |
| --- | --- |
| Gateway killed before recipient RPC | Fresh-authorized recovery commits once |
| Gateway killed after recipient reply, before journal confirm | Original durable result replayed; count stays one |
| Recipient killed before commit | Fence remains; recovery commits once |
| Recipient killed after commit, before reply | Recovery confirms original result; no duplicate |
| Two competing signed gateways | Both can return original result; one row only |
| Recipient down or wrong IPC key | Indeterminate; no reservation released |
| Changed output/identity or legacy reservation | Refuse incompatible recovery |
| Corrupted receipt or forged frame | Fail closed; no fabricated success |

Success requires exactly one durable effect row for successful recovery,
unchanged output/receipt and original journal capability provenance.
New completion evidence is append-only and must be positive.

## Next assurance phase: real Firecracker

Reuse existing independently supervised KVM, guardian, vsock, etcd and
recipient service machinery, but DO NOT substitute the old non-idempotent
recipient for this transactional backend. Run a NEW fault matrix with
independent gateway processes and transport partitions.

Evidence must carry a clean exact source revision, independent observed
process IDs, durable ledger hash/count, journal state, signed evidence lineage,
and an immutable, exclusive-create report with SHA256 sidecar. A failed run
remains INCOMPLETE. Preserve all six historic KVM proof bundles unchanged.

This PR is portable Linux multi-process assurance, NOT new KVM evidence.
