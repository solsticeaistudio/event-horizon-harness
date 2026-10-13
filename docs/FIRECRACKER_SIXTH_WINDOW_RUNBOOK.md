# Sixth Firecracker window: delayed recipient commit after gateway SIGKILL

**Experimental until real hardware execution.** This is a new hardware evidence
schema, not a modification to the original five-window PASS and checksum.

The narrow test probes the race the first five checkpoints cannot represent:
a recipient has accepted the request but has not committed it; the gateway
dies and restarts, both the consumed original capability and a newly signed
capability are denied while the recipient has zero commits; only then the
trusted supervisor releases the recipient, which durably commits exactly one.

## Pre-registered expected timeline

1. Genuine Firecracker jailed guest and protected package send authorized
   request to a separate trusted gateway after guardian + etcd validation.
2. Real recipient validates request, emits the exact checkpoint marker
   PHASE:inflight_before_commit before entering SQLite transaction, and blocks
   on a PRIVATE inherited supervisor-only pipe.
3. Supervisor independently inspects zero durable recipient commits,
   primary consumed authority, and a durable possibly-committed reservation.
4. Supervisor sends actual SIGKILL to the gateway child, verifies -9,
   and returns gateway-killed / possibly-committed to the original guest.
5. New gateway (same journal and etcd backend) returns authority-denied
   for the original capability and prior-effect-unknown for the fresh,
   separately guardian-signed capability. Recipient STILL has zero commits.
6. Supervisor releases the paused original recipient with the private R
   byte. Recipient commits SQLite with FULL synchronous durability; its
   broken acknowledgement channel cannot reverse the commit or crash the
   recipient. Independent host inspection finds exactly one durable commit,
   with its digest bound to the exact authorized effect.
7. Strict signed event chain verifies the order: recipient.inflight-observed,
   gateway.delayed-sigkill-observed, recipient.delayed-commit-observed.
   Guest/vsock, guardian, etcd oracle and cgroup teardown are independently
   bound in a separate report schema.

Any checkpoint, replay, recipient ledger, signature or teardown mismatch
MUST produce INCOMPLETE, never promote it to PASS. Never manually repair or
reserialize a partially recorded report.

## Portable tests first

GitHub CI tests the two earlier real-recipient SIGKILL phases, a portable
late-recipient-commit after real gateway SIGKILL, and signed sixth-window
schema tamper cases. Those tests alone do not establish KVM proof.

## Hardware operator command (only after CI green)

    cd ~/event-horizon-harness
    git fetch origin
    git switch --detach origin/feature/sixth-firecracker-delayed-recipient-commit
    bash scripts/run_package_etcd_lab.sh --kvm-delayed-commit

The disposable etcd cluster is created and removed by the existing
shell lab. Use the prepared Ubuntu x86_64 /dev/kvm environment; there is no
portable fallback. Keep original artifacts/reports/*-kvm-delayed-commit.json
and .sha256 unchanged; do not merge as hardware-verified until the original
report passes its standalone verifier.

## Limits

The host is WSL2/Linux, not physically independent hosts. Guardian and
recorder receipts use keys embedded in the report; attestation remains
synthetic. This is not physical power-loss recovery or exactly-once
generalization for arbitrary external recipients. The recipient intentionally
cooperates with one private test-only pause barrier.
