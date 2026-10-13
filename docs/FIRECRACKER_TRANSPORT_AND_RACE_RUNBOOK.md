# Firecracker lost-ACK and two-gateway recovery lab

**Status: portable CI only. No new hardware PASS report has been produced or
reviewed.** Keep this PR draft until hardware evidence has been independently
verified and published, with its source revision pinned.

The atomic recipient is a cooperating, same-SQLite-transaction fixture, not an
external API. The guest remains a real Firecracker jailed x86_64 KVM workload,
but executor attestation is a synthetic fixture, not a measured TPM. The
signer uses four independently supervised guardian roles and disposable
three-member etcd. These modes do not extend the six earlier KVM fault tests.

## Two different fault campaigns

### One lost recipient acknowledgment

The private recipient service accepts a signed original guest request,
atomically commits the synthetic effect/deduplication row, and then drops
exactly one authenticated IPC reply at `drop_ack_after_commit`. Neither
recipient nor gateway dies. The host independently checks the recipient's
unmodified durable effect/receipt and that both processes remain alive.

The original gateway must return `possibly-committed` and a signed
`fenced.indeterminate`. A replay of the original spent capability must fail;
a NEW signed capability may confirm the **same original receipt**, without
inserting a second row or changing the original authority provenance.

### Two different recovery gateway processes

Use the SAME original guest-originated lost-ACK event. The guest sends one new
signed recovery capability while the trusted supervisor, not the guest,
launches a second signed recovery using the previously issued third
four-guardian-approved capability. The original KVM guest does **not** produce
both recovery requests: the second is an explicit trusted host-generated
competitor bound to the same exact signed request and recipient. Two separate
gateway PIDs, pidfds and signed-recorder relay contracts are independently
required. Both gateways must return the original durable receipt; exactly one
SQLite effect must exist. The gateway workers are started together and requests
are concurrently submitted, but this does not prove both entered SQLite BEGIN
IMMEDIATE at precisely the same instant.

**Important control difference:** this mode does not run the isolated
majority-loss negative scenario, because that intentionally retires the
third capability. It retains four guest-originated mutation negatives, a
single-node outage during the effect, and denied replay after quorum
restoration. Its verifier expects exactly those controls and cannot accept a
normal majority-loss receipt in their place.

Portable Linux regression separately tests `drop_before_commit` where two
new signed gateway processes race for the first commit; that variation is
**not yet an actual KVM campaign**.

## Steps on an operator-owned Ubuntu 24.04 + /dev/kvm lab

After branch CI is green:

```bash
cd ~/event-horizon-harness
git fetch origin
git switch --track origin/feature/firecracker-transport-and-racing-recovery

PYTHONPATH=src:. /var/tmp/event-horizon-isolation-venv/bin/python -m unittest \
  tests.test_fenced_transport_and_race_portable \
  tests.test_kvm_ack_loss_bridge_portable \
  tests.test_kvm_racing_recovery_bridge_portable \
  tests.test_kvm_transport_race_evidence_contract -v

# Each option spins up an entirely new disposable 3-node etcd quorum;
# generates a unique exclusive-create JSON + SHA256; verifies both.
bash scripts/run_package_etcd_lab.sh --kvm-ack-loss
bash scripts/run_package_etcd_lab.sh --kvm-racing-recovery
```

**Never** run this against production etcd or with a dirty tracked source
tree. Inspect `artifacts/reports/*-kvm-ack-loss.json` and
`artifacts/reports/*-kvm-racing-recovery.json` only after a verifier has
returned PASS. A failed command may still create an immutable INCOMPLETE
report; do not edit or overwrite it. Preserve each original JSON and its
sidecar unchanged, review for secrets, and add the exact bytes to dedicated
`docs/evidence/artifacts/` folders in GitHub before changing this PR status.

The standalone verifiers are:

```bash
PYTHONPATH=src:. /var/tmp/event-horizon-isolation-venv/bin/python \
  scripts/verify_integrated_kvm_ack_loss.py artifacts/reports/<EXACT-ACK-REPORT>.json
PYTHONPATH=src:. /var/tmp/event-horizon-isolation-venv/bin/python \
  scripts/verify_integrated_kvm_racing_recovery.py artifacts/reports/<EXACT-RACE-REPORT>.json
```

## Explicitly out of scope

Network partitions or lost messages across actual host boundaries, TCP/IP
recipient transports, competing distributed machines, physical power failures,
malicious host/kernel, hardware-attested guest identity, and arbitrary external
effect APIs. An unreceived ACK **never** means a transaction failed. A positive
original receipt tied to the exact effect/request/output binding is required
for successful recovery.

Existing immutable hardware evidence from PR #66/#67 is not changed.
