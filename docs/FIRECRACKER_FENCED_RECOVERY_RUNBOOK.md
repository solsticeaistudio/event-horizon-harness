# PR #66 — Firecracker fenced recipient integration (hardware baseline)

This branch adds a **new opt-in, source-isolated baseline**. The real
Firecracker guest invokes the original authorized dataset effect through
the four-guardian / three-member etcd authority, an independent gateway
process, and the new authenticated fenced recipient process. It is NOT an
actual SIGKILL recovery or network-partition guarantee. All previously
published KVM evidence remains unchanged.

## Operator preflight

Run on your owned Ubuntu 24.04 x86_64 host with existing Firecracker assets,
`/dev/kvm`, the isolation virtual environment and Docker. **Do not run
this on any production etcd cluster.** The shell launcher starts THREE new
disposable etcd containers on dedicated local ports and checks they belong
to the owned environment before introducing any quorum faults.

Check out the PR branch:

    cd ~/event-horizon-harness
    git fetch origin
    git switch --track origin/feature/firecracker-fenced-recovery
    git status --short

If your local branch already exists, run `git switch
feature/firecracker-fenced-recovery && git pull --ff-only`.

Run the new portable tests first:

    PYTHONPATH=src:. /var/tmp/event-horizon-isolation-venv/bin/python \
      -m unittest tests.test_independent_fenced_recipient \
      tests.test_kvm_fenced_evidence_contract -v

Then run the **NEW baseline only**:

    bash scripts/run_package_etcd_lab.sh --kvm-fenced-baseline

It exits nonzero on failure and saves a fresh report under
`artifacts/reports/package-etcd-...-kvm-fenced-baseline.json`, plus SHA256.
It does NOT invoke the historic `--kvm-crash` or `--kvm-delayed-commit`
test, nor any replacement/fallback host-only test.

If a report has PASS status, the shell runner independently executes:

    /var/tmp/event-horizon-isolation-venv/bin/python \
      scripts/verify_integrated_kvm_fenced_baseline.py \
      artifacts/reports/<EXACT-OUTPUT-NAME>.json

The strict verifier requires the report to name the real KVM fenced schema,
a clean committed Git revision, source-bound four-guardian signer evidence,
three-member etcd consumption, observed Firecracker seccomp/chroot/network
isolation, signed event/receipt chain, child process identity, ONE durable
transaction, exact request/output/recipient digest, confirmed ORIGINAL
journal provenance, guest negative controls and complete teardown.

## Current assurance boundary

This baseline demonstrates one *initial* transaction across the guest +
independent recipient; it does NOT test gateway restart, recipient SIGKILL,
two simultaneous gateways or transport partitions within the KVM run.
Those still require a new supervisor-controlled fault matrix after a real
baseline passes. The Linux subprocess suite already tests such cases but
cannot be relabeled KVM evidence.

The recipient IPC key remains private in supervisor/gateway config; don't
include any private config paths, credentials, tokens or unsanitized lab
directories when sharing a report. Share only the final verified JSON and
SHA256 after reviewing them for sensitive details.

**Do not merge PR #66 based on portable CI alone.** The physical KVM
baseline and its verifier must pass on the operator-owned host first.


## Two-window KVM gateway SIGKILL experiment (after baseline passes)

The same draft now includes a **separate** supervisor-triggered hardware
fault runner. It kills the real gateway child at an authenticated checkpoint
after the original reservation, first BEFORE recipient commit and then AFTER
the atomic recipient commit but BEFORE gateway confirmation/acknowledgement.
The recipient continues in its own process. The real KVM guest then submits
the original spent capability (denied) and a fresh, separately guardian-signed
capability to a restarted gateway. A real durable recipient observation must
confirm exactly one effect row and preserve original capability provenance.

    bash scripts/run_package_etcd_lab.sh --kvm-fenced-crash

Each phase uses a new KVM guest, guardian session and originally empty
recipient ledger. PASS requires **both** phases, source-pinned receipt chains,
verified host-observed SIGKILL, distinct live PID identities, synthetic
attestation disclosure, clean teardown and a three-member etcd linearizable
consumption oracle. New exclusive-create results receive their OWN JSON and
SHA256 sidecar and can be rechecked using:

    /var/tmp/event-horizon-isolation-venv/bin/python \
      scripts/verify_integrated_kvm_fenced_crash.py \
      artifacts/reports/<EXACT-FENCED-CRASH-FILENAME>.json

This is NOT a hardware result until executed successfully on the owned KVM
host and independently verified. The CI test of this bridge is a portable
Linux-process regression, not proof of a Firecracker guest.

Recipient service SIGKILL, deliberately interrupted recipient IPC/network
and true competing gateway processes are NOT yet part of these two KVM
windows and must not be claimed. The two historical conservative-gateway
crash commands remain distinct and unmodified.
