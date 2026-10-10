# Independent EHH security evaluation pack

**Scope:** review of a research harness. This is not a commercial pentest engagement,
a bug bounty, a certification, or blanket authorization to target anyone else.

## What to evaluate first

1. **Historical real Firecracker/KVM isolation:** the October 10, 2026
   [operator-run record](evidence/2026-10-10-wsl2-firecracker.md),
   [original JSON](evidence/artifacts/2026-10-10/linux-isolation.json),
   and [SHA-256](evidence/artifacts/2026-10-10/linux-isolation.json.sha256).
   The tested source commit is `238ec72a610eae188491e924ee1bdeec9c7b3f64`.
   Its embedded recorder keys establish report integrity, **not** independent
   signer provenance or hardware attestation.
2. **Distributed authority software lab:** inspect
   [seven-process remote replay](SEVEN_PROCESS_REMOTE_AUTHORITY.md),
   [atomic signed etcd replay](ATOMIC_SIGNED_ETCD_REPLAY.md), and the
   `etcd authority quorum integration (disposable)` workflow.
   No guest-root / Firecracker run has been completed with this distributed
   authority path. Do not combine evidence from the two topologies.

## Verify the *published* report (no virtualization needed)

From a clean checkout, with Python 3.11+ and project dependencies installed:

```bash
python -m pip install -e ".[test]"
cd docs/evidence/artifacts/2026-10-10
sha256sum -c linux-isolation.json.sha256
cd ../../../..
python scripts/verify_linux_isolation.py \
  docs/evidence/artifacts/2026-10-10/linux-isolation.json
```

The SHA-256 validates published bytes, not the identity of the original
experiment operator; the signature verifier authenticates receipts relative
to public keys embedded in that same report. Independently pin the digest or
record a new witnessed run before making provenance claims.

## Reproduce the real KVM experiment on an independently operated machine

Follow [the complete Ubuntu/KVM preparation, boundary and cleanup guide](LINUX_ISOLATION.md).
Use an **owned** Ubuntu 24.04 x86_64 machine with working `/dev/kvm`,
cgroup v2 controllers, and a reviewed root-runner configuration. The
launcher touches cgroups and a jailed VM and is **not** appropriate on shared
or production infrastructure. Check out the exact historical experiment
commit if comparing the originally published result; for a new code version,
report the actual SHA and expect different randomized receipts.

```bash
git rev-parse HEAD
python3 scripts/prepare_linux_isolation.py
sudo /var/tmp/event-horizon-isolation-venv/bin/python \
  scripts/run_linux_isolation.py run \
  --report artifacts/reports/linux-isolation.json
/var/tmp/event-horizon-isolation-venv/bin/python \
  scripts/verify_linux_isolation.py artifacts/reports/linux-isolation.json
(cd artifacts/reports && sha256sum linux-isolation.json)
```

These commands assume the venv and dependencies were installed per
`docs/LINUX_ISOLATION.md`. A PASS is evidence for **three bounded synthetic
guest-root sessions**, not resistance to VM escapes, malicious host
administrators, covert channels, arbitrary model behavior, or production
multi-tenant isolation. Preserve fresh reports and checksums separately;
redact only derived summaries, never quietly modify signed evidence.

## Evaluate the distributed authority separately

Inspect and rerun the disposable etcd quorum workflow with actual three
etcd members. Its artifacts exercise a same-host seven-process software
topology. The newer **v2** report binds an etcd cluster-ID/checkpoint
snapshot to the signed event chain and checks seven cases against individual
`execution.*` event records. Four additional cases require signed raw
coordinator probes. Both classes of records remain **coordinator-observed**:
there is no independently operated side-effect oracle or cluster attestation
inside this report. Historical **v1** reports remain readable but only
establish consistency of signed coordinator PASS assertions.

A second operator should separately preserve the source SHA, actual etcd
cluster ID, their independently pinned signer key, checkpoint continuity,
full logs (sanitized), and all discrepancy details.

## Five questions for reviewers

1. Can an untrusted guest or executor obtain authority beyond the exact
   task policy, or replay/transfer authority across sessions?
2. Is any claimed denial, teardown or external effect missing a defensible
   primary observation? Can a coordinator falsely report PASS?
3. Can a trusted but compromised client manipulate expiry, checkpoints,
   resource consumption or availability to cross an authorization boundary?
4. Are there ambiguous distributed-commit or effect outcomes wrongly
   represented as definitely unexecuted?
5. Which host, signer, OS, etcd administrator and recorder assumptions remain
   trusted, and what minimal additional experiment would invalidate them?

## Reporting & safe harbor

Follow [SECURITY.md](../SECURITY.md) and [RED_TEAM.md](../RED_TEAM.md).
Test **only on your owned/sanctioned lab**, with synthetic fixtures.
Report plausible vulnerabilities via GitHub private vulnerability reporting,
or the private contact channel listed in SECURITY.md. Do not publish a
working bypass before coordinating with the maintainer. No bounty, payment,
response-time guarantee or right to attack third-party infrastructure is
offered. Feel free to report design objections and failed reproductions as
non-sensitive issues.

Please include: commit SHA; operator-controlled hardware/OS; exact commands;
expected invariant; observed counterexample; signed report digest, proof
source and pinned key provenance; whether the result was reproduced by a
second person; sanitized logs; and a proposed narrower claim if needed.

See [review findings template](INDEPENDENT_EVALUATION_FINDINGS.md).

## Preservation policy

No existing implementation module, including `raft_replay.py` or
`raft_core.py`, is removed by this hardening work. Historical unsafe Raft
proposals remain fail-closed, and repairing/test-driving Raft is a distinct
future engineering track. The current live replicated authority is etcd.
