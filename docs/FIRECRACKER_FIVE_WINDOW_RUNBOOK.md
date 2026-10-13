# Five-window Firecracker SIGKILL experiment — hardware validation pending

This is a **separate, opt-in experimental path**. It does not reinterpret the three-round `event-horizon.package-isolation.v4` PASS reports, and it is not proven by GitHub Actions' portable Linux tests.

## Preconditions

The existing Ubuntu 24.04 x86_64 EHH operator host must provide functional `/dev/kvm`, the pinned prepared Firecracker/jailer guest build, the root-owned staged authority runtime, Docker access, and the same prepared Python environment as the already verified `--bridged-recipient` baseline.

Once the runner PR is merged and portable CI is green, the **only** operator command is:

```bash
cd ~/event-horizon-harness
git switch main
git pull --ff-only
bash scripts/run_package_etcd_lab.sh --kvm-crash
```

Do not execute this flag before merge. Do not treat a pre-hardware passing CI job as real Firecracker evidence.

## Semantics

Each of five rounds starts a *fresh* Firecracker guest, constrained package service, four isolated guardian processes plus signer, a disposable recipient process/SQLite ledger, independent gateway, and one pinned etcd session in the owned three-node cluster. The guest supplies its exact signed request. The supervisor's kill timer starts only when that request—not preceding negative-control traffic—is forwarded.

The checkpoint is printed by the actual gateway child, which then blocks. The supervisor observes the exact marker, delivers `SIGKILL`, reaps the child with exit code `-9`, reads the recipient ledger and durable journal directly, and emits a signed `gateway.crash-observed` event. The guest must receive an **ambiguous failure**, never a synthetic successful effect. The receiver restarts a new gateway with the same authoritative journal and repeats the consumed original capability, followed by a fresh, separately guardian-signed capability in windows 2–5. After replay denial and unchanged recipient ledger the supervisor emits a signed `gateway.recovery-observed` event.

| Window | Expected external recipient commits | Durable reservation at kill | Fresh token outcome |
| --- | ---: | --- | --- |
| Before reservation | 0 | Absent | Not retried; reauthorization may execute, so no no-effect claim beyond the kill |
| Reserved, before handler dispatch | 0 | Possibly committed | Must be denied |
| Recipient committed, before gateway acknowledgement | 1 | Possibly committed | Must be denied |
| Handler returned, before completion record | 1 | Possibly committed | Must be denied |
| Completion recorded, before guest response | 1 | Possibly committed | Must be denied |

The independent verifier requires five ordered signed evidence chains, one trusted kill and recovery event per round, the real guardian approvals, kernel isolation observations, real KVM-backed guest summary, three-node etcd consumption records including the consumed *fresh* capability, independent recipient digests and child PIDs, and successful cgroup/guest teardown. The original JSON is preserved with a SHA-256 sidecar on PASS **or** INCOMPLETE.

## Limits and interpretation

- Five kill windows establish a controlled fail-closed recovery behavior under Linux process `SIGKILL`, not physical power-failure durability.
- Internal Ed25519 verification and embedded public keys prove evidence consistency, not external attestation or independently witnessed provenance.
- Synthetic guest attestation remains synthetic. The user-owned Docker cluster is not physical multi-host consensus separation.
- A zero-commit recipient ledger is *not* evidence that it is safe to release a previous reservation. **No automatic negative reconciliation or redispatch is implemented.**
- The first runtime/operator failure must produce `INCOMPLETE`; preserve its JSON/sidecar and diagnose rather than edit it or relabel it as a passing result.

Verification command against original report:

```bash
/var/tmp/event-horizon-isolation-venv/bin/python scripts/verify_integrated_kvm_crash.py artifacts/reports/<exact-kvm-crash-report>.json
```
