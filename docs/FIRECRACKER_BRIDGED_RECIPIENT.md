# Opt-in KVM durable recipient integration

The existing bridged-authority experiment passed on Ubuntu KVM at revision `8be130e`. This extension **does not modify that experiment**.

New operator command (only after this PR passes CI and is merged):

```bash
cd ~/event-horizon-harness
git switch main
git pull --ff-only
bash scripts/run_package_etcd_lab.sh --bridged-recipient
```

This reuses the owned three-node disposable etcd cluster, Firecracker guest vsock request path, four separately running signer guardians, separate trusted gateway process, and host-supervisor evidence receiver. It also starts a **third independently supervised process** for the external recipient. Recipient commits use SQLite `synchronous=FULL`; the gateway must durably reserve the logical effect in `DurableEffectJournal` before dispatching it.

A passing `isolated-authority-firecracker-etcd-bridged-recipient` report must show, in each of three rounds, exactly one recipient commit, the expected recipient request digest, and a supervisor-reconciled journal entry marked `recipient-confirmed` with a matching independently computed recipient ledger digest. The verifier rejects shared PIDs and any missing or contradictory signed observation. The original insecure-vs-protected package comparison and all v4 guardian/etcd/receipt checks still apply.

**Not yet proven:** The gateway is not deliberately SIGKILLed during the guest request in this command. No post-kill recovery attempt is made, and no five-window result should be claimed. The next step is a separate crash-injection run and verifier with the expected commit counts 0, 0, 1, 1, 1, performed against the actual Firecracker guest and independent recipient. The virtual machine's attestation remains synthetic, and the local recorder is not an external witness.

## Crash ambiguity and retry fencing

A reservation after crash remains `possibly-committed` unless the supervisor can independently observe the exact recipient commit and reconcile it. Absence of a recipient ledger row **never** proves that an in-flight effect cannot commit later. This integration **does not** release reservations on absence, timeout or gateway death; safe negative reconciliation will require fencing of all prior dispatch attempts and an independently durable non-commit proof. Historical published recipient reports at source `ea79595...` legitimately contain `possibly-committed`, while newly generated reports must include `recipient-confirmed` and a matching `receipt_digest`. Neither internal verification nor synthetic attestation constitutes an external independent witness.
