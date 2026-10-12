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

A passing `isolated-authority-firecracker-etcd-bridged-recipient` report must show, in each of three rounds, exactly one recipient commit, the expected recipient request digest, and a persistent journal entry marked `possibly-committed`. The verifier rejects shared PIDs and any missing or contradictory signed observation. The original insecure-vs-protected package comparison and all v4 guardian/etcd/receipt checks still apply.

**Not yet proven:** The gateway is not deliberately SIGKILLed during the guest request in this command. No post-kill recovery attempt is made, and no five-window result should be claimed. The next step is a separate crash-injection run and verifier with the expected commit counts 0, 0, 1, 1, 1, performed against the actual Firecracker guest and independent recipient. The virtual machine's attestation remains synthetic, and the local recorder is not an external witness.
