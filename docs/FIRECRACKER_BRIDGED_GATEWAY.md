# Experimental Firecracker to subprocess gateway bridge

Status: **implementation proposed; portable CI is not KVM evidence**.

This opt-in experiment uses the *existing* Firecracker guest/vsock transport,
package-worker service channel, four-guardian signer and disposable three-node
etcd setup, but forwards the private host effect-service socket's requests into
a distinct trusted gateway subprocess rather than running DatasetEffectBoundary
inside the supervisor's own Python thread.

The gateway receives an inherited private Unix socket, never caller-provided
backends, signer keys, device identity or trust policy. The supervisor owns a
second private socket that appends the gateway's authorization, dispatch,
completion and denial events to the existing externally verifiable local
ExternalRecorder instance. Child gateway death or recorder RPC failure is
**indeterminate**, not a successful denial. The supervisor continues to check
separate gateway PID, actual guest VM jail/UID/seccomp, and the baseline v4
integrated authority invariants.

Run on the **prepared operator-owned Linux/KVM machine**:

    cd ~/event-horizon-harness
    git switch main
    git pull --ff-only
    bash scripts/run_package_etcd_lab.sh --bridged-authority

For review before merge, check out this feature branch instead of main and run
the exact same lab command. Do not invoke this on production etcd. Like the
existing launcher, it builds a dedicated three-node disposable etcd cluster
only on loopback, owns its containers, and checks /dev/kvm and the pinned
Firecracker asset manifest. The signed output and SHA-256 sidecar use new
timestamped names containing 'bridged-authority'.

## What success will and will not establish

A successful operator KVM run would establish one real guest request path
through the actual guardian-authorized gateway **in a distinct host process**,
with the preexisting 3-member etcd replay checks and supervisor-signed internal
evidence. The v4 report should include a gateway_process_bridge observation
with the distinct child PID in each round.

This is **not** a five-window post-dispatch SIGKILL experiment. This mode does
not yet start the durable external recipient from the host-only campaign or
enable its outcome journal. It does not intentionally SIGKILL the gateway in a
post-commit window or then restart the VM/gateway. The four guardian principals
are on the same operator-controlled host, attestation remains synthetic, and
the local recorder does not supply an independent outside witness.

The gateway child is a trusted process using the supervisor's private inherited
descriptor; the bridged peer identity inherits the existing guest -> package
service transport assumptions and is **not a separate cryptographic proof of
guest identity**. Host-root compromise, independent attestations and power-loss
semantics are not tested.

## Review and release rules

- Default '--isolated-authority' path must not change.
- CI's portable test uses an ordinary fixture capability, not four guardians.
- A missing or crashed child, unexpected evidence record, or lost RPC fails the
  run; it must never be reported as a successful denial.
- Verify the pinned source commit and original report/checksum without changing
  the bytes. Publish evidence in a separate PR after an actual operator run.
- Only after bridge proof: couple this path to the separate durable recipient
  and DurableEffectJournal; add supervised crash checkpoints and a **new**
  strict crash evidence verifier. Do not reuse the baseline v4 PASS to claim
  five real Firecracker crash windows.
