# Adversarial boundary experiment

Run:

```bash
python -m event_horizon.adversarial_boundary --workdir .demo/adversarial-boundary --output .demo/adversarial-boundary/report.json
```

This executes actual subprocesses from `ProcessSeparatedHarness`. It
attempts a permitted one-use read, replay of that capability, an unsigned
mutation to the signer, a request forbidden by the static policy, an executor
credential probe, an authority outage, and replay following restart.

The report states the outcome for every attempt and the path to the real
recorder's signed evidence. The result fails if mandatory outcomes do not
occur. It is not a red-team penetration test, remote-code execution attack,
or a genuine host-root compromise. The standard harness processes are
running under one host user and do **not** establish OS/VM isolation.

For Firecracker/KVM, use the opt-in scripts described in
[LINUX_ISOLATION.md](LINUX_ISOLATION.md) and
[PACKAGE_ISOLATION.md](PACKAGE_ISOLATION.md). A real KVM experiment must
additionally record host-side network, filesystem, and reboot observations.
No Firecracker result is implied by this cross-platform test.

The tested authority is the existing SQLite single-authority topology.
A separate integration test is needed after the complete signed trusted
authority RPC is wired to the etcd backend. See ADR-001.
