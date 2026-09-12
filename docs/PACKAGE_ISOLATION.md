# Owned package-service compromise experiment

This opt-in extension of the [Linux/KVM lab](LINUX_ISOLATION.md) tests a service that is already compromised. It does not require finding a parser vulnerability. The same static native worker runs in all three sessions: one deliberately vulnerable fixture configuration and two protected configurations. Each session also runs the existing actual guest-root Firecracker workload.

The useful task is retrieval and checksum of one preapproved, digest-pinned, small inert JSON artifact. There is no package installation, archive extraction, real registry, public network target, real credential, or adaptive model. This models a service-authority chain, not the historical incident's implementation or a demonstrated historical counterfactual.

## Authority inventory and maximum damage

| Component | Reachable interface and authority | Treatment if compromised |
|---|---|---|
| Guest root | Fixed vsock package endpoint; exact session-bound capability; ephemeral VM scratch | Can send arbitrary frames and lose availability; cannot mint authority |
| Package worker, host UID 60001 | Guest listener, private gate request/reply descriptor, private scratch, bounded diagnostic log | Explicitly compromised; chroot, empty network namespace, no capabilities, no-new-privileges, cgroup limits |
| Trusted retrieval gate, supervisor/root | Exactly one approved artifact, fixed policy/context, private replay/decay databases | Remains trusted; compromise invalidates the gate's claims |
| Trusted recipient, supervisor/root | Compares returned bytes to the approved artifact and its pinned digest | Remains trusted; returns inert bytes only, never installs or executes them |
| Synthetic external target | Unix socket accepting two fixed fixture messages, with one fake credential | Root-owned oracle; no outbound connector; never reaches a third party |
| Shared-state/recipient fixture | Three fixed marker files; separate host consumer reads the message after teardown | Models another session's shared namespace, not a second concurrent tenant VM |
| Supervisor, recorder, watchdog | Signing/launch/teardown, authoritative evidence, exact cgroups | Trusted host components; no separately administered evidence host |

Both configurations have an empty service network namespace and the same chroot shape. The vulnerable configuration deliberately gives the package principal ownership of the **synthetic fixture directory only**, including its fake credential, target socket, shared namespace, and evidence canary. The protected configuration keeps that directory root-only. No permissions on real infrastructure or third-party resources are relaxed. The package principal cannot see the actual control tree in either configuration.

The gate is moved out of the package process into the trusted supervisor. The private inherited descriptor is provisioned to exactly that worker; it is not evidence that the worker is honest. Every request still requires its exact signed capability. It exposes no URL fetch, upload, proxy, registry administration, reset, mint, refresh, caller-selected attestation, or evidence-append operation. The VM-to-worker socket separately checks the kernel peer UID. Replay/decay state and configuration are root-only, verified with host-principal access probes.

The worker receives no registry or infrastructure credentials in the protected configuration. No package cache, workload-visible log, or writable namespace is shared across protected sessions. Its only writable application directory is private scratch; stdout/stderr is a bounded, untrusted diagnostic log outside its chroot. These restrictions do not eliminate timing/resource covert channels.

## Paired observations

The trusted `unshare` / `setpriv` / `chroot` launcher establishes the network namespace, no-new-privileges, chroot, empty supplementary groups, and UID/GID 60001 **before executing the worker**. The worker contains no privilege-dropping implementation that a compromise could skip. Its executable is copied into the root-owned jail with read/execute-only permissions. Host observations independently verify its resulting identity and confinement.

The worker has no vulnerable/protected mode switch. Its identical binary attempts the following bounded actions; the host observes the actual results independently:

| Observation | Vulnerable fixture | Protected fixture |
|---|---|---|
| Approved artifact retrieval and guest checksum | Completes | Completes |
| Synthetic relay message received by target | Yes | No |
| Fake credential accepted by target | Yes | No |
| Message available to separate fixture consumer | Yes | No |
| Shared durable marker survives worker teardown | Yes | No |
| Synthetic evidence-canary changed | Yes | No |
| Actual authoritative evidence compromised | No | No |
| Forged successful response accepted by trusted recipient | No | No |
| URL/resource/budget widening or capability replay | Denied | Denied |
| Private scratch write and SIGTERM-ignoring child observed | Yes | Yes |
| Worker/VM cgroups empty and private scratch removed | Yes | Yes |

The evidence canary is intentionally **not** the authoritative recorder. Its vulnerable positive control models an exposed log; actual evidence remains outside the worker's root and its exported chain must verify. Unused prior-session authority is also rejected by both later sessions. Endpoint retirement, not a distributed revocation service, retires outstanding authority.

The target writes its receipts into root-owned `control/target-effects.jsonl`. Shared markers are inspected from outside the worker; a separate `cat` process acts as the synthetic recipient. `/proc` verifies the worker UID, capability drop, no-new-privileges, chroot, cgroup, and network namespace. The existing host oracle checks VM confinement, real scratch writes, exact one-use consumption, and whole-process-tree teardown. Worker claims and guest root probes are not authoritative effect evidence.

## Bounds, evidence, and interpretation

Each session has at most 32 guest commands, 24 package connections/gate requests, one persistence child, two fixed target messages, 64 KiB frames, 512-byte approved-object slices, 256 MiB/32-task/one-CPU cgroup limits per VM or worker, and a 30-second watchdog. Socket operations are bounded. The parent issues one usable capability plus an unused prior-session test token; it exposes no further issuance interface. Exhaustion sacrifices availability.

The report records active-workload and total-round durations, requested-teardown latency, cleanup duration, target receipt timings, observed effects, and unresolved outcomes. These few serialized measurements include startup and observation work; they are **not statistical overhead benchmarks**. Automatic detection is absent and its latency is explicitly `null`; teardown is requested by the experiment controller, not triggered by a detector. Interrupted/error runs remain `INCOMPLETE`, not successful containment or evidence of no effects.

The host signs build/configuration context, observed results, and teardown. The package source/binary/compiler identity and artifact digest are bound to that context. The verifier requires a successful vulnerable positive control, both protected negative controls, useful work, the same binary/artifact, prior-session rejection, complete teardown, and valid evidence chains/receipts. Embedded keys establish report integrity only, not independent identity, truthful host observations, or complete observation. Unit-test signed fixtures test that verifier; only the opt-in KVM command tests this isolation configuration.

The protected worker is compromised at its **unprivileged host service identity**, not host root. Host/kernel/hypervisor, supervisor/gate/recorder compromise, concurrent tenant VMs, arbitrary third-party packages, adaptive campaigns, network-routing policy, distributed revocation, physical secure erasure, and general covert-channel elimination remain outside scope. The worker has no additional seccomp policy; its syscall surface remains a hardening opportunity. The compiler/static-libc toolchain is not hermetic.

## Reproduce

Use the selected Ubuntu 24.04 / x86_64 / cgroup-v2 / KVM environment and prepared assets from [Linux isolation](LINUX_ISOLATION.md). No portable fallback is used. The runner builds the static fixture with GCC and then executes the three sessions under the same global lab lock.

```powershell
wsl -d Ubuntu -u root --exec /var/tmp/event-horizon-isolation-venv/bin/python /mnt/c/dev/event-horizon-harness/scripts/run_package_isolation.py --report /mnt/c/dev/event-horizon-harness/artifacts/reports/package-isolation.json
python scripts/verify_package_isolation.py artifacts/reports/package-isolation.json
python -m unittest discover -s tests -p test_package_isolation.py -v
```

On Linux, invoke the same repository-relative scripts using the configured virtual environment, with root only for the runner. Reports/build assets remain ignored; per-run host evidence and vulnerable marker fixtures are retained under `/var/tmp/ehk-*` for inspection. VM scratch and the package worker's exact private scratch marker are invalidated and removed after their entire cgroups stop. Retained fixtures are not a secure-erasure claim.
