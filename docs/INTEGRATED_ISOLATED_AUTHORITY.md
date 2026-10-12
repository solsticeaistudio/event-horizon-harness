# Opt-in isolated authority, Firecracker and etcd experiment

This experiment connects the existing four-guardian signature contract to the
actual package retrieval request executed by Firecracker. It preserves one
vulnerable worker configuration and two protected configurations with the same
worker binary. It uses owned inert fixtures only.

**Attestation is synthetic. Locally signed evidence establishes internal
integrity, not independently witnessed hardware provenance or a trusted host.**

## Audit and integration points

The base inspected was `e13160b55af2b4c3eda93b8e8a10b0026573c80f`.

| Existing boundary | Audit finding | Integration change |
|---|---|---|
| `signed_guardian_authority.py` | Already verifies four pinned Ed25519 approvals, request/policy/challenge bindings and local policy; signer challenge is single-use | Reused without replacing its authorization contract |
| `isolated_authority_lab.py` | Services generated private keys after privilege drop but pinned a different static fixture | Optional trusted session configuration; existing peer-credential RPC and private service audit pipes |
| `run_linux_isolation.run_round()` | Issued both usable and spare capability via in-process broker for a new session | Explicit `authority_session`; rejects any supplied broker; requests the useful, fault-probe and spare capabilities from the isolated signer |
| `run_package_isolation.GateReceiver` | Trusted host gateway owns replay state, pins and effect callback; worker holds only request descriptor | Optional direct handler-dispatch observation; existing gateway still makes every authority decision |
| `authority_backends.py` | etcd VERSION==0 compare-and-put; pinned response cluster, revision/term and exact collision record; no retry/fallback | Reused unchanged |
| `package_authority_oracle.py` | Separate host linearizable range verifies exact capability, claims digest, expiry and record count | Retains exact primary binding; permits one separately bound retired fault token and records primary/total counts separately |
| Evidence verifiers | v1/v2/v3 package reports describe baseline/static/adaptive experiments | v4 adds integrated authority, guest fault controls and supervisor-channel-loss teardown |

The incompatible original fixture used a fixed session, `synthetic-dataset`,
five bytes and a 4096-byte ceiling. The new trusted session adapter pins the
actual `dataset-read` request, ephemeral `ehk-*` session, package artifact,
exact arguments, executor, synthetic measurement of Firecracker asset digests,
and a 512-byte ceiling. No RPC accepts a new policy, compiled ceiling, verifier
pin or measurement. The signer pins its locally compiled ceiling at trusted service startup;
its issue API accepts no externally supplied ceiling. The session permits
at most three independently approved tokens: the useful operation, a retired quorum-fault
probe, and an unused prior-session negative-control token.

## Trust architecture and execution order

1. The trusted root supervisor checks prepared Firecracker assets and installs
   read-only per-role session configuration. It stages public source only.
2. Four guardian processes run under UIDs 64001..64004. Each generates and keeps
   its own Ed25519 key. The supervisor pins only public keys in signer config.
3. The signer runs as UID 64010 and alone creates/holds the capability key.
   Guardian and signer sockets admit only coordinator UID 64020 via SO_PEERCRED.
   All six authority principals run in empty network namespaces, preventing
   access to the host's loopback etcd endpoints, even though the disposable lab
   uses no production credentials. Same-UID portable tests do not claim this.
4. The coordinator requests a signer challenge, collects each guardian's signed
   decision, and submits the four envelopes. Static policy, synthetic executor
   attestation, session lineage/budget and behavioral transition are evaluated
   in their respective services. The signer independently checks its policy,
   exact session request, approvals, challenge expiry/use and compiled ceiling.
5. The supervisor obtains the signer public key from the protected launch pipe,
   verifies the returned capability and approvals, and configures the host gate
   with that pin. Coordinator-provided public keys cannot replace it.
6. The real Firecracker guest receives the capability over the existing vsock
   channel and submits its actual request through the compromised package worker.
   The worker runs as host UID 60001 and the VM as UID 60000. The worker has
   neither authority configuration nor etcd endpoint access.
7. The existing host gate checks request/capability/context, consumes authority
   via etcd, and only then dispatches its fixed inert read handler. Direct host
   dispatch counters supplement signed authorization/completion records.
8. The host independently reads the committed etcd binding. Requested stop and
   loss of the supervisor watchdog control channel exercise teardown. Authority
   processes are stopped, pipes closed and temporary authority paths removed.

The root supervisor, gateway, recorder, kernel/hypervisor and etcd installation
remain trusted. Separate UIDs are not separate administrators or physical hosts.
The guardian services use existing `LineageBudgetGuardian`, `SequenceGuardian`
and `AttestationGuardian` evaluations; no physical TPM quote is manufactured.

## Adversarial coverage

The authority campaign checks forged, omitted, duplicate, modified and swapped
approvals; signed vetoes; expired/reused challenges; changed request, resource,
arguments, output ceiling, policy, executor and attestation; direct broker RPC
bypass; and signer-key substitution. The separate UID campaign also probes
signer config/memory access and wrong-UID socket admission. SIGSTOP faults test
missing signer/guardian availability followed by healthy resumed service.
The same session's independently issued capabilities are positive
controls; failed authority attempts happen before a VM or effect handler exists.

The actual guest path checks changed resource/executor/ceiling/key envelopes,
replay and prior-session capabilities. Two Docker etcd nodes are paused to lose
majority before a valid request: direct host observation must show no handler
dispatch. Consumption remains unknown during the outage; a linearizable read
after recovery establishes whether that token was consumed. It is retired without
retry either way; a separately approved token supplies the healthy control. A valid request then
succeeds while one node is paused (majority retained). Recovery must not
resurrect its consumed authority. An unresolved dispatch or consumption outcome
fails the run rather than becoming a successful denial.

The vulnerable configuration must still produce all five synthetic forbidden
worker effects; the protected configurations must not. OS ownership/chroot
boundaries prevent those effects. Guardian authorization is not credited with
preventing every worker-originated effect.

Issue #30 has a separately scoped commit: only the intentionally wrong-UID
probe may accept broken-pipe/reset as early refusal, and only after signer
liveness and a subsequent valid authorized call. Timeouts, EOF and arbitrary
socket errors are not generally classified as security denials.

## Run and verify

Complete the existing [KVM preparation](LINUX_ISOLATION.md), with Docker access
and the prepared Python environment. The launcher owns only its new containers
and network and refuses occupied loopback ports.

```bash
bash scripts/run_package_etcd_lab.sh --isolated-authority
```

The integrated path requires root privilege for UID/network/cgroup/KVM setup,
real KVM and a disposable real etcd quorum. There is no simulated or SQLite
fallback. It refuses to overwrite an existing report or checksum and requires
committed source before a hardware run. Results are saved once under
`artifacts/reports/`; failed runs remain `INCOMPLETE`.

```bash
/var/tmp/event-horizon-isolation-venv/bin/python scripts/verify_package_isolation.py PATH_TO_REPORT.json
(cd artifacts/reports && sha256sum -c REPORT_BASENAME.json.sha256)
```

The v4 verifier checks existing package evidence chains/receipts, paired effects,
actual issued capability signatures, all four approvals and their relationship
to the capability, pinned build/request/policy identity, etcd bindings, mandatory
negative controls, primary host denials/no dispatch and cleanup. Embedded keys
are not an external trust anchor. Raw reports contain public signed capability
material and must be reviewed before publication; the feature PR does not stage
them automatically.

Portable CI runs real AF_UNIX services under one UID, adapter/contract regressions
and deterministic verifier-tampering tests. It does not claim Firecracker or
privileged namespace coverage. Existing live etcd and privileged KVM experiments
remain explicit opt-ins.

The [local validation record](evidence/2026-10-12-integrated-authority-validation.md)
records the actual source revision, results and original report fingerprint.
The original successful report and SHA-256 sidecar were subsequently published in
[the 2026-10-12 evidence archive](evidence/artifacts/2026-10-12/README.md)
through PR #32. The validation record describes the earlier pre-publication
state. The report still requires an independently trusted witness before making
external hardware-provenance claims.

The exact experiment source commit `8f0ef678540d282f8b8b9aa1f67e8950fb0d5add`
is preserved on the archival branch
`evidence/source-2026-10-12-firecracker-etcd` (not on the squash-merged
`main` lineage). Fetch that branch when independently reproducing the run.

## Remaining assumptions

No external witness, hardware attestation, hostile host-root containment, HSM,
physical node separation, arbitrary adaptive guest agent, tenant concurrency,
rollback resilience or comprehensive covert-channel prevention is established.
The injected interruption closes the watchdog control channel; it does not
prove cleanup after every host crash or power loss. Interrupted effects after
dispatch remain potentially committed; this campaign injects quorum loss before
dispatch. Automatic attack detection is absent. The worker has no added seccomp
filter; process hardening and independent reproduction remain further work.

The final oracle records the total session consumption count and the primary
capability's count separately. Exactly one primary consumption and one handler
dispatch are required. The retired fault token may also have one committed
consumption without an effect. Its exact signed claims must match that record;
no unexpected third record is allowed. This is an availability cost of an
ambiguous consensus reply, not permission to retry an uncertain operation.
