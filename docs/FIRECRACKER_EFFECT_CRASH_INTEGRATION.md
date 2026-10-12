# Firecracker + four-guardian post-dispatch crash campaign (implementation contract)

Status: **design/acceptance contract only — no integrated run or result is claimed**.

## Objective

Close Issue #34 by exercising the uncertain external-effect outcome *in the actual
Firecracker guest path* using the existing four-guardian capability issuance,
owned three-node etcd replay store and durable recipient observation. Do not
substitute host-only `run_effect_crash_campaign.py` results for guest results.

## Existing seams (reuse, do not rewrite)

- `run_integrated_authority.py` / `run_linux_isolation.run_round`: actual
  KVM and privileged lab, including verified build assets and hard teardown.
- `integrated_authority_session.IsolatedSession`: protected signer and four
  distinct guardian approvals; no fixture broker in this experiment.
- `integrated_gateway_campaign.IntegratedPackageLab` /
  `run_package_isolation.GateReceiver`: guest/vsock request and fixed host
  handler, including direct dispatch observations.
- `DurableEffectJournal` / `TrustedEffectGateway`: reserve-before-dispatch
  and ambiguous-outcome denial on renewed authority.
- `run_effect_crash_campaign.py`: tested marker names, recipient-side durable
  ledger and supervisor-driven SIGKILL pattern.
- `package_authority_oracle.inspect_committed_consumption`: separate
  linearizable etcd consumption record inspection.

## Mandatory execution topology

1. Operator invokes a **new opt-in flag** under
   `scripts/run_package_etcd_lab.sh`; existing `--isolated-authority`,
   `--effect-crash` and baseline modes remain unchanged.
2. Preserve the privileged Firecracker runner's isolation checks: checked
   manifest, real `/dev/kvm`, separate UIDs/network namespaces, no implicit
   fallback to host-only mode, no production etcd, owned disposable containers.
3. Sign the real guest request using the four-guardian signer, independently
   pin its signer public key, and route the authorized guest attempt through
   the existing vsock channel to the trusted host gateway.
4. Put the **durable recipient in a process distinct from the host gateway**.
   Observe its SQLite (synchronous FULL) commit ledger from the supervisor.
   The gateway must no longer share its process lifetime with the supervisor.
   Never infer an effect from gateway logs or caller return values.
5. Explicit barriers signal only after the corresponding durable state is
   established; an independent supervisor sends real SIGKILL to the selected
   process (and independently records pid, signal, marker, wait status).
   Document separately which faults kill the gateway, the guest Firecracker
   VMM, or both. A VM kill alone does not prove gateway-process failure.
6. Restart a **new gateway process** with the same persistent journal, and
   reboot a **new real Firecracker VM** if a guest restart is part of the
   scenario. Attempt consumed-token replay and separately guardian-authorized
   replacement capability for the *identical session/request/effect identity*.
   If request identity changes, treat that as a different effect.
7. Use a supervisor-side linearizable etcd oracle to bind original/replacement
   consumed capability IDs and signed claims digests. Verify recipient record
   counts and row digests before the crash, after the crash, and after recovery.
8. Ensure privileged cleanup on every exit; never remove operator containers,
   modify existing v4 evidence, or overwrite a prior report.

## Five required crash windows

| Fault barrier | Expected recipient commits after kill and recovery |
|---|---:|
| After authority consumption / before journal reservation | 0 |
| After durable journal reservation / before handler dispatch | 0 |
| After durable recipient commit / before gateway acknowledgement | 1 |
| After handler return / before completion evidence | 1 |
| After completion evidence / before caller acknowledgement | 1 |

For all stages: old consumed capability is rejected. For stages 2–5:
separately guardian-approved replacement capability for that same logical
effect must be rejected as `prior-effect-unknown`, with unchanged recipient
count and digest. Stage 1 does **not** automatically reissue. Unexpected
timeout, EOF, missing crash checkpoint or orphaned process is **INCOMPLETE**,
not a successful security denial.

## Required negative and failure controls

- Reject fixture-broker capabilities, fewer than four guardian approvals,
  changed signer key, changed request digest, changed output ceiling, and
  wrong VM/executor binding before dispatch.
- Kill before recipient commit and after commit to prove that observed
  counts follow the actual fault stage; verify no silent second dispatch.
- On etcd majority loss or unknown consumption, do not retry an ambiguous
  token. Recover quorum, then inspect a linearizable record.
- Tamper with all five stage labels, kill markers, guardian approval bindings,
  capability/claims digests, recipient counts, and external receipt signatures
  (if present); verifier must reject each.
- Exercise crash while the guest/vsock channel is active, not only a host
  proxy synthetic request. Record the actual guest/host transport identity.
- Report separately gateway process death, VM process death, and success of
  teardown; do not conflate supervisor channel loss with SIGKILL.

## Evidence and independent verification

Use a **new schema** and separate strict verifier. Publish original JSON and
SHA-256 sidecar once, with exact source revision, build manifest digests,
VM ID, gateway/recipient PIDs, four guardian approval bindings, consumed
capability identities, etcd cluster/member headers, exact crash barrier and
SIGKILL exit status, persistent journal state, independently read recipient
counts/digests, replay outcomes, and any incomplete faults.

An embedded ephemeral Ed25519 key protects self-consistency **only**. Its
signature is not an independent witness. Never claim hardware attestation,
host-root resistance, physical separation, power-loss resilience or general
exactly-once external effects unless separate experiments establish them.

## Merge gates

- Portable tests cover protocol/barrier/replay/verifier behavior but **must
  not** be labeled KVM proof.
- One real operator-owned Ubuntu/KVM execution produces all five complete
  verified scenarios; an incomplete run fails the release gate.
- CI checks old v4 and host SIGKILL contracts for regression.
- Original report and checksum are preserved byte-for-byte in an evidence-only
  PR after review. Keep the implementation and evidence PRs separate.

## Suggested change order

1. Extract supervisor/recipient/gateway process lifetimes and marker transport
   with portable process tests; preserve existing baseline behavior.
2. Extend integrated signer session to reissue a distinct guardian-approved
   capability tied to the same request identity without broadening policy.
3. Add KVM/vsock crash injection at the host gateway boundary and verify
   actual VMM and gateway deaths independently.
4. Add strict cross-component evidence verifier and negative tampering tests.
5. Run the full KVM lab on the operator's Ubuntu setup, then publish evidence.

See [real-process campaign](../REAL_EFFECT_CRASH_CAMPAIGN.md) and
[existing integrated KVM lab](../INTEGRATED_ISOLATED_AUTHORITY.md).
