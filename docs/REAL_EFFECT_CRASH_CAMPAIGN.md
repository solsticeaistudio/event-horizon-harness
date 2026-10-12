# Real host-process effect crash campaign (experimental)

This is an **opt-in companion experiment** to
[the integrated Firecracker/KVM authority lab](INTEGRATED_ISOLATED_AUTHORITY.md).
It tests a previously untested timing window: a trusted gateway is terminated
with **real SIGKILL** after an external recipient durably commits an effect,
but before the gateway's caller receives acknowledgment.

This is **not** the four-guardian Firecracker experiment and does not establish
power-loss resilience, hardware attestation, or an outside witness. It uses a
fixture capability broker and synthetic attestation; replay uses actual EHH
signed capabilities and SQLite or a disposable three-member etcd cluster.

## Run without Docker / KVM

Linux-only portable real-process campaign:

```bash
python scripts/run_effect_crash_campaign.py --backend sqlite \
  --report artifacts/reports/effect-crash-local-$(date -u +%Y%m%dT%H%M%SZ).json
```

Inspect the unmodified original report with:

```bash
python scripts/verify_effect_crash_campaign.py \
  artifacts/reports/<exact-generated-report-name>.json
```

The JSON is written once, and its .sha256 sidecar is generated. Linux CI
also executes five actual subprocess SIGKILL checkpoints.

## Run against real disposable three-node etcd

On the prepared Ubuntu/WSL2 system already used by the earlier experiments:

```bash
git switch main
git pull --ff-only
bash scripts/run_package_etcd_lab.sh --effect-crash
```

The existing launcher checks loopback ports, creates its **own disposable
three-node etcd cluster**, pins the discovered cluster ID, runs the host
process campaign with real one-use compare-and-put authority, verifies the
report and checksum, and tears down its containers.

This opt-in mode does **not** start Firecracker or exercise guest-to-host
transport. The existing --isolated-authority mode is unchanged.

## Exact fault stages

A supervisor launches a separate recipient process and a trusted gateway
subprocess. The recipient durably commits to SQLite with synchronous=FULL.
The host supervisor reads the recipient journal **after** the gateway dies,
rather than trusting the gateway's return value. The supervisor kills the
worker only upon receipt of the expected checkpoint marker.

1. After authority consumption but before journal reservation: count 0.
2. After reservation but before recipient dispatch: count 0.
3. After recipient commit but before gateway client acknowledgment: count 1.
4. After handler return but before completion evidence recording: count 1.
5. After completion evidence but before caller acknowledgment: count 1.

After restart, the original consumed capability must fail. For stages 2-5,
a fresh capability for the same logical effect is tested and rejected by
the journal, and recipient observations cannot change. Stage 1 does not
automatically retry with new authority.

For etcd mode, a separate supervisor linearizable read verifies which
capability IDs/claims digests committed, including the second consumed token.

## Scope and trust

- All SIGKILL operations are real Linux process signals, not monkeypatches.
- Recipient and gateway are separate processes, but remain in the **same
  operator-controlled host trust domain**. A hostile host/root can forge or
  modify their local observations. This is not independent attestation.
- Each report has an internal ephemeral Ed25519 signature with embedded public
  key: signature validity detects modification relative to that embedded key,
  **not** externally witnessed provenance.
- Logical effect identity is bound to session ID and request ID; a malicious
  actor able to invent a new request ID can evade that deduplication scope.
- This fixture broker is not the production-bound four-guardian signer.
- No Firecracker guest, independently authenticated recipient receipt,
  host power loss, disk loss, physical multi-host isolation, or real hardware
  attestation is exercised in this first campaign.
- Host SQLite durability assumes the OS and storage honor fsync semantics.
  This experiment does not prove exactly-once remote effects.

## Verification and publication

Keep the original JSON and SHA-256 sidecar byte-for-byte unchanged. Run
`scripts/verify_effect_crash_campaign.py`; it validates the signed envelope,
strict schema, five checkpoints, and recipient/replay invariants. It does not
rerun the experiment. INCOMPLETE attempts remain explicitly marked.

No prior v4 Firecracker reports are modified. [Issue #34](https://github.com/solsticeaistudio/event-horizon-harness/issues/34)
remains open for the next full **guest-to-host plus guardian signer** experiment.
