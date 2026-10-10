# Host gateway and signed adversarial evidence: software-only integration

**Status:** host-side effect boundary integration plus CI-tested authority failures
and signed synthetic observations. The full distributed replay state machine,
hardware isolation, and independently pinned issuer trust remain open.

This increment exercises the actual EHH effect boundary used by the
Firecracker and compromised-package laboratories without requiring KVM on CI.

## Trust boundaries

The **Firecracker guest** sends only `{"request": ..., "capability": ...}` to
the existing vsock-to-host effect service. It has no backend selection field,
etcd client credentials, arbitrary code callback, network destination, signer
key or evidence key. The **host-owned effect service** checks peer UID, session,
fixed resource, read offset/length and the signed capability via
`TrustedEffectGateway`. It records authorization before invoking a fixed,
host-defined `object.read` implementation. It reports any uncertain effect
as `possibly-committed` and does not retry consumption or the effect.

The host config chooses `authority_backend`:

- **SQLite** (default in the legacy Firecracker lab): a durable local replay
  database within the trusted host's existing authority directory.
- **etcd**: `authority_backend: "etcd"`, host-only `etcd_gateway` settings
  matching `EtcdGatewayConfig`, and an out-of-band pinned
  `etcd_cluster_id`. Public network transport requires CA/client TLS keys;
  the explicit plaintext-loopback override is ONLY for disposable CI.

An invalid or unavailable selected backend denies authorization: it must
never fall back to SQLite or in-memory consumption. The guest wire protocol
cannot override these settings. The existing Firecracker runner uses SQLite;
an etcd deployment requires provisioning a secured host-side etcd cluster
and host config **without** passing secrets to the VM or package worker.

This is capability-replay consensus only. **Attestation nonce replay,
protected request authorization and the signed epoch/checkpoint protocol are
not yet committed atomically in etcd**. Until that work is complete, EHH's
full seven-process orchestrator is NOT a distributed EHH authority and an
etcd receipt is NOT a signed replay checkpoint.

## CI tests — no KVM needed

The ordinary Python CI tests:

- Signed synthetic read dispatched once through `DatasetEffectBoundary`;
  replay denied through multiple launches against durable SQLite state.
- Tampered arguments, cross-session access, wrong transport principal and
  attacker-chosen backend fields denied without granting a second effect.
- Pre-effect recorder outage burns the capability without dispatch.
- Explicit etcd quorum error injected at the host boundary refuses dispatch,
  with no local fallback.
- Multi-step synthetic seven-process adversarial run exports signed recorder
  event entries and exact observations. Independent verifier rejects edited
  observations, forged receipts, truncation, false PASS and key tampering.

The **disposable etcd-quorum CI** starts three real etcd 3.6 members and tests
identical Ed25519 capability redemption through multiple host gateways.
Exactly one of 24 competing attempts should dispatch. The test is repeated
with one member stopped. After the second failure, the minority must refuse
a new gateway effect. The job uses loopback-only plaintext in disposable CI,
not production transport.

## Run the signed synthetic experiment locally

From the checked-out repository, with project/attestation dependencies built
as required by the normal CI workflow:

```bash
python -m event_horizon.adversarial_boundary \
  --workdir .demo/adversarial \
  --output .demo/adversarial/report.json

python scripts/verify_adversarial_boundary.py \
  .demo/adversarial/report.json
```

The report includes **every recorder event and its Ed25519 receipt**;
the separate verifier checks event hashes, source and global sequences,
receipt signatures, chain tip, recorded observations and whether PASS
matches the signed decisions.

The report embeds the signer public key. This establishes internal integrity
only, not independent authenticity. An external reviewer can pin a PEM
recorder key obtained independently and run:

```bash
python scripts/verify_adversarial_boundary.py \
  .demo/adversarial/report.json \
  --pin-recorder-key reviewer-pinned-recorder.pem
```

A successful software-only report explicitly declares
`hardware_isolation_tested: false` and `etcd_backend_tested: false`;
the latter refers to this seven-process report, not the separate live etcd
CI. GitHub CI publishes the synthetic report and raw evidence stream as
the `eh-adversarial-evidence` build artifact.

## KVM stage: still a required independent experiment

The repository already has
[Linux Firecracker](LINUX_ISOLATION.md) and
[compromised package-worker](PACKAGE_ISOLATION.md) experiments, using
external watchdogs and trusted host observations. This commit changes the
host dataset effect service they use, so the real hardware suite needs
**fresh validation** on Ubuntu 24.04 x86_64 with KVM; prior hardware reports
are not evidence that this revision passed.

The next release gate is: (1) complete a signed atomic distributed replay
state-machine that includes capability, nonce, authorization, checkpoints;
(2) retest both KVM topologies with host-side effect observations;
(3) obtain externally pinned evidence/independent KVM attestation if claiming
third-party authenticated containment. Neither API-level tests nor embedded
signing keys alone prove VM escape resistance, host-kernel integrity,
record completeness or freedom from covert channels.
