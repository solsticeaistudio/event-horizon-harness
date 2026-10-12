# Post-hardening integrated authority experiment — 2026-10-12

This directory publishes the **original, unmodified** operator-generated JSON
report and original SHA-256 sidecar for a successful post-hardening WSL2
Firecracker/KVM + three-node etcd experiment. Publication did not rerun or alter
the experiment.

| Item | Value |
|---|---|
| Report | [package-etcd-20261012T190952Z-27747-isolated-authority.json](package-etcd-20261012T190952Z-27747-isolated-authority.json) |
| Checksum | [Original SHA-256 sidecar](package-etcd-20261012T190952Z-27747-isolated-authority.json.sha256) |
| JSON SHA-256 | `c26448ae11cefe1ca5337ba3600043f5b120ad9c666d78e6c1ba181c69f3aa01` |
| Experiment source commit | `4b2161157c9c78bcd127c8850d32ceb47e249b03` (current merged main at experiment time) |
| Report status/schema | `PASS` / `event-horizon.package-isolation.v4` |
| Experiment mode | `isolated-authority-firecracker-etcd` |
| Platform | WSL2 Linux kernel `6.6.87.2-microsoft-standard-WSL2`; actual Firecracker/KVM |
| etcd cluster | Three disposable members; cluster ID `2781485560237644177` |
| Attestation | `synthetic-fixture`; TPM2 disabled |

## What was observed

The experiment reports three real guest-root sessions (vulnerable,
protected, protected) with four independently keyed guardian processes,
a protected signer, coordinator UID isolation, a trusted gateway and etcd
authority consumption. The same five synthetic forbidden effects occurred
in the vulnerable control but none in either protected session.

Each session recorded **one useful effect dispatch**, **one primary capability
consumption**, and **two total etcd consumptions**. A separate quorum-loss
probe token was consumed despite its timeout, was observed via a
post-recovery linearizable read and was **not retried**. The six additional
guest/gateway attack scenarios per session were denied; there were 24
pre-guest authority controls per session. This report is not evidence that
timeout implies non-consumption or that an external effect is exactly-once.

This run was executed from `4b2161157c9c78bcd127c8850d32ceb47e249b03`, which includes the signer
ceiling hardening from PR #33 and the opt-in durable-effect journal from
PR #35. **The original integrated runner did not exercise the opt-in
durable journal or post-dispatch crash/recovery campaign.** Those remain
separate experiments under [Issue #34](https://github.com/solsticeaistudio/event-horizon-harness/issues/34).

## Trust and disclosure

**Attestation is synthetic. Evidence signatures are internally verifiable
using keys embedded in the report. There is no independent external
witness or independently witnessed hardware attestation.** The root host,
kernel/hypervisor, effect gateway, recorder and etcd were trusted during
the run. An operator-managed host could falsify local observations.
This is evidence of this specific bounded experimental configuration,
not production certification.

Content review of the complete uploaded report included all 31,185+
JSON nodes and checked sensitive field names, private key markers,
credential patterns, contact details and home-directory paths. No
private keys, real credentials or personal information were identified.
Public keys, signatures, expired lab capabilities, ephemeral `/var/tmp`
paths, UIDs, PIDs, container IDs, build hashes and synthetic fixture
metadata remain intentionally unredacted. This screening is not an
independent security audit.

The original earlier integrated experiment remains published separately
under [2026-10-12](../2026-10-12/README.md), with historical source
revision `8f0ef678540d282f8b8b9aa1f67e8950fb0d5add`
tagged `evidence-2026-10-12`. Neither historical report was modified.

## Verify without running the experiment

From the repository root, with project dependencies installed:

```bash
(cd docs/evidence/artifacts/2026-10-12-post-hardening && sha256sum -c package-etcd-20261012T190952Z-27747-isolated-authority.json.sha256)
python scripts/verify_package_isolation.py docs/evidence/artifacts/2026-10-12-post-hardening/package-etcd-20261012T190952Z-27747-isolated-authority.json
```

The report was generated and originally verified by the operator; the
JSON and sidecar were independently byte-checked during this publication
against their uploaded originals. No Firecracker experiment was rerun
for publication. Independent reproduction and a hardware-rooted
attestation are outstanding.
