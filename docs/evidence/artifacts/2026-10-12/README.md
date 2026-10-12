# Original integrated isolated-authority evidence - 2026-10-12

This directory publishes the original successful operator-owned WSL2 experiment
report and its original checksum, copied byte-for-byte after verification.
Publication did not rerun the experiment or modify its artifacts. Prior
`INCOMPLETE` reports remain local and unchanged.

**Attestation is synthetic. Evidence is internally signed using public keys
embedded in the report. There is no independent external witness, and this is
not independently witnessed hardware attestation.** Signatures and hash chains
establish internal integrity, not a trustworthy host or independently established
signer identity.

| Item | Value |
|---|---|
| Original JSON | [package-etcd-20261012T011216Z-22743-isolated-authority.json](package-etcd-20261012T011216Z-22743-isolated-authority.json) |
| Original checksum | [SHA-256 sidecar](package-etcd-20261012T011216Z-22743-isolated-authority.json.sha256) |
| SHA-256 of both original and published JSON | `01c39b20a09ba389f509eb77e591c7bbc5f5f8062413d04237e082bee858f9bb` |
| Actual experiment source commit | `8f0ef678540d282f8b8b9aa1f67e8950fb0d5add` |
| Publication base | `8c522fd9285d9cf6ad295fa97e93e863fa7e94f2`, merged PR #31 |
| Schema / result | `event-horizon.package-isolation.v4` / `PASS` |
| Execution | Three real Firecracker/KVM guest-root sessions: vulnerable, protected, protected |
| Authority | Four guardian processes, protected signer and coordinator under six distinct Linux UIDs |
| Distributed consumption | Three disposable etcd v3.6.0 members; actual cluster `12446301901540137953` |
| Host kernel | `6.6.87.2-microsoft-standard-WSL2` |
| Attestation | `synthetic-fixture`, TPM2 disabled |

## Verified assertions

The existing v4 verifier passed on the original and published JSON. It checks
three signed event chains, receipts, four-guardian approval relationships,
capability signatures, request/policy/build bindings, required negative controls,
paired effects, etcd observations and teardown assertions.

Each round records 24 authority controls, six additional actual guest/gateway
fault controls, successful approved retrieval, recipient verification and replay
rejection. The five forbidden fixture effects occurred in the vulnerable control
and not in either protected round, using the same worker binary. The two later
rounds also rejected a capability from the previous session.

**Each round has one primary consumption and one useful handler dispatch, but
two total etcd consumptions.** During majority loss, the separately approved
probe token committed after the client timeout without effect dispatch. A
post-recovery linearizable read confirmed that binding; the probe token was not
retried. A different approved capability succeeded with one member paused, and
recovery did not resurrect consumed authority. A timeout alone is not evidence
that consumption or an effect did not occur.

The detailed [validation record](../../2026-10-12-integrated-authority-validation.md)
was written before raw-artifact publication; its statements about unpublished
files describe that earlier stage. See the [integration architecture](../../../INTEGRATED_ISOLATED_AUTHORITY.md)
for interfaces and the trusted-host assumptions.

## Content inspection and preservation

Publication review recursively inspected all 31,185 JSON nodes, 315 distinct
field names and 1,031 distinct string values, including the signed transcripts
and service audit records. Review covered private-key markers, credential/token
patterns, sensitive field names, contact information, user-home paths, public
cryptographic material and the distinct human-readable values. No private keys,
real credentials or personal information were found. This review is not an
independent security audit.

The report intentionally retains public keys, signatures, expired experiment
capabilities, challenges, synthetic fixture labels, ephemeral `/var/tmp` paths,
Linux UIDs/PIDs, container identifiers, and host/build metadata. The
`credential_reuse` field describes the fake-credential fixture, not a real
published credential. No redaction, normalization or reformatting was performed.
Both the JSON bytes and sidecar bytes were compared exactly against the originals.
All pre-existing local reports and published artifact files were hash-checked
against a pre-publication snapshot and left unchanged.

## Verify without running an experiment

From the repository root with the project's Python dependencies installed:

```bash
(cd docs/evidence/artifacts/2026-10-12 && \
  sha256sum -c package-etcd-20261012T011216Z-22743-isolated-authority.json.sha256)
python scripts/verify_package_isolation.py \
  docs/evidence/artifacts/2026-10-12/package-etcd-20261012T011216Z-22743-isolated-authority.json
```

Remaining limits include a trusted host/root, recorder, gateway, kernel/hypervisor
and etcd installation; no independent hardware provenance; no tested interruption
after effect dispatch; and no comprehensive supervisor SIGKILL, host-crash,
power-loss, concurrent-tenant, rollback or unrestricted adaptive-attacker result.
The tested interruption closes the watchdog control channel. Endpoint shutdown
is not a global capability-revocation mechanism.
