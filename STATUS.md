# Event Horizon Harness — verified engineering status

This is a **research harness**, not a production containment product or a
third-party security certification. The [GitHub Actions workflow](https://github.com/solsticeaistudio/event-horizon-harness/actions/workflows/ci.yml)
is the source of truth for tests on the exact commit under review. Do not
reuse historical test counts as current verification.

## Tested baselines and evidence

- **Last established seven-process integration baseline:** commit
  `52bb5aa8df6cb788e4eb8565c68b8b3f6646cd12` (draft PR #6),
  [three-job CI PASS](https://github.com/solsticeaistudio/event-horizon-harness/actions/runs/38015116507):
  Python 3.11 ran **289 tests, 285 passed, 4 skipped**; Node/TypeScript
  and integration/repository-policy jobs also passed.
- The same baseline passed a [disposable three-node etcd quorum
  run](https://github.com/solsticeaistudio/event-horizon-harness/actions/runs/38015119518).
  It exercised signed nonce, capability, authorization replay, checkpoint
  continuity, seven-process integration, two-node majority, quorum loss,
  and fail-closed execution when the trusted replay backend was unavailable.
  The run exported signed coordinator observations; a separately pinned
  recorder identity is needed to authenticate their issuer.
- **This hardening branch:** adds deterministic signed revocation-chain tests
  and documentation cleanup. Its precise pass/fail count must be taken from
  the *latest workflow on this branch*, not the historical 289-test baseline.
- **Historical Linux/KVM experiment:** the [documented Firecracker
  setup](docs/LINUX_ISOLATION.md) was exercised on a particular WSL2/Ubuntu
  24.04.3 host in September 2026. This is not verification of the current
  distributed-authority revision, which has **not** yet passed a new KVM
  integration run. Production isolation and independent escape review remain
  unproven.
- The [TLA+ state-machine model](formal/EventHorizon.tla) includes
  lifecycle properties such as at-most-one committed effect and consumed
  capabilities not being reissued. Some subset invariants follow
  definitionally from the set intersection. **The model does not yet
  represent distributed replay-store rollback/restoration, etcd partitions,
  or actual host/kernel effects.** No new TLC claim is made by this branch.

## Current architecture

- Exact Ed25519 capability/request bindings and guardian unanimity
  enforcement are central to the normal software harness.
- Trusted signer, recorder, certificate service, and Node attestation
  verifier can share one signed replay authority. Its etcd backend commits
  nonce, capability, authorization and chained checkpoint transitions
  atomically. See [full seven-process test](docs/SEVEN_PROCESS_REMOTE_AUTHORITY.md).
- The host-side Firecracker dataset effect gateway has been wired to signed
  capability verification in the stacked branches, but full distributed
  authority + guest-root Firecracker testing still needs a supported KVM host.
- HSM-backed key-manager signing is configured to fail closed on HSM
  outages. Actual PKCS#11 device interoperability and key rotation need
  independent hardware validation.
- The **legacy** `raft_replay.py` is disabled for production proposals;
  `raft_core.py` is a separately labeled research-only fixed-membership
  laboratory. Real quorum-backed authority testing uses etcd, not custom
  Raft.
- `production_attestation.py` validates enrolled Ed25519-signed claims;
  its `tpm2` identifier **does not establish a TPM quote or PCR
  verification**. The TypeScript TPM verifier is distinct and does not
  establish fleet enrollment/hardware endorsement in these CI experiments.

## Known gaps before making stronger claims

1. Independent review of the trust-critical issuer/broker, replay transitions,
   protected request signer, host effect gate, verifier, and evidence recorder.
2. Reproduction on a fresh KVM-capable Linux host with root-compromised guest
   and independently captured host-side effect/access observations.
3. Reproducible signer/cluster credential provisioning, independently pinned
   witness/recorder identity, revocation rollback detection and audited
   recovery/epoch promotion.
4. Stronger formal specification of crash, partition, restore/rollback,
   cross-domain effects, client persistence and fail-closed decisions.
5. Separate primary deployment trust identities from simulated/test fixtures,
   verify production TPM quote generation and endorsement roots, and complete
   operational security hardening.

## Reproduce the checks

```bash
npm ci
npm run build
python -m pip install -e ".[test]"
python scripts/lint_python.py
python -m unittest discover -s tests -v
python scripts/check_repository_policy.py
```

CI adds the TypeScript suite, end-to-end demo, signed evidence verification,
cross-language replay interop, and real etcd quorum tests. Check the exact
commit SHA of the workflow before quoting results.

See [known limitations](KNOWN_LIMITATIONS.md),
[Linux isolation](docs/LINUX_ISOLATION.md),
[atomic signed replay](docs/ATOMIC_SIGNED_ETCD_REPLAY.md), and
[seven-process integration](docs/SEVEN_PROCESS_REMOTE_AUTHORITY.md).
