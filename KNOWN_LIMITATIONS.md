# Known limitations

Event Horizon Harness is a **research platform**, not a production
containment system. Its supported claims depend on which topology was
actually executed.

## Verified only in bounded software and KVM experiments

- The **default** run is same-host process separation, which cannot confine
  an adversary with host administrator authority. It is not a production
  microVM isolation boundary.
- A **historical separate** Firecracker/Ubuntu/WSL2 lab exercised root inside
  a restricted synthetic microVM. The updated distributed seven-process path
  has **not** yet been run under KVM or reviewed for VM escape resistance.
- The etcd replay authority uses its own trusted server clock for
  redemption/expiry decisions and bounds the incoming claimed timestamp.
  Service clock manipulation or skew beyond the configured tolerance fails
  closed; a compromised host clock is not within the demonstrated boundary.
  In-process per-client admission budgets and avoiding no-op checkpoint
  writes reduce, but do not eliminate, denial-of-service risks. Limits reset
  with a service restart and are not distributed across replicas.
- Distributed evidence format v2 derives seven execution outcomes from
  signed individual coordinator execution records, requires four signed
  structured coordinator probes, and binds an etcd ID/checkpoint snapshot to
  its evidence chain. It **does not** establish that the coordinator's
  observations were truthful or independently observed, nor cryptographically
  attest an actual etcd cluster. Historical v1 reports only authenticate
  coordinator PASS assertions. Independent signer pinning remains necessary.
- The recent seven-process CI runs use a real three-member etcd Raft cluster
  and a same-host signed HTTP authority. Real consensus is tested for
  capability, authorization and attestation nonce replay plus signed
  checkpoints. It is not an independently administered multi-host service.
  The effect executor retains a separate local replay/decay safety layer;
  external effects and local decay are not transactionally committed with
  etcd. Loss of quorum fails closed, sacrificing availability.
- A signed recorder report proves record/signature consistency under the
  provided recorder key; an independently pinned key is needed to authenticate
  the source. The report does not independently attest host-kernel behavior,
  effect completeness, absence of covert channels, or a truthful supervisor.
- Key/credential files belong to one trusted runner/user in the development
  process harness. A compromised host administrator, compromised signer,
  compromised etcd authority, or overwritten local checkpoint witness is
  outside the demonstrated trust boundary.
- The remote HTTP replay binding supports explicit TLS/mTLS, pins signer
  identity and disallows redirects. It does **not** establish production
  rate limiting, workload admission isolation, hardening against resource
  exhaustion, or robust disaster recovery.
- The `KeyManager` CRL is a locally signed, linear SQLite chain. It can
  detect tampering with retained entries. Without an externally pinned
  signed high-water checkpoint, a valid suffix could be deleted or restored
  without detection. Existing malformed historical chains must be
  investigated and repaired by an explicit operator migration, **not**
  automatically re-signed or silently accepted.
- An HSM-backed key-manager path fails closed on signing failures in the
  current stacked branch. PKCS#11 token compatibility, enrolled-key
  lifecycle, and HSM rotation are not demonstrated on physical devices.
- `production_attestation.py` verifies an enrolled Ed25519-signed claim.
  Its accepted string `tpm2` is merely a claimed method and does **not**
  provide TPM quote, PCR, endorsement, or boot measurement verification.
  The separate TypeScript TPM quote verifier does parse and verify
  attestation structures, but synthetic fixtures do not prove real hardware
  provenance or fleet enrollment.
- Four required guardians vote unanimously under an existing static policy
  ceiling. Tests use bounded scripted scenarios; adaptive model inputs
  cannot be assumed to discover all bypasses or establish absence of errors.
- Behavioral detection, canaries and per-capability decay are limited to
  modeled/synthetic paths. Decay is not currently a distributed monotonic
  session-wide clock shared with etcd.
- The formal TLA+ model covers a narrow single-capability lifecycle; some
  invariants are definitional set-subset statements. No sound formal proof
  of distributed rollback, partitions, restore, external effects, or host
  containment has been established.
- The old `raft_replay.py` implementation has an unsafe/incomplete Raft
  design and contains unsupported snapshot SQL. Proposal and cluster
  creation deliberately fail closed. The separately defined
  `raft_core.py` is a research-only deterministic testbed; **neither**
  is used as the production-suitable replay authority. The tested backend
  uses real etcd.
- The optional HTTP effect adapter uses preflight and commit, **not**
  a remote atomic two-phase commit. External writes require endpoint-side
  idempotency and uncertain-commit reconciliation. A failure should not
  be described as proof of no effect.
- No separate physical fail-safe, fully validated hardware TPM enrollment,
  independent security audit, or frontier-model containment proof exists.

## Claims and evidence

Tests are project-authored. A passing CI run is evidence for its exact
code revision, inputs, and environment, not a certification for future
changes. See [STATUS.md](STATUS.md) and
[seven-process signed replay](docs/SEVEN_PROCESS_REMOTE_AUTHORITY.md)
for reproducible tests and links.
