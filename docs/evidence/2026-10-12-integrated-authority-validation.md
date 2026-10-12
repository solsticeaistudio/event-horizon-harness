# Integrated isolated authority validation ? 2026-10-12 UTC

**Status: real local Firecracker/KVM + etcd execution passed. Raw evidence is
preserved locally and is not published by this feature PR.**

Four separately owned guardian processes and a protected signer authorized the
actual session-bound package retrieval subsequently executed by the real guest.
The host gateway used real etcd for one-use consumption before effect dispatch.
This is an integrated execution, not a concatenation of separate lab results.

**Attestation remains synthetic. Embedded public keys and internal signatures
establish integrity, not independently witnessed hardware provenance.**

## Run identity

| Item | Recorded value |
|---|---|
| Inspected base | `e13160b55af2b4c3eda93b8e8a10b0026573c80f` |
| Actual experiment source commit | `8f0ef678540d282f8b8b9aa1f67e8950fb0d5add` |
| Mode / schema / result | `isolated-authority-firecracker-etcd` / `event-horizon.package-isolation.v4` / `PASS` |
| Host | Owned Ubuntu 24.04 / WSL2, x86_64; kernel `6.6.87.2-microsoft-standard-WSL2` |
| Execution | Three real Firecracker v1.15.1 guest-root sessions; KVM; synthetic attestation; TPM2 disabled |
| Guardians | Behavioral transition UID 64001; executor attestation 64002; lineage/budget 64003; static policy 64004 |
| Signer / coordinator | UID 64010 / UID 64020; all six roles in separate empty network namespaces |
| VM / compromised worker | Host UID 60000 / 60001; guest reports UID 0 |
| etcd | Three disposable v3.6.0 Docker members; actual cluster `12446301901540137953` |
| etcd image ID | `sha256:3f179425019536765a47fecff29221ed4453a4f4e91aa33e21e1a2326079ad9e` |
| Original JSON | `artifacts/reports/package-etcd-20261012T011216Z-22743-isolated-authority.json` |
| Original checksum sidecar | Same path with `.sha256` appended |
| Original SHA-256 | `01c39b20a09ba389f509eb77e591c7bbc5f5f8062413d04237e082bee858f9bb` |
| Publication | This summary and source only; original JSON and sidecar remain untracked locally |

Each guardian generated its own private key inside its process. The signer
held the capability private key. Only public pins crossed the trusted startup
pipes. The report binds the source commit and prepared asset hashes through its
signed context's authority-attachment digest. It records individual guardian and
signer public-key fingerprints, approvals, challenges, exact request/policy
bindings and signed capabilities.

## Observed results and evidence paths

Paths below are relative to the original JSON root; `r` means `rounds[i]`.

| Check | Vulnerable round 0 | Protected round 1 | Protected round 2 | Evidence path |
|---|---|---|---|---|
| Legitimate retrieval and recipient digest | Pass | Pass | Pass | `r.observations.package.trusted_recipient_digest_verified` |
| Authority campaign | 24 controls passed | 24 controls passed | 24 controls passed | `r.isolated_authority.scenarios` |
| Actual guest fault campaign | 6 denials | 6 denials | 6 denials | `r.observations.integrated_gateway.scenarios` |
| Baseline guest invalid requests | 4 denied | 5 denied | 5 denied | `r.observations.denied_cases` |
| Replay before/after quorum recovery | Denied | Denied | Denied | `r.observations.replay_denied`, integrated scenarios |
| Wrong UID authority socket | Refused; healthy authorized call followed | Same | Same | `r.isolated_authority.wrong_uid`, authorization and service audit |
| Useful effect dispatches / primary consumptions | 1 / 1 | 1 / 1 | 1 / 1 | `r.observations.integrated_gateway.dispatches`, `authority_oracle.primary_record_count` |
| Total session consumptions | 2 | 2 | 2 | `r.observations.authority_oracle.record_count` |
| etcd final revision / Raft term | 3 / 2 | 5 / 2 | 7 / 2 | `r.observations.authority_oracle` |
| Five forbidden fixture effects | All observed | None observed | None observed | `r.observations.package.forbidden_effects` |
| Teardown trigger | Requested stop | Requested stop | Supervisor control-channel closure | `r.teardown` |
| Process groups, scratch, endpoints and authority services removed | Verified | Verified | Verified | `r.teardown`, `r.isolated_authority.process_cleanup`, `temporary_paths_removed` |

The 24 pre-guest controls cover forged, missing, duplicate, modified and swapped
approvals; guardian veto; expired/reused challenge; different request/resource;
expanded arguments/output/budget; network operation; executor, attestation,
policy and signer-key substitution; direct broker RPC bypass; signer config and
process-memory reads; guardian/signer unavailability with healthy recovery; and
issuance-budget exhaustion. These attempts never invoked a guest or handler.
Three successful independently approved issuances provide positive controls;
the signer's private audit permits exactly those three issuances.

The six actual guest controls are resource substitution, executor substitution,
output-ceiling expansion, signer-key substitution, majority loss and replay
after majority recovery. Signed primary gate denials appear between the host's
attack/result events without intervening dispatch/completion events. Missing or
forged capabilities, altered arguments, forbidden operations, ordinary replay,
and previous-session tokens retain the original package lab controls.

The quorum-loss injection paused two actual members before sending a separately
authorized probe capability. The gateway refused dispatch when its etcd call
timed out. **The token nevertheless committed after recovery in all three
rounds.** A subsequent linearizable read established the exact capability/claim
binding. This is why total consumption is two while useful consumption is one.
The probe token was not retried. A different approved token then completed the
useful action while one member was paused. Restoring the quorum did not enable
replay. A timeout by itself was never treated as proof of non-consumption.

The worker binary was identical in all rounds:
`36592dc743d59151f289ff373e59ba797efcee030ccd91e0db48ee8a076a65bc`.
The five vulnerable effects are synthetic relay, fake-credential reuse,
cross-session fixture message, durable shared state and evidence-canary tamper.
Their absence in protected modes is attributed to the tested OS/package
boundaries, not solely to guardian authorization.

## Validation performed

- Final Python suite: **372 tests run, 367 passed, 5 skipped, 0 failures/errors**.
- TypeScript suite: **62 passed, 1 real-TPM test skipped**; all workspace builds
  passed. Canonical cross-language vectors (25) and replay interoperability passed.
- Python lint, fixed capability vectors (8), and repository artifact/secret policy
  passed. Existing published package evidence still verifies unchanged.
- Real AF_UNIX portable authority campaign passed; it makes no distinct-UID claim.
  Three standalone distinct-UID Issue #30 trials also passed all nine original
  coordinator controls. The Issue #30 fix is in its own commit `631ed1e`.
- Full v4 verifier and original SHA-256 sidecar passed again after execution.
  All three signed event chains and the isolated signer/guardian relationships
  were checked against the report's embedded public keys.
- Fourteen in-memory mutations of the original were rejected: missing authority
  control, changed approval, changed capability, substituted signer pin, missing
  guest control, extra dispatch, changed cluster, changed consumption, missing
  cleanup, incomplete status, missing round, reversed event chain, invented
  hardware attestation and hidden vulnerable effect. Original bytes were untouched.
- Separate host inspection found no remaining PIDs for the run's authority
  services, no authority temporary directories, and no containers/network for
  this run. Its three cgroups were removed. One empty cgroup from October 10
  predates this work and was left untouched.
- Private-key/credential pattern inspection found no matches. This is not a
  comprehensive secret audit or approval to publish the raw report. Reports
  contain public signed capabilities, ephemeral paths and process metadata.

Five preceding development attempts remain local, labeled `INCOMPLETE`: aggregate
canonicalization depth, guest deadline during quorum loss, late consensus
consumption, safe underscore handling in tempfile identities, and transient
leader election before the healthy control. None is counted as a passing run;
none was overwritten. The final run follows the fixes recorded in Git history.

## Verify locally or reproduce independently

Verification does not rerun the experiment:

```bash
cd ~/event-horizon-harness
(cd artifacts/reports && sha256sum -c \
  package-etcd-20261012T011216Z-22743-isolated-authority.json.sha256)
/var/tmp/event-horizon-isolation-venv/bin/python scripts/verify_package_isolation.py \
  artifacts/reports/package-etcd-20261012T011216Z-22743-isolated-authority.json
```

For an independent run, use a separate checkout of the exact experiment commit,
complete [KVM preparation](../LINUX_ISOLATION.md), provide working Docker and
sudo access, then run `bash scripts/run_package_etcd_lab.sh --isolated-authority`.
The launcher creates a new disposable quorum and fresh immutable report paths.
It never imports this run's cluster ID or generates a simulated KVM success.
See [architecture and interfaces](../INTEGRATED_ISOLATED_AUTHORITY.md).

## Limits and next steps

| Priority / boundary | Remaining limit | Concrete next step |
|---|---|---|
| High for production trust | Trusted root supervisor, kernel/hypervisor, gateway, recorder and etcd can falsify local observations; synthetic attestation and embedded keys provide no independent provenance | Independently reproduce, pin reviewer-trusted keys, and design external witnessing or real attestation before making hardware trust claims |
| High for generalized effects | Faults were injected before dispatch; interruption after effect dispatch and recovery of uncertain effects remain untested | Add a separately scoped effect-lifecycle campaign with a durable recipient-side outcome oracle; never infer non-execution from timeout |
| Medium, lifecycle | Watchdog channel closure and managed teardown passed; arbitrary supervisor SIGKILL, host crash and power loss were not established | Exercise process death at each setup/execution stage and add a separately supervised authority cleanup mechanism |
| Medium, scope | One host, deterministic requests, no concurrent tenants, rollback resistance, arbitrary adaptive attacker or comprehensive covert-channel analysis | Extend these controls independently before deployment claims |
| Medium, authority availability | Three bounded issuances per session; a token may be consumed without an effect; unused tokens retire by endpoint shutdown, not global revocation | Model cancellation/reconciliation explicitly before supporting retryable remote effects |

No production infrastructure was used. No prior published report/checksum was
modified. Raw integrated evidence publication and any independent attestation
claim require separate review.
