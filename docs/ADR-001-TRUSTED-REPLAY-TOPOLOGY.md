# ADR-001 — Trusted Replay Authority: from isolated tests to EHH containment

Status: **Proposed (not implemented)**  
Applies to: Options A (SQLite) and B (etcd) from [AUTHORITY_BACKENDS.md](AUTHORITY_BACKENDS.md)  
Purpose: Preserve EHH's trust and atomicity boundaries while using distributed
consumption authority inside the actual process harness.

## Context and discovery

The seven-process development harness in `process_harness.py` currently
constructs signer and executor roles with **distinct**
`SqliteCapabilityConsumptionStore` databases/domains in `service.py`. The
attestation verifier and protected RPC authorizers also use SQLite-based
nonce/authorization replay. The etcd adapter in `authority_backends.py`
implements only the `CapabilityConsumptionStore` interface. It is **not**
wired into the seven-process harness.

`ReferenceReplayService.handle()` currently commits the replay transition
AND the monotonically increasing signed checkpoint in **one SQLite
transaction**. Swapping just the consumption persistence to etcd would
split these two facts across separate transactions, making the checkpoint
an unreliable witness. Do not present such a split as an atomic authority.

The executor is explicitly part of the compromised workload threat model.
Giving the executor direct etcd access, an etcd client certificate or a broad
etcd write token would convert workload compromise into authority compromise.

## Decision

1. Implement an independently hosted **Trusted Replay Authority (TRA)**.
   Only the TRA holds etcd client credentials or the private SQLite database
   volume. Signers and enforcement gateways use a narrow, authenticated
   replay RPC. The workload executor holds no authority-store credentials.
2. Keep the Option A and Option B authority semantics identical: a
   `(namespace, consumption_domain, capability_id)` can transition from
   unused to consumed at most once, with collision rejection, tombstones that
   are not automatically expired, and fail-closed behavior on unknown outcome.
   Distinct enforcement domains remain distinct; all replica identities
   within one enforcement domain must share the **same** authoritative key
   space (never per-server replay stores that can each accept independently).
3. Preserve the existing signed envelope and pinned signer/public keys for
   replay requests/responses. All requests specify operation, domain,
   request digest, and bounded expiry. The server enforces an explicit
   allowlist of authenticated callers and permitted domains; neither client
   identity nor a bearer capability confers carte-blanche direct DB access.
4. For Option A, issue the complete transition and signed checkpoint from
   one durable SQLite transaction. For Option B, move **both** the replay
   state-machine transition and checkpoint/chain-tip update to **one** etcd
   compare-and-swap transaction. Do not sign a success receipt that cannot be
   tied to the *same* committed transaction.
5. Process denial, mutation, crash recovery and proof emission at the
   trusted host/gateway. No infrastructure error falls back to local
   memory or to a second independent replay store. Any ambiguous response
   means **no new external effect** until authority is reconciled.
6. Keep `raft_replay.py` quarantined. The new fixed-membership
   `raft_core.py` is a research fault lab only; it must not be used as
   the TRA deployment backend. Production Option B delegates Raft to etcd.

## Target trust topology

```text
 untrusted model / compromised executor
         |
         | constrained action proposal (no etcd credentials)
         v
 trusted effect gateway / capability verifier
         |
         | Ed25519-authenticated, scoped replay RPC
         v
 TRUSTED REPLAY AUTHORITY (trusted administrative domain)
         |                  |
     Option A            Option B
  protected SQLite    restricted etcd mTLS client
    atomic txn         one quorum-backed atomic txn
         |                  |
         +---- durable decision + checkpoint ----+
                               |
                     independently signed receipt
                               |
                    external effect may dispatch
                               |
                 independent evidence observation
 ```

The trusted effect gateway must also mediate outgoing side effects. A
compromised executor must not be able to bypass it with ambient network,
filesystem, or external-service credentials. Proving this physical boundary
requires the separate Firecracker/KVM host experiment, not the standard
same-account process demo.

## Mandatory acceptance tests (fail unless observed)

- [ ] **Real authority selected:** starter/demo explicitly selects SQLite
  or etcd and reports the backend and trust topology in evidence.
- [ ] **No credential exposure:** compromised executor's environment,
  config, mounts and namespace contain no etcd client certificate,
  authentication token, database path or authority signing key.
- [ ] **Concurrent redemption:** 100 concurrent attempts across *distinct*
  gateway replicas in the same domain grant exactly one authorization.
- [ ] **One-node loss:** live 3-member etcd retains availability with two
  healthy members, with accepted replay history preserved.
- [ ] **Quorum loss:** no gateway can grant a new authorization or external
  effect while the cluster has only one of three members.
- [ ] **Old leader:** routing clients to a stale leader cannot acknowledge
  authorization after the term changes.
- [ ] **Timeout after commit:** the gateway reports uncertainty, does not
  execute another effect, and reconciles through verified authority state.
- [ ] **Atomic checkpoint:** a process crash between committing a
  consumption and emitting its receipt cannot advance a signed checkpoint
  independently from the committed transaction.
- [ ] **Nonce and protected RPC:** attestation nonce-create/consume and
  protected-request authorization use the same selected TRA semantics;
  replay fails across restarts and gateway replicas.
- [ ] **Real adversarial trace:** a controlled synthetic compromised worker
  attempts replay, cross-domain use, credential discovery and direct
  egress. Trusted host observations classify every attempted effect.
- [ ] **Evidence verifier:** a separate process, using only public keys and
  exported artifacts, checks decisions, effect observations, chain continuity
  and explicitly stated unknowns.
- [ ] **Isolation boundary:** opt-in Firecracker/KVM run shows no direct
  executor network path to the TRA's etcd/SQLite write authority.

## Implementation increments

1. Extract a common *authority protocol* (nonce, authorization, capability,
   checkpoints) and test the signing/verification contract independently
   of storage.
2. Build TRA server adapters for SQLite and etcd, with atomic
   checkpoint transitions. **Do not re-use the current direct etcd
   capability adapter as a complete signed TRA without this work.**
3. Switch signer and effect gateway to authenticated TRA clients; leave
   executor without database credentials. Expose a strict backend selector
   and never silently fall back.
4. Integrate attestation and protected RPC replay into the selected backend.
   Document existing process-vs-physical isolation limitations.
5. Run live multi-process/multi-gateway quorum tests, recording host-side
   decisions and injected faults.
6. Integrate the isolated executor Firecracker experiment and ship a
   reproducible adversarial-run artifact with an offline verifier.

## Non-goals / claims not established

This ADR does not claim a working distributed seven-role harness,
an externally administered trusted authority, hardware-rooted attestation,
a production-ready Raft implementation, Byzantine-fault tolerance, or a
frontier-model containment result. Those claims require separate evidence.

**Release gate:** do not mark Option B as operational EHH distributed replay
until the selected authority is wired end-to-end and all mandatory tests
relevant to the target deployment are green.
