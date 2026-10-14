# Consensus-backed fenced effect journal (prototype, stacked PR #70)

**Status:** source/portable and disposable real-etcd tests. **Not yet a
physically distributed, fault-independent deployment**. Requires draft PR
#69's mutually authenticated remote recipient.

## Why the additional state machine exists

The remote TLS recipient in #69 already deduplicates its own **cooperating
atomic SQLite effect**, but one trusted gateway still owns a local SQLite
reservation journal. Moving that gateway to another host without the original
journal would lose provenance and could lead to incompatible authorization.

`EtcdFencedEffectJournal` is a separate, explicit, host-trusted
consensus-backed reservation/confirmation implementation. It never deletes,
expires or leases effect reservations. Its etcd namespace and **cluster ID
MUST be identical** on every participant.

## Transaction design

1. After verifying/consuming the request's actual Ed25519 capability via an
   independent **shared etcd replay domain**, every gateway attempts a
   single etcd v3 Txn comparing both:
   `VERSION(effect_key)==0` AND `VERSION(capability_id_index)==0`.
2. A successful Txn atomically writes both keys, with fixed
   `tenant`, `environment`, `effect_key`, original
   `capability_id`, original claims/request digests,
   `fenced_protocol=atomic-sqlite-v1`, pinned `recipient_id`,
   output digest, `state=possibly-committed`. Distinct effects cannot
   reuse a capability ID within the same tenant/environment.
3. A losing gateway reads the original canonical reservation plus the
   corresponding original capability index via linearizable etcd Txn.
   It may continue **only** with a fresh independently signed and consumed
   capability and exact identical request/recipient/output bindings.
   Original capability identity never changes. Collision in capability
   ID, output, request, recipient, protocol or persisted index fails closed.
4. The separate recipient's **atomic business-effect/unique-idempotency
   transaction** is the actual at-most-once boundary. The gateway demands
   the same positive receipt from `apply` and independent `observe`.
   A negative or missing observation is never permission to clear a fence.
5. The gateway confirms receipt with a CAS on `MOD(effect_key)`.
   An ordinary, positively established CAS loss may re-read and verify the
   immutable record and positive receipt; a network timeout, truncated Txn
   response or unknown commit is raised immediately and **never auto-retried**.
   Duplicate confirmation of the **same** receipt is idempotent; a different
   receipt or original authority is rejected.

This does NOT make arbitrary payment, email or HTTP requests exactly once.
It only provides an authorization/fence mechanism for a cooperating recipient
whose *business effect and dedupe row are the same durable transaction*.

## Configuration / explicit gateway opt-in

The preexisting `scripts/fenced_tls_gateway_worker.py` supports two exact
non-overlapping config schemas. The legacy trusted single-host mode retains
`journal_path` and `replay_path` and uses SQLite. Distributed mode
**forbids** both local database keys and requires:

```json
{
  "etcd_cluster_id": "PINNED_NUMERIC_ETCD_CLUSTER_ID",
  "etcd_namespace": "your-reviewed-effect-domain",
  "etcd_gateway": {
    "endpoint": "https://etcd-internal.example:2379",
    "ca_file": "/etc/ehh-private/etcd-ca.pem",
    "client_cert_file": "/etc/ehh-private/etcd-client.pem",
    "client_key_file": "/etc/ehh-private/etcd-client.key",
    "timeout_seconds": 2.0
  }
}
```

These **replace**, rather than supplement, `journal_path` and
`replay_path` within the existing fully signed private gateway JSON config.
All other mandatory fields remain: `public_key_pem`, `key_id`,
`request`, `capability`, `verification_context`, `tls_recipient`,
`recorder_path`, `output`. Config includes actual signed verifier context
(`tenant`, `environment`) and the pinned recipient TLS parameters from #69.
No credentials or private IP routes belong inside the Firecracker guest.

Same `etcd_cluster_id`, `etcd_namespace`, `domain=effect-fence`
and `domain=external-effect` must be shared on every gateway. The
separate two domains store journal and capability consumption records
respectively; both depend on the same real quorum. Remote etcd requires
HTTPS + client certificate; insecure HTTP may only be opted in for
127.0.0.1 disposable lab traffic.

**NEVER** restore, bootstrap, wipe, change etcd cluster identity or point
at production etcd as part of a recovery trial. A restoring operator must
reconcile any potential historical rollback out-of-band; pinning the cluster
ID alone cannot detect an operator-controlled snapshot rollback.

## Test pyramid and explicit limits

- `python -m unittest tests.test_etcd_fenced_effect_journal -v`: fake
  linearizable state-machine unit tests for first-writer races, replays,
  collisions, missing/corrupt indexes, lost reserve/confirm ACK, lost
  quorum, changed cluster identity, same-receipt confirmation, and signed
  gateway replay rejection.
- `python -m unittest tests.test_etcd_effect_journal_live -v`: opt-in
  **actual etcd** tests requiring `EHH_ETCD_ENDPOINT` and a pinned
  `EHH_ETCD_CLUSTER_ID`. CI provisions *disposable* three-member Docker
  quorum on loopback, then tests one-node loss and majority loss separately.
- The tests do **not** demonstrate three physical failure domains, a
  separate physical gateway/recipient pair, power-off durability, signed
  independent etcd rollback witness, Byzantine corruption resistance,
  or exactly-once arbitrary external side effects.

For physically independent failover, place three etcd voting members in
three independent failure domains, deploy two distinct trusted gateway hosts
configured with the same pins, and preserve the cooperating recipient's
independent durable disk. Two laptops do not provide three independent etcd
failure domains; a third separate server/node is needed to claim safe quorum
survival of *either* laptop disappearing.

Keep PR #70 a draft until real two/three-host trials, provenance and
publication of exact JSON+SHA256 reports and independent verification.
