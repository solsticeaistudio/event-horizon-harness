# Signed etcd replay authority: atomic five-operation state machine

Status: **CI-tested implementation; not yet the complete seven-role EHH deployment.**

This module replaces the two-part "etcd capability consumption here, signed
checkpoint somewhere else" design with **one etcd transaction per signed
replay decision**. Its scope is the existing `remote_replay.py` authenticated
authority protocol, using an etcd-backed, cluster-wide implementation.

## What is now atomic?

Each signed, authorized transition (including a denied replay or nonce
inspection) commits in a **single etcd v3 Txn**:

1. A compare-and-swap of the global authoritative head's `mod_revision`.
2. An incremented head containing the checkpoint number and chained digest.
3. An immutable indexed checkpoint digest for pinned-client continuity.
4. The updated capability, authorization or nonce record when changed.

Every put succeeds together or none does. A CAS loser re-evaluates against
the newest head; an outage or ambiguous timeout **does not retry** and
**does not produce a signed accepted receipt**. Already-consumed capabilities,
authorization nonces, and attestation nonces are never automatically leased
away or deleted.

One global head serializes all changes; it is intentionally a hotspot, not
a throughput-optimized sharded consensus protocol. All writers must use the
same namespace, service ID and pinned cluster identity.

Supported signed operation types:

- `nonce-create` — bind exact attestation context and expiration.
- `nonce-inspect` — read canonical nonce record and mark expiry if necessary.
- `nonce-consume` — one-use consumption with context binding.
- `authorization-consume` — one-use protected-request replay barrier.
- `capability-consume` — one-use signed capability replay barrier.

The experimental `raft-vote` and `raft-append` op names are **not**
supported by this production-intended authority.

## Signing, client policy and operation

Use `EtcdSignedReplayService` in an independent trusted service process.
Only the trusted service may hold etcd mTLS certificates and its
Ed25519 server signing key. Authenticated client keys are restricted to an
explicit set of allowed operations and partitions.

Example **disposable local** setup (actual deployments MUST use mTLS and
independently provisioned keys/certificates):

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_horizon.authority_backends import EtcdGatewayConfig
from event_horizon.etcd_signed_replay import EtcdSignedReplayService
from event_horizon.remote_replay import (
    AuthenticatedReplayClient, RemoteCapabilityConsumptionStore,
    ReplayClientPolicy, ReplayRequestSigner,
)

signer = ReplayRequestSigner(client_private_seed, "eh-distributed")
policy = ReplayClientPolicy.create(
    signer.public_key_pem,
    operations={"capability-consume", "authorization-consume",
                "nonce-create", "nonce-consume", "nonce-inspect"},
    partitions={"broker", "auth", "attestation"},
)
service = EtcdSignedReplayService.connect(
    EtcdGatewayConfig(
        endpoint="http://127.0.0.1:2379",
        allow_insecure_loopback=True,
    ),
    expected_cluster_id=PINNED_CLUSTER_ID,
    namespace="eh-production-domain",
    service_id="eh-distributed",
    epoch=1,
    signing_key=server_private_seed,
    clients={policy.key_id: policy},
    bootstrap=True,  # EXPLICIT ONE-TIME OPERATOR ACTION ONLY
)
client = AuthenticatedReplayClient(
    signer, service.handle, service.public_key_pem, epoch=1,
)
store = RemoteCapabilityConsumptionStore(client, partition="broker")
```

Do not put `client_private_seed`, `server_private_seed` or etcd
transport credentials into the guest executor. In deployment the client
should connect via `HttpReplayTransport` to a separate
`ReplayHttpServer` configured with TLS/mTLS and pinned keys, rather
than invoke `service.handle` in the same Python process.

Normal startup **refuses to create** missing etcd authority data.
`bootstrap=True` is only for intentional first provisioning. A missing
head after startup is an error rather than implicit reset.

## Tests and evidence

- `tests/test_etcd_signed_replay.py` models serializable transactions
  deterministically and verifies 5 operations, nonce expiry, restart,
  simultaneous attempts, signed replay continuity, rollback detection,
  lost quorum and commit-then-timeout uncertainty.
- `tests/test_etcd_signed_replay_live.py` runs against the disposable
  *real three-node etcd Raft cluster* from
  `.github/workflows/etcd-quorum.yml`. It checks nonce issuance/consume,
  protected authorization replay and repeated capability consumption,
  signed checkpoints, replica concurrency, single-member failure and
  majority loss after checkpointed state exists.

A signed receipt proves the committed decision *within the trust model*
but does not prove physical workload isolation, an uncompromised authority
host, operator honesty, full process integration or absence of all effects.

## Remaining gates

1. **Wire all seven-role harness callers** (the Node attestation nonce
   bridge, signer, protected RPC verification and executor-side interface)
   through this external signed replay authority. Today those existing
   roles still use their original local SQLite configurations.
2. Configure authenticated **cross-host** service transport and separately
   provision server and client keys; no Etcd write certificate may reach
   the compromised executor. The current KVM effect service uses an empty
   network namespace and has not been integrated with that cross-host link.
3. Operationalize signer-key rotation and explicitly audited epoch promotion
   with checkpoint continuity and a recoverable client high-water mark.
4. Re-run actual Firecracker/WSL2 KVM experiments on an external host, with
   independent host-side effects/oracles and KVM confinement observations.

**Safety claim:** the atomic signed etcd replay service is implemented and
can be live-tested. Full distributed EHH containment is NOT thereby proven.
