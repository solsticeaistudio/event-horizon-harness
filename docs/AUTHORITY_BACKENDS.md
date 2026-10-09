# Capability consumption: local, etcd, and Raft

EHH exposes the same **fail-closed capability consumption contract** across
two supported storage adapters. These are mutually exclusive **deployments of
the same authority**, not two stores used at once; there must be no accidental
fallback from etcd to SQLite after an outage.

## Option A: trusted single authority

Use `local_authority(path, namespace="default", domain="broker")` from
`event_horizon.authority_backends`. This delegates to EHH's existing
`SqliteCapabilityConsumptionStore`, which already uses `BEGIN IMMEDIATE`,
a `(namespace, domain, capability_id)` primary key, synchronous FULL, and a
single committed transaction per consume. It rejects a reused ID with
different claims and persists replays across restarts.

**Topology:** one trusted authority service owning a protected volume; other
components access it over authenticated RPC. SQLite itself supports
cooperating same-host writers but it is NOT a distributed leader election
protocol. On authority outage, refuse new execution. Keep signer and
executor replay domains deliberate and separate.

## Option B: etcd consensus-backed authority

```python
from event_horizon.authority_backends import (
    EtcdGatewayConfig, etcd_authority,
)
config = EtcdGatewayConfig(
    endpoint="https://etcd.internal:2379",
    ca_file="/path/to/ca.pem",
    client_cert_file="/path/to/client.pem",
    client_key_file="/path/to/client.key",
    # An API token can be configured if the gateway's auth is enabled.
    auth_token=None,
)
authority = etcd_authority(
    config, expected_cluster_id="PINNED_DECIMAL_CLUSTER_ID",
    namespace="production", domain="broker",
)
authority.consume("cap_0123456789abcdef01234567", "a" * 64, 5000, 1000)
```

`expected_cluster_id` must be the real cluster ID, not the placeholder.
Each consume performs **one** etcd v3 `/v3/kv/txn` request:

- Compare key VERSION=0.
- On absent key, atomically PUT canonical capability binding.
- Otherwise atomically range-read the binding and distinguish replay
  (same claims and expiry) from collision (different claims).
- Require a pinned cluster ID, Raft term, revision, and structurally
  valid branch acknowledgment. On errors or ambiguous timeout,
  **deny execution**. Do not automatically retry the uncertain result.
- **Never attach a lease or expire the tombstone**: replay history cannot
  disappear just because the capability has expired.
- The range in the transaction is non-serializable (linearizable).

The implementation uses etcd's existing mature Raft consensus: we do not
replace etcd's internal election, persistence, or quorum logic. The JSON
gateway is an API and **requires** separately secured cluster deployment,
authenticated authorization and network access controls. Mutual TLS here
protects transport; the gateway does not use client TLS CN authentication as
an etcd user identity. Configure etcd auth/ACLs or equivalent admission
controls for the allowed prefix.

**Production validation still required:** real 3/5-member etcd deployment,
partition and crash tests, gateway token/ACL provisioning, recovery and
backup/restore policies, capacity limits, snapshot/compaction policies,
and end-to-end integration with the signer and execution gateways.

## Experimental Python Raft path

`raft_replay.py` is deliberately quarantined: direct `propose` and cluster
creation fail closed. Its partially implemented leader election and log
replication are NOT an authority service. A real custom consensus protocol
also requires crash-safe `term/voted_for/log`, durable quorum commit,
old-leader fencing, conflict rollback, snapshot installation, joint consensus,
read-index safety, transport authentication, and exhaustive partition tests.
Do not use the experimental implementation as a replacement for etcd Raft.

## Testing

`python -m unittest tests.test_authority_backends -v` tests a synthetic,
atomic fake-etcd transport, including contention, ambiguity, collision,
partition denial and pinned cluster validation. The Python CI suite also
exercises native SQLite and signed remote replay. The fake transport proves
the adapter's contract **under its simulated assumptions**, not real etcd
cluster availability or linearizability.
