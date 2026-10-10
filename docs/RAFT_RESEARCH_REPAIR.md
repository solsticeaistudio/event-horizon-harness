# Raft repair: durable research bridge (not production authority)

The original `raft_replay.py` attempted an HTTP-based Raft service without
validated persistent quorum, authenticated peer RPC, old-leader fencing or
safe snapshot restore. Its original `create_raft_cluster(...)` remains
**deliberately fail-closed**. We did not delete that implementation.

## What now works

A deliberately separate `create_research_raft_cluster(...)` factory
constructs **three or more odd-numbered, fixed voting members**, each with
its own SQLite WAL database and `synchronous=FULL`. It reuses the
`DurableRaftNode` crash-fault laboratory instead of the unsafe legacy
network implementation. The preserved `RaftConsensus` wrapper now exposes:

- `elect()` for explicit deterministic election with durable terms and votes
- `committed_checkpoint()` returning a LOCAL digest over the committed log
  prefix, with per-entry applied result included
- `propose(command, checkpoint, checkpoint_digest)` requiring an exact
  prior committed-prefix guard and a real majority of durable append replies
- `close()` to shut down the local SQLite node cleanly

The old snapshot metadata path now quotes no reserved SQL identifiers,
hashes the actual canonical snapshot bytes with SHA-256, and requires at
least one committed entry. It **does not** truncate the log, support
InstallSnapshot RPC, or restore durable authority from snapshot metadata.

## Minimal owned synthetic example

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from event_horizon.raft_replay import RaftNode, create_research_raft_cluster

with TemporaryDirectory() as root:
    nodes = [RaftNode(name, f"research://{name}") for name in ("a", "b", "c")]
    cluster = create_research_raft_cluster(
        nodes, [Path(root) / f"{node.node_id}.sqlite" for node in nodes]
    )
    try:
        leader = cluster[0]
        assert leader.elect()
        before = leader.committed_checkpoint()
        accepted = leader.propose({
            "op": "consume", "scope": "synthetic:broker",
            "capability_id": "cap_0123456789abcdef01234567",
            "claims_digest": "a" * 64,
            "expires_at": 5000, "consumed_at": 1000,
        }, *before)
        assert accepted
        # A second proposal requires a *new* committed-prefix checkpoint.
        assert not leader.propose({
            "op": "consume", "scope": "synthetic:broker",
            "capability_id": "cap_0123456789abcdef01234567",
            "claims_digest": "a" * 64,
            "expires_at": 5000, "consumed_at": 1000,
        }, *leader.committed_checkpoint())
    finally:
        for node in cluster:
            node.close()
```

This is a deterministic **in-process simulation** of crash-fault Raft
rules, not evidence of an authenticated network or multi-host cluster.
The checkpoint is generated locally and is not a linearizable quorum read,
cryptographically signed externally, or independently witnessed.

## Security and validation boundaries

The repair adds tests for leader change, stale-prefix proposal denial,
majority failure, quorum-backed consumption, replay collision, restart
persistence, malformed log gaps, and atomic rollback of in-memory indices
when an SQLite commit fails. The separate real etcd Raft cluster remains
EHH's validated distributed authority backend.

Still missing before custom Raft can be operational authority:
authenticated peer transport and replay protection; deterministic election
timeouts and heartbeats under bounded network faults; formal conformance
and model-based randomized partitions; secure snapshot creation/installation
and log compaction; cluster reconfiguration/joint consensus; durable
transactional state-machine output and independently pinned checkpoints;
and real multi-process/multi-host adversarial validation.

Do not pass the research bridge into the trusted production capability
issuer or expose it as an HTTP service. `raft_core.py` and `raft_replay.py`
are **both retained** for continued development.
