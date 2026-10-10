"""Regression tests for repaired legacy Raft RESEARCH adapter.

All tests are deterministic and use owned SQLite fixtures; no network authority
or production replay backend is activated by this module.
"""
from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from event_horizon.raft_replay import (
    RaftConsensus, RaftLogEntry, RaftNode, RaftUnavailableError,
    create_research_raft_cluster,
)
from event_horizon.replay_state import CapabilityConsumptionError

TOKEN = "cap_0123456789abcdef01234567"
DIGEST = "a" * 64


def command(token=TOKEN, binding=DIGEST):
    return {
        "op": "consume", "scope": "synthetic:broker",
        "capability_id": token, "claims_digest": binding,
        "expires_at": 5000, "consumed_at": 1000,
    }


class ResearchBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.nodes = [
            RaftNode(name, "research://" + name) for name in ("a", "b", "c")
        ]
        self.paths = [
            Path(self.temp.name) / (node.node_id + ".sqlite") for node in self.nodes
        ]
        self.cluster = create_research_raft_cluster(self.nodes, self.paths)
        self.addCleanup(self.close_cluster)

    def close_cluster(self):
        for consensus in self.cluster:
            try:
                consensus.close()
            except sqlite3.ProgrammingError:
                pass

    def test_repaired_legacy_api_commits_through_durable_quorum(self):
        leader = self.cluster[0]
        self.assertTrue(leader.elect())
        prior = leader.committed_checkpoint()
        self.assertEqual(prior[0], 0)
        self.assertTrue(leader.propose(command(), *prior))
        for node in self.cluster:
            self.assertEqual(node._durable_core.known_consumption(
                "synthetic:broker", TOKEN), (DIGEST, 5000))
            self.assertEqual(node.committed_checkpoint(), leader.committed_checkpoint())
        # Stale checkpoint cannot masquerade as fresh leader authority.
        with self.assertRaisesRegex(RaftUnavailableError, "checkpoint changed"):
            leader.propose(command(), *prior)
        current = leader.committed_checkpoint()
        self.assertFalse(leader.propose(command(), *current))
        with self.assertRaises(CapabilityConsumptionError):
            leader.propose(command(binding="b" * 64), *leader.committed_checkpoint())

    def test_quorum_loss_stale_leader_and_durable_restart(self):
        leader = self.cluster[0]
        self.assertTrue(leader.elect())
        prior = leader.committed_checkpoint()
        class Lost:
            def append_entries(self, *args, **kwargs):
                raise OSError("simulated partition")
            def request_vote(self, *args, **kwargs):
                raise OSError("simulated partition")
        leader._durable_core.peers = {"b": Lost(), "c": Lost()}
        with self.assertRaisesRegex(RaftUnavailableError, "quorum"):
            leader.propose(command(), *prior)
        self.assertEqual(leader.committed_checkpoint(), prior)
        # B and C can elect without A and commit another token.
        b = self.cluster[1]
        b._durable_core.peers = {"a": Lost(), "c": self.cluster[2]._durable_core}
        self.assertTrue(b.elect())
        new_token = "cap_aaaaaaaaaaaaaaaaaaaaaaaa"
        self.assertTrue(b.propose(command(token=new_token), *b.committed_checkpoint()))
        # Restore links and drive A to observe the newer term.
        for node in self.cluster:
            node._durable_core.connect({
                other._durable_core.node_id: other._durable_core
                for other in self.cluster if other is not node
            })
        b._durable_core._replicate("a")
        self.assertFalse(leader.is_leader())
        with self.assertRaises(RaftUnavailableError):
            leader.propose(command(), *leader.committed_checkpoint())
        self.assertIsNone(leader._durable_core.known_consumption(
            "synthetic:broker", TOKEN))
        self.assertEqual(leader._durable_core.known_consumption(
            "synthetic:broker", new_token), (DIGEST, 5000))

    def test_snapshot_metadata_sql_and_digest_are_valid_but_not_compacted(self):
        node = RaftNode("legacy", "research://legacy")
        consensus = RaftConsensus(
            node, [node], None,
            snapshot_threshold=1, snapshot_interval_ms=0,
        )
        consensus._snapshot_db_path = Path(self.temp.name) / "snapshots.sqlite"
        consensus._current_term = 2
        consensus._commit_index = 1
        consensus._log = [RaftLogEntry(
            index=1, term=2, command={"op": "noop"},
            checkpoint=1, checkpoint_digest="c" * 64,
        )]
        consensus._maybe_create_snapshot()
        self.assertIsNotNone(consensus._snapshot)
        self.assertEqual(
            consensus._snapshot.snapshot_digest,
            hashlib.sha256(consensus._snapshot.snapshot_data).hexdigest(),
        )
        with sqlite3.connect(consensus._snapshot_db_path) as db:
            row = db.execute(
                "SELECT last_included_index, digest, data FROM snapshots"
            ).fetchone()
        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], consensus._snapshot.snapshot_digest)
        self.assertEqual(row[2], consensus._snapshot.snapshot_data)
        # Deliberately no unsafe log truncation or snapshot installation.
        self.assertEqual(len(consensus._log), 1)
        consensus.close()

    def test_old_unsafe_transport_is_still_disabled(self):
        node = RaftNode("legacy", "http://127.0.0.1:9999")
        consensus = RaftConsensus(node, [node], None)
        with self.assertRaisesRegex(RaftUnavailableError, "unauthenticated"):
            consensus.start()
        with self.assertRaises(RaftUnavailableError):
            consensus.elect()
        with self.assertRaises(RaftUnavailableError):
            consensus.committed_checkpoint()

    def test_duplicate_database_paths_and_even_membership_rejected(self):
        with self.assertRaises(ValueError):
            create_research_raft_cluster(self.nodes, [self.paths[0]] * 3)
        with self.assertRaises(ValueError):
            create_research_raft_cluster(self.nodes[:2], self.paths[:2])


if __name__ == "__main__":
    unittest.main()
