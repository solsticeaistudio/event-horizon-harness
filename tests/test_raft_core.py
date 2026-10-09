from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from event_horizon.raft_core import (
    DurableRaftNode, RaftCoreError, RaftCoreUnavailable,
)
from event_horizon.replay_state import CapabilityConsumptionError

MEMBERS = ("a", "b", "c")
TOKEN = "cap_0123456789abcdef01234567"
DIGEST = "a" * 64


def command(token=TOKEN, digest=DIGEST):
    return {
        "op": "consume", "scope": "broker",
        "capability_id": token, "claims_digest": digest,
        "expires_at": 5000, "consumed_at": 1000,
    }


class RaftResearchCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = {m: Path(self.temp.name) / (m + ".sqlite") for m in MEMBERS}
        self.nodes = {
            m: DurableRaftNode(self.paths[m], node_id=m, member_ids=MEMBERS)
            for m in MEMBERS
        }
        self._connect()

    def _connect(self):
        for m, node in self.nodes.items():
            node.connect({peer: value for peer, value in self.nodes.items() if peer != m})

    def tearDown(self):
        for node in self.nodes.values():
            node.close()

    def test_quorum_commit_applies_same_state_to_all_replicas(self):
        self.assertTrue(self.nodes["a"].elect())
        self.assertTrue(self.nodes["a"].propose(command()))
        for node in self.nodes.values():
            self.assertEqual(node.commit_index, 1)
            self.assertEqual(node.known_consumption("broker", TOKEN), (DIGEST, 5000))
        self.assertFalse(self.nodes["a"].propose(command()))
        for node in self.nodes.values():
            self.assertEqual(node.commit_index, 2)

    def test_durable_terms_votes_and_commit_survive_restart(self):
        self.assertTrue(self.nodes["a"].elect())
        self.assertTrue(self.nodes["a"].propose(command()))
        old_term = self.nodes["b"].term
        self.nodes["b"].close()
        self.nodes["b"] = DurableRaftNode(self.paths["b"], node_id="b", member_ids=MEMBERS)
        self._connect()
        self.assertEqual(self.nodes["b"].term, old_term)
        self.assertEqual(self.nodes["b"].commit_index, 1)
        self.assertEqual(self.nodes["b"].known_consumption("broker", TOKEN), (DIGEST, 5000))
        self.assertFalse(self.nodes["b"].request_vote(old_term, "c", 0, 0)[1])

    def test_loss_of_majority_fails_closed(self):
        self.assertTrue(self.nodes["a"].elect())
        class Partition:
            def append_entries(self, *args, **kwargs):
                raise OSError("partition")
            def request_vote(self, *args, **kwargs):
                raise OSError("partition")
        self.nodes["a"].peers = {"b": Partition(), "c": Partition()}
        with self.assertRaisesRegex(RaftCoreUnavailable, "quorum"):
            self.nodes["a"].propose(command())
        self.assertEqual(self.nodes["a"].commit_index, 0)
        self.assertIsNone(self.nodes["a"].known_consumption("broker", TOKEN))

    def test_new_leader_fences_stale_leader_and_overwrites_uncommitted(self):
        self.assertTrue(self.nodes["a"].elect())
        class Partition:
            def append_entries(self, *args, **kwargs):
                raise OSError("partition")
            def request_vote(self, *args, **kwargs):
                raise OSError("partition")
        self.nodes["a"].peers = {"b": Partition(), "c": Partition()}
        with self.assertRaises(RaftCoreUnavailable):
            self.nodes["a"].propose(command())
        # A's uncommitted log makes A's vote unsafe for B; B and C form quorum.
        self.nodes["b"].peers = {"a": Partition(), "c": self.nodes["c"]}
        self.assertTrue(self.nodes["b"].elect())
        token_b = "cap_aaaaaaaaaaaaaaaaaaaaaaaa"
        self.assertTrue(self.nodes["b"].propose(command(token_b)))
        self._connect()
        self.nodes["b"]._replicate("a")
        self.assertEqual(self.nodes["a"].role, "follower")
        self.assertEqual(self.nodes["a"].term, self.nodes["b"].term)
        self.assertEqual(self.nodes["a"].known_consumption("broker", TOKEN), None)
        self.assertEqual(self.nodes["a"].known_consumption("broker", token_b), (DIGEST, 5000))

    def test_same_token_different_claims_is_not_an_ordinary_replay(self):
        self.assertTrue(self.nodes["a"].elect())
        self.assertTrue(self.nodes["a"].propose(command()))
        with self.assertRaises(CapabilityConsumptionError):
            self.nodes["a"].propose(command(digest="b" * 64))
        for node in self.nodes.values():
            self.assertEqual(node.known_consumption("broker", TOKEN), (DIGEST, 5000))

    def test_uncommitted_log_does_not_survive_as_authority(self):
        self.assertTrue(self.nodes["a"].elect())
        self.nodes["a"].peers = {
            p: type("Lost", (), {"append_entries": lambda *_: (_ for _ in ()).throw(OSError("lost"))})()
            for p in ("b", "c")
        }
        with self.assertRaises(RaftCoreUnavailable):
            self.nodes["a"].propose(command())
        self.nodes["a"].close()
        self.nodes["a"] = DurableRaftNode(self.paths["a"], node_id="a", member_ids=MEMBERS)
        self.assertEqual(self.nodes["a"].last_index, 1)
        self.assertEqual(self.nodes["a"].commit_index, 0)
        self.assertIsNone(self.nodes["a"].known_consumption("broker", TOKEN))


if __name__ == "__main__":
    unittest.main()
