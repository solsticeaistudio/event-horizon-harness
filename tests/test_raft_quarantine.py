from __future__ import annotations

import unittest
from unittest.mock import Mock

from event_horizon.raft_replay import (
    RaftConsensus, RaftNode, RaftUnavailableError, create_raft_cluster,
)


class RaftFailClosedTests(unittest.TestCase):
    def test_propose_cannot_claim_an_uncommitted_replay_as_success(self):
        node = RaftNode("node-1", "http://127.0.0.1:9999")
        consensus = RaftConsensus(node, [node], Mock())
        consensus._state = "leader"
        with self.assertRaisesRegex(RaftUnavailableError, "durable quorum commit"):
            consensus.propose({"op": "consume"}, 1, "0" * 64)
        self.assertEqual(consensus._log, [])

    def test_cluster_factory_cannot_enable_unverified_authority(self):
        with self.assertRaisesRegex(RaftUnavailableError, "old-leader fencing"):
            create_raft_cluster(
                [], [], service_id="synthetic", epoch=1,
                signing_key=b"0" * 32, clients={},
            )


if __name__ == "__main__":
    unittest.main()
