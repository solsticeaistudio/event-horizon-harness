"""Opt-in real etcd integration: only run with EHH_ETCD_ENDPOINT.

The CI workflow provisions three disposable local Docker etcd nodes.
This test never connects to production etcd unless explicitly configured.
"""
from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import unittest
import urllib.request
import uuid

from event_horizon.authority_backends import (
    EtcdGatewayConfig, etcd_authority, EtcdV3TransactionTransport
)
from event_horizon.replay_state import CapabilityConsumptionError


def cluster_id(endpoint: str) -> str:
    """Perform real linearizable range, never trust cluster-id discovery alone."""
    key = base64.b64encode(b"/eh-ci-discovery").decode("ascii")
    req = urllib.request.Request(
        endpoint + "/v3/kv/range",
        data=json.dumps({"key": key, "serializable": False}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=4) as response:
        data = json.loads(response.read())
    return str(data["header"]["cluster_id"])


@unittest.skipUnless(os.environ.get("EHH_ETCD_ENDPOINT"), "requires disposable etcd cluster")
class LiveEtcdCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = os.environ["EHH_ETCD_ENDPOINT"]
        self.pinned = os.environ.get("EHH_ETCD_CLUSTER_ID") or cluster_id(self.endpoint)
        self.config = EtcdGatewayConfig(
            endpoint=self.endpoint, allow_insecure_loopback=True
        )
        self.namespace = "e2e." + uuid.uuid4().hex
        self.store = etcd_authority(
            self.config, expected_cluster_id=self.pinned,
            namespace=self.namespace, domain="broker"
        )

    def test_concurrent_consumption_uses_real_atomic_txn(self):
        token = "cap_0123456789abcdef01234567"
        digest = "a" * 64
        def worker(_):
            return self.store.consume(token, digest, 5000, 1000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(worker, range(24)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 23)
        self.assertEqual(
            self.store.consume(token, digest, 5000, 1001), False
        )
        with self.assertRaisesRegex(CapabilityConsumptionError, "collided"):
            self.store.consume(token, "b" * 64, 5000, 1001)


if __name__ == "__main__":
    unittest.main()
