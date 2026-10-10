from __future__ import annotations

import base64
import concurrent.futures
import json
import tempfile
import unittest
from pathlib import Path

from event_horizon.authority_backends import (
    EtcdGatewayConfig,
    EtcdV3CapabilityConsumptionStore,
    local_authority,
)
from event_horizon.replay_state import CapabilityConsumptionError

TOKEN = "cap_0123456789abcdef01234567"
DIGEST = "a" * 64
CLUSTER = "139003440588"


def b64(x):
    return base64.b64encode(x).decode("ascii")


class FakeEtcd:
    """Atomic simulation of etcd's Txn compare, put and linearizable range."""

    def __init__(self):
        import threading
        self.lock = threading.Lock()
        self.data = {}
        self.revision = 1
        self.available = True
        self.wrong_cluster = False
        self.ambiguous_commit = False

    def __call__(self, txn):
        if not self.available:
            raise OSError("partition")
        with self.lock:
            key = txn["compare"][0]["key"]
            self.assert_transaction(txn, key)
            succeeded = key not in self.data
            if succeeded:
                self.data[key] = txn["success"][0]["requestPut"]["value"]
                self.revision += 1
                responses = [{"response_put": {"header": {"revision": str(self.revision)}}}]
            else:
                responses = [{"response_range": {"kvs": [
                    {"key": key, "value": self.data[key]}
                ], "count": "1"}}]
            if self.ambiguous_commit:
                raise TimeoutError("response lost after commit")
            return {
                "header": {"cluster_id": "different" if self.wrong_cluster else CLUSTER,
                           "revision": str(self.revision), "raft_term": "7"},
                "succeeded": succeeded, "responses": responses,
            }

    def assert_transaction(self, txn, key):
        assert txn["compare"] == [{
            "target": "VERSION", "result": "EQUAL",
            "key": key, "version": "0",
        }]
        assert txn["failure"] == [{
            "requestRange": {"key": key, "serializable": False}
        }]
        assert len(txn["success"]) == 1
        assert "lease" not in txn["success"][0]["requestPut"]


class AuthorityBackendTests(unittest.TestCase):
    def test_sqlite_single_host_persists_replay_across_process_reopen(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "authority.sqlite"
            first = local_authority(path)
            self.assertTrue(first.consume(TOKEN, DIGEST, 5000, 1000))
            first.close()
            second = local_authority(path)
            self.assertFalse(second.consume(TOKEN, DIGEST, 5000, 1001))
            with self.assertRaisesRegex(CapabilityConsumptionError, "collided"):
                second.consume(TOKEN, "b" * 64, 5000, 1001)
            second.close()

    def test_etcd_consensus_cas_allows_one_writer_under_contention(self):
        cluster = FakeEtcd()
        def call(_):
            store = EtcdV3CapabilityConsumptionStore(cluster, expected_cluster_id=CLUSTER)
            return store.consume(TOKEN, DIGEST, 5000, 1000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(call, range(64)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 63)
        self.assertEqual(len(cluster.data), 1)

    def test_etcd_distinguishes_replay_from_colliding_claims(self):
        cluster = FakeEtcd()
        store = EtcdV3CapabilityConsumptionStore(cluster, expected_cluster_id=CLUSTER)
        self.assertTrue(store.consume(TOKEN, DIGEST, 5000, 1000))
        self.assertFalse(store.consume(TOKEN, DIGEST, 5000, 1001))
        with self.assertRaisesRegex(CapabilityConsumptionError, "collided"):
            store.consume(TOKEN, "b" * 64, 5000, 1002)
        with self.assertRaisesRegex(CapabilityConsumptionError, "collided"):
            store.consume(TOKEN, DIGEST, 5001, 1002)

    def test_network_partition_refuses_authority(self):
        cluster = FakeEtcd()
        cluster.available = False
        store = EtcdV3CapabilityConsumptionStore(cluster, expected_cluster_id=CLUSTER)
        with self.assertRaises(CapabilityConsumptionError):
            store.consume(TOKEN, DIGEST, 5000, 1000)

    def test_lost_response_fails_closed_even_if_transaction_committed(self):
        cluster = FakeEtcd()
        cluster.ambiguous_commit = True
        store = EtcdV3CapabilityConsumptionStore(cluster, expected_cluster_id=CLUSTER)
        with self.assertRaisesRegex(CapabilityConsumptionError, "uncertain"):
            store.consume(TOKEN, DIGEST, 5000, 1000)
        self.assertEqual(len(cluster.data), 1)
        cluster.ambiguous_commit = False
        self.assertFalse(store.consume(TOKEN, DIGEST, 5000, 1001))

    def test_rejects_wrong_cluster_and_malformed_decisions(self):
        cluster = FakeEtcd()
        cluster.wrong_cluster = True
        store = EtcdV3CapabilityConsumptionStore(cluster, expected_cluster_id=CLUSTER)
        with self.assertRaisesRegex(CapabilityConsumptionError, "identity"):
            store.consume(TOKEN, DIGEST, 5000, 1000)
        for broken in [
            {"succeeded": True, "responses": []},
            {"header": {"cluster_id": CLUSTER, "raft_term": "0", "revision": "1"},
             "succeeded": True, "responses": [{"response_put": {}}]},
        ]:
            with self.subTest(broken=broken):
                with self.assertRaises(CapabilityConsumptionError):
                    EtcdV3CapabilityConsumptionStore(lambda _: broken, expected_cluster_id=CLUSTER).consume(
                        TOKEN, DIGEST, 5000, 1000
                    )

    def test_missing_response_record_cannot_be_treated_as_replay(self):
        reply = {"header": {"cluster_id": CLUSTER, "revision": "8", "raft_term": "2"},
                 "succeeded": False, "responses": [{"response_range": {}}]}
        store = EtcdV3CapabilityConsumptionStore(lambda _: reply, expected_cluster_id=CLUSTER)
        with self.assertRaises(CapabilityConsumptionError):
            store.consume(TOKEN, DIGEST, 5000, 1000)

    def test_production_transport_must_use_tls(self):
        with self.assertRaises(ValueError):
            EtcdGatewayConfig(endpoint="http://10.0.0.8:2379")
        with self.assertRaises(ValueError):
            EtcdGatewayConfig(endpoint="https://etcd.internal:2379")
        with self.assertRaises(ValueError):
            EtcdGatewayConfig(endpoint="http://localhost:2379")
        config = EtcdGatewayConfig(endpoint="http://127.0.0.1:2379", allow_insecure_loopback=True)
        self.assertTrue(config.allow_insecure_loopback)
        with self.assertRaises(ValueError):
            EtcdGatewayConfig(endpoint="http://127.0.0.1:2379/admin", allow_insecure_loopback=True)


if __name__ == "__main__":
    unittest.main()
