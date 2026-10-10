"""Opt-in real etcd integration: only run with EHH_ETCD_ENDPOINT.

The CI workflow provisions three disposable local Docker etcd nodes.
This test never connects to production etcd unless explicitly configured.
"""
from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import tempfile
import time
import unittest
import urllib.request
import uuid
from pathlib import Path
from unittest.mock import Mock

from event_horizon.authority_backends import (
    EtcdGatewayConfig, etcd_authority, EtcdV3TransactionTransport
)
from event_horizon.replay_state import CapabilityConsumptionError
from event_horizon.broker import CapabilityBroker
from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.models import ActionRequest
from scripts.capability_fixture_support import authority_context, issue_options


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


def signed_effect_gateway_fixture(
    endpoint: str, pinned_cluster_id: str, session: str, directory: str, *, replica: int
):
    """Return a host-side gateway and signed request against real etcd.

    All replicas use the same signed capability and consensus-backed domain,
    but distinct local decay databases. The workload cannot choose the store.
    """
    request = ActionRequest(
        "etcd-gateway-fixture", session, "attacker-agent", "object.read",
        "synthetic-dataset", "exec-1",
        {"offset": 0, "length": 5}, "consensus-backed synthetic read",
    )
    auth = authority_context(request, time.time())
    broker = CapabilityBroker(b"live-etcd-gateway-fixture-key-32bytes", ttl_seconds=60)
    capability = broker.issue(request, **issue_options(auth), max_output_bytes=512)
    directory = Path(directory)
    config = {
        "verification_context": {
            **{name: auth[name] for name in (
                "device_id", "executor_measurement",
                "verifier_policy_digest", "policy_digest", "attestation"
            )},
            "tenant": "default",
            "environment": "synthetic",
        },
        "public_key_pem": broker.public_key_pem,
        "key_id": broker.key_id,
        "dataset": "hello-world",
        "session_id": session,
        "resource_id": "synthetic-dataset",
        "vm_uid": 60000,
        "replay_database": str(directory / f"unused-replay-{replica}.sqlite"),
        "decay_database": str(directory / f"decay-{replica}.sqlite"),
        "authority_backend": "etcd",
        "etcd_gateway": {
            "endpoint": endpoint, "allow_insecure_loopback": True,
            "timeout_seconds": 1.0,
        },
        "etcd_cluster_id": pinned_cluster_id,
    }
    gate = DatasetEffectBoundary(config, Mock())
    return gate, {"request": request.canonical_payload(), "capability": capability.to_dict()}


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

    def test_real_signed_gateway_replicas_enforce_quorum_consumption(self):
        # Host-side parser, Ed25519 verifier, etcd CAS, trusted effect handler.
        with tempfile.TemporaryDirectory() as root:
            first, message = signed_effect_gateway_fixture(
                self.endpoint, self.pinned, self.namespace, root, replica=0
            )
            replicas = [(first, message)]
            for n in range(1, 8):
                # All replicas verify the *same* exact signed capability and
                # share the consensus keyspace, with independent local files.
                config = dict(first.config)
                config["decay_database"] = str(Path(root) / f"decay-{n}.sqlite")
                replicas.append((DatasetEffectBoundary(config, Mock()), message))
            try:
                def attempt(n):
                    gateway, message = replicas[n % len(replicas)]
                    return gateway.execute(message, peer_uid=60000)
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as workers:
                    results = list(workers.map(attempt, range(24)))
                self.assertEqual(sum(item["success"] for item in results), 1, results)
                self.assertEqual(
                    sum(item["effect_state"] == "completed" for item in results), 1,
                )
                self.assertTrue(all(
                    item["effect_state"] == "not-started"
                    for item in results if not item["success"]
                ))
            finally:
                for gateway, _ in replicas:
                    gateway.close()

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
