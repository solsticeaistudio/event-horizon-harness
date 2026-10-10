"""Live signed replay authority conformance against disposable three-node etcd.

RUN ONLY against explicit EHH_ETCD_ENDPOINT set by etcd-quorum CI. This
module does not provision production credentials or tolerate non-loopback
plaintext endpoints.
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
import uuid
import urllib.request
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.authority_backends import EtcdGatewayConfig
from event_horizon.canonical import digest
from event_horizon.etcd_signed_replay import EtcdSignedReplayService
from event_horizon.remote_replay import (
    AuthenticatedReplayClient, ReplayClientPolicy, ReplayRequestSigner,
    RemoteAuthorizationReplayStore, RemoteCapabilityConsumptionStore,
)
from tests.test_etcd_live import cluster_id
from event_horizon.process_harness import ProcessSeparatedHarness
from event_horizon.intent_canonicalizer import AuthorizationDenied
from event_horizon.remote_replay import ReplayHttpServer
from event_horizon.trusted_replay_client import (
    provision_replay_client_policies, role_client_seed_path,
)

SID = "etcd-live-signed-replay"


def provision(endpoint: str | None = None, namespace: str | None = None, *, bootstrap=True):
    endpoint = endpoint or os.environ["EHH_ETCD_ENDPOINT"]
    cluster = os.environ.get("EHH_ETCD_CLUSTER_ID") or cluster_id(endpoint)
    config = EtcdGatewayConfig(
        endpoint=endpoint, allow_insecure_loopback=True, timeout_seconds=1.0,
    )
    server_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    client_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    signer = ReplayRequestSigner(client_key, SID)
    policy = ReplayClientPolicy.create(
        signer.public_key_pem,
        operations={
            "nonce-create", "nonce-consume", "nonce-inspect",
            "capability-consume", "authorization-consume",
        },
        partitions={"capabilities", "nonces", "authorizations"},
    )
    params = dict(
        expected_cluster_id=cluster,
        namespace=namespace or "signed." + uuid.uuid4().hex,
        service_id=SID, epoch=1, signing_key=server_key,
        clients={policy.key_id: policy},
    )
    service = EtcdSignedReplayService.connect(config, **params, bootstrap=bootstrap)
    client = AuthenticatedReplayClient(
        signer, service.handle, service.public_key_pem, epoch=1,
    )
    return service, client, config, params


@unittest.skipUnless(os.environ.get("EHH_ETCD_ENDPOINT"), "requires disposable etcd")
class LiveSignedReplayTests(unittest.TestCase):
    def test_real_seven_process_harness_shares_signed_authority(self):
        """Exercise Node verifier + trusted signer + protected recorder/cert.

        All protected services hit the same live etcd authority via signed
        HTTP RPC, not an in-memory reference mock. The executor receives
        neither authority key nor etcd transport configuration.
        """
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory)
            policies = provision_replay_client_policies(scope, SID)
            endpoint = self._seven_process_authority(scope, policies)
            service, server = endpoint
            server.start()
            remote = {
                "url": server.url, "service_id": SID, "epoch": 1,
                "server_public_key_pem": service.public_key_pem,
                "ca_cert_path": None, "client_cert_path": None,
                "client_key_path": None,
            }
            try:
                with ProcessSeparatedHarness(
                    scope, ttl_seconds=30.0, remote_authority=remote,
                ) as harness:
                    request = {
                        "request_id": "distributed-7-process",
                        "session_id": "signed-replay-session",
                        "agent_id": "attacker-agent",
                        "operation": "object.read",
                        "resource_id": "target-source",
                        "executor_id": "exec-1",
                        "arguments": {"offset": 0, "length": 64},
                        "purpose": "distributed signed authority end-to-end",
                    }
                    action, capability, attestation = harness.request_capability(request)
                    first = harness.execute(action, capability, attestation)
                    self.assertTrue(first.success, first.error)
                    replay = harness.execute(action, capability, attestation)
                    self.assertFalse(replay.success)
                    self.assertEqual(replay.effect_state, "not-started")
                    self.assertIn("replay", replay.error.lower())
                    self.assertFalse(harness.root_probe()["private_key_material_present"])
                    config = json.loads(harness.config_paths["executor"].read_text())
                    self.assertNotIn("remote_replay", config)
                    self.assertNotIn("client_seed_path", str(config))
                    self.assertNotIn("etcd", str(config))
                    # Node nonce transitions and 4 protected-role operations
                    # advance the same etcd checkpoint chain.
                    _, checkpoint, checkpoint_hash = service.checkpoint()
                    self.assertGreaterEqual(checkpoint, 10)
                    self.assertRegex(checkpoint_hash, r"^[0-9a-f]{64}$")
                    self.assertTrue(harness.call("recorder", "verify", {})["valid"])
                    harness.stop_role("signer")
                    harness.restart_role("signer")
                    self.assertFalse(harness.execute(action, capability, attestation).success)
                    # Exercise the certificate's *protected* mutation endpoint,
                    # not only its unauthenticated info/verify operations.
                    teardown = harness.teardown_executor()
                    self.assertTrue(teardown["verified"])
                    certificate = harness.build_certificate(
                        run_id="distributed-quorum-harness",
                        session_id=action.session_id,
                        assertions={"teardown_verified": True},
                        mode="simulation",
                    )
                    self.assertEqual(
                        certificate["certificate"]["schema"],
                        "event-horizon.containment-certificate.v0.5",
                    )
                    self._assert_trusted_partitions_committed(service)
                    # No silent local fallback, even after trusted restart.
            finally:
                server.close()

    def _assert_trusted_partitions_committed(self, service):
        """Read actual quorum-backed record keys as an independent oracle."""
        raw = f"{service.prefix}/record/".encode("utf-8")
        end = raw[:-1] + bytes([raw[-1] + 1])
        request = urllib.request.Request(
            os.environ["EHH_ETCD_ENDPOINT"] + "/v3/kv/range",
            data=json.dumps({
                "key": base64.b64encode(raw).decode("ascii"),
                "range_end": base64.b64encode(end).decode("ascii"),
                "serializable": False,
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            stored = json.loads(response.read())
        paths = {
            base64.b64decode(entry["key"]).decode("utf-8")
            for entry in stored.get("kvs", [])
        }
        required = {
            "/record/nonce/attestation.nonces/",
            "/record/capability-consume/capability.authority/",
            "/record/authorization-consume/protected.signer/",
            "/record/authorization-consume/protected.recorder/",
            "/record/authorization-consume/protected.certificate/",
        }
        for fragment in required:
            self.assertTrue(
                any(fragment in key for key in paths),
                f"missing real etcd authority state: {fragment}",
            )

    def _seven_process_authority(self, scope, policies):
        from event_horizon.authority_backends import EtcdV3TransactionTransport
        from pathlib import Path
        from event_horizon.remote_replay import ReplayHttpServer
        endpoint = os.environ["EHH_ETCD_ENDPOINT"]
        config = EtcdGatewayConfig(
            endpoint=endpoint, allow_insecure_loopback=True, timeout_seconds=2.0,
        )
        authority = EtcdSignedReplayService(
            EtcdV3TransactionTransport(config),
            expected_cluster_id=self.pinned_or_discover(endpoint),
            namespace="seven." + uuid.uuid4().hex,
            service_id=SID,
            epoch=1,
            signing_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
            clients={p.key_id: p for p in policies.values()},
            bootstrap=True,
        )
        return authority, ReplayHttpServer(authority)

    @staticmethod
    def pinned_or_discover(endpoint):
        return os.environ.get("EHH_ETCD_CLUSTER_ID") or cluster_id(endpoint)

    def test_signed_capability_nonce_and_authorization_under_real_quorum(self):
        service, client, config, params = provision()
        nonce = "A" * 43
        cap = "cap_0123456789abcdef01234567"
        context = {
            "deviceId": "dev", "executorId": "exec",
            "purpose": "attestation", "sessionId": "session",
        }
        self.assertTrue(client.call("nonce-create", "nonces", {
            "nonce": nonce, "context": context,
            "context_digest": digest(context),
            "issued_at": 1000, "expires_at": 5000,
        })["accepted"])
        self.assertTrue(client.call("nonce-consume", "nonces", {
            "nonce": nonce, "context_digest": digest(context), "now": 3000,
        })["accepted"])
        self.assertFalse(client.call("nonce-consume", "nonces", {
            "nonce": nonce, "context_digest": digest(context), "now": 3001,
        })["accepted"])
        auth = RemoteAuthorizationReplayStore(client, partition="authorizations")
        self.assertTrue(auth.consume("A" * 43, "b" * 64, 5000, 1000))
        self.assertFalse(auth.consume("A" * 43, "b" * 64, 5000, 1001))
        # Real transport and second independently initialized replica use
        # one global ordering and token keyspace.
        replica = EtcdSignedReplayService.connect(config, **params, bootstrap=False)
        def redeem(i):
            each_client = AuthenticatedReplayClient(
                client.signer, service.handle if i % 2 else replica.handle,
                service.public_key_pem, epoch=1,
            )
            return RemoteCapabilityConsumptionStore(
                each_client, partition="capabilities",
            ).consume(cap, "a"*64, 5000, 1000)
        with ThreadPoolExecutor(max_workers=8) as pool:
            attempts = list(pool.map(redeem, range(16)))
        self.assertEqual(attempts.count(True), 1, attempts)
        self.assertEqual(attempts.count(False), 15, attempts)
        self.assertEqual(service.checkpoint(), replica.checkpoint())
        self.assertEqual(service.checkpoint()[1], 21)
        self.assertFalse(
            RemoteCapabilityConsumptionStore(client, partition="capabilities")
            .consume(cap, "a"*64, 5000, 1001)
        )


if __name__ == "__main__":
    unittest.main()
