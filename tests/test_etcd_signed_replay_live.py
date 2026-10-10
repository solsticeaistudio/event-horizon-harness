"""Live signed replay authority conformance against disposable three-node etcd.

RUN ONLY against explicit EHH_ETCD_ENDPOINT set by etcd-quorum CI. This
module does not provision production credentials or tolerate non-loopback
plaintext endpoints.
"""
from __future__ import annotations

import os
import tempfile
import unittest
import uuid
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
        self.assertTrue(auth.consume("B" * 43, "b" * 64, 5000, 1000))
        self.assertFalse(auth.consume("B" * 43, "b" * 64, 5000, 1001))
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
