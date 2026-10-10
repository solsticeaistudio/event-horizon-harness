"""Deterministic signed etcd replay tests without Docker, plus live tests elsewhere."""
from __future__ import annotations

import base64
import copy
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.canonical import canonical_bytes, digest, strict_json_loads
from event_horizon.etcd_signed_replay import EtcdSignedReplayService
from event_horizon.remote_replay import (
    AuthenticatedReplayClient, ReplayClientPolicy, ReplayRequestSigner,
    HttpReplayTransport, ReplayHttpServer, ReplayProtocolError, ReplayStateError,
    ReplayUnavailableError, RemoteCapabilityConsumptionStore,
    RemoteAuthorizationReplayStore,
)

CID = "139003440588"
SID = "signed-remote-etcd"
NONCE = "A" * 43
CAP = "cap_0123456789abcdef01234567"


def b64(v):
    return base64.b64encode(v).decode("ascii")


class AtomicEtcd:
    """Simulates linearizable etcd v3 Txn, not actual Raft/network behavior."""

    def __init__(self):
        self.data = {}
        self.revision = 1
        self.lock = threading.RLock()
        self.available = True
        self.ambiguous = False
        self.raft_term = 1
        self.cluster_id = CID

    def __call__(self, txn):
        with self.lock:
            if not self.available:
                raise OSError("quorum unavailable")
            succeeded = True
            for cmp in txn["compare"]:
                key = cmp["key"]
                current = self.data.get(key)
                value = 0 if current is None else current[1] if cmp["target"] == "MOD" else current[2]
                target = int(cmp["mod_revision" if cmp["target"] == "MOD" else "version"])
                if cmp["result"] == "EQUAL":
                    succeeded = succeeded and value == target
                else:
                    raise AssertionError("unsupported fake compare")
            ops = txn["success"] if succeeded else txn["failure"]
            writes = any("requestPut" in op for op in ops)
            if writes:
                self.revision += 1
            response = []
            for op in ops:
                if "requestPut" in op:
                    p = op["requestPut"]
                    previous = self.data.get(p["key"])
                    self.data[p["key"]] = (
                        p["value"], self.revision, 1 if previous is None else previous[2] + 1,
                    )
                    response.append({"response_put": {}})
                elif "requestRange" in op:
                    key = op["requestRange"]["key"]
                    entry = self.data.get(key)
                    kvs = [] if entry is None else [{
                        "key": key, "value": entry[0],
                        "mod_revision": str(entry[1]),
                    }]
                    response.append({"response_range": {"kvs": kvs}})
                else:
                    raise AssertionError("unsupported fake operation")
            if self.ambiguous and writes:
                self.ambiguous = False
                raise TimeoutError("commit happened but response lost")
            result = {
                "header": {
                    "cluster_id": self.cluster_id,
                    "revision": str(self.revision),
                    "raft_term": str(self.raft_term),
                },
                "responses": response,
            }
            # etcd protobuf JSON may omit false booleans.
            if succeeded:
                result["succeeded"] = True
            return result


class SignedEtcdTests(unittest.TestCase):
    def setUp(self):
        self.etcd = AtomicEtcd()
        self.server_seed = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.client_seed = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        self.signer = ReplayRequestSigner(self.client_seed, SID)
        self.policy = ReplayClientPolicy.create(
            self.signer.public_key_pem,
            operations={
                "capability-consume", "authorization-consume",
                "nonce-create", "nonce-consume", "nonce-inspect",
            },
            partitions={"broker", "nonce", "auth"},
        )
        self.trusted_clock = {"seconds": 1.5}
        self.params = dict(
            transition_clock=lambda: self.trusted_clock["seconds"],
            expected_cluster_id=CID, namespace="study",
            service_id=SID, epoch=1, signing_key=self.server_seed,
            clients={self.policy.key_id: self.policy},
        )
        self.service = EtcdSignedReplayService(self.etcd, **self.params, bootstrap=True)

    def client(self, transport=None):
        return AuthenticatedReplayClient(
            self.signer, transport or self.service.handle,
            self.service.public_key_pem, epoch=1,
        )

    def test_capability_and_authorization_share_one_checkpoint_sequence(self):
        c = self.client()
        cap = RemoteCapabilityConsumptionStore(c, partition="broker")
        auth = RemoteAuthorizationReplayStore(c, partition="auth")
        self.assertTrue(cap.consume(CAP, "a" * 64, 5000, 1000))
        self.assertTrue(auth.consume(NONCE, "b" * 64, 5000, 1000))
        self.assertFalse(cap.consume(CAP, "a" * 64, 5000, 1000))
        self.assertFalse(auth.consume(NONCE, "b" * 64, 5000, 1000))
        self.assertEqual(c.checkpoint, 2)
        self.assertEqual(self.service.checkpoint()[1:], (2, c.checkpoint_digest))
        self.assertEqual(
            len([key for key in self.etcd.data if b"/checkpoint/" in base64.b64decode(key)]),
            3,
        )

    def test_nonce_lifecycle_binds_and_commits_state_and_checkpoint_together(self):
        c = self.client()
        context = {
            "deviceId": "device-1", "executorId": "exec-1",
            "purpose": "attest", "sessionId": "session-1",
        }
        create = {
            "nonce": NONCE, "context": context,
            "context_digest": digest(context), "issued_at": 1000, "expires_at": 2000,
        }
        self.assertTrue(c.call("nonce-create", "nonce", create)["accepted"])
        bad = c.call("nonce-consume", "nonce", {
            "nonce": NONCE, "context_digest": "f" * 64, "now": 1500,
        })
        self.assertEqual(bad["status"], "wrong-context")
        consumed = c.call("nonce-consume", "nonce", {
            "nonce": NONCE, "context_digest": digest(context), "now": 1500,
        })
        self.assertTrue(consumed["accepted"])
        self.assertEqual(consumed["result"]["record"]["state"], "consumed")
        self.assertFalse(c.call("nonce-consume", "nonce", {
            "nonce": NONCE, "context_digest": digest(context), "now": 1501,
        })["accepted"])
        self.assertEqual(c.checkpoint, 2)
        # On restart, no new bootstrap and no previous nonce disclosure.
        restarted = EtcdSignedReplayService(self.etcd, **self.params)
        self.assertEqual(restarted.checkpoint()[1:], self.service.checkpoint()[1:])
        self.assertEqual(c.call("nonce-inspect", "nonce", {"nonce": NONCE, "now": 1900})["status"], "found")

    def test_expiry_and_collision_semantics(self):
        c = self.client()
        context = {"deviceId": "d", "executorId": "e", "purpose": "p", "sessionId": "s"}
        creation = {
            "nonce": NONCE, "context": context,
            "context_digest": digest(context), "issued_at": 1000, "expires_at": 2000,
        }
        self.assertTrue(c.call("nonce-create", "nonce", creation)["accepted"])
        self.assertEqual(c.call("nonce-create", "nonce", creation)["status"], "already-exists")
        self.trusted_clock["seconds"] = 2.5
        expired = c.call("nonce-consume", "nonce", {
            "nonce": NONCE, "context_digest": digest(context), "now": 2500,
        })
        self.assertEqual(expired["status"], "expired")
        self.assertFalse(expired["accepted"])
        self.assertEqual(c.call("nonce-inspect", "nonce", {"nonce": NONCE, "now": 2600})["result"]["record"]["state"], "expired")

    def test_mutated_signature_and_unauthorized_partition_denied(self):
        req = self.signer.sign(
            operation="capability-consume", partition="broker",
            payload={"token": CAP, "binding_digest": "a" * 64,
                     "expires_at": 5000, "consumed_at": 1000},
            expected_epoch=1, minimum_checkpoint=0,
            minimum_checkpoint_digest=self.service.checkpoint()[2],
        )
        with self.assertRaises(ReplayProtocolError):
            self.service.handle({**req, "partition": "auth"})
        before = self.service.checkpoint()
        denied = self.client().call("capability-consume", "other", req["payload"])
        self.assertFalse(denied["accepted"])
        self.assertEqual(denied["status"], "client-not-authorized")
        self.assertEqual(before, self.service.checkpoint())

    def test_concurrent_competing_redeemers_exactly_one(self):
        def attempt(i):
            return RemoteCapabilityConsumptionStore(
                self.client(), partition="broker"
            ).consume(CAP, "c"*64, 5000, 1000)
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(attempt, range(24)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 23)
        self.assertEqual(self.service.checkpoint()[1], 1)

    def test_quorum_outage_and_ambiguous_response_fail_closed(self):
        c = self.client()
        self.etcd.available = False
        with self.assertRaises(ReplayUnavailableError):
            c.call("capability-consume", "broker", {
                "token": CAP, "binding_digest": "a"*64,
                "expires_at": 5000, "consumed_at": 1000,
            })
        self.etcd.available = True
        self.etcd.ambiguous = True
        with self.assertRaises(ReplayUnavailableError):
            c.call("capability-consume", "broker", {
                "token": CAP, "binding_digest": "a"*64,
                "expires_at": 5000, "consumed_at": 1000,
            })
        # No client signed accepted response, even though etcd committed.
        self.assertEqual(c.checkpoint, 0)
        self.assertEqual(self.service.checkpoint()[1], 1)
        self.assertFalse(RemoteCapabilityConsumptionStore(c, partition="broker").consume(CAP, "a"*64, 5000, 1000))

    def test_operator_rollback_cannot_satisfy_pinned_client(self):
        c = self.client()
        s = RemoteCapabilityConsumptionStore(c, partition="broker")
        self.assertTrue(s.consume(CAP, "a"*64, 5000, 1000))
        head_snapshot = copy.deepcopy(self.etcd.data)
        self.assertTrue(s.consume("cap_111111111111111111111111", "a"*64, 5000, 1000))
        self.etcd.data = head_snapshot
        with self.assertRaises(ReplayProtocolError):
            s.consume("cap_222222222222222222222222", "a"*64, 5000, 1000)

    def test_existing_signed_http_rpc_serves_atomic_etcd_authority(self):
        # EHH's external replay HTTP binding accepts the new backend with
        # no new unauthenticated protocol or client capability.
        server = ReplayHttpServer(self.service)
        server.start()
        try:
            client = self.client(HttpReplayTransport(server.url))
            store = RemoteCapabilityConsumptionStore(client, partition="broker")
            self.assertTrue(store.consume(CAP, "e"*64, 5000, 1000))
            self.assertFalse(store.consume(CAP, "e"*64, 5000, 1001))
            self.assertEqual(client.checkpoint, 1)
            self.assertEqual(self.service.checkpoint()[1], 1)
        finally:
            server.close()

    def test_bootstrap_explicit_wrong_signer_and_unauthorized_raft_op_fail(self):
        with self.assertRaises(ReplayStateError):
            EtcdSignedReplayService(
                self.etcd, **{**self.params, "signing_key": Ed25519PrivateKey.generate()}
            )
        with self.assertRaises(ReplayStateError):
            EtcdSignedReplayService(
                AtomicEtcd(), **self.params, bootstrap=False,
            )
        c = self.client()
        with self.assertRaises(ReplayProtocolError):
            c.call("raft-vote", "broker", {"term": 1})


    def test_server_clock_rejects_backdated_nonce_redemption(self):
        c = self.client()
        context = {
            "deviceId": "device", "executorId": "executor",
            "purpose": "attest", "sessionId": "session",
        }
        self.assertTrue(c.call("nonce-create", "nonce", {
            "nonce": NONCE, "context": context,
            "context_digest": digest(context),
            "issued_at": 1000, "expires_at": 2000,
        })["accepted"])
        self.trusted_clock["seconds"] = 2.5
        response = c.call("nonce-consume", "nonce", {
            "nonce": NONCE, "context_digest": digest(context),
            "now": 1500,  # A signed but stale client timestamp.
        })
        self.assertEqual(response["status"], "expired")
        self.assertFalse(response["accepted"])

    def test_no_op_denials_and_inspection_do_not_write_checkpoints(self):
        c = self.client()
        baseline = self.service.checkpoint()
        for _ in range(5):
            self.assertEqual(c.call("nonce-inspect", "nonce", {
                "nonce": NONCE, "now": 1500,
            })["status"], "unknown")
        self.assertEqual(self.service.checkpoint(), baseline)
        cap = RemoteCapabilityConsumptionStore(c, partition="broker")
        self.assertTrue(cap.consume(CAP, "f" * 64, 5000, 1500))
        committed = self.service.checkpoint()
        for _ in range(5):
            self.assertFalse(cap.consume(CAP, "f" * 64, 5000, 1500))
        self.assertEqual(self.service.checkpoint(), committed)

    def test_client_rate_budget_fails_closed_without_etcd_writes(self):
        params = {**self.params, "max_client_requests_per_minute": 2}
        limited = EtcdSignedReplayService(self.etcd, **params)
        c = self.client(limited.handle)
        for _ in range(2):
            self.assertEqual(c.call("nonce-inspect", "nonce", {
                "nonce": NONCE, "now": 1500,
            })["status"], "unknown")
        prior = limited.checkpoint()
        with self.assertRaises(ReplayProtocolError):
            c.call("nonce-inspect", "nonce", {"nonce": NONCE, "now": 1500})
        self.assertEqual(limited.checkpoint(), prior)


if __name__ == "__main__":
    unittest.main()
