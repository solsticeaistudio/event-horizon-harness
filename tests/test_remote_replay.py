from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.canonical import digest
from event_horizon.remote_replay import (
    AuthenticatedReplayClient,
    HttpReplayTransport,
    ReferenceReplayService,
    RemoteAuthorizationReplayStore,
    RemoteCapabilityConsumptionStore,
    ReplayClientPolicy,
    ReplayHttpServer,
    ReplayProtocolError,
    ReplayRequestSigner,
    ReplayUnavailableError,
    genesis_checkpoint_digest,
)


SERVICE_ID = "event-horizon-replay"
CAPABILITIES = "capability.authority"
AUTHORIZATIONS = "protected.signer"
NONCES = "attestation.nonces"


class RemoteReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.server_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.client_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        self.signer = ReplayRequestSigner(self.client_key, SERVICE_ID)
        policy = ReplayClientPolicy.create(
            self.signer.public_key_pem,
            operations={
                "authorization-consume",
                "capability-consume",
                "nonce-consume",
                "nonce-create",
                "nonce-inspect",
            },
            partitions={CAPABILITIES, AUTHORIZATIONS, NONCES},
        )
        self.service = ReferenceReplayService(
            self.root / "authority.sqlite3",
            service_id=SERVICE_ID,
            epoch=1,
            signing_key=self.server_key,
            clients={policy.key_id: policy},
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temporary.cleanup()

    def client(self, transport=None) -> AuthenticatedReplayClient:
        return AuthenticatedReplayClient(
            self.signer,
            transport or self.service.handle,
            self.service.public_key_pem,
            epoch=1,
        )

    def test_capability_and_authorization_adapters_are_one_use(self) -> None:
        client = self.client()
        capabilities = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
        capability_id = "cap_0123456789abcdef01234567"
        self.assertTrue(capabilities.consume(capability_id, "a" * 64, 5000, 1000))
        self.assertFalse(capabilities.consume(capability_id, "a" * 64, 5000, 1001))

        authorizations = RemoteAuthorizationReplayStore(client, partition=AUTHORIZATIONS)
        nonce = "A" * 43
        self.assertTrue(authorizations.consume(nonce, "b" * 64, 5000, 1000))
        self.assertFalse(authorizations.consume(nonce, "b" * 64, 5000, 1001))

    def test_parallel_consumption_has_exactly_one_success(self) -> None:
        capability_id = "cap_abcdefabcdefabcdefabcdef"

        def consume(_index: int) -> bool:
            store = RemoteCapabilityConsumptionStore(self.client(), partition=CAPABILITIES)
            return store.consume(capability_id, "c" * 64, 5000, 1000)

        with ThreadPoolExecutor(max_workers=24) as executor:
            results = list(executor.map(consume, range(48)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 47)

    def test_collision_is_not_treated_as_an_ordinary_replay(self) -> None:
        store = RemoteCapabilityConsumptionStore(self.client(), partition=CAPABILITIES)
        capability_id = "cap_111111111111111111111111"
        self.assertTrue(store.consume(capability_id, "d" * 64, 5000, 1000))
        with self.assertRaisesRegex(RuntimeError, "collided"):
            store.consume(capability_id, "e" * 64, 5000, 1001)

    def test_nonce_lifecycle_preserves_context_and_atomic_transition(self) -> None:
        client = self.client()
        nonce = "A" * 43
        context = {
            "deviceId": "device-1",
            "executorId": "executor-1",
            "purpose": "capability-issue",
            "sessionId": "session-1",
        }
        context_digest = digest(context)
        created = client.call(
            "nonce-create",
            NONCES,
            {
                "nonce": nonce,
                "context": context,
                "context_digest": context_digest,
                "issued_at": 1000,
                "expires_at": 2000,
            },
        )
        self.assertTrue(created["accepted"])
        wrong = client.call(
            "nonce-consume",
            NONCES,
            {"nonce": nonce, "context_digest": "f" * 64, "now": 1500},
        )
        self.assertEqual(wrong["status"], "wrong-context")
        consumed = client.call(
            "nonce-consume",
            NONCES,
            {"nonce": nonce, "context_digest": context_digest, "now": 1500},
        )
        self.assertTrue(consumed["accepted"])
        self.assertEqual(consumed["result"]["record"]["context"], context)
        replay = client.call(
            "nonce-consume",
            NONCES,
            {"nonce": nonce, "context_digest": context_digest, "now": 1501},
        )
        self.assertEqual(replay["status"], "consumed")

    def test_request_signature_and_exact_fields_are_enforced(self) -> None:
        request = self.signer.sign(
            operation="capability-consume",
            partition=CAPABILITIES,
            payload={
                "token": "cap_222222222222222222222222",
                "binding_digest": "a" * 64,
                "expires_at": 5000,
                "consumed_at": 1000,
            },
            expected_epoch=1,
            minimum_checkpoint=0,
            minimum_checkpoint_digest=self.service.checkpoint()[2],
        )
        tampered = {**request, "partition": AUTHORIZATIONS}
        with self.assertRaisesRegex(ReplayProtocolError, "signature"):
            self.service.handle(tampered)
        with self.assertRaisesRegex(ReplayProtocolError, "fields"):
            self.service.handle({**request, "unknown": True})

    def test_client_policy_cannot_cross_an_operation_partition_boundary(self) -> None:
        client = self.client()
        response = client.call(
            "capability-consume",
            "capability.unconfigured",
            {
                "token": "cap_232323232323232323232323",
                "binding_digest": "a" * 64,
                "expires_at": 5000,
                "consumed_at": 1000,
            },
        )
        self.assertFalse(response["accepted"])
        self.assertEqual(response["status"], "client-not-authorized")

    def test_expired_unknown_client_and_server_key_substitution_fail_closed(self) -> None:
        payload = {
            "token": "cap_242424242424242424242424",
            "binding_digest": "a" * 64,
            "expires_at": 5000,
            "consumed_at": 1000,
        }
        expired_signer = ReplayRequestSigner(
            self.client_key,
            SERVICE_ID,
            now=lambda: 0.0,
        )
        expired = expired_signer.sign(
            operation="capability-consume",
            partition=CAPABILITIES,
            payload=payload,
            expected_epoch=1,
            minimum_checkpoint=0,
            minimum_checkpoint_digest=self.service.checkpoint()[2],
        )
        with self.assertRaisesRegex(ReplayProtocolError, "freshness"):
            self.service.handle(expired)

        unknown_signer = ReplayRequestSigner(Ed25519PrivateKey.generate(), SERVICE_ID)
        unknown = unknown_signer.sign(
            operation="capability-consume",
            partition=CAPABILITIES,
            payload=payload,
            expected_epoch=1,
            minimum_checkpoint=0,
            minimum_checkpoint_digest=self.service.checkpoint()[2],
        )
        with self.assertRaisesRegex(ReplayProtocolError, "not registered"):
            self.service.handle(unknown)

        wrong_server = Ed25519PrivateKey.generate().public_key()
        substituted = AuthenticatedReplayClient(
            self.signer,
            self.service.handle,
            wrong_server,
            epoch=1,
        )
        with self.assertRaisesRegex(ReplayProtocolError, "not pinned"):
            substituted.call("capability-consume", CAPABILITIES, payload)

    def test_response_forgery_and_request_substitution_fail_closed(self) -> None:
        def forged(request):
            response = self.service.handle(request)
            return {**response, "accepted": not response["accepted"]}

        store = RemoteCapabilityConsumptionStore(self.client(forged), partition=CAPABILITIES)
        with self.assertRaisesRegex(ReplayProtocolError, "signature"):
            store.consume("cap_333333333333333333333333", "a" * 64, 5000, 1000)

        saved_response = None

        def swapped(request):
            nonlocal saved_response
            current = self.service.handle(request)
            if saved_response is None:
                saved_response = current
                return current
            return saved_response

        client = self.client(swapped)
        first = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
        self.assertTrue(first.consume("cap_444444444444444444444444", "a" * 64, 5000, 1000))
        with self.assertRaisesRegex(ReplayProtocolError, "exact request"):
            first.consume("cap_555555555555555555555555", "a" * 64, 5000, 1000)

    def test_restored_old_database_is_detected_as_checkpoint_regression(self) -> None:
        client = self.client()
        store = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
        self.assertTrue(store.consume("cap_666666666666666666666666", "a" * 64, 5000, 1000))
        snapshot = self.root / "snapshot.sqlite3"
        self._backup(self.service.path, snapshot)
        self.assertTrue(store.consume("cap_777777777777777777777777", "a" * 64, 5000, 1000))

        stale = self._service_for(snapshot, epoch=1)
        try:
            client.transport = stale.handle
            with self.assertRaisesRegex(ReplayProtocolError, "regressed"):
                store.consume("cap_888888888888888888888888", "a" * 64, 5000, 1000)
        finally:
            stale.close()

    def test_fork_advanced_past_client_counter_cannot_replace_known_history(self) -> None:
        client = self.client()
        store = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
        self.assertTrue(store.consume("cap_676767676767676767676767", "a" * 64, 5000, 1000))
        snapshot = self.root / "fork.sqlite3"
        self._backup(self.service.path, snapshot)
        self.assertTrue(store.consume("cap_787878787878787878787878", "a" * 64, 5000, 1000))
        known_checkpoint = client.checkpoint
        known_digest = client.checkpoint_digest

        fork = self._service_for(snapshot, epoch=1)
        try:
            fork_store = RemoteCapabilityConsumptionStore(
                AuthenticatedReplayClient(
                    self.signer,
                    fork.handle,
                    fork.public_key_pem,
                    epoch=1,
                ),
                partition=CAPABILITIES,
            )
            for index in range(3):
                token = f"cap_{index + 80:024x}"
                self.assertTrue(fork_store.consume(token, "b" * 64, 5000, 1000))
            self.assertGreater(fork.checkpoint()[1], known_checkpoint)
            client.transport = fork.handle
            with self.assertRaisesRegex(ReplayProtocolError, "continuity"):
                store.consume("cap_898989898989898989898989", "a" * 64, 5000, 1000)
            self.assertEqual(client.checkpoint, known_checkpoint)
            self.assertEqual(client.checkpoint_digest, known_digest)
        finally:
            fork.close()

    def test_explicit_failover_preserves_checkpoint_and_rejects_stale_primary(self) -> None:
        client = self.client()
        store = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
        self.assertTrue(store.consume("cap_999999999999999999999999", "a" * 64, 5000, 1000))
        epoch, checkpoint, checkpoint_digest = self.service.checkpoint()
        self.assertEqual(epoch, 1)
        replica_path = self.root / "replica.sqlite3"
        self._backup(self.service.path, replica_path)
        promoted = self._service_for(replica_path, epoch=1)
        promoted_key = Ed25519PrivateKey.generate()
        promoted.promote(
            2,
            continuity_checkpoint=checkpoint,
            continuity_digest=checkpoint_digest,
            signing_key=promoted_key,
        )
        try:
            client.adopt_epoch(
                2,
                checkpoint=checkpoint,
                checkpoint_digest=checkpoint_digest,
                server_public_key=promoted.public_key_pem,
            )
            client.transport = promoted.handle
            promoted_store = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
            self.assertTrue(
                promoted_store.consume("cap_aaaaaaaaaaaaaaaaaaaaaaaa", "b" * 64, 5000, 1000)
            )
            promoted_checkpoint = client.checkpoint

            stale_client = AuthenticatedReplayClient(
                self.signer,
                self.service.handle,
                self.service.public_key_pem,
                epoch=2,
                checkpoint=checkpoint,
                checkpoint_digest=checkpoint_digest,
            )
            with self.assertRaisesRegex(ReplayProtocolError, "stale epoch"):
                RemoteCapabilityConsumptionStore(
                    stale_client,
                    partition=CAPABILITIES,
                ).consume("cap_bbbbbbbbbbbbbbbbbbbbbbbb", "b" * 64, 5000, 1000)
            self.assertGreater(promoted_checkpoint, checkpoint)
        finally:
            promoted.close()

    def test_zero_checkpoint_promotion_rebinds_genesis_to_the_new_epoch(self) -> None:
        empty_path = self.root / "empty-replica.sqlite3"
        empty = self._service_for(empty_path, epoch=1)
        old_digest = genesis_checkpoint_digest(SERVICE_ID, 1)
        try:
            empty.promote(
                2,
                continuity_checkpoint=0,
                continuity_digest=old_digest,
            )
            self.assertEqual(
                empty.checkpoint(),
                (2, 0, genesis_checkpoint_digest(SERVICE_ID, 2)),
            )
        finally:
            empty.close()

    def test_client_checkpoint_state_is_unambiguous(self) -> None:
        genesis = genesis_checkpoint_digest(SERVICE_ID, 1)
        omitted = self.client()
        self.assertEqual((omitted.checkpoint, omitted.checkpoint_digest), (0, genesis))
        explicit = AuthenticatedReplayClient(
            self.signer,
            self.service.handle,
            self.service.public_key_pem,
            epoch=1,
            checkpoint=0,
            checkpoint_digest=genesis,
        )
        self.assertEqual((explicit.checkpoint, explicit.checkpoint_digest), (0, genesis))

        invalid_states = (
            (-1, None),
            (0.5, None),
            (0, "a" * 64),
            (1, None),
            (1, "short"),
        )
        for checkpoint, checkpoint_digest in invalid_states:
            with self.subTest(checkpoint=checkpoint, checkpoint_digest=checkpoint_digest):
                with self.assertRaises(ReplayProtocolError):
                    AuthenticatedReplayClient(
                        self.signer,
                        self.service.handle,
                        self.service.public_key_pem,
                        epoch=1,
                        checkpoint=checkpoint,
                        checkpoint_digest=checkpoint_digest,
                    )

        omitted.adopt_epoch(2, checkpoint=0)
        self.assertEqual(
            (omitted.epoch, omitted.checkpoint, omitted.checkpoint_digest),
            (2, 0, genesis_checkpoint_digest(SERVICE_ID, 2)),
        )

    def test_epoch_adoption_rejects_rollback_and_fork(self) -> None:
        client = self.client()
        store = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
        self.assertTrue(store.consume("cap_eeeeeeeeeeeeeeeeeeeeeeee", "a" * 64, 5000, 1000))
        with self.assertRaisesRegex(ReplayProtocolError, "regresses"):
            client.adopt_epoch(
                2,
                checkpoint=0,
                checkpoint_digest=genesis_checkpoint_digest(SERVICE_ID, 2),
            )
        with self.assertRaisesRegex(ReplayProtocolError, "forks"):
            client.adopt_epoch(2, checkpoint=client.checkpoint, checkpoint_digest="a" * 64)

    def test_outage_fails_closed(self) -> None:
        def unavailable(_request):
            raise OSError("network unavailable")

        store = RemoteCapabilityConsumptionStore(self.client(unavailable), partition=CAPABILITIES)
        with self.assertRaises(ReplayUnavailableError):
            store.consume("cap_cccccccccccccccccccccccc", "a" * 64, 5000, 1000)

    def test_http_binding_uses_the_same_authenticated_contract(self) -> None:
        server = ReplayHttpServer(self.service)
        server.start()
        try:
            client = self.client(HttpReplayTransport(server.url))
            store = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
            self.assertTrue(store.consume("cap_dddddddddddddddddddddddd", "a" * 64, 5000, 1000))
            self.assertFalse(store.consume("cap_dddddddddddddddddddddddd", "a" * 64, 5000, 1001))
        finally:
            server.close()

    def test_server_key_rotation_updates_client_pinned_key(self) -> None:
        """Server key rotation can be adopted by client."""
        old_key_id = self.service.server_key_id
        new_key_id, new_pem = self.service.rotate_key()
        self.assertNotEqual(new_key_id, old_key_id)
        client = self.client()
        client.rotate_key(new_pem)
        store = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
        self.assertTrue(store.consume("cap_eeeeeeeeeeeeeeeeeeeeeeee", "a" * 64, 5000, 1000))
        self.assertFalse(store.consume("cap_eeeeeeeeeeeeeeeeeeeeeeee", "a" * 64, 5000, 1001))

    def test_server_key_rotation_with_explicit_key(self) -> None:
        """Server key rotation with explicit key material."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        old_key_id = self.service.server_key_id
        explicit_key = Ed25519PrivateKey.generate()
        new_key_id, new_pem = self.service.rotate_key(signing_key=explicit_key)
        self.assertNotEqual(new_key_id, old_key_id)
        client = self.client()
        client.rotate_key(new_pem)
        store = RemoteCapabilityConsumptionStore(client, partition=CAPABILITIES)
        self.assertTrue(store.consume("cap_ffffffffffffffffffffffff", "a" * 64, 5000, 1000))

    def test_tls_transport_requires_certificates(self) -> None:
        """TLS transport requires CA, client cert, and key."""
        with self.assertRaises(ValueError):
            HttpReplayTransport("https://example.com")
        with self.assertRaises(ValueError):
            HttpReplayTransport("https://example.com", ca_cert_path="/tmp/ca.pem")
        with self.assertRaises(ValueError):
            HttpReplayTransport("https://example.com", ca_cert_path="/tmp/ca.pem", client_cert_path="/tmp/cert.pem")

    def test_tls_server_requires_cert_and_key(self) -> None:
        """TLS server requires cert, key, and CA together."""
        with self.assertRaises(ValueError):
            ReplayHttpServer(self.service, certfile="/tmp/cert.pem")
        with self.assertRaises(ValueError):
            ReplayHttpServer(self.service, certfile="/tmp/cert.pem", keyfile="/tmp/key.pem")
        with self.assertRaises(ValueError):
            ReplayHttpServer(self.service, cafile="/tmp/ca.pem")

    def _service_for(self, path: Path, *, epoch: int) -> ReferenceReplayService:
        policy = ReplayClientPolicy.create(
            self.signer.public_key_pem,
            operations={
                "authorization-consume",
                "capability-consume",
                "nonce-consume",
                "nonce-create",
                "nonce-inspect",
            },
            partitions={CAPABILITIES, AUTHORIZATIONS, NONCES},
        )
        return ReferenceReplayService(
            path,
            service_id=SERVICE_ID,
            epoch=epoch,
            signing_key=self.server_key,
            clients={policy.key_id: policy},
        )

    @staticmethod
    def _backup(source: Path, destination: Path) -> None:
        source_database = sqlite3.connect(source)
        destination_database = sqlite3.connect(destination)
        try:
            source_database.backup(destination_database)
        finally:
            source_database.close()
            destination_database.close()


if __name__ == "__main__":
    unittest.main()
