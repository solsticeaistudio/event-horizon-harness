from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.protected_boundary import load_private_seed
from event_horizon.remote_replay import (
    ReferenceReplayService, ReplayHttpServer, RemoteCapabilityConsumptionStore,
)
from event_horizon.trusted_replay_client import (
    provision_replay_client_policies, remote_client, role_remote_settings,
    role_client_seed_path,
)


class RoleReplayIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.service_id = "scope-replay-service"
        self.policies = provision_replay_client_policies(self.root, self.service_id)
        self.service = ReferenceReplayService(
            self.root / "authority.sqlite3",
            service_id=self.service_id, epoch=1,
            signing_key=Ed25519PrivateKey.generate(),
            clients={p.key_id: p for p in self.policies.values()},
        )
        self.http = ReplayHttpServer(self.service)
        self.http.start()
        self.authority = {
            "url": self.http.url, "service_id": self.service_id, "epoch": 1,
            "server_public_key_pem": self.service.public_key_pem,
            "ca_cert_path": None, "client_cert_path": None, "client_key_path": None,
        }

    def tearDown(self):
        self.http.close()
        self.service.close()

    def config(self, role="signer"):
        return role_remote_settings(self.root, role, self.authority)

    def test_distinct_scoped_identity_per_trusted_role_not_executor(self):
        self.assertEqual(set(self.policies), {"verifier", "signer", "recorder", "certificate"})
        self.assertEqual(len({p.key_id for p in self.policies.values()}), 4)
        self.assertEqual(self.policies["verifier"].operations,
                         {"nonce-create", "nonce-consume", "nonce-inspect"})
        self.assertEqual(self.policies["signer"].operations,
                         {"capability-consume", "authorization-consume"})
        for role in self.policies:
            self.assertEqual(len(load_private_seed(role_client_seed_path(self.root, role))), 32)
        with self.assertRaises(ValueError):
            role_remote_settings(self.root, "executor", self.authority)

    def test_checkpoint_survives_trusted_client_restart(self):
        config = self.config()
        first = remote_client(config)
        store = RemoteCapabilityConsumptionStore(first, partition="capability.authority")
        self.assertTrue(store.consume("cap_0123456789abcdef01234567", "a"*64, 5000, 1000))
        self.assertEqual(first.checkpoint, 1)
        checkpoint = Path(config["checkpoint_state_path"])
        self.assertTrue(checkpoint.is_file())
        restart = remote_client(config)
        self.assertEqual((restart.checkpoint, restart.checkpoint_digest),
                         (first.checkpoint, first.checkpoint_digest))
        self.assertFalse(
            RemoteCapabilityConsumptionStore(restart, partition="capability.authority")
            .consume("cap_0123456789abcdef01234567", "a"*64, 5000, 1001)
        )
        self.assertEqual(restart.checkpoint, 2)

    def test_key_substitution_and_plaintext_external_endpoint_fail_closed(self):
        config = self.config()
        self.authority["url"] = "http://10.1.2.3:2379/v1/transition"
        with self.assertRaisesRegex(ValueError, "plaintext"):
            self.config()
        self.authority["url"] = self.http.url
        changed = dict(config, server_public_key_pem="forged")
        with self.assertRaises(ValueError):
            remote_client(changed)

    def test_invalid_checkpoint_witness_rejected_not_reset(self):
        config = self.config()
        state = Path(config["checkpoint_state_path"])
        state.write_text('{"bad":true}', encoding="utf-8")
        with self.assertRaises(RuntimeError):
            remote_client(config)

    def test_remote_verifier_client_has_restricted_pem_not_guest(self):
        config = self.config("verifier")
        pem = Path(config["client_private_key_pem_path"])
        self.assertTrue(pem.is_file())
        self.assertFalse((self.root / "executor-state" / "replay-client-executor.seed").exists())
        self.assertIn("PRIVATE KEY", pem.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
