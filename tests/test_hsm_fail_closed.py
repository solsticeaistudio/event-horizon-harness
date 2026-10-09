from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.hsm_backend import HSMKeyInfo
from event_horizon.key_management import KeyManager, KeyManagementError


class FailedHSM:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        pem = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.info = HSMKeyInfo(
            key_id="synthetic-hsm-key", label="hsm-label",
            public_key_pem=pem, created_at="2026-01-01T00:00:00Z",
        )
        self.sign_calls = []

    def initialize(self):
        return None

    def get_public_key(self, label):
        return self.info

    def sign_ed25519(self, label, data):
        self.sign_calls.append(label)
        raise RuntimeError("HSM offline")

    def generate_ed25519_key(self, label, key_id):
        raise RuntimeError("HSM offline")


class HSMFailClosedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.backend = FailedHSM()
        self.manager = KeyManager(
            recorder=Mock(),
            db_path=Path(self.temp.name) / "keys.sqlite",
            hsm_backend=self.backend,
            hsm_key_label="hsm-label",
        )
        self.addCleanup(self.manager.close)

    def test_signer_does_not_fall_back_to_software_on_hsm_outage(self):
        with self.assertRaisesRegex(KeyManagementError, "refusing software fallback"):
            self.manager._sign({"purpose": "synthetic"})
        self.assertEqual(self.backend.sign_calls, ["hsm-label"])

    def test_key_generation_does_not_fall_back_on_hsm_outage(self):
        with self.assertRaisesRegex(KeyManagementError, "refusing software fallback"):
            self.manager.generate_key("synthetic")

    def test_key_rotation_refuses_untested_software_substitution(self):
        with self.assertRaisesRegex(KeyManagementError, "refusing software rotation"):
            self.manager.rotate_key("synthetic-hsm-key")

    def test_public_key_comes_from_configured_hsm(self):
        self.assertEqual(self.manager.public_key_pem, self.backend.info.public_key_pem)
        self.assertEqual(self.manager.key_id, self.backend.info.key_id)


if __name__ == "__main__":
    unittest.main()
