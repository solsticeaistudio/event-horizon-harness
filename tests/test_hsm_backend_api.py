from __future__ import annotations

import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.hsm_backend import HSMKeyInfo, PKCS11Backend


class HSMBackendContractTests(unittest.TestCase):
    def test_public_key_lookup_returns_key_metadata_with_stable_identity(self):
        public_key = Ed25519PrivateKey.generate().public_key()
        backend = PKCS11Backend("synthetic-library")
        backend._initialized = True
        backend._pkcs11 = SimpleNamespace(
            ObjectClass=SimpleNamespace(PUBLIC_KEY="public"),
            KeyType=SimpleNamespace(ED25519="ed25519"),
        )
        backend._session = Mock()
        backend._session.get_key.return_value.export_public_key.return_value = public_key
        info = backend.get_public_key("test-label")
        self.assertIsInstance(info, HSMKeyInfo)
        self.assertEqual(info.label, "test-label")
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.assertEqual(info.key_id, "ed25519:" + hashlib.sha256(raw).hexdigest()[:32])
        self.assertIn("BEGIN PUBLIC KEY", info.public_key_pem)
        self.assertEqual(
            backend._session.get_key.call_args.kwargs,
            {"object_class": "public", "key_type": "ed25519", "label": "test-label"},
        )


if __name__ == "__main__":
    unittest.main()
