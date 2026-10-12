"""Portable tests of the real trusted boundary's separate process lifetime.

These use synthetic SQLite/local host state and do not claim Firecracker,
four-guardian signatures or externally trusted recorder provenance.
"""
from __future__ import annotations

import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_horizon.broker import capability_key_id

from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import exchange, GatewayTransportError


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux process transport")
class RealGatewaySubprocessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        config = {
            "recorder_path": str(root / "evidence.jsonl"),
            "boundary": {
                "session_id": "test-session",
                "vm_uid": 60001,
                "dataset": "name,value\nalpha,12\n",
                "resource_id": "synthetic-dataset",
                "authority_backend": "sqlite",
                "replay_database": str(root / "replay.sqlite"),
                "decay_database": str(root / "decay.sqlite"),
                "public_key_pem": public,
                "key_id": capability_key_id(private.public_key()),
                "verification_context": {"tenant": "default", "environment": "synthetic"},
            },
        }
        self.path = root / "trusted.json"
        self.path.write_text(json.dumps(config))

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_boundary_denies_malformed_request_in_different_pid(self):
        proc, channel = start_effect_gateway(self.path)
        try:
            # Invalid envelope is rejected by DatasetEffectBoundary, not
            # the transport's old diagnostic-only ping handler.
            reply = exchange(channel, {"unexpected": "guest-controlled"})
            self.assertFalse(reply["success"])
            self.assertEqual(reply["effect_state"], "not-started")
            # Multi-request gateway now exits only when the owning supervisor
            # closes its request stream. A single request is not a shutdown.
            channel.shutdown(1)
            self.assertEqual(proc.wait(timeout=5), 0)
            self.assertTrue((self.path.parent / "evidence.jsonl").is_file())
        finally:
            channel.close()
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            proc.stderr.close()

    def test_sigkill_closes_real_boundary_channel(self):
        proc, channel = start_effect_gateway(self.path)
        try:
            proc.kill()
            self.assertEqual(proc.wait(timeout=5), -signal.SIGKILL)
            with self.assertRaises(GatewayTransportError):
                exchange(channel, {"request": {}, "capability": {}})
        finally:
            channel.close()
            proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
