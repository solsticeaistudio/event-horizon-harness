"""Portable safety checks for opt-in durable recipient gateway configuration."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.broker import capability_key_id
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class NoopRecorder:
    def append(self, *args, **kwargs):
        return {}


class DurableGatewayConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        key = Ed25519PrivateKey.generate().public_key()
        from cryptography.hazmat.primitives import serialization
        public = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.config = {
            "session_id": "session-fixture", "vm_uid": 60001,
            "dataset": "abcde", "resource_id": "synthetic-dataset",
            "authority_backend": "sqlite",
            "replay_database": str(root / "replay.sqlite"),
            "decay_database": str(root / "decay.sqlite"),
            "public_key_pem": public, "key_id": capability_key_id(key),
            "verification_context": {"tenant": "default", "environment": "synthetic"},
        }
        self.root = root

    def tearDown(self):
        self.temp.cleanup()

    def test_recipient_without_journal_is_rejected(self):
        self.config["recipient_socket"] = str(self.root / "receiver.sock")
        with self.assertRaises(ValueError):
            DatasetEffectBoundary(self.config, NoopRecorder())

    def test_journal_without_recipient_is_rejected(self):
        self.config["outcome_journal"] = str(self.root / "effects.sqlite")
        with self.assertRaises(ValueError):
            DatasetEffectBoundary(self.config, NoopRecorder())

    def test_external_effect_mode_constructs_durable_journal(self):
        self.config["recipient_socket"] = str(self.root / "receiver.sock")
        self.config["outcome_journal"] = str(self.root / "effects.sqlite")
        self.config["recipient_effect_key"] = "pinned-logical-effect"
        boundary = DatasetEffectBoundary(self.config, NoopRecorder())
        try:
            self.assertIsNotNone(boundary.gateway.outcome_journal)
            self.assertTrue((self.root / "effects.sqlite").exists())
        finally:
            boundary.close()

    def test_known_oversize_output_rejected_without_recipient_or_reservation(self):
        from types import SimpleNamespace
        from event_horizon.models import ActionRequest
        self.config["recipient_socket"] = str(self.root / "receiver.sock")
        self.config["outcome_journal"] = str(self.root / "effects.sqlite")
        self.config["recipient_effect_key"] = "a" * 64
        boundary = DatasetEffectBoundary(self.config, NoopRecorder())
        try:
            called = []
            boundary.gateway.effects["object.read"] = lambda request: called.append(request)
            class TrustedVerifier:
                def verify_and_consume(self, *args, **kwargs):
                    return SimpleNamespace(
                        capability_id="cap_one", max_output_bytes=2,
                    )
            boundary.gateway.verifier = TrustedVerifier()
            request = ActionRequest(
                "read-one", "session-fixture", "agent", "object.read",
                "synthetic-dataset", "exec-1",
                {"offset": 0, "length": 5}, "test oversized response",
            )
            capability = SimpleNamespace(claims=SimpleNamespace(capability_id="cap_one"))
            decision = boundary.gateway.execute(
                request, capability, {},
                executor_measurement="fixture", device_id="fixture",
                verifier_policy_digest="fixture", policy_digest="fixture",
            )
            self.assertFalse(decision.accepted)
            self.assertEqual(decision.effect_state, "not-started")
            self.assertEqual(decision.error_class, "pre-dispatch-denied")
            self.assertEqual(called, [])
            self.assertIsNone(boundary.outcome_journal.observe(
                tenant="default", environment="synthetic", capability_id="cap_one",
            ))
        finally:
            boundary.close()

    def test_baseline_mode_still_has_no_external_dispatch(self):
        boundary = DatasetEffectBoundary(self.config, NoopRecorder())
        try:
            self.assertIsNone(boundary.gateway.outcome_journal)
        finally:
            boundary.close()


if __name__ == "__main__":
    unittest.main()
