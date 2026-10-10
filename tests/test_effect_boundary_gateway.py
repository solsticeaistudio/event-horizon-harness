from __future__ import annotations

import copy
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from event_horizon.broker import CapabilityBroker
from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.models import ActionRequest
from event_horizon.replay_state import CapabilityConsumptionError
from scripts.capability_fixture_support import authority_context, issue_options


class HostEffectBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.recorder = Mock()
        self.recorder.append.return_value = None
        self.request = ActionRequest(
            "host-read", "vm-session", "attacker-agent", "object.read",
            "synthetic-dataset", "exec-1", {"offset": 0, "length": 7}, "read fixture",
        )
        self.context = authority_context(self.request, time.time())
        self.broker = CapabilityBroker(b"trusted-gateway-test-fixture-key-32bytes", ttl_seconds=60)
        self.capability = self.broker.issue(
            self.request, **issue_options(self.context), max_output_bytes=4096,
        )
        self.config = {
            "verification_context": {
                **{k: self.context[k] for k in
                   ("device_id", "executor_measurement", "verifier_policy_digest",
                    "policy_digest", "attestation")},
                "tenant": "default",
                "environment": "synthetic",
            },
            "public_key_pem": self.broker.public_key_pem,
            "key_id": self.broker.key_id,
            "dataset": "sample-data",
            "session_id": self.request.session_id,
            "resource_id": self.request.resource_id,
            "vm_uid": 60000,
            "replay_database": str(Path(self.tmp.name) / "replay.sqlite"),
            "decay_database": str(Path(self.tmp.name) / "decay.sqlite"),
        }

    def message(self):
        return {
            "request": self.request.canonical_payload(),
            "capability": self.capability.to_dict(),
        }

    def test_genuine_host_gateway_executes_once_and_persists_after_restart(self):
        first = DatasetEffectBoundary(self.config, self.recorder)
        self.assertIsNotNone(first.gateway)
        self.assertEqual(first.backend, "sqlite")
        outcome = first.execute(self.message(), peer_uid=60000)
        self.assertTrue(outcome["success"], outcome)
        self.assertEqual(outcome["output"], "sample-")
        self.assertEqual(outcome["effect_state"], "completed")
        self.assertFalse(first.execute(self.message(), peer_uid=60000)["success"])
        first.close()
        second = DatasetEffectBoundary(self.config, self.recorder)
        try:
            denial = second.execute(self.message(), peer_uid=60000)
            self.assertFalse(denial["success"])
            self.assertEqual(denial["effect_state"], "not-started")
        finally:
            second.close()
        types = [call.args[0] for call in self.recorder.append.call_args_list]
        self.assertEqual(types.count("execution.completed"), 1)
        self.assertEqual(types.count("execution.authorized"), 1)
        self.assertIn("execution.denied", types)

    def test_forged_argument_peer_and_session_never_consume_authority(self):
        boundary = DatasetEffectBoundary(self.config, self.recorder)
        try:
            for attack in (
                {"request": {**self.message()["request"], "session_id": "other-session"},
                 "capability": self.message()["capability"]},
                {"request": {**self.message()["request"], "arguments": {"offset": 1, "length": 7}},
                 "capability": self.message()["capability"]},
            ):
                denial = boundary.execute(attack, peer_uid=60000)
                self.assertFalse(denial["success"])
                self.assertEqual(denial["effect_state"], "not-started")
            self.assertFalse(boundary.execute(self.message(), peer_uid=12345)["success"])
            self.assertTrue(boundary.execute(self.message(), peer_uid=60000)["success"])
        finally:
            boundary.close()
        self.assertEqual(
            [call.args[0] for call in self.recorder.append.call_args_list].count("execution.completed"),
            1,
        )

    def test_missing_recorder_blocks_dispatch_and_burns_capability(self):
        boundary = DatasetEffectBoundary(self.config, self.recorder)
        self.recorder.append.side_effect = RuntimeError("recorder unavailable")
        try:
            result = boundary.execute(self.message(), peer_uid=60000)
            self.assertFalse(result["success"])
            self.assertEqual(result["effect_state"], "not-started")
            self.recorder.append.side_effect = None
            replay = boundary.execute(self.message(), peer_uid=60000)
            self.assertFalse(replay["success"])
            self.assertEqual(replay["effect_state"], "not-started")
        finally:
            boundary.close()

    def test_selected_etcd_backend_denies_quorum_outage_without_sqlite_fallback(self):
        self.config.update({
            "authority_backend": "etcd",
            "etcd_gateway": {
                "endpoint": "http://127.0.0.1:2379",
                "allow_insecure_loopback": True,
            },
            "etcd_cluster_id": "123456789",
        })
        backend = Mock()
        backend.consume.side_effect = CapabilityConsumptionError("quorum unavailable")
        with patch("event_horizon.authority_backends.etcd_authority", return_value=backend) as factory:
            boundary = DatasetEffectBoundary(self.config, self.recorder)
            try:
                decision = boundary.execute(self.message(), peer_uid=60000)
                self.assertFalse(decision["success"])
                self.assertEqual(decision["effect_state"], "not-started")
                self.assertEqual(decision["error"], "authority-denied")
                self.assertEqual(
                    [c.args[0] for c in self.recorder.append.call_args_list].count("execution.completed"), 0
                )
                factory.assert_called_once()
                self.assertEqual(factory.call_args.kwargs["expected_cluster_id"], "123456789")
            finally:
                boundary.close()

    def test_unknown_backend_and_mixed_credential_config_refuse_startup(self):
        self.config["authority_backend"] = "memory"
        with self.assertRaises(ValueError):
            DatasetEffectBoundary(self.config, self.recorder)
        self.config["authority_backend"] = "sqlite"
        self.config["etcd_gateway"] = {"endpoint": "http://127.0.0.1:2379"}
        with self.assertRaises(ValueError):
            DatasetEffectBoundary(self.config, self.recorder)

    def test_guest_cannot_select_backend_or_transport_credentials(self):
        boundary = DatasetEffectBoundary(self.config, self.recorder)
        try:
            forged = self.message()
            forged["authority_backend"] = "memory"
            self.assertFalse(boundary.execute(forged, peer_uid=60000)["success"])
            self.assertTrue(boundary.execute(self.message(), peer_uid=60000)["success"])
        finally:
            boundary.close()


if __name__ == "__main__":
    unittest.main()
