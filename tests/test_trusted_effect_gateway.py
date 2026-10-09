from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from event_horizon.models import ActionRequest
from event_horizon.replay_state import CapabilityConsumptionError
from event_horizon.trusted_effect_gateway import (
    TrustedEffectGateway, select_consumption_store
)


TOKEN = "cap_0123456789abcdef01234567"
DIGEST = "a" * 64


def request():
    return ActionRequest(
        request_id="gateway-test", session_id="session", agent_id="agent",
        operation="object.read", resource_id="synthetic", executor_id="executor",
        arguments={"offset": 0}, purpose="research",
    )


class FakeTrustedVerifier:
    def __init__(self, store):
        self.store = store

    def verify_and_consume(self, capability, request, **kwargs):
        accepted = self.store.consume(TOKEN, DIGEST, 5000, 1000)
        if not accepted:
            raise PermissionError("replay")


class OutageStore:
    def consume(self, *args):
        raise CapabilityConsumptionError("authority unavailable")


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.effects = []
        self.recorder = Mock()
        self.req = request()
        self.cap = SimpleNamespace(claims=SimpleNamespace(capability_id=TOKEN))
        self.args = dict(
            executor_measurement="synthetic",
            device_id="device",
            verifier_policy_digest="policy",
            policy_digest="static",
        )

    def gateway(self, store, effect=None):
        effect = effect or (lambda _: self.effects.append("effect") or "ok")
        return TrustedEffectGateway(
            FakeTrustedVerifier(store), {"object.read": effect}, self.recorder
        )

    def test_sqlite_gateway_consumes_before_effect_and_replay_cannot_execute_twice(self):
        path = Path(self.tmp.name) / "trusted-authority.sqlite"
        store = select_consumption_store(
            backend="sqlite", sqlite_path=str(path),
            namespace="test", domain="gateway",
        )
        gw = self.gateway(store)
        first = gw.execute(self.req, self.cap, {}, **self.args)
        self.assertTrue(first.accepted)
        self.assertEqual(first.effect_state, "completed")
        self.assertEqual(self.effects, ["effect"])
        store.close()
        restarted = select_consumption_store(
            backend="sqlite", sqlite_path=str(path),
            namespace="test", domain="gateway",
        )
        replay = self.gateway(restarted).execute(self.req, self.cap, {}, **self.args)
        self.assertFalse(replay.accepted)
        self.assertEqual(replay.effect_state, "not-started")
        self.assertEqual(self.effects, ["effect"])
        restarted.close()

    def test_quorum_outage_fails_before_any_effect(self):
        outcome = self.gateway(OutageStore()).execute(
            self.req, self.cap, {}, **self.args
        )
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.error_class, "authority-denied")
        self.assertEqual(self.effects, [])

    def test_evidence_outage_blocks_effect(self):
        path = Path(self.tmp.name) / "test-evidence.sqlite"
        store = select_consumption_store(
            backend="sqlite", sqlite_path=str(path),
            namespace="test", domain="gateway",
        )
        self.recorder.append.side_effect = OSError("recorder unavailable")
        outcome = self.gateway(store).execute(self.req, self.cap, {}, **self.args)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.effect_state, "not-started")
        self.assertEqual(self.effects, [])
        store.close()

    def test_effect_exception_is_indeterminate_and_never_retried(self):
        path = Path(self.tmp.name) / "test-failed-effect.sqlite"
        store = select_consumption_store(
            backend="sqlite", sqlite_path=str(path),
            namespace="test", domain="gateway",
        )
        def interrupted(_):
            self.effects.append("effect")
            raise RuntimeError("lost response")
        gw = self.gateway(store, interrupted)
        outcome = gw.execute(self.req, self.cap, {}, **self.args)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.effect_state, "possibly-committed")
        replay = gw.execute(self.req, self.cap, {}, **self.args)
        self.assertFalse(replay.accepted)
        self.assertEqual(self.effects, ["effect"])
        store.close()

    def test_unrecognized_operation_never_reaches_authority_or_effect(self):
        store = Mock()
        req = ActionRequest(
            request_id="unsupported", session_id="session", agent_id="agent",
            operation="shell.execute", resource_id="synthetic", executor_id="executor",
            arguments={}, purpose="research",
        )
        outcome = self.gateway(store).execute(req, self.cap, {}, **self.args)
        self.assertEqual(outcome.error_class, "unsupported-operation")
        store.consume.assert_not_called()
        self.assertEqual(self.effects, [])

    def test_backend_selection_has_no_silent_fallback(self):
        with self.assertRaises(ValueError):
            select_consumption_store(
                backend="etcd", namespace="test", domain="gateway",
                sqlite_path=str(Path(self.tmp.name) / "unsafe.sqlite"),
            )
        with self.assertRaises(ValueError):
            select_consumption_store(
                backend="memory", namespace="test", domain="gateway",
            )


if __name__ == "__main__":
    unittest.main()
