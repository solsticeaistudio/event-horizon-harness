from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from event_horizon.executor import SacrificialExecutor
from event_horizon.models import ActionRequest


class ExecutionOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.effects = []
        self.broker = Mock()
        self.broker.verify_and_consume.return_value = SimpleNamespace(
            capability_id="cap_synthetic", max_output_bytes=96
        )
        self.recorder = Mock()
        self.executor = SacrificialExecutor(
            executor_id="executor", device_id="device",
            measurement="synthetic-measurement",
            verifier_policy_digest="policy-digest",
            policy_digest="static-policy-digest",
            broker=self.broker, recorder=self.recorder,
        )
        self.request = ActionRequest(
            request_id="request", session_id="session", agent_id="agent",
            operation="compute.run", resource_id="approved-compute",
            executor_id="executor", arguments={}, purpose="test",
        )

    def run_effect(self, callback):
        self.executor.compute_profiles["approved-compute"] = callback
        return self.executor.execute(self.request, Mock(), {})

    def test_effect_then_callback_failure_is_indeterminate(self):
        def effect(_):
            self.effects.append("committed")
            raise RuntimeError("response handler failed")

        result = self.run_effect(effect)
        self.assertFalse(result.success)
        self.assertEqual(self.effects, ["committed"])
        self.assertEqual(result.effect_state, "possibly-committed")
        self.assertEqual(self.recorder.append.call_args.args[0], "execution.indeterminate")

    def test_effect_then_oversized_output_is_not_reported_as_no_effect(self):
        def effect(_):
            self.effects.append("committed")
            return "x" * 2048

        result = self.run_effect(effect)
        self.assertFalse(result.success)
        self.assertEqual(self.effects, ["committed"])
        self.assertEqual(result.effect_state, "possibly-committed")
        self.assertEqual(self.recorder.append.call_args.args[0], "execution.indeterminate")

    def test_effect_then_circular_result_is_indeterminate(self):
        def effect(_):
            self.effects.append("committed")
            cyclic = []
            cyclic.append(cyclic)
            return cyclic

        result = self.run_effect(effect)
        self.assertFalse(result.success)
        self.assertEqual(result.effect_state, "possibly-committed")
        self.assertEqual(self.recorder.append.call_args.args[0], "execution.indeterminate")

    def test_effect_then_evidence_recorder_outage_is_indeterminate(self):
        self.recorder.append.side_effect = OSError("recorder unavailable")
        def effect(_):
            self.effects.append("committed")
            return "ok"

        result = self.run_effect(effect)
        self.assertFalse(result.success)
        self.assertEqual(self.effects, ["committed"])
        self.assertEqual(result.effect_state, "possibly-committed")

    def test_success_requires_completion_record(self):
        result = self.run_effect(lambda _: {"ok": True})
        self.assertTrue(result.success)
        self.assertEqual(result.effect_state, "completed")
        self.assertEqual(self.recorder.append.call_args.args[0], "execution.completed")

    def test_pre_dispatch_denial_has_not_started(self):
        self.broker.verify_and_consume.side_effect = PermissionError("denied")
        result = self.run_effect(lambda _: self.effects.append("never"))
        self.assertFalse(result.success)
        self.assertEqual(result.effect_state, "not-started")
        self.assertEqual(self.effects, [])
        self.assertEqual(self.recorder.append.call_args.args[0], "execution.denied")


if __name__ == "__main__":
    unittest.main()
