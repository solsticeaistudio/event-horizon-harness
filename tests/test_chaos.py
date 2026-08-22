from __future__ import annotations

import unittest
import tempfile

from event_horizon.chaos import (
    EFFECT_COMMITTED_POINTS,
    FAULT_DISPOSITIONS,
    DeterministicChaosHarness,
    DeterministicFaultInjector,
    InjectedFault,
)
from event_horizon.factory import build_local_harness


class DeterministicChaosTests(unittest.TestCase):
    def test_every_named_fault_has_an_explicit_safe_disposition(self) -> None:
        harness = DeterministicChaosHarness()
        self.assertGreaterEqual(len(FAULT_DISPOSITIONS), 50)
        for point, disposition in FAULT_DISPOSITIONS.items():
            with self.subTest(point=point):
                result = harness.run(point)
                self.assertEqual(result.disposition, disposition)
                self.assertIn(
                    result.effect_state, {"not-committed", "committed", "indeterminate"}
                )
                if result.effect_state != "not-committed":
                    self.assertFalse(result.retry_permitted)

    def test_post_effect_faults_are_never_reported_as_denials(self) -> None:
        harness = DeterministicChaosHarness()
        for point in EFFECT_COMMITTED_POINTS:
            with self.subTest(point=point):
                result = harness.run(point)
                self.assertEqual(result.effect_state, "committed")
                self.assertIn(result.disposition, {"indeterminate", "reconcile"})

    def test_fault_injection_is_disabled_by_default_and_forbidden_in_production(self) -> None:
        inert = DeterministicFaultInjector({"executor.before-effect": 1})
        inert.hit("executor.before-effect")
        with self.assertRaises(PermissionError):
            DeterministicFaultInjector(
                {"executor.before-effect": 1}, enabled=True, environment="production"
            )

    def test_enabled_test_plan_is_deterministic_and_one_shot(self) -> None:
        injector = DeterministicFaultInjector(
            {"executor.before-effect": 2}, enabled=True, environment="test"
        )
        injector.hit("executor.before-effect")
        with self.assertRaises(InjectedFault) as raised:
            injector.hit("executor.before-effect")
        self.assertEqual(raised.exception.disposition, "deny")
        injector.hit("executor.before-effect")

    def test_unknown_fault_points_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            DeterministicFaultInjector({"unknown": 1}, enabled=True, environment="test")
        with self.assertRaises(ValueError):
            DeterministicChaosHarness().run("unknown")

    def test_pure_operation_post_effect_fault_is_provably_not_committed(self) -> None:
        # Migrated from the pre-purity-model behavior. object.read is an
        # architecturally declared pure operation, so a local fault after the
        # handler ran is positive proof that no external effect occurred.
        with tempfile.TemporaryDirectory() as directory:
            authority, executor, recorder, _broker = build_local_harness(directory)
            request, capability, attestation = authority.request_capability({
                "request_id": "chaos-request", "session_id": "chaos-session",
                "agent_id": "attacker-agent", "operation": "object.read",
                "resource_id": "target-source", "executor_id": "exec-1",
                "arguments": {"length": 1, "offset": 0}, "purpose": "chaos test",
            })
            executor.fault_injector = DeterministicFaultInjector(
                {"executor.after-effect": 1}, enabled=True, environment="test"
            )
            result = executor.execute(request, capability, attestation)
            self.assertFalse(result.success)
            self.assertEqual(result.effect_state, "not_committed")
            self.assertEqual(recorder.events()[-1]["event_type"], "execution.denied")

    def test_effectful_operation_post_effect_fault_stays_indeterminate(self) -> None:
        # compute.run handlers are potentially effectful: after the handler is
        # invoked, a local fault can never be reported as proof of no effect.
        with tempfile.TemporaryDirectory() as directory:
            authority, executor, recorder, _broker = build_local_harness(directory)
            request, capability, attestation = authority.request_capability({
                "request_id": "chaos-compute", "session_id": "chaos-session",
                "agent_id": "attacker-agent", "operation": "compute.run",
                "resource_id": "safe-hash", "executor_id": "exec-1",
                "arguments": {"value": "chaos"}, "purpose": "chaos test",
            })
            executor.fault_injector = DeterministicFaultInjector(
                {"executor.after-effect": 1}, enabled=True, environment="test"
            )
            result = executor.execute(request, capability, attestation)
            self.assertFalse(result.success)
            self.assertEqual(result.effect_state, "possibly_committed")
            self.assertIn("indeterminate effect state", result.error)
            self.assertEqual(recorder.events()[-1]["event_type"], "execution.indeterminate")


if __name__ == "__main__":
    unittest.main()
