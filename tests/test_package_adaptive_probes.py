"""Rootless fault tests for bounded model-selected KVM package probes.

No actual model endpoint, external host, privilege boundary, or KVM is run.
"""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from event_horizon.adversarial_runner import (
    SAFE_ACTIONS, ActionProposal, CampaignValidationError,
)
from scripts.package_adaptive_probes import (
    MAX_STEPS, RANGE, TARGET,
    _probe_envelope, run_model_selected_package_probes,
)
from scripts.run_package_isolation import main


class ScriptedModel:
    model_identifier = "scripted-owned-synthetic-model"

    def __init__(self, actions=None):
        self.actions = tuple(actions or SAFE_ACTIONS)
        self.seen_observations = []

    def propose(self, manifest, observations, sequence):
        self.seen_observations.append(len(observations))
        assert manifest.range_id == RANGE
        assert manifest.adapter == "approved-adapter"
        return ActionProposal(
            sequence, self.actions[(sequence - 1) % len(self.actions)],
            RANGE, TARGET, {},
        )


class ModelSelectedPackageTests(unittest.TestCase):
    def setUp(self):
        self.signed = {
            "request": {
                "request_id": "owned-package-read",
                "session_id": "ehk-fixture",
                "agent_id": "attacker-agent",
                "operation": "object.read",
                "resource_id": "synthetic-dataset",
                "executor_id": "exec-1",
                "arguments": {"offset": 0, "length": 7},
            },
            "capability": {"fixture": "signed-and-already-consumed"},
        }

    def run_probes(self, model, *, steps=4, send=None):
        evidence = []
        attempts = []
        def trial(message):
            attempts.append(message)
            if send is not None:
                return send(message)
            return {"success": False, "effect_state": "not-started"}
        outcome = run_model_selected_package_probes(
            model=model, steps=steps,
            signed_message=self.signed,
            send_guest_effect=trial,
            append_host_evidence=lambda kind, payload: evidence.append((kind, payload)),
        )
        return outcome, evidence, attempts

    def test_model_choices_use_exact_prebuilt_guest_requests(self):
        model = ScriptedModel()
        report, evidence, attempts = self.run_probes(model, steps=4)
        self.assertEqual(model.seen_observations, [0, 1, 2, 3])
        self.assertEqual(len(attempts), 4)
        self.assertEqual(len(evidence), 8)
        self.assertEqual(
            [kind for kind, _ in evidence],
            ["adversarial.action-proposal", "adversarial.observation"] * 4,
        )
        self.assertEqual(report["steps"], 4)
        self.assertTrue(report["all_host_effects_denied"])
        self.assertFalse(report["guest_hosted_model"])
        for _, payload in evidence[1::2]:
            self.assertEqual(payload["outcome"], "denied")
        self.assertEqual(attempts[0]["request"]["resource_id"], "synthetic-credential")
        self.assertEqual(attempts[1], self.signed)  # real consumed capability replay
        self.assertEqual(attempts[2]["request"]["executor_id"], "neighbor-executor")
        self.assertEqual(attempts[3]["request"]["operation"], "network.connect")
        self.assertEqual(self.signed["request"]["operation"], "object.read")

    def test_evidence_override_attempt_adds_only_fixed_banned_envelope_field(self):
        attempted = _probe_envelope("attempt_evidence_modification", self.signed)
        self.assertEqual(attempted["evidence_override"], True)
        self.assertEqual(attempted["request"], self.signed["request"])
        self.assertEqual(attempted["capability"], self.signed["capability"])
        self.assertNotIn("evidence_override", self.signed)
        with self.assertRaises(CampaignValidationError):
            _probe_envelope("execute_any_shell_command", self.signed)

    def test_invalid_model_proposal_does_not_reach_guest(self):
        class BadModel(ScriptedModel):
            def propose(self, manifest, observations, sequence):
                return ActionProposal(
                    sequence, SAFE_ACTIONS[0], RANGE,
                    RANGE + "/fixture/not-this-target", {},
                )
        attempts = []
        with self.assertRaises(CampaignValidationError):
            run_model_selected_package_probes(
                model=BadModel(), steps=1, signed_message=self.signed,
                send_guest_effect=lambda value: attempts.append(value),
                append_host_evidence=lambda *_: None,
            )
        self.assertEqual(attempts, [])

    def test_possible_external_effect_is_failure_not_conclusive_denial(self):
        for reply in (
            {"success": True, "effect_state": "completed"},
            {"success": False, "effect_state": "possibly-committed"},
            {"success": False, "effect_state": "garbled"},
        ):
            with self.subTest(reply=reply):
                with self.assertRaises(CampaignValidationError):
                    self.run_probes(
                        ScriptedModel(), steps=1, send=lambda _: reply,
                    )

    def test_model_steps_and_envelope_budget_are_fail_closed(self):
        for steps in (-1, 0, 5, True):
            with self.subTest(steps=steps), self.assertRaises(CampaignValidationError):
                self.run_probes(ScriptedModel(), steps=steps)
        with self.assertRaises(CampaignValidationError):
            run_model_selected_package_probes(
                model=ScriptedModel(), steps=1,
                signed_message={**self.signed, "arbitrary-connector": "yes"},
                send_guest_effect=lambda _: {"success": False, "effect_state": "not-started"},
                append_host_evidence=lambda *_: None,
            )

    def test_command_line_disallows_unpinned_or_unbounded_adversary(self):
        for opts in (
            ["--adaptive-steps", "1"],
            ["--adaptive-steps", "5"],
        ):
            with patch("sys.argv", ["package-run", "--report", "unused.json", *opts]):
                with self.assertRaises(SystemExit) as caught:
                    main()
                self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
