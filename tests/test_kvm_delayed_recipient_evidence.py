"""Reject fabricated or structurally invalid sixth-window crash evidence.

These are portable signed-recorder tests, not real Firecracker evidence.
"""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from event_horizon.canonical import digest
from event_horizon.recorder import ExternalRecorder
from scripts.verify_kvm_delayed_recipient_bridge import verify_delayed_bridge
from scripts.verify_integrated_kvm_delayed_commit import verify_report, SCHEMA, MODE


class SixthWindowEvidenceTests(unittest.TestCase):
    def build(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        recorder = ExternalRecorder(Path(temp.name) / "receipts.jsonl")
        original_digest = "a" * 64
        effect = "b" * 64
        empty = {"count": 0, "rows_digest": digest([])}
        final = {"count": 1, "rows_digest": digest([[effect, original_digest]])}
        pause = {
            "phase": "inflight_before_commit",
            "gateway_pid": 20001, "recipient_pid": 20002,
            "recipient_before": empty, "recipient_at_pause": empty,
            "journal_state": "possibly-committed",
            "effect_key": effect, "request_digest": original_digest,
        }
        death = {
            "phase": "inflight_before_commit",
            "gateway_pid": 20001, "signal": 9, "exit_code": -9,
            "recipient_at_kill": empty,
            "journal_state": "possibly-committed",
        }
        late = {
            "phase": "inflight_before_commit",
            "killed_gateway_pid": 20001, "recovery_gateway_pid": 20003,
            "recipient_pid": 20002, "signal": 9, "exit_code": -9,
            "before": empty, "at_pause": empty,
            "after_kill": empty, "before_release": empty,
            "after_release": final,
            "journal_state": "possibly-committed",
            "request_digest": original_digest, "effect_key": effect,
            "original_replay": {"success": False, "error": "authority-denied"},
            "replacement_replay": {
                "success": False, "effect_state": "possibly-committed",
                "error": "prior-effect-unknown",
            },
            "recipient_release_confirmed": True,
        }
        receipts = []
        def add(name, payload, source):
            receipts.append(recorder.append(name, payload, source_id=source)["receipt"])
        add("execution.authorized", {
            "request_id": "dataset-read",
            "request_digest": original_digest, "capability_id": "cap_primary",
        }, "host-effect-service")
        add("execution.dispatch", {
            "request_digest": original_digest, "dispatch_count": 1,
            "gateway_pid": 20001,
        }, "host-effect-service")
        add("recipient.inflight-observed", pause, "host-supervisor")
        add("gateway.delayed-sigkill-observed", death, "host-supervisor")
        add("execution.denied", {
            "request_id": "dataset-read",
            "error_class": "authority-denied",
            "effect_state": "not-started",
        }, "host-effect-service")
        add("recipient.delayed-commit-observed", late, "host-supervisor")
        good, tip = recorder.verify()
        self.assertTrue(good)
        return late, recorder.events(), receipts, tip, recorder.public_key_pem, original_digest, effect

    def invoke(self, state):
        late, events, receipts, tip, pem, req, effect = state
        return verify_delayed_bridge(
            report=late, events=events, receipts=receipts,
            tip=tip, public_key_pem=pem,
            request_digest=req, effect_key=effect,
        )

    def test_correctly_signed_inflight_then_sigkill_then_commit(self):
        self.assertTrue(self.invoke(self.build()))

    def test_absence_cannot_be_misrepresented_as_final_commit(self):
        state = list(self.build())
        state[0] = copy.deepcopy(state[0])
        state[0]["after_release"] = state[0]["before"]
        with self.assertRaises(ValueError):
            self.invoke(state)

    def test_replaying_a_fresh_capability_as_success_is_rejected(self):
        state = list(self.build())
        state[0] = copy.deepcopy(state[0])
        state[0]["replacement_replay"] = {
            "success": True, "effect_state": "completed", "error": None,
        }
        with self.assertRaises(ValueError):
            self.invoke(state)

    def test_missing_signed_commit_observation_is_rejected(self):
        state = list(self.build())
        state[1] = state[1][:-1]
        state[2] = state[2][:-1]
        state[3] = state[1][-1]["event_hash"]
        with self.assertRaises(ValueError):
            self.invoke(state)

    def test_portable_data_cannot_claim_firecracker_proof(self):
        for report in ({}, {"schema": SCHEMA, "experiment_mode": MODE,
                            "status": "PASS", "rounds": []}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                verify_report(report)


if __name__ == "__main__":
    unittest.main()
