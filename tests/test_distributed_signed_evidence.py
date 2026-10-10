from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.distributed_signed_evidence import (
    DistributedEvidenceError, REQUIRED_CASES, SCHEMA, STRICT_SCHEMA, verify_distributed_report,
)
from event_horizon.recorder import ExternalRecorder


class DistributedSignedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        recorder = ExternalRecorder(
            Path(self.temp.name) / "evidence.jsonl",
            signing_key=Ed25519PrivateKey.generate(),
        )
        events = [
            recorder.append("capability.issued", {"request_id": f"request-{n}"})
            for n in range(2)
        ]
        events += [
            recorder.append("execution.completed", {
                "request_id": f"request-{n}", "success": True,
            }) for n in range(2)
        ]
        for case in sorted(REQUIRED_CASES):
            events.append(recorder.append(
                "adversarial.observation", {"case": case, "passed": True},
                source_id="coordinator",
            ))
        okay, tip = recorder.verify()
        self.assertTrue(okay)
        self.key = recorder.public_key_pem
        self.report = {
            "schema": SCHEMA,
            "topology": "same-host-seven-process-live-etcd",
            "hardware_isolation_tested": False,
            "etcd_backend_tested": True,
            "observations": {case: True for case in REQUIRED_CASES},
            "passed": True,
            "signed_evidence": {
                "recorder_public_key_pem": self.key,
                "event_count": len(events),
                "events": events,
                "chain_tip": tip,
            },
        }

    def test_complete_signed_evidence_valid_without_exaggerating_claims(self):
        result = verify_distributed_report(self.report)
        self.assertTrue(result["verified"])
        self.assertTrue(result["passed"])
        self.assertFalse(result["hardware_isolation_tested"])
        self.assertFalse(result["authenticated_recorder_identity"])
        result = verify_distributed_report(
            self.report, pinned_recorder_public_key=self.key,
        )
        self.assertTrue(result["authenticated_recorder_identity"])

    def test_tampered_reports_fail(self):
        for attack in (
            "wrong-pin", "changed-observation", "forged-signature",
            "missing-event", "false-pass", "fake-hardware", "spoofed-key",
            "changed-completion",
        ):
            report = copy.deepcopy(self.report)
            pinned = None
            if attack == "wrong-pin":
                pinned = "different public key"
            elif attack == "changed-observation":
                report["observations"]["valid_effect"] = False
            elif attack == "forged-signature":
                report["signed_evidence"]["events"][0]["receipt"]["signature"] = "invalid"
            elif attack == "missing-event":
                report["signed_evidence"]["events"].pop()
                report["signed_evidence"]["event_count"] -= 1
            elif attack == "false-pass":
                report["passed"] = False
            elif attack == "fake-hardware":
                report["hardware_isolation_tested"] = True
            elif attack == "spoofed-key":
                report["signed_evidence"]["recorder_public_key_pem"] = "forged"
            elif attack == "changed-completion":
                report["signed_evidence"]["events"][3]["event_type"] = "execution.denied"
            with self.subTest(attack=attack), self.assertRaises(DistributedEvidenceError):
                verify_distributed_report(report, pinned_recorder_public_key=pinned)


    def _strict_report(self, *, corrupted_replay=False, missing_context=False):
        recorder = ExternalRecorder(
            Path(self.temp.name) / ("strict-bad" if corrupted_replay else "strict-good"),
            signing_key=Ed25519PrivateKey.generate(),
        )
        events = []
        first = "distributed-7-process"
        second = "during-authority-outage"
        events.append(recorder.append("capability.issued", {"request_id": first}))
        outcomes = [
            (first, True, "completed"),
            (first, corrupted_replay, "completed" if corrupted_replay else "not-started"),
            (first, False, "not-started"),
        ]
        for request_id, success, state in outcomes:
            events.append(recorder.append(
                "execution.completed" if success else "execution.denied",
                {"request_id": request_id, "success": success, "effect_state": state},
                source_id="coordinator",
            ))
        events.append(recorder.append("capability.issued", {"request_id": second}))
        for request_id, success, state in [
            (second, True, "completed"),
            (second, False, "not-started"),
            (first, False, "not-started"),
        ]:
            events.append(recorder.append(
                "execution.completed" if success else "execution.denied",
                {"request_id": request_id, "success": success, "effect_state": state},
                source_id="coordinator",
            ))
        probes = {
            "executor_credential_probe": {
                "private_key_material_present": False,
                "ambient_authority_environment_hits": [],
                "executor_config_has_remote_replay": False,
            },
            "authority_outage": {"success": False, "effect_state": "not-started", "evidence_gap": "authority-unavailable"},
            "unsigned_signer_mutation": {"denied": True},
            "guardian_veto": {"denied": True, "request_id": "forbidden-distributed-op"},
            "signed_certificate": {
                "certificate_schema": "event-horizon.containment-certificate.v0.5",
            },
        }
        for case, observation in probes.items():
            events.append(recorder.append(
                "adversarial.probe", {"case": case, "observation": observation},
                source_id="coordinator",
            ))
        if not missing_context:
            events.append(recorder.append("distributed.authority.context", {
                "cluster_id": "1001", "service_id": "test-etcd",
                "epoch": 1, "checkpoint": 12, "checkpoint_digest": "e" * 64,
            }, source_id="coordinator"))
        for case in sorted(REQUIRED_CASES):
            events.append(recorder.append("adversarial.observation", {
                "case": case, "passed": True,
            }, source_id="coordinator"))
        valid, tip = recorder.verify()
        self.assertTrue(valid)
        return {
            "schema": STRICT_SCHEMA,
            "topology": "same-host-seven-process-live-etcd",
            "hardware_isolation_tested": False,
            "etcd_backend_tested": True,
            "observations": {case: True for case in REQUIRED_CASES},
            "passed": True,
            "signed_evidence": {
                "recorder_public_key_pem": recorder.public_key_pem,
                "event_count": len(events), "events": events, "chain_tip": tip,
            },
        }

    def test_strict_report_derives_execution_cases_and_signs_context(self):
        result = verify_distributed_report(self._strict_report())
        self.assertTrue(result["passed"])
        self.assertEqual(result["event_derived_execution_cases"], 6)
        self.assertEqual(result["signed_coordinator_probe_cases"], 5)
        self.assertTrue(result["signed_authority_context"])
        self.assertFalse(result["independent_cluster_attestation"])

    def test_strict_report_rejects_coordinator_pass_without_primary_proof(self):
        for issue in ("corrupted_replay", "missing_context"):
            with self.subTest(issue=issue), self.assertRaises(DistributedEvidenceError):
                verify_distributed_report(self._strict_report(**{issue: True}))


if __name__ == "__main__":
    unittest.main()
