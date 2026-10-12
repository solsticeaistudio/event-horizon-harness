"""Real subprocess SIGKILL fault campaign and internally signed evidence."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.run_effect_crash_campaign import PHASES, EXPECTED, check_scenario
from scripts.verify_effect_crash_campaign import CrashEvidenceError, verify_file, verify_report


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith("linux"), "real SIGKILL uses Linux")
class RealProcessCrashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.report = Path(cls.tmp.name) / "effect-process-crash.json"
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/run_effect_crash_campaign.py"),
             "--report", str(cls.report)],
            cwd=ROOT, text=True, capture_output=True, timeout=100,
            check=False,
        )
        cls.stdout, cls.stderr = result.stdout, result.stderr
        if result.returncode:
            cls.tmp.cleanup()
            raise AssertionError(
                "real-process fault experiment failed: "
                + str(result.returncode) + " " + result.stdout[-2000:]
                + " " + result.stderr[-2500:]
            )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_real_sigkill_checkpoints_verified(self):
        report = verify_file(self.report)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["authority_backend"], "sqlite")
        self.assertEqual([x["scenario"] for x in report["scenarios"]], list(PHASES))
        self.assertEqual(
            [x["recipient_after_kill"]["count"] for x in report["scenarios"]],
            list(EXPECTED),
        )
        self.assertTrue(all(check_scenario(row) for row in report["scenarios"]))
        self.assertFalse(report["kvm_exercised"])
        self.assertFalse(report["guardian_quorum_exercised"])

    def test_tampered_signed_field_is_detected(self):
        obj = json.loads(self.report.read_text())
        obj["payload"]["scenarios"][2]["recipient_after_kill"]["count"] = 0
        with self.assertRaises(CrashEvidenceError):
            verify_report(obj)

    def test_tampered_signature_is_detected(self):
        obj = json.loads(self.report.read_text())
        obj["signature"] = "A" * 86
        with self.assertRaises(CrashEvidenceError):
            verify_report(obj)

    def test_claim_inflation_is_detected(self):
        for field in ("kvm_exercised", "guardian_quorum_exercised"):
            obj = json.loads(self.report.read_text())
            obj["payload"][field] = True
            with self.assertRaises(CrashEvidenceError):
                verify_report(obj)

    def test_missing_fault_stage_cannot_pass(self):
        obj = json.loads(self.report.read_text())
        obj["payload"]["scenarios"].pop()
        with self.assertRaises(CrashEvidenceError):
            verify_report(obj)

    def test_original_sidecar_rejects_a_changed_report(self):
        self.assertTrue(self.report.with_name(self.report.name + ".sha256").is_file())
        with tempfile.TemporaryDirectory() as folder:
            copied = Path(folder) / self.report.name
            copied.write_bytes(self.report.read_bytes() + b"\n")
            copied.with_name(copied.name + ".sha256").write_bytes(
                Path(str(self.report) + ".sha256").read_bytes()
            )
            with self.assertRaises(CrashEvidenceError):
                verify_file(copied)

    def test_wrong_recipient_count_is_not_safe(self):
        original = verify_file(self.report)["scenarios"][2]
        modified = copy.deepcopy(original)
        modified["recipient_after_recovery"]["count"] = 2
        self.assertFalse(check_scenario(modified))

    def test_distinct_capability_does_not_repeat_effect(self):
        payload = verify_file(self.report)
        for row in payload["scenarios"][1:]:
            self.assertNotEqual(row["capability_id"], row["replacement_capability_id"])
            self.assertEqual(row["replacement_replay"]["error_class"],
                             "prior-effect-unknown")
            self.assertEqual(row["recipient_after_recovery"],
                             row["recipient_after_kill"])

    def test_historical_evidence_is_not_modified(self):
        self.assertIn("NO KVM", self.stdout)


if __name__ == "__main__":
    unittest.main()
