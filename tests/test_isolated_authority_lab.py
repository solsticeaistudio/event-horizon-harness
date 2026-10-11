"""Actual multi-process signer/guardian isolation regression (no Docker/root)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.run_isolated_authority_lab import SCENARIOS, run, main


@unittest.skipUnless(sys.platform == "linux", "requires Unix peer credentials")
class IsolatedAuthorityLabTests(unittest.TestCase):
    def test_nine_real_coordinator_attack_cases_against_five_services(self):
        result = run(distinct_uids=False)
        self.assertEqual(result["schema"], "event-horizon.coordinator-compromise-lab.v1")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["run_mode"], "same-uid-processes")
        self.assertFalse(result["os_identity_isolation_tested"])
        self.assertEqual(len(result["roles"]), 5)
        self.assertEqual(result["actual_processes"], len(SCENARIOS) + 5)
        self.assertEqual({x["scenario"] for x in result["tests"]}, set(SCENARIOS))
        cases = {x["scenario"]: x for x in result["tests"]}
        self.assertEqual(cases["legitimate"]["status"], "PASS")
        self.assertTrue(cases["legitimate"]["replay_denied"])
        for attack in ("forge_guardian", "omit_guardian", "duplicate_guardian",
                       "widen_request", "forge_claimed_policy", "prohibited_operation"):
            with self.subTest(attack=attack):
                self.assertEqual(cases[attack]["status"], "PASS")
                self.assertTrue(cases[attack]["issuer_denied"])
        # Same UID can access files under ordinary Unix permissions; DO NOT
        # assert or advertise independent OS credential isolation in CI.
        self.assertEqual(cases["read_protected_config"]["status"], "NOT-ASSESSED")
        self.assertEqual(cases["read_signer_memory"]["status"], "NOT-ASSESSED")
        self.assertEqual(
            {info["uid"] for info in result["roles"].values()},
            {os.geteuid()},
        )

    def test_distinct_uid_mode_refuses_rootless_invocation(self):
        if os.geteuid() != 0:
            with self.assertRaises(PermissionError):
                run(distinct_uids=True)

    def test_cli_emits_machine_readable_report_without_private_keys(self):
        with tempfile.TemporaryDirectory() as location:
            output = Path(location) / "result.json"
            with patch("sys.argv", [
                "isolated-role-lab", "--report", str(output),
            ]):
                main()
            payload = json.loads(output.read_text())
            self.assertEqual(payload["status"], "PASS")
            self.assertEqual(payload["run_mode"], "same-uid-processes")
            self.assertNotIn("PRIVATE KEY", output.read_text())


if __name__ == "__main__":
    unittest.main()
