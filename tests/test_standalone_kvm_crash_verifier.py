"""Regression: standalone verifier runs without inherited Python import paths."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.verify_integrated_kvm_crash import parse_report_json

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_integrated_kvm_crash.py"


class StandaloneKvmVerifierTests(unittest.TestCase):
    def test_report_parser_accepts_real_finite_float_timestamps(self):
        example = {
            "event_timestamp": 1791855083.2628138,
            "requested_teardown_latency_ms": 308.13724000472575,
            "phases": [0, 0, 1, 1, 1],
        }
        self.assertEqual(parse_report_json(json.dumps(example).encode()), example)

    def test_report_parser_rejects_duplicate_json_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            parse_report_json(b'{"rounds":5,"rounds":0}')

    def test_report_parser_rejects_nonfinite_numbers(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":-Infinity}', b'{"x":1e309}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_report_json(raw)

    def test_report_parser_rejects_invalid_utf8(self):
        with self.assertRaises(UnicodeDecodeError):
            parse_report_json(b'{"x":"\\xff"}'.replace(b'\\xff', bytes([255])))

    def test_help_runs_from_unrelated_working_directory(self):
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--help"],
                cwd=directory,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("report", result.stdout)
        self.assertNotIn("ModuleNotFoundError", result.stderr)


if __name__ == "__main__":
    unittest.main()
