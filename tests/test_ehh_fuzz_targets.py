"""Fuzz entrypoint regression tests; rootless and network-free.

Atheris exercises exactly the same .exercise() functions under coverage
guidance in a separate CI job. These tests do not claim fuzz coverage.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.ehh_fuzz_targets import FuzzTargets, MAX_INPUT_BYTES, TARGETS

ROOT = Path(__file__).resolve().parents[1]


class FuzzTargetsTests(unittest.TestCase):
    def test_frame_parser_canonical_roundtrip_and_malformed_seeds(self):
        engine = FuzzTargets("frame")
        try:
            seeds = engine.seeds()
            self.assertEqual(engine.exercise(seeds[0]), "accepted")
            self.assertEqual(engine.exercise(seeds[1]), "rejected")
            self.assertEqual(engine.exercise(seeds[3]), "rejected")
            self.assertEqual(engine.exercise(seeds[4]), "rejected")
            self.assertEqual(engine.exercise(seeds[5]), "rejected")
            self.assertEqual(engine.exercise(bytes(MAX_INPUT_BYTES + 1)),
                             "bounded-rejection")
        finally:
            engine.close()

    def test_canonical_parser_detects_ambiguous_and_noncanonical_inputs(self):
        engine = FuzzTargets("canonical")
        try:
            self.assertEqual(engine.exercise(b'{"a":1}'), "accepted")
            self.assertEqual(engine.exercise(b'{"a":1,"a":2}'), "rejected")
            self.assertEqual(engine.exercise(b'{"x":1.0}'), "rejected")
            self.assertEqual(engine.exercise(b'{"x":-0}'), "rejected")
            self.assertEqual(engine.exercise(b'{"x":"\xff"}'), "rejected")
        finally:
            engine.close()

    def test_signed_capability_cannot_be_modified_or_replayed(self):
        engine = FuzzTargets("capability")
        try:
            self.assertEqual(engine.exercise(engine.valid_capability), "accepted")
            self.assertEqual(engine.exercise(engine.valid_capability), "rejected")
            # Structured mutations explore deep verifier branches without
            # relying on an extremely unlikely random valid JSON payload.
            for mode in range(4):
                for field in (0, 1, 15, 254):
                    with self.subTest(mode=mode, field=field):
                        case = bytes((0xF0, mode, field))
                        self.assertEqual(engine.exercise(case), "rejected")
            self.assertEqual(engine.exercise(b'{"claims":{}}'), "rejected")
        finally:
            engine.close()

    def test_gateway_effects_cannot_be_reached_by_mutations(self):
        engine = FuzzTargets("gateway")
        try:
            self.assertIsNotNone(engine.boundary)
            self.assertEqual(engine.exercise(engine.valid_gateway), "accepted")
            self.assertEqual(engine.exercise(engine.valid_gateway), "denied")
            for mode in range(9):
                with self.subTest(mode=mode):
                    self.assertEqual(engine.exercise(bytes((0xF0, mode))), "denied")
            self.assertEqual(engine.recorder.counts["execution.completed"], 1)
            self.assertEqual(engine.exercise(b'{"capability":{},"request":{}}'), "denied")
            self.assertEqual(engine.recorder.counts["execution.completed"], 1)
        finally:
            engine.close()

    def test_reject_unknown_target(self):
        with self.assertRaises(ValueError):
            FuzzTargets("live-production-network")

    def test_reproducible_cli_smoke_reports_are_explicitly_not_fuzz_assurance(self):
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.run(
                [sys.executable, "scripts/run_ehh_fuzz.py", "--target", "all",
                 "--smoke", "--iterations", "12", "--report-dir", directory],
                cwd=ROOT, capture_output=True, text=True, timeout=45,
            )
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            for target in TARGETS:
                report = json.loads((Path(directory) / f"{target}.json").read_text())
                self.assertEqual(report["schema"], "event-horizon.fuzz-smoke.v1")
                self.assertEqual(report["status"], "PASS")
                self.assertGreaterEqual(report["cases"], 12)
                self.assertIn("NOT coverage-guided", report["scope"])
                self.assertEqual(sum(report["outcomes"].values()), report["cases"])


if __name__ == "__main__":
    unittest.main()
