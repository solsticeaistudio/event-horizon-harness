from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from event_horizon.public_demo import SUMMARY_LABELS, main


class PublicDemoTests(unittest.TestCase):
    def test_public_demo_exercises_every_reported_boundary(self):
        with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as artifacts:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["--workdir", work, "--artifacts-dir", artifacts])
            self.assertEqual(result, 0, output.getvalue())
            summary = json.loads((Path(artifacts) / "latest-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(all(summary["results"].values()))
            self.assertFalse(summary["simulator_is_hardware_attestation"])
            self.assertTrue((Path(artifacts) / "latest-containment-certificate.json").is_file())
            self.assertTrue((Path(artifacts) / "latest-certificate-signer-public.pem").is_file())
            for _key, label, expected in SUMMARY_LABELS:
                self.assertIn(f"{label:<34} {expected}", output.getvalue())
            self.assertIn("not hardware-backed attestation", output.getvalue())
            self.assertIn("--trusted-key .demo/latest-certificate-signer-public.pem", output.getvalue())


if __name__ == "__main__":
    unittest.main()
