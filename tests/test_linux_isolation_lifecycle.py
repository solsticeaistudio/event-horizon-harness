"""Prevent pre-VM attestation crashes and destructive scratch teardown regressions.

Tests here are intentionally rootless: the real Firecracker/KVM experiment
still has to run on an owned Linux host with working cgroup delegation.
"""
from __future__ import annotations

import ast
import inspect
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from scripts.run_linux_isolation import (
    _forensic_erase_file,
    _overwrite_pass,
    _overwrite_pass_random,
    run_round,
)


class LinuxRoundLifecycleTests(unittest.TestCase):
    def test_attestation_initialized_before_any_read_and_single_signed_context(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(run_round)))
        func = tree.body[0]
        names = [n for n in ast.walk(func) if isinstance(n, ast.Name) and n.id == "attestation_mode"]
        writes = [n.lineno for n in names if isinstance(n.ctx, ast.Store)]
        reads = [n.lineno for n in names if isinstance(n.ctx, ast.Load)]
        self.assertTrue(writes and reads)
        self.assertLess(min(writes), min(reads), "signed context accessed mode before initialization")

        context_logs = [
            n for n in ast.walk(func) if isinstance(n, ast.Constant)
            and n.value == "isolation.context"
        ]
        self.assertEqual(
            len(context_logs), 1,
            "evidence verifier allows exactly one signed isolation.context per session",
        )
        assessments = [
            n for n in ast.walk(func) if isinstance(n, ast.Constant)
            and n.value == "attestation.assessed"
        ]
        self.assertEqual(len(assessments), 1)

    def test_scratch_overwrite_stays_within_original_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scratch.ext4"
            original = b"a" * 8192
            path.write_bytes(original)
            fd = os.open(path, os.O_RDWR)
            try:
                _overwrite_pass(fd, len(original), b"\\x00")
                self.assertEqual(path.stat().st_size, len(original))
                self.assertEqual(path.read_bytes(), b"\\x00" * len(original))
                _overwrite_pass(fd, len(original), b"\\xff")
                self.assertEqual(path.stat().st_size, len(original))
                self.assertEqual(path.read_bytes(), b"\\xff" * len(original))
                _overwrite_pass_random(fd, len(original))
                self.assertEqual(path.stat().st_size, len(original))
            finally:
                os.close(fd)

    def test_forensic_erase_returns_truncated_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scratch.ext4"
            path.write_bytes(b"sentinel" * 2048)
            _forensic_erase_file(path)
            self.assertEqual(path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
