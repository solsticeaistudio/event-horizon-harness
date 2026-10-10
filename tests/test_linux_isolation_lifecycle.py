"""Prevent pre-VM attestation crashes and destructive scratch teardown regressions.

Tests here are intentionally rootless: the real Firecracker/KVM experiment
still has to run on an owned Linux host with working cgroup delegation.
"""
from __future__ import annotations

import ast
import inspect
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts.run_linux_isolation import (
    _forensic_erase_file,
    _overwrite_pass,
    _overwrite_pass_random,
    run_round,
    stage_effect_service,
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

    def test_effect_service_staged_outside_private_checkout(self):
        # The real Ubuntu host's /home/<user> is not traversable by UID 60001.
        # The trusted service must import from a separate root-owned snapshot.
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            run.chmod(0o711)
            entry = stage_effect_service(run)
            stage = run / "trusted-service"
            self.assertEqual(entry, stage / "scripts/linux_effect_service.py")
            self.assertTrue(entry.is_file())
            self.assertTrue((stage / "src/event_horizon/effect_boundary.py").is_file())
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o444)
            for directory in [stage, *[p for p in stage.rglob("*") if p.is_dir()]]:
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
            for file in (p for p in stage.rglob("*.py") if p.is_file()):
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o444)

            # Isolated Python ignores PYTHONPATH and does not need to traverse
            # the user's private source checkout. Running --help imports the
            # full effect-boundary dependency graph without opening a socket.
            result = subprocess.run(
                [sys.executable, "-I", str(entry), "--help"],
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "/nonexistent",
                     "PYTHONDONTWRITEBYTECODE": "1"},
                cwd="/",
                capture_output=True, text=True, check=True, timeout=15,
            )
            self.assertIn("--listener-fd", result.stdout)
            self.assertIn("--config", result.stdout)

    def test_service_snapshot_rejects_source_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "checkout"
            (source / "scripts").mkdir(parents=True)
            (source / "src/event_horizon").mkdir(parents=True)
            (source / "scripts/linux_effect_service.py").symlink_to("/etc/passwd")
            with patch("scripts.run_linux_isolation.ROOT", source):
                with self.assertRaisesRegex(RuntimeError, "unexpected effect-service source file"):
                    stage_effect_service(Path(tmp) / "run")

    def test_scratch_overwrite_stays_within_original_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scratch.ext4"
            original = b"a" * 8192
            path.write_bytes(original)
            fd = os.open(path, os.O_RDWR)
            try:
                _overwrite_pass(fd, len(original), b"\x00")
                self.assertEqual(path.stat().st_size, len(original))
                self.assertEqual(path.read_bytes(), b"\x00" * len(original))
                _overwrite_pass(fd, len(original), b"\xff")
                self.assertEqual(path.stat().st_size, len(original))
                self.assertEqual(path.read_bytes(), b"\xff" * len(original))
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
