"""Portable contract tests for independently supervised SIGKILL barriers.

These do not exercise KVM, vsock, guardians or etcd.
"""
from __future__ import annotations

import signal
import sys
import unittest

from scripts.effect_crash_process_supervisor import (
    CrashControlError, kill_at_checkpoint, launch_crash_target,
)


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux SIGKILL")
class CrashSupervisorTests(unittest.TestCase):
    @staticmethod
    def child(body: str):
        return launch_crash_target([sys.executable, "-u", "-c", body])

    def test_real_kill_after_matching_marker(self):
        proc = self.child("import time; print('PHASE:post_commit', flush=True); time.sleep(30)")
        observation = kill_at_checkpoint(proc, "post_commit", timeout=3)
        self.assertEqual(observation.signal, signal.SIGKILL)
        self.assertEqual(observation.exit_code, -signal.SIGKILL)
        self.assertEqual(observation.pid, proc.pid)

    def test_wrong_marker_cannot_claim_success(self):
        proc = self.child("import time; print('PHASE:before_commit', flush=True); time.sleep(30)")
        with self.assertRaises(CrashControlError):
            kill_at_checkpoint(proc, "post_commit", timeout=3)
        self.assertIsNotNone(proc.poll())

    def test_eof_is_incomplete(self):
        proc = self.child("pass")
        with self.assertRaises(CrashControlError):
            kill_at_checkpoint(proc, "post_commit", timeout=3)
        self.assertIsNotNone(proc.poll())

    def test_timeout_is_incomplete_and_reaped(self):
        proc = self.child("import time; time.sleep(30)")
        with self.assertRaises(CrashControlError):
            kill_at_checkpoint(proc, "post_commit", timeout=0.1)
        self.assertIsNotNone(proc.poll())

    def test_invalid_markers_rejected(self):
        proc = self.child("import time; time.sleep(30)")
        try:
            for marker in ("", "a:b", "a\\nb"):
                with self.assertRaises(ValueError):
                    kill_at_checkpoint(proc, marker, timeout=1)
        finally:
            proc.kill()
            proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
