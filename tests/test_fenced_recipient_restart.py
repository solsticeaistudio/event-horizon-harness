"""Portable tests for exact-subprocess-owned recipient socket restart.

These are Linux process tests, NOT Firecracker evidence. They deliberately
test failure to clean up a path unless the prior child was SIGKILLed.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

from scripts.fenced_recipient_restart import (
    UnsafeRecipientRestart, pinned_socket_inode, remove_killed_recipient_socket,
)


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Unix sockets and SIGKILL")
class FencedRecipientRestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.path = self.root / "recipient.sock"

    def spawn_child(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(60)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        return child

    def test_exact_reaped_sigkill_and_pinned_inode_required(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            original = pinned_socket_inode(self.path)
            child = self.spawn_child()
            with self.assertRaises(UnsafeRecipientRestart):
                remove_killed_recipient_socket(
                    child, self.path, expected_inode=original,
                )
            self.assertTrue(self.path.exists())
            child.kill()
            self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
            evidence = remove_killed_recipient_socket(
                child, self.path, expected_inode=original,
            )
            self.assertEqual(evidence["killed_pid"], child.pid)
            self.assertEqual(evidence["stale_socket_inode"], original)
            self.assertTrue(evidence["stale_socket_removed"])
            self.assertFalse(self.path.exists())

    def test_replaced_socket_not_removed(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as first:
            first.bind(str(self.path))
            os.chmod(self.path, 0o600)
            prior_inode = pinned_socket_inode(self.path)
            child = self.spawn_child()
            child.kill()
            child.wait(timeout=5)
            self.path.unlink()
            # A file substitution must be rejected, even after proven death.
            self.path.write_text("not a recipient")
            with self.assertRaises(UnsafeRecipientRestart):
                remove_killed_recipient_socket(
                    child, self.path, expected_inode=prior_inode,
                )
            self.assertTrue(self.path.exists())
            self.assertEqual(self.path.read_text(), "not a recipient")

    def test_surviving_child_or_symlink_not_cleanup_authority(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            original = pinned_socket_inode(self.path)
            child = self.spawn_child()
            with self.assertRaises(UnsafeRecipientRestart):
                remove_killed_recipient_socket(
                    child, self.path, expected_inode=original,
                )
            child.terminate()
            child.wait(timeout=5)
            with self.assertRaises(UnsafeRecipientRestart):
                remove_killed_recipient_socket(
                    child, self.path, expected_inode=original,
                )
            self.assertTrue(self.path.exists())


if __name__ == "__main__":
    unittest.main()
