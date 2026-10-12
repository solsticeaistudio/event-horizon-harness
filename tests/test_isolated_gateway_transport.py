"""Portable subprocess transport tests, not Firecracker/KVM evidence."""
from __future__ import annotations

import os
import signal
import sys
import unittest

from scripts.isolated_gateway_transport import (
    GatewayTransportError, exchange, start_gateway_process,
)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux process controls")
class GatewayTransportTests(unittest.TestCase):
    def test_child_has_distinct_pid_and_framed_reply(self):
        child, channel = start_gateway_process()
        try:
            response = exchange(channel, {"diagnostic": "ping"})
            self.assertEqual(response["diagnostic"], "pong")
            self.assertEqual(response["pid"], child.pid)
            self.assertNotEqual(child.pid, os.getpid())
            self.assertEqual(child.wait(timeout=5), 0)
        finally:
            channel.close()
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stderr.close()

    def test_dead_gateway_never_becomes_success(self):
        child, channel = start_gateway_process()
        try:
            child.kill()
            self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
            with self.assertRaises(GatewayTransportError):
                exchange(channel, {"diagnostic": "ping"})
        finally:
            channel.close()
            child.stderr.close()

    def test_unrecognized_command_fails_closed(self):
        child, channel = start_gateway_process()
        try:
            with self.assertRaises(GatewayTransportError):
                exchange(channel, {"diagnostic": "unauthorized"})
            self.assertNotEqual(child.wait(timeout=5), 0)
        finally:
            channel.close()
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stderr.close()


if __name__ == "__main__":
    unittest.main()
