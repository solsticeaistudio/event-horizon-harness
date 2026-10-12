"""Portable regression for the same receiver used in opt-in KVM guest bridge.

The signed capability in this test is a fixture; only a real KVM operator run
can support claims about Firecracker and four separate guardian principals.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

from event_horizon.broker import CapabilityBroker
from event_horizon.models import ActionRequest
from event_horizon.protocol import encode_frame, read_frame
from event_horizon.recorder import ExternalRecorder
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from scripts.integrated_gateway_process_bridge import BridgedGateReceiver


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux subprocesses")
class GuestGatewayBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.broker = CapabilityBroker(ttl_seconds=120)
        self.request = ActionRequest(
            "read-one", "bridge-test", "attacker-agent", "object.read",
            "synthetic-dataset", "exec-1", {"offset": 0, "length": 5},
            "bounded test read",
        )
        context = authority_context(self.request, time.time(), max_output_bytes=512)
        self.cap = self.broker.issue(
            self.request, **issue_options(context), max_output_bytes=512,
        )
        self.config = {
            "session_id": self.request.session_id,
            "vm_uid": os.getuid(),
            "dataset": "abcde",
            "resource_id": self.request.resource_id,
            "public_key_pem": self.broker.public_key_pem,
            "key_id": self.broker.key_id,
            "verification_context": verify_options(context),
            "replay_database": str(root / "replay.sqlite"),
            "decay_database": str(root / "decay.sqlite"),
            "observe_integrated_dispatch": True,
            "expected_request_digest": self.request.request_digest,
            "expected_request_id": self.request.request_id,
            "expected_capability_id": self.cap.claims.capability_id,
        }
        self.recorder = ExternalRecorder(root / "events.jsonl")
        self.host, self.service = socket.socketpair()
        self.receiver = BridgedGateReceiver(self.host, self.recorder, self.config)
        self.thread = threading.Thread(target=self.receiver.run, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.service.close()
        self.thread.join(timeout=12)
        if self.thread.is_alive():
            self.fail("bridge did not release gateway child after EOF")
        self.assertIsNone(self.receiver.failure)
        self.assertIsNone(self.receiver.record_failure)
        self.temp.cleanup()

    def send(self, value):
        self.service.sendall(encode_frame(value))
        with self.service.makefile("rb") as stream:
            return read_frame(stream)

    def test_real_signed_effect_and_replay_traverse_distinct_gateway_pid(self):
        envelope = {
            "request": self.request.canonical_payload(),
            "capability": self.cap.to_dict(),
        }
        denied = self.send({"request": envelope["request"]})
        self.assertFalse(denied["success"])
        self.assertEqual(denied["effect_state"], "not-started")
        first = self.send(envelope)
        self.assertTrue(first["success"], first)
        self.assertEqual(first["output"], "abcde")
        replay = self.send(envelope)
        self.assertFalse(replay["success"])
        self.assertIsInstance(self.receiver.gateway_pid, int)
        self.assertNotEqual(self.receiver.gateway_pid, os.getpid())
        self.assertEqual(self.receiver.dispatches, 1)
        completed = [e for e in self.recorder.events()
                     if e["event_type"] == "execution.completed"]
        self.assertEqual(len(completed), 1)

    def test_invalid_request_rejected_by_child_boundary(self):
        denied = self.send({"unexpected": "guest-controlled"})
        self.assertFalse(denied["success"])
        self.assertEqual(denied["effect_state"], "not-started")
        self.assertEqual(self.receiver.dispatches, 0)


if __name__ == "__main__":
    unittest.main()
