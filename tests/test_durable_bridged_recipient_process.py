"""Linux subprocess tests for the real gateway + separate durable recipient.

These are portable guardian fixtures, NOT evidence of Firecracker/KVM or SIGKILL.
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
from event_horizon.canonical import digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.models import ActionRequest
from event_horizon.protocol import encode_frame, read_frame
from event_horizon.recorder import ExternalRecorder
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from scripts.effect_crash_recipient import observed_recipient
from scripts.integrated_gateway_process_bridge import RecipientBridgedGateReceiver


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux AF_UNIX subprocesses")
class DurableBridgedRecipientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.request = ActionRequest(
            "effect-one", "recipient-test", "attacker-agent", "object.read",
            "synthetic-dataset", "exec-1", {"offset": 0, "length": 5},
            "bounded synthetic effect",
        )
        self.broker = CapabilityBroker(ttl_seconds=120)
        context = authority_context(self.request, time.time(), max_output_bytes=512)
        self.original = self.broker.issue(
            self.request, **issue_options(context), max_output_bytes=512,
        )
        self.replacement = self.broker.issue(
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
            "recipient_socket": str(root / "recipient.sock"),
            "recipient_database": str(root / "recipient.sqlite"),
            "recipient_request_digest": self.request.request_digest,
            "recipient_effect_key": digest({
                "session_id": self.request.session_id,
                "request_id": self.request.request_id,
            }),
            "outcome_journal": str(root / "journal.sqlite"),
        }
        self.recorder = ExternalRecorder(root / "events.jsonl")
        self.host, self.service = socket.socketpair()
        self.receiver = RecipientBridgedGateReceiver(
            self.host, self.recorder, self.config,
            isolated_recipient=False,
        )
        self.thread = threading.Thread(target=self.receiver.run, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.service.close()
        self.thread.join(timeout=12)
        self.assertFalse(self.thread.is_alive(), "recipient bridge thread did not exit")
        self.assertIsNone(self.receiver.failure)
        self.assertIsNone(self.receiver.record_failure)
        self.tmp.cleanup()

    def send(self, capability):
        msg = {"request": self.request.canonical_payload(),
               "capability": capability.to_dict()}
        self.service.sendall(encode_frame(msg))
        with self.service.makefile("rb") as stream:
            return read_frame(stream)

    def test_commit_once_then_new_signed_capability_cannot_repeat_effect(self):
        first = self.send(self.original)
        self.assertTrue(first["success"], first)
        self.assertEqual(first["output"], "abcde")
        after_commit = observed_recipient(Path(self.config["recipient_database"]))
        self.assertEqual(after_commit["count"], 1)
        original_again = self.send(self.original)
        self.assertFalse(original_again["success"])
        self.assertEqual(original_again["error"], "authority-denied")
        renewed = self.send(self.replacement)
        self.assertFalse(renewed["success"])
        self.assertEqual(renewed["effect_state"], "possibly-committed")
        self.assertEqual(renewed["error"], "prior-effect-unknown")
        self.assertEqual(observed_recipient(Path(self.config["recipient_database"])),
                         after_commit)
        journal = DurableEffectJournal(self.config["outcome_journal"])
        reservation = journal.observe(
            tenant="default", environment="synthetic",
            capability_id=self.original.claims.capability_id,
        )
        self.assertEqual(reservation["state"], "possibly-committed")
        self.assertEqual(reservation["request_digest"], self.request.request_digest)
        self.assertEqual(self.receiver.dispatches, 1)
        self.assertNotEqual(self.receiver.gateway_pid, self.receiver.recipient_pid)
        self.assertNotEqual(self.receiver.gateway_pid, os.getpid())
        self.assertNotEqual(self.receiver.recipient_pid, os.getpid())


if __name__ == "__main__":
    unittest.main()
