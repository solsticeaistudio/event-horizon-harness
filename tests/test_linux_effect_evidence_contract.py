"""Regression tests for the trusted service-to-recorder authorization handshake.

The actual microVM test requires KVM. These tests exercise the same
unprivileged-service-to-independent-recorder socket protocol without KVM.
"""
from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from event_horizon.protocol import encode_frame
from event_horizon.recorder import ExternalRecorder
from scripts.linux_effect_service import RecorderClient
from scripts.run_linux_isolation import EvidenceReceiver


class LinuxEffectEvidenceContractTests(unittest.TestCase):
    def test_authorized_then_completed_events_receive_signed_acknowledgments(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = ExternalRecorder(Path(directory) / "events.jsonl")
            trusted_side, service_side = socket.socketpair()
            receiver = EvidenceReceiver(trusted_side, recorder)
            thread = threading.Thread(target=receiver.run, daemon=True)
            thread.start()
            client = RecorderClient(service_side.detach())
            try:
                client.append("execution.authorized", {
                    "request_id": "synthetic-request",
                    "request_digest": "a" * 64,
                    "capability_id": "synthetic-capability",
                })
                client.append("execution.completed", {
                    "request_id": "synthetic-request",
                    "capability_id": "synthetic-capability",
                    "success": True,
                    "output_bytes": 7,
                    "effect_state": "completed",
                })
            finally:
                client.stream.close()
                client.channel.close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertIsNone(receiver.failure)
            events = recorder.events()
            self.assertEqual(
                [event["event_type"] for event in events],
                ["execution.authorized", "execution.completed"],
            )
            self.assertEqual(len(receiver.receipts), 2)
            for event, receipt in zip(events, receiver.receipts, strict=True):
                self.assertEqual(event["source_id"], "host-effect-service")
                self.assertEqual(receipt["payload"]["event_hash"], event["event_hash"])
                self.assertTrue(ExternalRecorder.verify_receipt(
                    receipt, recorder.public_key_pem,
                ))

    def test_unknown_service_event_never_gets_recorded_or_acknowledged(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = ExternalRecorder(Path(directory) / "events.jsonl")
            trusted_side, service_side = socket.socketpair()
            receiver = EvidenceReceiver(trusted_side, recorder)
            thread = threading.Thread(target=receiver.run, daemon=True)
            thread.start()
            try:
                service_side.sendall(encode_frame({
                    "event_type": "isolation.context",
                    "payload": {"attempt": "untrusted-domain-substitution"},
                }))
                service_side.shutdown(socket.SHUT_WR)
                service_side.settimeout(2)
                self.assertEqual(service_side.recv(4096), b"")
            finally:
                service_side.close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertIsInstance(receiver.failure, ValueError)
            self.assertEqual(recorder.events(), [])
            self.assertEqual(receiver.receipts, [])


if __name__ == "__main__":
    unittest.main()
