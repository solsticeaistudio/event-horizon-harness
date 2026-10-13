"""Real child-process regression for the KVM recipient SIGKILL bridge.

This test uses the same guest-shaped signed request/gateway/recorder/recipient
logic, but is portable Linux, NOT a Firecracker or hardware attestation run.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from event_horizon.broker import CapabilityBroker
from event_horizon.canonical import digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.models import ActionRequest
from event_horizon.protocol import encode_frame, read_frame
from event_horizon.recorder import ExternalRecorder
from scripts.capability_fixture_support import authority_context, issue_options, verify_options

from scripts.kvm_fenced_ack_loss_bridge import KvmLostAckReceiver

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"),
                     "requires Linux process credentials and pidfds")
class KvmAckLossBridgePortableTests(unittest.TestCase):

    def _launch_service(self, *, directory, socket_path, database, key, phase=None):
        path = directory / "service.json"
        path.write_text(json.dumps({
            "socket_path": str(socket_path),
            "recipient_database": str(database),
            "recipient_id": "ehh-owned-kvm-fenced-v1",
            "auth_key_hex": key.hex(),
        }))
        path.chmod(0o600)
        args = [sys.executable, "-u", "-m", "scripts.fenced_recipient_service",
                "--config", str(path)]
        if phase is not None:
            args += ["--lab-fault", phase]
        service = subprocess.Popen(
            args, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        ready, _, _ = select.select([service.stdout], [], [], 8)
        line = service.stdout.readline().strip() if ready else b""
        if line != b"READY" or service.poll() is not None:
            error = service.stderr.read(1024) if service.poll() is not None else b""
            service.kill()
            service.wait(timeout=5)
            self.fail(f"independent recipient startup failed: {line!r} {error!r}")
        return service

    @staticmethod
    def _exchange(sock, message):
        sock.sendall(encode_frame(message))
        with sock.makefile("rb") as stream:
            return read_frame(stream)

    def test_sigkill_before_and_after_commit_then_fresh_authority(self):
        for phase in ("drop_ack_after_commit",):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                database = root / "recipient.sqlite"
                socket_path = root / "recipient.sock"
                key = bytes(range(32))
                request = ActionRequest(
                    "dataset-read", "recipient-ack-loss-" + phase, "agent",
                    "object.read", "synthetic-dataset", "exec-1",
                    {"offset": 0, "length": 5},
                    "authorized synthetic dataset read",
                )
                context = authority_context(
                    request, time.time(), max_output_bytes=512,
                )
                broker = CapabilityBroker(ttl_seconds=120)
                primary = broker.issue(
                    request, **issue_options(context), max_output_bytes=512,
                )
                spare = broker.issue(
                    request, **issue_options(context), max_output_bytes=512,
                )
                first = {
                    "request": request.canonical_payload(),
                    "capability": primary.to_dict(),
                }
                recovered = {
                    "request": request.canonical_payload(),
                    "capability": spare.to_dict(),
                }
                effect_key = digest({
                    "session_id": request.session_id,
                    "request_id": request.request_id,
                })
                config = {
                    "verification_context": verify_options(context),
                    "session_id": request.session_id,
                    "vm_uid": os.geteuid(),
                    "dataset": "owned-value",
                    "resource_id": request.resource_id,
                    "public_key_pem": broker.public_key_pem,
                    "key_id": broker.key_id,
                    "authority_backend": "sqlite",
                    "replay_database": str(root / "replay.sqlite"),
                    "decay_database": str(root / "decay.sqlite"),
                    "outcome_journal": str(root / "outcomes.sqlite"),
                    "fenced_recipient": {
                        "socket_path": str(socket_path),
                        "recipient_id": "ehh-owned-kvm-fenced-v1",
                        "auth_key_hex": key.hex(),
                    },
                    "recipient_database": str(database),
                    "recipient_effect_key": effect_key,
                    "expected_request_id": request.request_id,
                    "expected_request_digest": request.request_digest,
                    "expected_capability_id": primary.claims.capability_id,
                    "expected_recovery_capability_id": spare.claims.capability_id,
                    "expected_signed_effect_message_digest": digest(first),
                    "fenced_output_offset": 0,
                    "fenced_output_length": 5,
                    "observe_integrated_dispatch": True,
                }
                service = self._launch_service(
                    directory=root, socket_path=socket_path,
                    database=database, key=key, phase="drop_ack_after_commit",
                )
                left, right = socket.socketpair()
                recorder = ExternalRecorder(root / "events.jsonl")
                receiver = KvmLostAckReceiver(
                    left, recorder, config, 
                )
                receiver.recipient_process = service
                receiver.recipient_pid = service.pid

                task = threading.Thread(target=receiver._run_gateway, daemon=True)
                task.start()
                self.assertTrue(receiver.gateway_ready.wait(timeout=8))
                try:
                    interrupted = self._exchange(right, first)
                    self.assertFalse(interrupted["success"], interrupted)
                    self.assertEqual(interrupted["error"], "recipient-indeterminate")
                    self.assertEqual(interrupted["effect_state"], "possibly-committed")
                    self.assertEqual(self._exchange(right, first)["error"], "authority-denied")
                    response = self._exchange(right, recovered)
                    self.assertTrue(response["success"], response)
                    self.assertEqual(response["output"], "owned")
                finally:
                    right.close()
                    task.join(timeout=15)
                    for child in (service, receiver.recipient_process):
                        if child is not None:
                            if child.poll() is None:
                                child.kill()
                            child.wait(timeout=5)
                            for handle in (child.stdout, child.stderr):
                                if handle is not None:
                                    handle.close()
                self.assertFalse(task.is_alive())
                self.assertIsNone(receiver.failure)
                self.assertIsNone(receiver.record_failure)
                self.assertIsNotNone(receiver.ack_loss_report)
                self.assertEqual(receiver.ack_loss_report["recipient_pid"], service.pid)
                self.assertTrue(receiver.ack_loss_report["recipient_alive_after_drop"])
                self.assertIsNotNone(receiver.recovery_report)
                self.assertTrue(receiver.recovery_report["recipient_alive_after_recovery"])
                self.assertEqual(
                    receiver.ack_loss_report["recipient_count_at_drop"],
                    1,
                )
                self.assertEqual(
                    FencedSqliteRecipient(
                        database, recipient_id="ehh-owned-kvm-fenced-v1",
                    ).commit_count(), 1,
                )
                record = DurableEffectJournal(
                    config["outcome_journal"],
                ).observe_effect(
                    tenant="default", environment="synthetic", effect_key=effect_key,
                )
                self.assertEqual(record["state"], "recipient-confirmed")
                self.assertEqual(record["capability_id"], primary.claims.capability_id)
                self.assertEqual(
                    record["receipt_digest"], receiver.recovery_report["receipt_digest"],
                )
                self.assertTrue(recorder.verify()[0])


if __name__ == "__main__":
    unittest.main()
