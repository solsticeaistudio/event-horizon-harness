"""Actual gateway worker SIGKILL phases with durable recipient and restart.

Linux subprocess evidence only: this is NOT a Firecracker/guardian/KVM run.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
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
from event_horizon.models import ActionRequest
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from scripts.effect_crash_process_supervisor import kill_at_checkpoint
from scripts.effect_crash_recipient import observed_recipient
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import exchange, GatewayTransportError
from scripts.real_gateway_crash_checkpoints import PHASES


@unittest.skipUnless(sys.platform.startswith("linux"), "real SIGKILL on Linux")
class RealGatewayCrashCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.request = ActionRequest(
            "read-one", "crash-" + self.root.name, "attacker-agent", "object.read",
            "synthetic-dataset", "exec-1", {"offset": 0, "length": 5},
            "bounded guest-shaped recipient effect",
        )
        broker = CapabilityBroker(ttl_seconds=120)
        ctx = authority_context(self.request, time.time(), max_output_bytes=512)
        self.original = broker.issue(
            self.request, **issue_options(ctx), max_output_bytes=512,
        )
        self.fresh = broker.issue(
            self.request, **issue_options(ctx), max_output_bytes=512,
        )
        self.recipient_path = self.root / "recipient.sqlite"
        self.recipient_socket = self.root / "recipient.sock"
        self.journal_path = self.root / "journal.sqlite"
        config = {
            "recorder_path": str(self.root / "gateway-events.jsonl"),
            "boundary": {
                "session_id": self.request.session_id,
                "vm_uid": os.getuid(),
                "dataset": "abcde",
                "resource_id": self.request.resource_id,
                "public_key_pem": broker.public_key_pem,
                "key_id": broker.key_id,
                "verification_context": verify_options(ctx),
                "replay_database": str(self.root / "replay.sqlite"),
                "decay_database": str(self.root / "decay.sqlite"),
                "recipient_socket": str(self.recipient_socket),
                "recipient_database": str(self.recipient_path),
                "recipient_effect_key": digest({
                    "session_id": self.request.session_id,
                    "request_id": self.request.request_id,
                }),
                "outcome_journal": str(self.journal_path),
            },
        }
        self.config_path = self.root / "gateway.json"
        self.config_path.write_text(json.dumps(config, sort_keys=True))
        recipient_config = {
            "recipient_socket": str(self.recipient_socket),
            "recipient_database": str(self.recipient_path),
            "effect_key": config["boundary"]["recipient_effect_key"],
            "request_digest": self.request.request_digest,
        }
        cfg = self.root / "recipient.json"
        cfg.write_text(json.dumps(recipient_config, sort_keys=True))
        self.recipient = subprocess.Popen(
            [sys.executable, "-u", "-m", "scripts.kvm_effect_recipient_service",
             "--config", str(cfg)],
            cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.addCleanup(self.stop_recipient)
        ready, _, _ = select.select([self.recipient.stdout], [], [], 10)
        self.assertTrue(ready, "recipient did not signal ready")
        self.assertEqual(self.recipient.stdout.readline().strip(), b"READY")

    def stop_recipient(self):
        if self.recipient.poll() is None:
            self.recipient.terminate()
            try:
                self.recipient.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.recipient.kill()
                self.recipient.wait(timeout=3)
        self.recipient.stdout.close()
        self.recipient.stderr.close()

    def payload(self, cap):
        return {"request": self.request.canonical_payload(), "capability": cap.to_dict()}

    def test_each_phase_kills_real_gateway_and_never_double_commits(self):
        # Unittest runs a clean temp setup for each test; build five isolated
        # request/journal namespaces here instead of reusing a reservation.
        for index, phase in enumerate(PHASES):
            with self.subTest(phase=phase):
                with tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    original_json = json.loads(self.config_path.read_text())
                    old = original_json["boundary"]
                    old["session_id"] = self.request.session_id
                    old["replay_database"] = str(root / "replay.sqlite")
                    old["decay_database"] = str(root / "decay.sqlite")
                    old["outcome_journal"] = str(root / "journal.sqlite")
                    # Every phase must also have a distinct recipient process,
                    # so it cannot miscount old commits from a prior phase.
                    old["recipient_socket"] = str(root / "recipient.sock")
                    old["recipient_database"] = str(root / "recipient.sqlite")
                    entry = root / "config.json"
                    entry.write_text(json.dumps(original_json))
                    recipient_cfg = root / "recipient-config.json"
                    recipient_cfg.write_text(json.dumps({
                        "recipient_socket": old["recipient_socket"],
                        "recipient_database": old["recipient_database"],
                        "effect_key": old["recipient_effect_key"],
                        "request_digest": self.request.request_digest,
                    }))
                    recipient = subprocess.Popen(
                        [sys.executable, "-u", "-m", "scripts.kvm_effect_recipient_service",
                         "--config", str(recipient_cfg)],
                        cwd=Path(__file__).resolve().parents[1],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    try:
                        self.assertTrue(select.select([recipient.stdout], [], [], 10)[0])
                        self.assertEqual(recipient.stdout.readline().strip(), b"READY")
                        process, channel = start_effect_gateway(entry, crash_phase=phase)
                        result = []
                        def send():
                            try:
                                result.append(exchange(channel, self.payload(self.original)))
                            except BaseException as exc:
                                result.append(exc)
                        attempt = threading.Thread(target=send)
                        try:
                            attempt.start()
                            kill = kill_at_checkpoint(process, phase, timeout=20)
                            self.assertEqual(kill.exit_code, -signal.SIGKILL)
                            self.assertEqual(kill.pid, process.pid)
                            attempt.join(timeout=8)
                            self.assertFalse(attempt.is_alive())
                            self.assertEqual(len(result), 1)
                            self.assertIsInstance(result[0], Exception)
                        finally:
                            channel.close()
                            if process.poll() is None:
                                process.kill()
                            process.wait(timeout=5)
                            process.stdout.close()
                            process.stderr.close()

                        after_kill = observed_recipient(Path(old["recipient_database"]))
                        expected = (0, 0, 1, 1, 1)[index]
                        self.assertEqual(after_kill["count"], expected)
                        journal = DurableEffectJournal(old["outcome_journal"])
                        reservation = journal.observe(
                            tenant="default", environment="synthetic",
                            capability_id=self.original.claims.capability_id,
                        )
                        self.assertEqual(reservation is None, index == 0)
                        recovered, recovery_socket = start_effect_gateway(entry)
                        try:
                            old_reply = exchange(recovery_socket, self.payload(self.original))
                            self.assertFalse(old_reply["success"])
                            self.assertEqual(old_reply["error"], "authority-denied")
                            if index != 0:
                                fresh_reply = exchange(recovery_socket, self.payload(self.fresh))
                                self.assertFalse(fresh_reply["success"])
                                self.assertEqual(fresh_reply["effect_state"], "possibly-committed")
                        finally:
                            recovery_socket.close()
                            recovered.wait(timeout=5)
                            recovered.stderr.close()
                        self.assertEqual(observed_recipient(Path(old["recipient_database"])),
                                         after_kill)
                    finally:
                        if recipient.poll() is None:
                            recipient.terminate()
                        recipient.wait(timeout=5)
                        recipient.stdout.close()
                        recipient.stderr.close()


if __name__ == "__main__":
    unittest.main()
