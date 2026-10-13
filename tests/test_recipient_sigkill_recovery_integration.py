"""Real recipient SIGKILL with a live gateway, durable journal and restart.

This is portable Linux subprocess evidence, NOT a Firecracker or hardware
attestation claim. The recipient is a separate process from the real gateway.
The fault is selected by the trusted test supervisor, never the guest.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
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
from scripts.effect_crash_recipient import RECIPIENT_CRASH_PHASES, observed_recipient
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import exchange

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith("linux"), "actual SIGKILL requires Linux")
class RecipientCrashRecoveryTests(unittest.TestCase):
    def test_recipient_kill_before_and_after_durable_commit(self):
        for phase, expected in zip(RECIPIENT_CRASH_PHASES, (0, 1), strict=True):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                request = ActionRequest(
                    "read-one", "recipient-" + root.name, "attacker-agent",
                    "object.read", "synthetic-dataset", "exec-1",
                    {"offset": 0, "length": 5}, "recipient crash recovery test",
                )
                broker = CapabilityBroker(ttl_seconds=120)
                ctx = authority_context(request, time.time(), max_output_bytes=512)
                original = broker.issue(
                    request, **issue_options(ctx), max_output_bytes=512,
                )
                fresh = broker.issue(
                    request, **issue_options(ctx), max_output_bytes=512,
                )
                effect_key = digest({
                    "session_id": request.session_id, "request_id": request.request_id,
                })
                endpoint, recipient_db, journal_path = (
                    root / "recipient.sock", root / "recipient.sqlite",
                    root / "outcome.sqlite",
                )
                recipient_config = {
                    "recipient_socket": str(endpoint),
                    "recipient_database": str(recipient_db),
                    "effect_key": effect_key,
                    "request_digest": request.request_digest,
                }
                recipient_file = root / "recipient.json"
                recipient_file.write_text(json.dumps(recipient_config))
                gateway_file = root / "gateway.json"
                gateway_file.write_text(json.dumps({
                    "recorder_path": str(root / "gateway-events.jsonl"),
                    "boundary": {
                        "session_id": request.session_id,
                        "vm_uid": os.getuid(),
                        "dataset": "abcde",
                        "resource_id": request.resource_id,
                        "public_key_pem": broker.public_key_pem,
                        "key_id": broker.key_id,
                        "verification_context": verify_options(ctx),
                        "replay_database": str(root / "replay.sqlite"),
                        "decay_database": str(root / "decay.sqlite"),
                        "recipient_socket": str(endpoint),
                        "recipient_database": str(recipient_db),
                        "recipient_effect_key": effect_key,
                        "outcome_journal": str(journal_path),
                    },
                }))
                def launch_recipient(crash=None):
                    argv = [
                        sys.executable, "-u", "-m",
                        "scripts.kvm_effect_recipient_service",
                        "--config", str(recipient_file),
                    ]
                    if crash is not None:
                        argv.extend(["--crash-phase", crash])
                    proc = subprocess.Popen(
                        argv, cwd=ROOT,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
                    )
                    ready, _, _ = select.select([proc.stdout], [], [], 10)
                    if not ready or proc.stdout.readline().strip() != b"READY":
                        if proc.poll() is None:
                            proc.kill()
                        proc.wait(timeout=5)
                        raise AssertionError("external recipient process never announced READY")
                    return proc

                recipient = launch_recipient(crash=phase)
                gateway = None
                channel = None
                try:
                    gateway, channel = start_effect_gateway(gateway_file)
                    result = []

                    def authorized_request():
                        try:
                            result.append(exchange(channel, {
                                "request": request.canonical_payload(),
                                "capability": original.to_dict(),
                            }))
                        except BaseException as exc:
                            result.append(exc)

                    client = threading.Thread(target=authorized_request, daemon=True)
                    client.start()
                    killed = kill_at_checkpoint(recipient, phase, timeout=15)
                    self.assertEqual(killed.pid, recipient.pid)
                    self.assertEqual(killed.exit_code, -signal.SIGKILL)
                    client.join(timeout=8)
                    self.assertFalse(client.is_alive(), "gateway did not resolve recipient failure")
                    self.assertEqual(len(result), 1)
                    self.assertIsInstance(result[0], dict, result[0])
                    self.assertFalse(result[0]["success"])
                    self.assertEqual(result[0]["effect_state"], "possibly-committed")
                    self.assertEqual(result[0]["error"], "effect-indeterminate")
                    at_kill = observed_recipient(recipient_db)
                    self.assertEqual(at_kill["count"], expected)

                    journal = DurableEffectJournal(journal_path)
                    reservation = journal.observe(
                        tenant="default", environment="synthetic",
                        capability_id=original.claims.capability_id,
                    )
                    self.assertIsNotNone(reservation)
                    self.assertEqual(reservation["state"], "possibly-committed")
                    self.assertEqual(reservation["request_digest"], request.request_digest)
                    self.assertEqual(
                        reservation["claims_digest"], digest(original.claims.to_dict()),
                    )

                    # Re-open the SAME independently durable recipient database.
                    # The socket is a stale kernel name after our confirmed kill:
                    # refuse symlinks and untrusted ownership before unlinking.
                    socket_info = os.lstat(endpoint)
                    self.assertTrue(stat.S_ISSOCK(socket_info.st_mode))
                    self.assertEqual(socket_info.st_uid, os.getuid())
                    endpoint.unlink()
                    recipient.stdout.close()
                    recipient.stderr.close()
                    recipient = launch_recipient()
                    self.assertNotEqual(recipient.pid, killed.pid)

                    consumed = exchange(channel, {
                        "request": request.canonical_payload(),
                        "capability": original.to_dict(),
                    })
                    self.assertFalse(consumed["success"])
                    self.assertEqual(consumed["error"], "authority-denied")

                    replacement = exchange(channel, {
                        "request": request.canonical_payload(),
                        "capability": fresh.to_dict(),
                    })
                    self.assertFalse(replacement["success"])
                    self.assertEqual(replacement["effect_state"], "possibly-committed")
                    self.assertEqual(replacement["error"], "prior-effect-unknown")

                    self.assertEqual(observed_recipient(recipient_db), at_kill)
                    self.assertEqual(
                        journal.observe(
                            tenant="default", environment="synthetic",
                            capability_id=original.claims.capability_id,
                        ), reservation,
                    )
                finally:
                    if channel is not None:
                        channel.close()
                    if gateway is not None:
                        if gateway.poll() is None:
                            gateway.kill()
                        gateway.wait(timeout=5)
                        if gateway.stderr is not None:
                            gateway.stderr.close()
                    if recipient.poll() is None:
                        recipient.terminate()
                    recipient.wait(timeout=5)
                    if recipient.stdout is not None:
                        recipient.stdout.close()
                    if recipient.stderr is not None:
                        recipient.stderr.close()


if __name__ == "__main__":
    unittest.main()
