"""The delayed-recipient race omitted by the first five KVM crash windows.

Portable real gateway and independent recipient process test: a supervisor
pauses a recipient AFTER it accepts the exact request but BEFORE its commit,
SIGKILLs the actual gateway, confirms the recipient ledger is empty, restarts
the gateway with the SAME durable journal, denies original and fresh signed
capabilities, THEN releases the old recipient's pending commit. The commit
must land exactly once. This is not yet a Firecracker hardware claim.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
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
from scripts.effect_crash_process_supervisor import wait_for_checkpoint
from scripts.effect_crash_recipient import observed_recipient
from scripts.isolated_effect_gateway_worker import start_effect_gateway
from scripts.isolated_gateway_transport import exchange, GatewayTransportError

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith("linux"), "real SIGKILL needs Linux")
class DelayedRecipientCommitAfterGatewayDeathTests(unittest.TestCase):
    def test_recipient_can_commit_later_but_fresh_capability_remains_fenced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            request = ActionRequest(
                "read-one", "delayed-" + root.name, "attacker-agent",
                "object.read", "synthetic-dataset", "exec-1",
                {"offset": 0, "length": 5}, "inflight late recipient commit",
            )
            broker = CapabilityBroker(ttl_seconds=120)
            context = authority_context(request, time.time(), max_output_bytes=512)
            original = broker.issue(request, **issue_options(context),
                                    max_output_bytes=512)
            fresh = broker.issue(request, **issue_options(context),
                                 max_output_bytes=512)
            identity = digest({
                "session_id": request.session_id, "request_id": request.request_id,
            })
            recipient_database = root / "recipient.sqlite"
            journal_path = root / "journal.sqlite"
            recipient_config = root / "recipient.json"
            recipient_config.write_text(json.dumps({
                "recipient_socket": str(root / "recipient.sock"),
                "recipient_database": str(recipient_database),
                "effect_key": identity,
                "request_digest": request.request_digest,
            }))
            gateway_config = root / "gateway.json"
            gateway_config.write_text(json.dumps({
                "recorder_path": str(root / "gateway-events.jsonl"),
                "boundary": {
                    "session_id": request.session_id,
                    "vm_uid": os.getuid(),
                    "dataset": "abcde",
                    "resource_id": request.resource_id,
                    "public_key_pem": broker.public_key_pem,
                    "key_id": broker.key_id,
                    "verification_context": verify_options(context),
                    "replay_database": str(root / "replay.sqlite"),
                    "decay_database": str(root / "decay.sqlite"),
                    "outcome_journal": str(journal_path),
                    "recipient_socket": str(root / "recipient.sock"),
                    "recipient_database": str(recipient_database),
                    "recipient_effect_key": identity,
                },
            }))
            release_read, release_write = os.pipe()
            recipient = None
            gateway = None
            gateway_channel = None
            recovered = None
            recovered_channel = None
            try:
                recipient = subprocess.Popen(
                    [sys.executable, "-u", "-m", "scripts.kvm_effect_recipient_service",
                     "--config", str(recipient_config),
                     "--pause-before-commit-fd", str(release_read)],
                    cwd=ROOT, pass_fds=(release_read,), close_fds=True,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, start_new_session=True,
                )
                os.close(release_read)
                release_read = -1
                readable, _, _ = select.select([recipient.stdout], [], [], 10)
                self.assertTrue(readable, "recipient process did not become ready")
                self.assertEqual(recipient.stdout.readline().strip(), b"READY")
                gateway, gateway_channel = start_effect_gateway(gateway_config)
                sent = []
                def pending_request():
                    try:
                        sent.append(exchange(gateway_channel, {
                            "request": request.canonical_payload(),
                            "capability": original.to_dict(),
                        }))
                    except BaseException as exc:
                        sent.append(exc)

                pending = threading.Thread(target=pending_request, daemon=True)
                pending.start()
                wait_for_checkpoint(recipient, "inflight_before_commit", timeout=15)
                self.assertIsNone(gateway.poll(), "gateway died before injected kill")
                self.assertEqual(observed_recipient(recipient_database)["count"], 0)
                journal = DurableEffectJournal(journal_path)
                row = journal.observe(
                    tenant="default", environment="synthetic",
                    capability_id=original.claims.capability_id,
                )
                self.assertIsNotNone(row, "request had no durable reservation")
                self.assertEqual(row["state"], "possibly-committed")
                self.assertEqual(row["request_digest"], request.request_digest)
                self.assertEqual(row["claims_digest"], digest(original.claims.to_dict()))

                killed_pid = gateway.pid
                gateway.kill()
                self.assertEqual(gateway.wait(timeout=5), -signal.SIGKILL)
                pending.join(timeout=8)
                self.assertFalse(pending.is_alive())
                self.assertEqual(len(sent), 1)
                self.assertIsInstance(sent[0], GatewayTransportError)
                self.assertEqual(observed_recipient(recipient_database)["count"], 0)

                gateway_channel.close()
                gateway_channel = None
                gateway.stderr.close()
                gateway.stderr = None
                gateway = None

                recovered, recovered_channel = start_effect_gateway(gateway_config)
                self.assertNotEqual(recovered.pid, killed_pid)
                old = exchange(recovered_channel, {
                    "request": request.canonical_payload(),
                    "capability": original.to_dict(),
                })
                self.assertFalse(old["success"])
                self.assertEqual(old["error"], "authority-denied")

                new = exchange(recovered_channel, {
                    "request": request.canonical_payload(),
                    "capability": fresh.to_dict(),
                })
                self.assertFalse(new["success"])
                self.assertEqual(new["effect_state"], "possibly-committed")
                self.assertEqual(new["error"], "prior-effect-unknown")
                self.assertEqual(observed_recipient(recipient_database)["count"], 0)

                # A zero-commit observation did NOT justify releasing the
                # reservation. Now the old recipient is allowed to commit.
                os.write(release_write, b"R")
                os.close(release_write)
                release_write = -1
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if observed_recipient(recipient_database)["count"] == 1:
                        break
                    time.sleep(0.02)
                final = observed_recipient(recipient_database)
                self.assertEqual(final["count"], 1)
                self.assertEqual(
                    final["rows_digest"], digest([[identity, request.request_digest]]),
                )
                self.assertIsNone(recipient.poll(),
                                  "recipient must survive lost gateway acknowledgement")
                self.assertEqual(
                    journal.observe(
                        tenant="default", environment="synthetic",
                        capability_id=original.claims.capability_id,
                    ), row,
                )
                # Fresh capability was consumed but never dispatched.
                fresh_again = exchange(recovered_channel, {
                    "request": request.canonical_payload(),
                    "capability": fresh.to_dict(),
                })
                self.assertFalse(fresh_again["success"])
                self.assertEqual(fresh_again["error"], "authority-denied")
                self.assertEqual(observed_recipient(recipient_database), final)
            finally:
                if release_read >= 0:
                    os.close(release_read)
                if release_write >= 0:
                    os.close(release_write)
                for channel in (gateway_channel, recovered_channel):
                    if channel is not None:
                        channel.close()
                for child in (gateway, recovered, recipient):
                    if child is None:
                        continue
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)
                    if child.stdout is not None:
                        child.stdout.close()
                    if child.stderr is not None:
                        child.stderr.close()


if __name__ == "__main__":
    unittest.main()
