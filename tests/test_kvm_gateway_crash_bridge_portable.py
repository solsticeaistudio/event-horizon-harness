"""Portable integration of the exact bridge used by later guest/vsock KVM runs.

Executes five actual independent-gateway SIGKILL processes with a separately
supervised durable recipient, then uses a NEW process and SAME journal for
denial tests. No hardware Firecracker or four-guardian claim is made here.
"""
from __future__ import annotations

import os
import copy
from pathlib import Path
import signal
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
from scripts.kvm_gateway_crash_bridge import KvmGatewayCrashReceiver
from scripts.real_gateway_crash_checkpoints import PHASES
from scripts.verify_kvm_gateway_crash_bridge import verify_crash_bridge


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                     "real process SIGKILL and pidfd require Linux")
class CrashBridgeSupervisorTests(unittest.TestCase):
    def test_all_five_windows_survive_recovery_without_duplicate_commit(self):
        for phase, expected in zip(PHASES, (0, 0, 1, 1, 1), strict=True):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                request = ActionRequest(
                    "dataset-read", "crash-" + root.name, "attacker-agent",
                    "object.read", "synthetic-dataset", "exec-1",
                    {"offset": 0, "length": 5}, "bounded crash read",
                )
                broker = CapabilityBroker(ttl_seconds=120)
                ctx = authority_context(request, time.time(), max_output_bytes=512)
                original = broker.issue(request, **issue_options(ctx), max_output_bytes=512)
                spare = broker.issue(request, **issue_options(ctx), max_output_bytes=512)
                config = {
                    "session_id": request.session_id,
                    "vm_uid": os.getuid(),
                    "dataset": "abcde",
                    "resource_id": request.resource_id,
                    "public_key_pem": broker.public_key_pem,
                    "key_id": broker.key_id,
                    "verification_context": verify_options(ctx),
                    "replay_database": str(root / "replay.sqlite"),
                    "decay_database": str(root / "decay.sqlite"),
                    "observe_integrated_dispatch": True,
                    "recipient_socket": str(root / "recipient.sock"),
                    "recipient_database": str(root / "recipient.sqlite"),
                    "recipient_request_digest": request.request_digest,
                    "recipient_effect_key": digest({
                        "session_id": request.session_id,
                        "request_id": request.request_id,
                    }),
                    "outcome_journal": str(root / "journal.sqlite"),
                    "expected_request_digest": request.request_digest,
                    "expected_request_id": request.request_id,
                    "expected_capability_id": original.claims.capability_id,
                    "expected_recovery_capability_id": spare.claims.capability_id,
                }
                recorder = ExternalRecorder(root / "events.jsonl")
                host, client = socket.socketpair()
                receiver = KvmGatewayCrashReceiver(
                    host, recorder, config, crash_phase=phase,
                    isolated_recipient=False,
                )
                thread = threading.Thread(target=receiver.run, daemon=True)
                thread.start()
                try:
                    self.assertTrue(receiver.recipient_ready.wait(10),
                                    "recipient startup never completed")
                    self.assertIsNone(receiver.failure)
                    with client.makefile("rb") as stream:
                        def send(cap):
                            client.sendall(encode_frame({
                                "request": request.canonical_payload(),
                                "capability": cap.to_dict(),
                            }))
                            return read_frame(stream)
                        # A real Firecracker guest sends forbidden probes
                        # before its signed request. Those probes must NOT
                        # arm the kill timer or consume a capability.
                        client.sendall(encode_frame({
                            "request": request.canonical_payload(),
                        }))
                        negative = read_frame(stream)
                        self.assertFalse(negative["success"])
                        self.assertEqual(negative["effect_state"], "not-started")
                        self.assertIsNone(receiver.crash_report)
                        crashed = send(original)
                        self.assertFalse(crashed["success"])
                        self.assertEqual(crashed["effect_state"], "possibly-committed")
                        self.assertEqual(crashed["error"], "gateway-killed")
                        old = send(original)
                        self.assertFalse(old["success"])
                        self.assertEqual(old["error"], "authority-denied")
                        if phase != PHASES[0]:
                            # Phase two has zero commits but a durable reservation;
                            # a new signed capability must still be fenced.
                            fresh = send(spare)
                            self.assertFalse(fresh["success"])
                            self.assertEqual(fresh["effect_state"], "possibly-committed")
                            self.assertEqual(fresh["error"], "prior-effect-unknown")
                    self.assertEqual(observed_recipient(root / "recipient.sqlite")["count"], expected)
                finally:
                    client.close()
                    thread.join(12)
                    self.assertFalse(thread.is_alive(), "receiver failed to terminate")
                self.assertIsNone(receiver.failure)
                self.assertIsNone(receiver.record_failure)
                observation = receiver.crash_report
                self.assertIsNotNone(observation)
                self.assertEqual(observation["phase"], phase)
                self.assertEqual(observation["signal"], signal.SIGKILL)
                self.assertEqual(observation["exit_code"], -signal.SIGKILL)
                self.assertEqual(observation["expected_commits"], expected)
                self.assertEqual(observation["recipient_after_kill"]["count"], expected)
                self.assertNotEqual(receiver.crashed_gateway_pid, receiver.recovery_gateway_pid)
                self.assertNotEqual(receiver.recipient_pid, receiver.crashed_gateway_pid)
                reservation = DurableEffectJournal(root / "journal.sqlite").observe(
                    tenant="default", environment="synthetic",
                    capability_id=original.claims.capability_id,
                )
                self.assertEqual(reservation is None, phase == PHASES[0])
                self.assertEqual(receiver.dispatches, 0 if phase in PHASES[:2] else 1)
                self.assertTrue(recorder.verify()[0])
                self.assertEqual(len([row for row in recorder.events()
                                      if row["event_type"] == "gateway.crash-observed"]), 1)
                valid, tip = recorder.verify()
                self.assertTrue(valid)
                evidence = dict(
                    phase=phase,
                    crashed=receiver.crash_report,
                    recovery=receiver.recovery_report,
                    events=recorder.events(),
                    receipts=receiver.receipts,
                    tip=tip,
                    public_key_pem=recorder.public_key_pem,
                    request_digest=request.request_digest,
                    effect_key=config["recipient_effect_key"],
                )
                self.assertTrue(verify_crash_bridge(**evidence))
                tampered = copy.deepcopy(evidence)
                tampered["recovery"]["recovery_pid"] = receiver.crashed_gateway_pid
                with self.assertRaises(ValueError):
                    verify_crash_bridge(**tampered)
                forged = copy.deepcopy(evidence)
                forged["events"][-1]["payload"]["recovery_pid"] = 1
                with self.assertRaises(ValueError):
                    verify_crash_bridge(**forged)


if __name__ == "__main__":
    unittest.main()
