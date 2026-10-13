"""Portable end-to-end contract test of the actual sixth-window KVM bridge.

Sends real signed requests over the bridge to a separate gateway and separate
durable recipient. Does not use Firecracker; passing cannot prove KVM.
"""
from __future__ import annotations

import copy
import os
import select
from pathlib import Path
import signal
import socket
import tempfile
import threading
import time
import unittest

from event_horizon.broker import CapabilityBroker
from event_horizon.canonical import digest
from event_horizon.models import ActionRequest
from event_horizon.recorder import ExternalRecorder
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from scripts.effect_crash_recipient import observed_recipient
from scripts.isolated_gateway_transport import exchange
from scripts.kvm_delayed_recipient_bridge import SixthWindowGateReceiver
from scripts.verify_kvm_delayed_recipient_bridge import verify_delayed_bridge


@unittest.skipUnless(os.name == "posix" and hasattr(os, "pidfd_open"),
                     "requires Linux pidfd and SIGKILL")
class SixthWindowLiveBridgeTests(unittest.TestCase):
    def test_actual_gateway_and_recipient_late_commit_bridge(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            request = ActionRequest(
                "read-one", "sixth-" + root.name, "attacker-agent", "object.read",
                "synthetic-dataset", "exec-1", {"offset": 0, "length": 5},
                "sixth-window portable bridge",
            )
            broker = CapabilityBroker(ttl_seconds=120)
            ctx = authority_context(request, time.time(), max_output_bytes=512)
            original = broker.issue(request, **issue_options(ctx), max_output_bytes=512)
            spare = broker.issue(request, **issue_options(ctx), max_output_bytes=512)
            effect_key = digest({"session_id": request.session_id,
                                 "request_id": request.request_id})
            config = {
                "session_id": request.session_id,
                "vm_uid": os.getuid(),
                "dataset": "abcde",
                "resource_id": request.resource_id,
                "public_key_pem": broker.public_key_pem, "key_id": broker.key_id,
                "verification_context": verify_options(ctx),
                "replay_database": str(root / "replay.sqlite"),
                "decay_database": str(root / "decay.sqlite"),
                "outcome_journal": str(root / "outcome.sqlite"),
                "recipient_database": str(root / "recipient.sqlite"),
                "recipient_socket": str(root / "recipient.sock"),
                "recipient_effect_key": effect_key,
                "recipient_request_digest": request.request_digest,
                "expected_request_id": request.request_id,
                "expected_request_digest": request.request_digest,
                "expected_capability_id": original.claims.capability_id,
                "expected_recovery_capability_id": spare.claims.capability_id,
                "observe_integrated_dispatch": True,
            }
            recorder = ExternalRecorder(root / "signed-events.jsonl")
            bridge_sock, guest_sock = socket.socketpair()
            receiver = SixthWindowGateReceiver(bridge_sock, recorder, config)
            receiver.isolated_recipient = False
            worker = threading.Thread(target=receiver.run, daemon=True)
            worker.start()
            try:
                self.assertTrue(receiver.recipient_ready.wait(10))
                self.assertIsNone(receiver.failure)
                def message(cap):
                    return {"request": request.canonical_payload(),
                            "capability": cap.to_dict()}
                self.assertTrue(receiver.gateway_ready.wait(timeout=10))
                self.assertIsNotNone(receiver.gateway_process)
                self.assertIsNone(receiver.gateway_process.poll())
                # Mirror ALL four guest/vsock negative controls before the
                # first authorized exchange, not just the happy fault path.
                # Original Ubuntu failure happened in this exact stage.
                valid = message(original)
                negative = {"missing_capability": {"request": valid["request"]}}
                forged = copy.deepcopy(valid)
                forged["capability"]["signature"] = "A" * 86
                negative["forged_signature"] = forged
                widened = copy.deepcopy(valid)
                widened["request"]["arguments"]["length"] = 1
                negative["argument_substitution"] = widened
                forbidden = copy.deepcopy(valid)
                forbidden["request"]["operation"] = "network.connect"
                negative["unauthorized_operation"] = forbidden
                for name, bad in negative.items():
                    with self.subTest(preflight=name):
                        try:
                            outcome = exchange(guest_sock, bad)
                        except Exception as exc:
                            process_status = (receiver.gateway_process.poll()
                                              if receiver.gateway_process is not None else None)
                            gateway_trace = ""
                            if (receiver.gateway_process is not None):
                                stream = receiver.gateway_process.stderr
                                if stream is not None and select.select(
                                        [stream], [], [], 0)[0]:
                                    gateway_trace = os.read(stream.fileno(), 8192).decode(
                                        "utf-8", errors="replace"
                                    )
                            self.fail(
                                f"gateway_trace={gateway_trace!r}; "
                                f"preflight {name} failed: {exc!r}; "
                                f"bridge_failure={receiver.failure!r}; "
                                f"record_failure={receiver.record_failure!r}; "
                                f"gateway_status={process_status!r}; "
                                f"dispatches={receiver.dispatches}; "
                                f"signed_events={[x['event_type'] for x in recorder.events()]!r}; "
                                f"contract_current={receiver.event_contract.current_capability!r}; "
                                f"contract_authorized={receiver.event_contract.authorized!r}"
                            )
                        self.assertFalse(outcome["success"])
                        self.assertEqual(outcome["effect_state"], "not-started")
                        self.assertEqual(receiver.dispatches, 0)
                first = exchange(guest_sock, message(original))
                self.assertEqual(first["error"], "gateway-killed")
                self.assertFalse(first["success"])
                self.assertEqual(first["effect_state"], "possibly-committed")
                old = exchange(guest_sock, message(original))
                self.assertEqual(old["error"], "authority-denied")
                fresh = exchange(guest_sock, message(spare))
                self.assertEqual(fresh["error"], "prior-effect-unknown")
                self.assertEqual(fresh["effect_state"], "possibly-committed")
            finally:
                guest_sock.close()
                worker.join(timeout=10)
            self.assertFalse(worker.is_alive(), "supervisor child leaked")
            self.assertIsNone(receiver.failure)
            self.assertIsNotNone(receiver.delayed_report)
            report = receiver.delayed_report
            self.assertEqual(report["exit_code"], -signal.SIGKILL)
            self.assertEqual(report["before"]["count"], 0)
            self.assertEqual(report["before_release"]["count"], 0)
            self.assertEqual(report["after_release"]["count"], 1)
            self.assertEqual(observed_recipient(root / "recipient.sqlite")["count"], 1)
            good, tip = recorder.verify()
            self.assertTrue(good)
            self.assertTrue(verify_delayed_bridge(
                report=report, events=recorder.events(), receipts=receiver.receipts,
                tip=tip, public_key_pem=recorder.public_key_pem,
                request_digest=request.request_digest, effect_key=effect_key,
            ))


if __name__ == "__main__":
    unittest.main()
