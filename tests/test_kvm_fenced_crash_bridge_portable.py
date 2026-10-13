"""Real host-process regression for the exact KVM fenced-crash bridge.

The bridge, capability verifier, receipt, journal, signer proxy and SIGKILL
run in independent child processes. No Firecracker guest or hardware KVM
is claimed by this portable regression.
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
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.models import ActionRequest
from event_horizon.protocol import encode_frame, read_frame
from event_horizon.recorder import ExternalRecorder
from scripts.capability_fixture_support import authority_context, issue_options, verify_options
from scripts.isolated_effect_gateway_worker import FENCED_KVM_CRASH_PHASES
from scripts.kvm_fenced_crash_bridge import FencedKvmCrashReceiver


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"),
                     "actual Linux child SIGKILL and peer creds required")
class KvmFencedCrashPortableBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ehh-kvm-fenced-bridge-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.service = None
        self.addCleanup(self.stop_service)
        self.sock_path = self.root / "recipient.sock"
        self.recipient_db = self.root / "recipient.sqlite"
        self.key = bytes(range(32))
        self.request = ActionRequest(
            "dataset-read", "fenced-bridge-session", "agent", "object.read",
            "synthetic-dataset", "exec-1", {"offset": 0, "length": 5},
            "authorized synthetic dataset read",
        )
        self.context = authority_context(
            self.request, time.time(), max_output_bytes=512,
        )
        self.broker = CapabilityBroker(ttl_seconds=120)
        self.primary = self.broker.issue(
            self.request, **issue_options(self.context), max_output_bytes=512,
        )
        self.spare = self.broker.issue(
            self.request, **issue_options(self.context), max_output_bytes=512,
        )
        self.effect_key = digest({
            "session_id": self.request.session_id,
            "request_id": self.request.request_id,
        })
        self.start_service()

    def stop_service(self):
        if self.service is not None:
            if self.service.poll() is None:
                self.service.kill()
            self.service.wait(timeout=5)
            for handle in (self.service.stdout, self.service.stderr):
                if handle is not None:
                    handle.close()
            self.service = None

    def start_service(self):
        config_path = self.root / "recipient-config.json"
        config_path.write_text(json.dumps({
            "socket_path": str(self.sock_path),
            "recipient_database": str(self.recipient_db),
            "recipient_id": "ehh-owned-kvm-fenced-v1",
            "auth_key_hex": self.key.hex(),
        }))
        config_path.chmod(0o600)
        self.service = subprocess.Popen(
            [sys.executable, "-u", "-m", "scripts.fenced_recipient_service",
             "--config", str(config_path)],
            cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        ready, _, _ = select.select([self.service.stdout], [], [], 8)
        line = self.service.stdout.readline().strip() if ready else b""
        self.assertEqual(line, b"READY", self.service.poll())

    def host_config(self, path):
        return {
            "verification_context": verify_options(self.context),
            "session_id": self.request.session_id,
            "vm_uid": os.geteuid(),
            "dataset": "owned-value",
            "resource_id": self.request.resource_id,
            "public_key_pem": self.broker.public_key_pem,
            "key_id": self.broker.key_id,
            "authority_backend": "sqlite",
            "replay_database": str(path / "replay.sqlite"),
            "decay_database": str(path / "decay.sqlite"),
            "outcome_journal": str(path / "outcomes.sqlite"),
            "fenced_recipient": {
                "socket_path": str(self.sock_path),
                "recipient_id": "ehh-owned-kvm-fenced-v1",
                "auth_key_hex": self.key.hex(),
            },
            "recipient_database": str(self.recipient_db),
            "recipient_effect_key": self.effect_key,
            "expected_request_id": self.request.request_id,
            "expected_request_digest": self.request.request_digest,
            "expected_capability_id": self.primary.claims.capability_id,
            "expected_recovery_capability_id": self.spare.claims.capability_id,
            "expected_signed_effect_message_digest": digest({
                "request": self.request.canonical_payload(),
                "capability": self.primary.to_dict(),
            }),
            "fenced_output_offset": 0,
            "fenced_output_length": 5,
            "observe_integrated_dispatch": True,
        }

    def exchange(self, peer, payload):
        peer.sendall(encode_frame(payload))
        with peer.makefile("rb") as reader:
            return read_frame(reader)

    def test_real_child_crash_and_fresh_authorized_recovery_in_both_phases(self):
        for phase in FENCED_KVM_CRASH_PHASES:
            with self.subTest(phase=phase):
                # Distinct journal and replay state, so each phase is isolated.
                phase_dir = self.root / phase
                phase_dir.mkdir()
                cfg = self.host_config(phase_dir)
                recipient = FencedSqliteRecipient(
                    self.recipient_db, recipient_id="ehh-owned-kvm-fenced-v1",
                )
                if phase != FENCED_KVM_CRASH_PHASES[0]:
                    # Only one row is required per unique effect. This second
                    # window uses a new logical session so no prior row remains.
                    self.request = ActionRequest(
                        "dataset-read-second", "fenced-bridge-second", "agent",
                        "object.read", "synthetic-dataset", "exec-1",
                        {"offset": 0, "length": 5},
                        "authorized synthetic dataset read",
                    )
                    self.context = authority_context(
                        self.request, time.time(), max_output_bytes=512,
                    )
                    self.primary = self.broker.issue(
                        self.request, **issue_options(self.context), max_output_bytes=512,
                    )
                    self.spare = self.broker.issue(
                        self.request, **issue_options(self.context), max_output_bytes=512,
                    )
                    self.effect_key = digest({
                        "session_id": self.request.session_id,
                        "request_id": self.request.request_id,
                    })
                    cfg = self.host_config(phase_dir)
                recorder = ExternalRecorder(phase_dir / "events.jsonl")
                left, right = socket.socketpair()
                receiver = FencedKvmCrashReceiver(
                    left, recorder, cfg, phase=phase,
                )
                receiver.recipient_pid = self.service.pid
                worker = threading.Thread(target=receiver._run_gateway, daemon=True)
                worker.start()
                try:
                    first = {
                        "request": self.request.canonical_payload(),
                        "capability": self.primary.to_dict(),
                    }
                    fresh = {
                        "request": self.request.canonical_payload(),
                        "capability": self.spare.to_dict(),
                    }
                    interrupted = self.exchange(right, first)
                    self.assertEqual(interrupted["error"], "gateway-killed")
                    self.assertEqual(interrupted["effect_state"], "possibly-committed")
                    self.assertEqual(self.exchange(right, first)["error"], "authority-denied")
                    recovered = self.exchange(right, fresh)
                    self.assertTrue(recovered["success"], recovered)
                    self.assertEqual(recovered["output"], "owned")
                finally:
                    right.close()
                    worker.join(timeout=15)
                self.assertFalse(worker.is_alive())
                self.assertIsNone(receiver.failure)
                self.assertIsNone(receiver.record_failure)
                self.assertIsNotNone(receiver.crash_report)
                self.assertIsNotNone(receiver.recovery_report)
                self.assertEqual(receiver.crash_report["recipient_count_after_kill"],
                                 0 if phase == FENCED_KVM_CRASH_PHASES[0] else 2)
                # Across two independent logical effects the ledger contains
                # two rows; the receipt sequence belongs to the newly added row.
                self.assertEqual(recipient.commit_count(),
                                 1 if phase == FENCED_KVM_CRASH_PHASES[0] else 2)
                binding = DurableEffectJournal(cfg["outcome_journal"]).observe_effect(
                    tenant="default", environment="synthetic",
                    effect_key=self.effect_key,
                )
                self.assertEqual(binding["capability_id"],
                                 self.primary.claims.capability_id)
                self.assertEqual(binding["state"], "recipient-confirmed")
                self.assertEqual(receiver.recovery_report["receipt_digest"],
                                 binding["receipt_digest"])
                self.assertTrue(recorder.verify()[0])


if __name__ == "__main__":
    unittest.main()
