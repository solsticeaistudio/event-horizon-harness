"""Real independent gateway/recipient process tests for atomic fenced recovery.

These tests are Linux host-process evidence only, NOT Firecracker or arbitrary
external API exactly-once. Tests enforce positive durable observation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from event_horizon.broker import CapabilityBroker, CapabilityVerifier
from event_horizon.canonical import digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_effect_recovery import FencedEffectRecoveryGateway
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.fenced_recipient_transport import FencedRecipientClient
from event_horizon.models import ActionRequest
from event_horizon.protocol import encode_frame
from event_horizon.recorder import ExternalRecorder
from event_horizon.trusted_effect_gateway import select_consumption_store
from scripts.capability_fixture_support import authority_context, issue_options, verify_options


ROOT = Path(__file__).resolve().parents[1]
SUPPORTED = sys.platform == "linux" and hasattr(socket, "SO_PEERCRED")


@unittest.skipUnless(SUPPORTED, "independent recipient requires Linux SO_PEERCRED")
class IndependentFencedRecipientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ehh-fenced-ipc-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "recipient.sqlite"
        self.sock = self.root / "recipient.sock"
        self.journal_path = self.root / "journal.sqlite"
        self.replay_path = self.root / "replay.sqlite"
        self.recipient_id = "owned-independent-recipient-v1"
        self.key = secrets.token_bytes(32)
        self.processes = []
        self.addCleanup(self.cleanup_processes)
        self.request = ActionRequest(
            "fenced-ipc", "fenced-ipc-session", "agent", "object.read",
            "synthetic-data", "exec-1", {"offset": 0, "length": 5}, "trusted test",
        )
        self.context = authority_context(
            self.request, time.time(), max_output_bytes=512,
        )
        self.broker = CapabilityBroker(ttl_seconds=120)
        self.journal = DurableEffectJournal(self.journal_path)
        self.store = select_consumption_store(
            backend="sqlite", namespace=self.request.session_id,
            domain="external-effect", sqlite_path=str(self.replay_path),
        )
        self.addCleanup(self.store.close)
        self.service = None
        self.start_service()

    def cleanup_processes(self):
        for proc in self.processes:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()

    def config_file(self, name, config):
        path = self.root / (name + ".json")
        path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
        path.chmod(0o600)
        return path

    def new_process(self, module, config, name, phase=None):
        path = self.config_file(name, config)
        command = [sys.executable, "-u", "-m", module, "--config", str(path)]
        if phase is not None:
            command.extend(["--lab-fault", phase])
        proc = subprocess.Popen(
            command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.processes.append(proc)
        return proc

    def marker(self, proc, expected):
        ready, _, _ = select.select([proc.stdout], [], [], 10)
        line = proc.stdout.readline().decode(errors="replace").strip() if ready else ""
        if line != expected:
            err = ""
            if proc.poll() is not None:
                err = proc.stderr.read(2000).decode(errors="replace")
            self.fail(
                f"expected {expected!r}, got {line!r}; code={proc.poll()}; stderr={err}"
            )
        self.assertIsNone(proc.poll())
        self.assertNotEqual(proc.pid, os.getpid())

    def service_config(self):
        return {
            "socket_path": str(self.sock), "recipient_database": str(self.db),
            "recipient_id": self.recipient_id, "auth_key_hex": self.key.hex(),
        }

    def start_service(self, phase=None):
        # Explicit supervisor-owned stale endpoint removal ONLY after the
        # original child has been killed/reaped and inode type/owner checked.
        if os.path.lexists(self.sock):
            info = os.lstat(self.sock)
            self.assertTrue(stat.S_ISSOCK(info.st_mode))
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_mode & 0o077, 0)
            self.sock.unlink()
        self.service = self.new_process(
            "scripts.fenced_recipient_service", self.service_config(),
            "service-" + str(len(self.processes)), phase,
        )
        self.marker(self.service, "READY")

    def kill(self, proc):
        self.assertIsNone(proc.poll())
        proc.kill()
        self.assertEqual(proc.wait(timeout=5), -signal.SIGKILL)

    def committed(self):
        return FencedSqliteRecipient(
            self.db, recipient_id=self.recipient_id,
        ).commit_count()

    def effect(self):
        return self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=digest({
                "session_id": self.request.session_id,
                "request_id": self.request.request_id,
            }),
        )

    def token(self):
        return self.broker.issue(
            self.request, **issue_options(self.context), max_output_bytes=512,
        )

    def remote(self, *, key=None, recipient_id=None):
        return FencedRecipientClient(
            self.sock, recipient_id=recipient_id or self.recipient_id,
            auth_key=self.key if key is None else key, timeout=2,
        )

    def run_parent(self, cap, *, key=None, output="owned-value", recipient_id=None):
        gateway = FencedEffectRecoveryGateway(
            CapabilityVerifier(
                self.broker.public_key_pem, self.broker.key_id, self.store,
            ),
            ExternalRecorder(self.root / (
                "parent-recorder-" + cap.claims.capability_id + ".jsonl"
            )),
            self.journal, self.remote(key=key, recipient_id=recipient_id),
            output_factory=lambda _: output,
        )
        v = verify_options(self.context)
        return gateway.execute(
            self.request, cap, v["attestation"],
            executor_measurement=v["executor_measurement"],
            device_id=v["device_id"],
            verifier_policy_digest=v["verifier_policy_digest"],
            policy_digest=v["policy_digest"],
        )

    def gateway_config(self, cap, name, output="owned-value", recipient_id=None):
        return {
            "public_key_pem": self.broker.public_key_pem,
            "key_id": self.broker.key_id,
            "request": self.request.canonical_payload(),
            "capability": cap.to_dict(),
            "verification_context": verify_options(self.context),
            "socket_path": str(self.sock),
            "recipient_id": recipient_id or self.recipient_id,
            "auth_key_hex": self.key.hex(),
            "journal_path": str(self.journal_path),
            "replay_path": str(self.replay_path),
            "recorder_path": str(self.root / (name + ".jsonl")),
            "output": output,
        }

    def spawn_gateway(self, cap, name, *, phase=None, output="owned-value",
                      recipient_id=None):
        return self.new_process(
            "scripts.fenced_remote_gateway_worker",
            self.gateway_config(cap, name, output, recipient_id),
            name, phase,
        )

    def result(self, proc):
        stdout, stderr = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, 0, stderr.decode(errors="replace"))
        lines = stdout.decode().splitlines()
        self.assertEqual(len(lines), 1, repr(lines))
        self.assertTrue(lines[0].startswith("RESULT:"), repr(lines))
        return json.loads(lines[0][7:])

    def test_authenticated_ipc_success_and_recovery_across_processes(self):
        first = self.token()
        outcome = self.result(self.spawn_gateway(first, "gateway-1"))
        self.assertTrue(outcome["accepted"])
        self.assertEqual(outcome["output"], "owned-value")
        fresh = self.token()
        recovered = self.result(self.spawn_gateway(fresh, "gateway-2"))
        self.assertTrue(recovered["accepted"])
        self.assertEqual(recovered["output"], "owned-value")
        self.assertEqual(self.committed(), 1)
        self.assertEqual(self.effect()["capability_id"], first.claims.capability_id)
        self.assertEqual(self.effect()["state"], "recipient-confirmed")
        self.assertEqual(self.run_parent(first).error_class, "authority-denied")

    def _gateway_sigkill(self, phase, count):
        first = self.token()
        proc = self.spawn_gateway(first, "gateway-killed", phase=phase)
        self.marker(proc, "PHASE:" + phase)
        self.assertEqual(self.committed(), count)
        self.assertEqual(self.effect()["state"], "possibly-committed")
        self.kill(proc)
        self.assertEqual(self.run_parent(first).error_class, "authority-denied")
        recovery = self.result(self.spawn_gateway(self.token(), "gateway-recovery"))
        self.assertTrue(recovery["accepted"])
        self.assertEqual(self.committed(), 1)
        self.assertEqual(self.effect()["capability_id"], first.claims.capability_id)
        self.assertEqual(self.effect()["state"], "recipient-confirmed")

    def test_gateway_sigkill_before_recipient_rpc_then_recover(self):
        self._gateway_sigkill("before_recipient_rpc", 0)

    def test_gateway_sigkill_after_recipient_reply_then_recover(self):
        self._gateway_sigkill("after_recipient_reply", 1)

    def _recipient_sigkill(self, phase, count):
        self.kill(self.service)
        self.start_service(phase=phase)
        first = self.token()
        proc = self.spawn_gateway(first, "client-" + phase)
        self.marker(self.service, "PHASE:" + phase)
        self.assertEqual(self.committed(), count)
        self.kill(self.service)
        denial = self.result(proc)
        self.assertFalse(denial["accepted"])
        self.assertEqual(denial["error_class"], "recipient-indeterminate")
        self.assertEqual(self.effect()["state"], "possibly-committed")
        self.start_service()
        self.assertEqual(self.run_parent(first).error_class, "authority-denied")
        recovered = self.result(self.spawn_gateway(
            self.token(), "recovery-" + phase,
        ))
        self.assertTrue(recovered["accepted"])
        self.assertEqual(self.committed(), 1)
        self.assertEqual(self.effect()["capability_id"], first.claims.capability_id)
        self.assertEqual(self.effect()["state"], "recipient-confirmed")

    def test_recipient_sigkill_before_commit_then_recover(self):
        self._recipient_sigkill("before_commit", 0)

    def test_recipient_sigkill_after_commit_before_reply_then_recover(self):
        self._recipient_sigkill("after_commit_before_reply", 1)

    def test_two_competing_gateway_processes_commit_only_once(self):
        first, second = self.token(), self.token()
        one = self.spawn_gateway(first, "competing-a")
        two = self.spawn_gateway(second, "competing-b")
        answers = [self.result(one), self.result(two)]
        self.assertEqual(sum(a["accepted"] for a in answers), 2, answers)
        self.assertEqual(self.committed(), 1)
        self.assertIn(self.effect()["capability_id"], {
            first.claims.capability_id, second.claims.capability_id,
        })
        self.assertEqual(self.effect()["state"], "recipient-confirmed")
        self.assertEqual(self.run_parent(first).error_class, "authority-denied")
        self.assertEqual(self.run_parent(second).error_class, "authority-denied")

    def test_disconnected_recipient_is_not_negative_reconciliation(self):
        cap = self.token()
        self.kill(self.service)
        outcome = self.run_parent(cap)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.error_class, "recipient-indeterminate")
        self.assertEqual(self.effect()["state"], "possibly-committed")
        self.assertEqual(self.committed(), 0)
        self.start_service()
        recovered = self.run_parent(self.token())
        self.assertTrue(recovered.accepted)
        self.assertEqual(self.committed(), 1)
        self.assertEqual(self.effect()["capability_id"], cap.claims.capability_id)

    def test_changed_output_recipient_and_corrupt_receipt_fail_closed(self):
        first = self.token()
        self.assertTrue(self.run_parent(first).accepted)
        changed = self.run_parent(self.token(), output="modified")
        self.assertEqual(changed.error_class, "effect-binding-conflict")
        different = self.run_parent(
            self.token(), recipient_id="other-recipient",
        )
        self.assertEqual(different.error_class, "effect-binding-conflict")
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE effects SET receipt_digest=?", ("f" * 64,))
        damaged = self.run_parent(self.token())
        self.assertEqual(damaged.error_class, "recipient-indeterminate")
        self.assertEqual(self.committed(), 1)

    def test_wrong_ipc_key_does_not_commit_and_can_recover(self):
        cap = self.token()
        denied = self.run_parent(cap, key=secrets.token_bytes(32))
        self.assertFalse(denied.accepted)
        self.assertEqual(denied.error_class, "recipient-indeterminate")
        self.assertEqual(self.committed(), 0)
        self.assertEqual(self.effect()["state"], "possibly-committed")
        self.assertTrue(self.run_parent(self.token()).accepted)
        self.assertEqual(self.committed(), 1)

    def test_legacy_reservation_ineligible_even_with_new_process(self):
        first = self.token()
        key = digest({
            "session_id": self.request.session_id,
            "request_id": self.request.request_id,
        })
        self.assertTrue(self.journal.reserve(
            tenant="default", environment="synthetic", effect_key=key,
            capability_id=first.claims.capability_id,
            request_digest=self.request.request_digest,
            claims_digest=digest(first.claims.to_dict()),
        ))
        decision = self.run_parent(self.token())
        self.assertEqual(decision.error_class, "effect-binding-conflict")
        self.assertEqual(self.committed(), 0)

    def test_unauthenticated_direct_socket_request_does_not_commit(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(2)
            channel.connect(str(self.sock))
            channel.sendall(encode_frame({
                "nonce": "a" * 32, "body": {
                    "operation": "apply", "recipient_id": self.recipient_id,
                    "effect_key": "a" * 64, "request_digest": "b" * 64,
                    "output": "attack",
                },
                "mac": "0" * 64,
            }))
            self.assertEqual(channel.recv(64), b"")
        self.assertEqual(self.committed(), 0)
        self.assertTrue(self.run_parent(self.token()).accepted)
        self.assertEqual(self.committed(), 1)


if __name__ == "__main__":
    unittest.main()
