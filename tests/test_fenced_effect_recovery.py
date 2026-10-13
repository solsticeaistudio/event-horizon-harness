"""Real signed capability recovery against one atomic, fenced SQLite recipient.

Portable process/SQLite guarantees; not a new Firecracker result and not
exactly-once execution of arbitrary nontransactional third-party effects.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

from event_horizon.broker import CapabilityBroker, CapabilityVerifier
from event_horizon.canonical import digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_effect_recovery import FencedEffectRecoveryGateway
from event_horizon.fenced_recipient import (
    FencedSqliteRecipient, FencedRecipientBindingError, FencedRecipientError,
)
from event_horizon.models import ActionRequest
from event_horizon.recorder import ExternalRecorder
from event_horizon.trusted_effect_gateway import select_consumption_store
from scripts.capability_fixture_support import (
    authority_context, issue_options, verify_options,
)


class FencedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.recipient_db = self.root / "fenced-recipient.sqlite"
        self.journal_db = self.root / "journal.sqlite"
        self.replay_db = self.root / "replay.sqlite"
        self.request = ActionRequest(
            "fenced-read", "fenced-session", "agent", "object.read",
            "synthetic-data", "exec-1", {"offset": 0, "length": 5},
            "fenced recovery test",
        )
        self.context = authority_context(
            self.request, time.time(), max_output_bytes=512,
        )
        self.broker = CapabilityBroker(ttl_seconds=120)
        self.recorder = ExternalRecorder(self.root / "events.jsonl")
        self.effects = FencedSqliteRecipient(
            self.recipient_db, recipient_id="owned-recipient-v1",
        )
        self.journal = DurableEffectJournal(self.journal_db)
        self.now_kwargs = verify_options(self.context)
        self.now_kwargs.pop("tenant")
        self.now_kwargs.pop("environment")
        self.store = select_consumption_store(
            backend="sqlite", sqlite_path=str(self.replay_db),
            namespace=self.request.session_id, domain="external-effect",
        )
        self.addCleanup(self.store.close)

    def token(self, request=None):
        return self.broker.issue(
            request or self.request, **issue_options(self.context),
            max_output_bytes=512,
        )

    def gateway(self, *, recipient=None, journal=None, recorder=None,
                output_factory=None, preflight=None):
        return FencedEffectRecoveryGateway(
            CapabilityVerifier(self.broker.public_key_pem,
                               self.broker.key_id, self.store),
            self.recorder if recorder is None else recorder,
            self.journal if journal is None else journal,
            self.effects if recipient is None else recipient,
            output_factory=output_factory or (lambda req: "owned-value"),
            pre_dispatch_rule=preflight,
        )

    def run_token(self, token, gateway=None, request=None):
        return (gateway or self.gateway()).execute(
            request or self.request, token, self.context["attestation"],
            executor_measurement=self.context["executor_measurement"],
            device_id=self.context["device_id"],
            verifier_policy_digest=self.context["verifier_policy_digest"],
            policy_digest=self.context["policy_digest"],
        )

    def key(self):
        return digest({"session_id": self.request.session_id,
                       "request_id": self.request.request_id})

    def test_normal_commit_and_new_token_recover_stored_result(self):
        first, second = self.token(), self.token()
        one = self.run_token(first)
        self.assertTrue(one.accepted)
        self.assertEqual(one.output, "owned-value")
        recovered = self.run_token(second, self.gateway())
        self.assertTrue(recovered.accepted)
        self.assertEqual(recovered.output, "owned-value")
        self.assertEqual(self.effects.commit_count(), 1)
        self.assertFalse(self.run_token(second).accepted)
        record = self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=self.key(),
        )
        self.assertEqual(record["capability_id"], first.claims.capability_id)
        self.assertEqual(record["state"], "recipient-confirmed")
        self.assertEqual(len([e for e in self.recorder.events()
                              if e["event_type"] == "fenced.recipient-confirmed"]), 2)

    def test_after_commit_ack_lost_reconciliation_after_restart(self):
        first, second = self.token(), self.token()
        class LostAck(FencedSqliteRecipient):
            def apply(inner, **kwargs):
                super().apply(**kwargs)
                raise ConnectionResetError("gateway lost ack after durable commit")
        lost_ack = LostAck(self.recipient_db, recipient_id="owned-recipient-v1")
        initial = self.run_token(first, self.gateway(recipient=lost_ack))
        self.assertFalse(initial.accepted)
        self.assertEqual(initial.effect_state, "possibly-committed")
        self.assertEqual(self.effects.commit_count(), 1)
        self.assertEqual(self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=self.key(),
        )["state"], "possibly-committed")
        # Fresh gateway + recipient instance reopen durable state.
        restarted = FencedSqliteRecipient(
            self.recipient_db, recipient_id="owned-recipient-v1",
        )
        recovered = self.run_token(second, self.gateway(recipient=restarted))
        self.assertTrue(recovered.accepted)
        self.assertEqual(recovered.output, "owned-value")
        self.assertEqual(restarted.commit_count(), 1)

    def test_before_commit_failure_can_safely_resume_without_release(self):
        class DieBeforeCommit(FencedSqliteRecipient):
            def apply(inner, **kwargs):
                raise ConnectionError("recipient unavailable before commit")
        first, fresh = self.token(), self.token()
        result = self.run_token(first, self.gateway(recipient=DieBeforeCommit(
            self.recipient_db, recipient_id="owned-recipient-v1",
        )))
        self.assertFalse(result.accepted)
        self.assertEqual(result.error_class, "recipient-indeterminate")
        self.assertEqual(self.effects.commit_count(), 0)
        recovered = self.run_token(fresh, self.gateway())
        self.assertTrue(recovered.accepted)
        self.assertEqual(self.effects.commit_count(), 1)
        self.assertEqual(self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=self.key(),
        )["capability_id"], first.claims.capability_id)

    def test_older_inflight_commit_races_newly_authorized_recovery(self):
        class DelayedOriginal(FencedSqliteRecipient):
            ready = threading.Event()
            release = threading.Event()
            def apply(inner, **kwargs):
                inner.ready.set()
                if not inner.release.wait(timeout=10):
                    raise RuntimeError("old effect did not resume")
                return super().apply(**kwargs)
        original = DelayedOriginal(
            self.recipient_db, recipient_id="owned-recipient-v1",
        )
        first, fresh = self.token(), self.token()
        outcome = []
        thread = threading.Thread(target=lambda: outcome.append(self.run_token(
            first, self.gateway(recipient=original)
        )), daemon=True)
        thread.start()
        self.assertTrue(original.ready.wait(timeout=10))
        self.assertEqual(self.effects.commit_count(), 0)
        recovered = self.run_token(fresh, self.gateway())
        self.assertTrue(recovered.accepted)
        self.assertEqual(self.effects.commit_count(), 1)
        original.release.set()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertTrue(outcome[0].accepted)
        self.assertEqual(self.effects.commit_count(), 1)

    def test_original_commits_first_after_new_gateway_has_reserved(self):
        class DelayedNew(FencedSqliteRecipient):
            ready = threading.Event()
            release = threading.Event()
            def apply(inner, **kwargs):
                inner.ready.set()
                if not inner.release.wait(timeout=10):
                    raise RuntimeError("fresh effect did not resume")
                return super().apply(**kwargs)
        # First permanently reserves, but cannot commit.
        class OldInterrupted(FencedSqliteRecipient):
            def apply(inner, **kwargs):
                raise ConnectionError("interrupted")
        first, fresh = self.token(), self.token()
        self.assertFalse(self.run_token(first, self.gateway(
            recipient=OldInterrupted(self.recipient_db, recipient_id="owned-recipient-v1")
        )).accepted)
        new = DelayedNew(self.recipient_db, recipient_id="owned-recipient-v1")
        outcome = []
        thread = threading.Thread(target=lambda: outcome.append(self.run_token(
            fresh, self.gateway(recipient=new)
        )), daemon=True)
        thread.start()
        self.assertTrue(new.ready.wait(timeout=10))
        # The old request was already authorized before the crash; it can still
        # arrive late, independent of new capability consumption.
        original_commit = self.effects.apply(
            effect_key=self.key(), request_digest=self.request.request_digest,
            output="owned-value",
        )
        self.assertTrue(original_commit.newly_committed)
        new.release.set()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertTrue(outcome[0].accepted)
        self.assertEqual(self.effects.commit_count(), 1)

    def test_binding_conflict_never_dispatches_second_effect(self):
        first = self.token()
        self.assertTrue(self.run_token(first).accepted)
        modified = ActionRequest(
            self.request.request_id, self.request.session_id, self.request.agent_id,
            self.request.operation, self.request.resource_id,
            self.request.executor_id, {"offset": 1, "length": 4},
            self.request.purpose,
        )
        # A real verifier MUST refuse a signed cap for the original request.
        mismatch = self.run_token(self.token(), request=modified)
        self.assertEqual(mismatch.error_class, "authority-denied")
        self.assertEqual(self.effects.commit_count(), 1)

    def test_stored_output_rebinding_is_rejected_not_overwritten(self):
        first, fresh = self.token(), self.token()
        self.assertTrue(self.run_token(first).accepted)
        outcome = self.run_token(
            fresh, self.gateway(output_factory=lambda _: "CHANGED"),
        )
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.error_class, "effect-binding-conflict")
        self.assertEqual(self.effects.observe(
            effect_key=self.key(), request_digest=self.request.request_digest,
        ).output, "owned-value")
        self.assertEqual(self.effects.commit_count(), 1)

    def test_legacy_reserved_effect_cannot_be_mistaken_for_atomic_fence(self):
        old = self.token()
        self.journal.reserve(
            tenant="default", environment="synthetic", effect_key=self.key(),
            capability_id=old.claims.capability_id,
            request_digest=self.request.request_digest,
            claims_digest=digest(old.claims.to_dict()),
        )
        actual = self.run_token(self.token())
        self.assertFalse(actual.accepted)
        self.assertEqual(actual.error_class, "effect-binding-conflict")
        self.assertEqual(self.effects.commit_count(), 0)
        self.assertIsNone(self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=self.key(),
        )["fenced_protocol"])

    def test_migrate_existing_legacy_sqlite_journal_without_upgrading_authority(self):
        legacy_db = self.root / "old-layout.sqlite"
        with sqlite3.connect(legacy_db) as conn:
            conn.execute("""CREATE TABLE effects (
                tenant TEXT NOT NULL, environment TEXT NOT NULL,
                effect_key TEXT NOT NULL, capability_id TEXT NOT NULL,
                request_digest TEXT NOT NULL, claims_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                receipt_digest TEXT,
                PRIMARY KEY (tenant, environment, capability_id),
                UNIQUE (tenant, environment, effect_key))""")
            conn.execute(
                "INSERT INTO effects VALUES(?,?,?,?,?,?,?,?)",
                ("default", "synthetic", self.key(), "cap_legacy",
                 self.request.request_digest, "a" * 64, "possibly-committed", None),
            )
        os.chmod(legacy_db, 0o600)
        upgraded = DurableEffectJournal(legacy_db)
        row = upgraded.observe_effect(
            tenant="default", environment="synthetic", effect_key=self.key(),
        )
        self.assertIsNone(row["fenced_protocol"])
        self.assertIsNone(row["fenced_recipient_id"])
        result = self.run_token(self.token(), self.gateway(journal=upgraded))
        self.assertEqual(result.error_class, "effect-binding-conflict")
        self.assertEqual(self.effects.commit_count(), 0)

    def test_different_cooperating_recipient_identity_cannot_hijack_recovery(self):
        self.assertTrue(self.run_token(self.token()).accepted)
        elsewhere = FencedSqliteRecipient(
            self.root / "other-recipient.sqlite", recipient_id="other-recipient",
        )
        response = self.run_token(self.token(), self.gateway(recipient=elsewhere))
        self.assertEqual(response.error_class, "effect-binding-conflict")
        self.assertEqual(elsewhere.commit_count(), 0)
        self.assertEqual(self.effects.commit_count(), 1)

    def test_corrupted_recipient_receipt_fails_closed(self):
        first, fresh = self.token(), self.token()
        self.assertTrue(self.run_token(first).accepted)
        with sqlite3.connect(self.recipient_db) as db:
            db.execute("UPDATE effects SET receipt_digest=?", ("f" * 64,))
        recovered = self.run_token(fresh)
        self.assertEqual(recovered.error_class, "recipient-indeterminate")
        self.assertEqual(self.effects.commit_count(), 1)

    def test_same_capability_replay_denied_even_after_success(self):
        cap = self.token()
        self.assertTrue(self.run_token(cap).accepted)
        self.assertEqual(self.run_token(cap).error_class, "authority-denied")
        self.assertEqual(self.effects.commit_count(), 1)

    def test_bad_signature_denied(self):
        from event_horizon.models import IssuedCapability
        cap = self.token()
        corrupt = IssuedCapability(
            cap.claims, "A" * 86, cap.key_id,
        )
        self.assertEqual(self.run_token(corrupt).error_class, "authority-denied")
        self.assertEqual(self.effects.commit_count(), 0)

    def test_recorder_outage_never_reaches_recipient(self):
        recorder = Mock()
        recorder.append.side_effect = OSError("unavailable")
        got = self.run_token(self.token(), self.gateway(recorder=recorder))
        self.assertEqual(got.error_class, "evidence-unavailable")
        self.assertEqual(self.effects.commit_count(), 0)

    def test_journal_failure_never_reaches_recipient(self):
        journal = self.journal
        original = journal.reserve_fenced
        try:
            journal.reserve_fenced = Mock(side_effect=OSError("no disk"))
            got = self.run_token(self.token())
        finally:
            journal.reserve_fenced = original
        self.assertEqual(got.error_class, "effect-journal-unavailable")
        self.assertEqual(self.effects.commit_count(), 0)

    def test_preflight_denies_before_reservation(self):
        cap = self.token()
        result = self.run_token(cap, self.gateway(preflight=lambda r,c: False))
        self.assertEqual(result.error_class, "pre-dispatch-denied")
        self.assertEqual(self.effects.commit_count(), 0)
        self.assertIsNone(self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=self.key(),
        ))

    def test_output_ceiling_fails_before_reservation(self):
        huge = self.gateway(output_factory=lambda _: "x" * 513)
        result = self.run_token(self.token(), huge)
        self.assertEqual(result.error_class, "pre-dispatch-denied")
        self.assertEqual(self.effects.commit_count(), 0)

    def test_nonrecoverable_float_output_is_rejected_before_fencing(self):
        decision = self.run_token(
            self.token(), self.gateway(output_factory=lambda _: {"value": 1.25}),
        )
        self.assertEqual(decision.error_class, "pre-dispatch-denied")
        self.assertEqual(self.effects.commit_count(), 0)
        self.assertIsNone(self.journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=self.key(),
        ))
        with self.assertRaises(ValueError):
            self.effects.apply(
                effect_key=self.key(), request_digest=self.request.request_digest,
                output={"value": 1.25},
            )
        self.assertEqual(self.effects.commit_count(), 0)

    def test_failed_completion_evidence_can_be_recovered(self):
        first, fresh = self.token(), self.token()
        recorder = Mock()
        recorder.append.side_effect = [None, OSError("disk failed")]
        first_result = self.run_token(first, self.gateway(recorder=recorder))
        self.assertEqual(first_result.error_class, "evidence-indeterminate")
        self.assertEqual(self.effects.commit_count(), 1)
        self.assertTrue(self.run_token(fresh).accepted)
        self.assertEqual(self.effects.commit_count(), 1)

    def test_signed_recipient_identity_must_stay_pinned(self):
        self.effects.apply(
            effect_key=self.key(), request_digest=self.request.request_digest,
            output="owned-value",
        )
        with self.assertRaises(FencedRecipientBindingError):
            FencedSqliteRecipient(self.recipient_db, recipient_id="evil-replacement")
        self.assertEqual(self.effects.commit_count(), 1)

    def test_symlinked_recipient_database_is_rejected(self):
        linked = self.root / "alias.sqlite"
        linked.symlink_to(self.recipient_db)
        with self.assertRaises((OSError, FencedRecipientError)):
            FencedSqliteRecipient(linked, recipient_id="owned-recipient-v1")

    def test_atomic_dedupe_across_many_concurrent_instances(self):
        def commit(_):
            return FencedSqliteRecipient(
                self.recipient_db, recipient_id="owned-recipient-v1",
            ).apply(effect_key=self.key(), request_digest=self.request.request_digest,
                    output="owned-value")
        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(pool.map(commit, range(32)))
        self.assertEqual(sum(r.newly_committed for r in receipts), 1)
        self.assertEqual(len({r.receipt_digest for r in receipts}), 1)
        self.assertEqual(self.effects.commit_count(), 1)

    def _real_sigkill_then_recover(self, phase):
        import json
        import select
        import signal
        import subprocess
        import sys

        first = self.token()
        config = {
            "public_key_pem": self.broker.public_key_pem,
            "key_id": self.broker.key_id,
            "request": self.request.canonical_payload(),
            "capability": first.to_dict(),
            "verification_context": verify_options(self.context),
            "recipient_path": str(self.recipient_db),
            "recipient_id": "owned-recipient-v1",
            "journal_path": str(self.journal_db),
            "replay_path": str(self.replay_db),
            "recorder_path": str(self.root / "killed-gateway-events.jsonl"),
            "output": "owned-value",
        }
        path = self.root / "trusted-kill-config.json"
        path.write_text(json.dumps(config))
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "scripts.fenced_recovery_sigkill_worker",
             "--config", str(path), "--phase", phase],
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
        )
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 12)
            marker = proc.stdout.readline().strip() if ready else b""
            if marker != ("PHASE:" + phase).encode():
                raise AssertionError(
                    "child never reached verified transaction checkpoint: "
                    + repr(marker) + " status=" + repr(proc.poll())
                    + " stderr=" + (proc.stderr.read(3000).decode(errors="replace")
                                    if proc.poll() is not None else "running")
                )
            self.assertIsNone(proc.poll())
            expected_at_kill = (1 if phase == "after_recipient_commit" else 0)
            self.assertEqual(self.effects.commit_count(), expected_at_kill)
            reservation = self.journal.observe_effect(
                tenant="default", environment="synthetic", effect_key=self.key(),
            )
            self.assertIsNotNone(reservation)
            self.assertEqual(reservation["state"], "possibly-committed")
            self.assertEqual(reservation["capability_id"], first.claims.capability_id)
            killed_pid = proc.pid
            proc.kill()
            self.assertEqual(proc.wait(timeout=5), -signal.SIGKILL)
            # Original signed capability is already durably consumed.
            self.assertEqual(self.run_token(first).error_class, "authority-denied")
            fresh = self.token()
            result = self.run_token(fresh, self.gateway())
            self.assertTrue(result.accepted)
            self.assertEqual(result.effect_state, "completed")
            self.assertEqual(result.output, "owned-value")
            self.assertEqual(self.effects.commit_count(), 1)
            self.assertEqual(self.journal.observe_effect(
                tenant="default", environment="synthetic", effect_key=self.key(),
            )["state"], "recipient-confirmed")
            reconciliation = [
                e for e in self.recorder.events()
                if e["event_type"] == "fenced.recipient-confirmed"
            ]
            self.assertEqual(len(reconciliation), 1)
            self.assertEqual(reconciliation[0]["payload"]["original_capability_id"],
                             first.claims.capability_id)
            self.assertEqual(reconciliation[0]["payload"]["recovery"], True)
            self.assertEqual(reconciliation[0]["payload"]["new_effect_commit"],
                             expected_at_kill == 0)
            self.assertNotEqual(killed_pid, os.getpid())
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "pidfd_open"),
                         "real gateway SIGKILL requires Linux")
    def test_real_gateway_sigkill_before_recipient_commit_then_progress(self):
        self._real_sigkill_then_recover("before_recipient_commit")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "pidfd_open"),
                         "real gateway SIGKILL requires Linux")
    def test_real_gateway_sigkill_after_recipient_commit_before_ack(self):
        self._real_sigkill_then_recover("after_recipient_commit")



if __name__ == "__main__":
    unittest.main()
