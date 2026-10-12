"""Positive-only local recipient reconciliation; never infer absence is safe."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from event_horizon.effect_outcome_journal import (
    DurableEffectJournal, EffectAlreadyReserved,
)
from scripts.effect_crash_recipient import _recipient_db
from scripts.recipient_journal_reconciliation import (
    RecipientReconciliationError, reconcile_durable_commit,
)

KEY = "a" * 64
REQUEST = "b" * 64
CLAIMS = "c" * 64
CAP = "cap_fixture"


class PositiveReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.path = root / "recipient.sqlite"
        self.journal = DurableEffectJournal(root / "outcome.sqlite")
        self.parameters = dict(
            tenant="default", environment="synthetic", effect_key=KEY,
            capability_id=CAP, request_digest=REQUEST, claims_digest=CLAIMS,
        )
        self.journal.reserve(**self.parameters)
        with _recipient_db(self.path):
            pass

    def reconcile(self):
        return reconcile_durable_commit(
            recipient_database=self.path, journal=self.journal,
            **self.parameters,
        )

    def insert(self, *, key=KEY, request=REQUEST):
        with _recipient_db(self.path) as db:
            db.execute("INSERT INTO commits(effect_key,request_digest) VALUES (?,?)",
                       (key, request))

    def test_confirm_only_after_reading_actual_durable_commit(self):
        self.insert()
        receipt = self.reconcile()
        self.assertEqual(receipt["state"], "recipient-confirmed")
        self.assertEqual(receipt["recipient_commit_count"], 1)
        self.assertEqual(receipt["receipt_digest"],
                         self.reconcile()["receipt_digest"])
        row = self.journal.observe(
            tenant="default", environment="synthetic", capability_id=CAP,
        )
        self.assertEqual(row["receipt_digest"], receipt["receipt_digest"])
        with self.assertRaises(EffectAlreadyReserved):
            self.journal.reserve(**(self.parameters | {
                "capability_id": "cap_new", "claims_digest": "d" * 64,
            }))

    def test_missing_or_wrong_commit_never_releases_reservation(self):
        with self.assertRaises(RecipientReconciliationError):
            self.reconcile()
        self.insert(key="d" * 64)
        with self.assertRaises(RecipientReconciliationError):
            self.reconcile()
        row = self.journal.observe(
            tenant="default", environment="synthetic", capability_id=CAP,
        )
        self.assertEqual(row["state"], "possibly-committed")
        self.assertFalse(self.journal.reserve(**self.parameters))

    def test_multiple_commits_not_silently_confirmed(self):
        self.insert()
        self.insert()
        with self.assertRaises(RecipientReconciliationError):
            self.reconcile()

    def test_readonly_source_and_ownership(self):
        self.insert()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.path.chmod(0o644)
        with self.assertRaises(RecipientReconciliationError):
            self.reconcile()

    def test_symlink_to_recipient_database_rejected(self):
        self.insert()
        symlink = self.path.with_suffix(".link")
        symlink.symlink_to(self.path)
        self.path = symlink
        with self.assertRaises(RecipientReconciliationError):
            self.reconcile()


if __name__ == "__main__":
    unittest.main()
