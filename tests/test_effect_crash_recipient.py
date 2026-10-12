"""Portable tests for supervisor-side durable recipient observations."""
from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from scripts.effect_crash_recipient import _recipient_db, observed_recipient


class DurableRecipientTests(unittest.TestCase):
    def test_commit_survives_database_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recipient.sqlite"
            before = observed_recipient(path)
            self.assertEqual(before["count"], 0)
            with _recipient_db(path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("INSERT INTO commits(effect_key, request_digest) VALUES (?, ?)",
                             ("test-effect", "request-a"))
                conn.execute("COMMIT")
            after = observed_recipient(path)
            self.assertEqual(after["count"], 1)
            self.assertNotEqual(before["rows_digest"], after["rows_digest"])
            self.assertEqual(after, observed_recipient(path))

    def test_second_commit_is_detectable_not_silently_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recipient.sqlite"
            with _recipient_db(path) as conn:
                for _ in range(2):
                    conn.execute("INSERT INTO commits(effect_key, request_digest) VALUES (?, ?)",
                                 ("effect", "same-request"))
            self.assertEqual(observed_recipient(path)["count"], 2)


if __name__ == "__main__":
    unittest.main()
