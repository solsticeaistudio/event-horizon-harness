"""Regression for hardware failure at post-kill journal observation.

The attestation authority context intentionally has no top-level tenant field.
Namespace identity lives only in the trusted gateway verification options.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from event_horizon.effect_outcome_journal import DurableEffectJournal
from scripts.kvm_crash_journal_evidence import observe_crash_reservation


class KvmPostKillJournalIdentityTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        path = str(Path(self.folder.name) / "outcomes.sqlite")
        self.journal = DurableEffectJournal(path)
        self.config = {
            "outcome_journal": path,
            "verification_context": {"tenant": "default", "environment": "synthetic"},
        }
        self.binding = {
            "capability_id": "cap_original",
            "request_digest": "a" * 64,
            "claims_digest": "b" * 64,
        }

    def inspect(self):
        return observe_crash_reservation(self.config, **self.binding)

    def test_no_reservation_before_first_crash(self):
        self.assertIsNone(self.inspect())

    def test_reserved_state_is_read_from_nested_verification_context(self):
        self.assertTrue(self.journal.reserve(
            tenant="default", environment="synthetic",
            effect_key="c" * 64, **self.binding,
        ))
        self.assertEqual(self.inspect()["state"], "possibly-committed")

    def test_rebound_request_is_rejected(self):
        self.journal.reserve(
            tenant="default", environment="synthetic",
            effect_key="c" * 64, **self.binding,
        )
        self.binding["request_digest"] = "d" * 64
        with self.assertRaisesRegex(RuntimeError, "rebound"):
            self.inspect()

    def test_missing_or_malformed_namespace_fails_closed(self):
        for verification in (None, {}, {"tenant": "default"}, {
            "tenant": "", "environment": "synthetic",
        }):
            with self.subTest(verification=verification):
                self.config["verification_context"] = verification
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_no_cross_tenant_fallback(self):
        self.journal.reserve(
            tenant="default", environment="synthetic",
            effect_key="c" * 64, **self.binding,
        )
        self.config["verification_context"] = {
            "tenant": "other", "environment": "synthetic",
        }
        self.assertIsNone(self.inspect())


if __name__ == "__main__":
    unittest.main()
