"""Real Linux transport EOF and competing recovery gateway regression tests.

These tests use independently supervised processes and real durable SQLite, but
are NOT proof of a Firecracker guest or any uncooperative external effect.
"""
from __future__ import annotations

import unittest

from tests.test_independent_fenced_recipient import IndependentFencedRecipientTests


class FencedTransportAndRaceTests(IndependentFencedRecipientTests):
    def test_drop_ack_after_commit_keeps_recipient_alive_and_original_fence(self):
        self.kill(self.service)
        self.start_service("drop_ack_after_commit")
        original = self.token()
        response = self.run_parent(original)
        self.assertFalse(response.accepted)
        self.assertEqual(response.error_class, "recipient-indeterminate")
        self.assertEqual(response.effect_state, "possibly-committed")
        self.marker(self.service, "DROPPED:drop_ack_after_commit")
        self.assertIsNone(self.service.poll(), "recipient must stay alive")
        self.assertEqual(self.committed(), 1)
        self.assertEqual(self.effect()["state"], "possibly-committed")
        self.assertEqual(self.effect()["capability_id"], original.claims.capability_id)
        self.assertEqual(self.run_parent(original).error_class, "authority-denied")
        fresh = self.token()
        healed = self.run_parent(fresh)
        self.assertTrue(healed.accepted, healed.error_class)
        self.assertEqual(healed.output, "owned-value")
        self.assertEqual(self.committed(), 1)
        self.assertEqual(self.effect()["state"], "recipient-confirmed")
        self.assertEqual(self.effect()["capability_id"], original.claims.capability_id)

    def test_before_commit_drop_never_clears_original_reservation(self):
        self.kill(self.service)
        self.start_service("drop_before_commit")
        original = self.token()
        response = self.run_parent(original)
        self.assertFalse(response.accepted)
        self.assertEqual(response.effect_state, "possibly-committed")
        self.marker(self.service, "DROPPED:drop_before_commit")
        self.assertIsNone(self.service.poll())
        self.assertEqual(self.committed(), 0)
        self.assertEqual(self.effect()["state"], "possibly-committed")
        self.assertEqual(self.run_parent(original).error_class, "authority-denied")
        healed = self.run_parent(self.token())
        self.assertTrue(healed.accepted, healed.error_class)
        self.assertEqual(self.committed(), 1)
        self.assertEqual(self.effect()["capability_id"], original.claims.capability_id)

    def test_two_separately_authorized_recovery_processes_race(self):
        for phase, old_count in (("drop_before_commit", 0), ("drop_ack_after_commit", 1)):
            with self.subTest(phase=phase):
                # The first test subcase can reuse a fresh fixture. Explicitly
                # reset by using the original base setUp/cleanup for each phase
                # only when this class itself created a separate case.
                if phase == "drop_ack_after_commit":
                    self.cleanup_processes()
                    self.tmp.cleanup()
                    IndependentFencedRecipientTests.setUp(self)
                self.kill(self.service)
                self.start_service(phase)
                original = self.token()
                unknown = self.run_parent(original)
                self.assertEqual(unknown.error_class, "recipient-indeterminate")
                self.marker(self.service, "DROPPED:" + phase)
                self.assertEqual(self.committed(), old_count)
                first, second = self.token(), self.token()
                self.assertNotEqual(first.claims.capability_id, second.claims.capability_id)
                one = self.spawn_gateway(first, "race-first")
                two = self.spawn_gateway(second, "race-second")
                answers = [self.result(one), self.result(two)]
                self.assertTrue(all(result["accepted"] for result in answers), answers)
                self.assertEqual(self.committed(), 1)
                self.assertEqual(self.effect()["state"], "recipient-confirmed")
                self.assertEqual(self.effect()["capability_id"], original.claims.capability_id)
                self.assertEqual(self.run_parent(first).error_class, "authority-denied")
                self.assertEqual(self.run_parent(second).error_class, "authority-denied")


if __name__ == "__main__":
    unittest.main()
