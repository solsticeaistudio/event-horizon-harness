"""Durable no-retry boundaries; no assertion of exactly-once external effects."""
from __future__ import annotations

import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from event_horizon.effect_outcome_journal import DurableEffectJournal, EffectJournalError, EffectAlreadyReserved
from event_horizon.models import ActionRequest
from event_horizon.trusted_effect_gateway import TrustedEffectGateway


CAP = "cap_0123456789abcdef01234567"
HASH = "a" * 64
CLAIMS = "b" * 64
RECEIPT = "c" * 64


def reservation():
    return dict(tenant="fixture-tenant", environment="synthetic",
                effect_key="e" * 64, capability_id=CAP,
                request_digest=HASH, claims_digest=CLAIMS)


def request(*, length=5):
    return ActionRequest("effect-id", "session", "agent", "object.read", "resource",
                         "executor", {"offset": 0, "length": length}, "test")


class AlwaysAuthorized:
    """Deliberately ignores replay to independently exercise the durable journal."""
    def verify_and_consume(self, capability, request, **kwargs):
        return SimpleNamespace(
            capability_id=CAP, max_output_bytes=64,
            to_dict=lambda: {"capability_id": CAP, "max_output_bytes": 64},
        )


class OutcomeJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "durable.sqlite"

    def journal(self):
        return DurableEffectJournal(self.path)

    def test_absolute_disk_path_required(self):
        with self.assertRaises(ValueError):
            DurableEffectJournal(":memory:")

    def test_reservation_is_durable_and_never_reexecuted(self):
        journal = self.journal()
        self.assertTrue(journal.reserve(**reservation()))
        restarted = self.journal()
        self.assertFalse(restarted.reserve(**reservation()))
        self.assertEqual(restarted.observe(tenant="fixture-tenant", environment="synthetic",
                                           capability_id=CAP)["state"], "possibly-committed")

    def test_concurrent_reservation_admits_only_one_dispatch(self):
        def attempt(_):
            return self.journal().reserve(**reservation())
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, (1, 2)))
        self.assertEqual(sorted(outcomes), [False, True])

    def test_changed_binding_is_rejected_not_treated_as_replay(self):
        journal = self.journal()
        journal.reserve(**reservation())
        with self.assertRaises(EffectAlreadyReserved):
            journal.reserve(**(reservation() | {"request_digest": "d" * 64}))
        self.assertFalse(journal.reserve(**reservation()))

    def test_new_capability_cannot_repeat_same_logical_effect(self):
        journal = self.journal()
        self.assertTrue(journal.reserve(**reservation()))
        new_token = reservation() | {"capability_id": "cap_different",
                                     "claims_digest": "f" * 64}
        with self.assertRaises(EffectAlreadyReserved):
            self.journal().reserve(**new_token)
        self.assertFalse(self.journal().reserve(**reservation()))

    def test_confirm_only_from_explicit_trusted_recipient_observation(self):
        journal = self.journal()
        with self.assertRaises(EffectJournalError):
            journal.confirm_from_trusted_recipient(**reservation(), receipt_digest=RECEIPT)
        journal.reserve(**reservation())
        journal.confirm_from_trusted_recipient(**reservation(), receipt_digest=RECEIPT)
        journal.confirm_from_trusted_recipient(**reservation(), receipt_digest=RECEIPT)
        with self.assertRaises(EffectJournalError):
            journal.confirm_from_trusted_recipient(**reservation(), receipt_digest="d"*64)
        self.assertEqual(self.journal().observe(tenant="fixture-tenant", environment="synthetic",
                                               capability_id=CAP)["receipt_digest"], RECEIPT)
        self.assertFalse(self.journal().reserve(**reservation()))

    def test_gateway_crash_after_effect_before_ack_blocks_repeat_across_restart(self):
        executed = []
        journal = self.journal()
        token = SimpleNamespace(claims=SimpleNamespace(capability_id=CAP))
        args = dict(executor_measurement="fixture", device_id="fixture",
                    verifier_policy_digest="policy", policy_digest="policy")
        req = request()

        def handler(_):
            executed.append("recipient committed")
            raise RuntimeError("acknowledgment lost after recipient commit")

        kwargs = dict(tenant="fixture-tenant", outcome_journal=journal)
        original = TrustedEffectGateway(AlwaysAuthorized(), {"object.read": handler},
                                        Mock(), **kwargs)
        outcome = original.execute(req, token, {}, **args)
        self.assertEqual(outcome.effect_state, "possibly-committed")
        self.assertEqual(executed, ["recipient committed"])

        recovered = TrustedEffectGateway(
            AlwaysAuthorized(), {"object.read": lambda _: executed.append("UNSAFE REPEAT")},
            Mock(), tenant="fixture-tenant", outcome_journal=self.journal(),
        )
        denied = recovered.execute(req, token, {}, **args)
        self.assertEqual(denied.effect_state, "possibly-committed")
        self.assertEqual(denied.error_class, "prior-dispatch-unknown")
        self.assertEqual(executed, ["recipient committed"])

    def test_gateway_blocks_new_capability_for_same_logical_action(self):
        actions = []
        args = dict(executor_measurement="fixture", device_id="fixture",
                    verifier_policy_digest="policy", policy_digest="policy")
        current = request()

        class FreshVerifier:
            def __init__(self, cap_id):
                self.cap_id = cap_id
            def verify_and_consume(self, capability, request, **kwargs):
                return SimpleNamespace(
                    capability_id=self.cap_id, max_output_bytes=64,
                    to_dict=lambda: {"capability_id": self.cap_id, "max_output_bytes": 64},
                )

        def make_gate(cap_id, effect):
            return TrustedEffectGateway(FreshVerifier(cap_id), {"object.read": effect},
                                        Mock(), outcome_journal=self.journal())

        first_id = "cap_original"
        second_id = "cap_new"
        first = make_gate(first_id, lambda _: actions.append("committed") or "ok")
        self.assertTrue(first.execute(current,
            SimpleNamespace(claims=SimpleNamespace(capability_id=first_id)), {},
            **args).accepted)
        second = make_gate(second_id, lambda _: actions.append("UNSAFE SECOND DISPATCH"))
        blocked = second.execute(current,
            SimpleNamespace(claims=SimpleNamespace(capability_id=second_id)), {}, **args)
        self.assertEqual(blocked.effect_state, "possibly-committed")
        self.assertEqual(blocked.error_class, "prior-effect-unknown")
        self.assertEqual(actions, ["committed"])

    def test_trusted_pre_dispatch_rule_prevents_oversized_known_read(self):
        journal = self.journal()
        effects = []
        req = request(length=1000)
        guard = lambda action, claims: action.arguments["length"] <= claims.max_output_bytes
        gw = TrustedEffectGateway(
            AlwaysAuthorized(), {"object.read": lambda _: effects.append("effect")},
            Mock(), tenant="fixture-tenant", outcome_journal=journal,
            pre_dispatch_rules={"object.read": guard},
        )
        response = gw.execute(req, SimpleNamespace(claims=SimpleNamespace(capability_id=CAP)),
                              {}, executor_measurement="fixture", device_id="fixture",
                              verifier_policy_digest="policy", policy_digest="policy")
        self.assertFalse(response.accepted)
        self.assertEqual(response.effect_state, "not-started")
        self.assertEqual(response.error_class, "pre-dispatch-denied")
        self.assertEqual(effects, [])
        self.assertIsNone(journal.observe(tenant="fixture-tenant",
                                          environment="synthetic", capability_id=CAP))

    def test_unavailable_journal_does_not_dispatch(self):
        class BrokenJournal:
            def reserve(self, **kwargs):
                raise sqlite3.OperationalError("disk unavailable")
        effects = []
        gw = TrustedEffectGateway(
            AlwaysAuthorized(), {"object.read": lambda _: effects.append("effect")},
            Mock(), outcome_journal=BrokenJournal(),
        )
        outcome = gw.execute(request(),
            SimpleNamespace(claims=SimpleNamespace(capability_id=CAP)), {},
            executor_measurement="fixture", device_id="fixture",
            verifier_policy_digest="policy", policy_digest="policy")
        self.assertEqual(outcome.effect_state, "not-started")
        self.assertEqual(outcome.error_class, "effect-journal-unavailable")
        self.assertEqual(effects, [])


if __name__ == "__main__":
    unittest.main()
