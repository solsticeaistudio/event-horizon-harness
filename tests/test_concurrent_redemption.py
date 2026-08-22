from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from event_horizon.broker import CapabilityBroker, CapabilityVerifier
from event_horizon.concurrency_harness import (
    ConcurrentRedemptionHarness,
    VulnerableNonAtomicConsumptionStore,
    sqlite_verifier_factories,
)
from event_horizon.models import ActionRequest
from event_horizon.replay_state import InMemoryCapabilityConsumptionStore
from scripts.capability_fixture_support import authority_context, issue_options, verify_options


FIXED_NOW = 1_700_000_000.0


class ConcurrentRedemptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = ActionRequest(
            "race-request", "race-session", "attacker-agent", "object.read",
            "target-source", "exec-1", {"length": 1, "offset": 0}, "race test",
        )
        self.authority = authority_context(self.request, FIXED_NOW)
        self.context = verify_options(self.authority)
        self.broker = CapabilityBroker(
            b"concurrency-test-key-no-authority",
            ttl_seconds=60,
            consumption_store=InMemoryCapabilityConsumptionStore(),
        )
        self.capability = self.broker.issue(
            self.request, **issue_options(self.authority), max_output_bytes=1_024, now=FIXED_NOW
        )

    def test_256_simultaneous_retries_commit_at_most_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            factories = sqlite_verifier_factories(
                Path(directory) / "consumption.sqlite3",
                self.broker.public_key_pem,
                self.broker.key_id,
            )
            result = ConcurrentRedemptionHarness(factories, attempts=256).run(
                self.capability,
                self.request,
                self.context,
                now=FIXED_NOW,
                partition_attempts=frozenset(range(0, 256, 31)),
                dropped_response_attempts=frozenset(range(0, 256, 17)),
            )
        self.assertTrue(result.invariant_passed)
        self.assertEqual(result.accepted_redemptions, 1)
        self.assertEqual(result.committed_effects, 1)
        self.assertEqual(
            result.replay_denials + result.partition_denials + result.accepted_redemptions,
            result.attempts,
        )
        self.assertEqual(result.distinct_idempotency_keys, result.attempts)

    def test_restart_different_idempotency_keys_and_policy_refresh_do_not_revive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "consumption.sqlite3"
            first = sqlite_verifier_factories(
                path, self.broker.public_key_pem, self.broker.key_id, replicas=2
            )
            initial = ConcurrentRedemptionHarness(first, attempts=128).run(
                self.capability, self.request, self.context, now=FIXED_NOW
            )
            restarted = sqlite_verifier_factories(
                path, self.broker.public_key_pem, self.broker.key_id, replicas=2
            )
            retry = ConcurrentRedemptionHarness(restarted, attempts=128).run(
                self.capability, self.request, self.context, now=FIXED_NOW
            )
        self.assertEqual(initial.committed_effects, 1)
        self.assertEqual(retry.committed_effects, 0)
        self.assertEqual(retry.replay_denials, 128)

    def test_positive_control_detects_non_atomic_double_redemption(self) -> None:
        competitors = 100
        with self.assertRaises(PermissionError):
            VulnerableNonAtomicConsumptionStore(competitors)
        with patch.dict(os.environ, {"EH_ENABLE_VULNERABLE_CONTROL": "1"}):
            with self.assertWarnsRegex(RuntimeWarning, "NON-ATOMIC"):
                store = VulnerableNonAtomicConsumptionStore(competitors)
            factories = tuple(
                lambda: CapabilityVerifier(
                    self.broker.public_key_pem, self.broker.key_id, store
                )
                for _ in range(2)
            )
            result = ConcurrentRedemptionHarness(
                factories, attempts=competitors
            ).run(self.capability, self.request, self.context, now=FIXED_NOW)
        self.assertGreater(result.committed_effects, 1)
        self.assertFalse(result.invariant_passed)


if __name__ == "__main__":
    unittest.main()
