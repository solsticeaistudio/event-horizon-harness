from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from event_horizon.broker import CapabilityBroker
from event_horizon.canary import (
    CanaryAuthority,
    CanaryError,
    CanaryResponsePolicy,
    CanaryVerifier,
    canary_ids_do_not_overlap,
)
from event_horizon.canonical import digest
from event_horizon.replay_state import InMemoryCapabilityConsumptionStore
from event_horizon.denial_certificate import DenialCertificateBuilder
from event_horizon.executor import SacrificialExecutor
from event_horizon.models import ActionRequest, IssuedCapability, ValidationError
from event_horizon.recorder import ExternalRecorder


NOW_MS = 1_700_000_000_000
REPRESENTATION = {"token": "eh_test_authority", "scope": "synthetic-admin"}


class CanaryCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.recorder = ExternalRecorder(Path(self.tmp.name) / "canary-events.jsonl")
        self.authority = CanaryAuthority(b"canary-test-key-with-no-external-authority")
        self.verifier = CanaryVerifier(
            self.authority.public_key_pem,
            self.authority.key_id,
            self.recorder,
            tenant="tenant-a",
            environment="test-range",
            clock_ms=lambda: NOW_MS,
        )
        self.canary = self.authority.issue(
            campaign_id="campaign-positive-control",
            session_id="session-a",
            workload_id="executor-a",
            tenant="tenant-a",
            environment="test-range",
            seed_location="decoy-cache/session-a",
            policy_version="policy-v1",
            representation=REPRESENTATION,
            now_ms=NOW_MS,
            enabled=True,
        )
        self.request = ActionRequest(
            "canary-attempt", "session-a", "agent-a", "object.read", "decoy-cache",
            "executor-a", {}, "probe synthetic authority",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_seeding_is_disabled_by_default_and_forbidden_in_production(self) -> None:
        options = {
            "campaign_id": "c", "session_id": "s", "workload_id": "w",
            "tenant": "tenant-a", "environment": "test-range", "seed_location": "decoy",
            "policy_version": "v1", "representation": REPRESENTATION, "now_ms": NOW_MS,
        }
        with self.assertRaisesRegex(CanaryError, "disabled"):
            self.authority.issue(**options)
        with self.assertRaisesRegex(CanaryError, "production"):
            self.authority.issue(**options, enabled=True, production=True)

    def test_discovery_and_redemption_are_trusted_events_and_no_effect_occurs(self) -> None:
        discovered = self.verifier.record_interaction(
            "discovery", self.canary, now_ms=NOW_MS
        )
        self.assertEqual(discovered["canary_id"], self.canary.claims.canary_id)
        executor = SacrificialExecutor(
            executor_id="executor-a",
            device_id="executor-a",
            measurement="1" * 64,
            verifier_policy_digest="2" * 64,
            policy_digest="3" * 64,
            broker=CapabilityBroker(
            b"unused-real-capability-key-material",
            consumption_store=InMemoryCapabilityConsumptionStore(),
        ),
            recorder=self.recorder,
            tenant="tenant-a",
            environment="test-range",
            canary_verifier=self.verifier,
            objects={"decoy-cache": {"unchanged": True}},
        )
        result = executor.execute(self.request, self.canary, {})
        self.assertFalse(result.success)
        self.assertIn("non-effect tripwires", result.error)
        self.assertEqual(executor.objects["decoy-cache"], {"unchanged": True})
        event_types = [event["event_type"] for event in self.recorder.events()]
        self.assertIn("canary.discovery", event_types)
        self.assertIn("canary.redemption", event_types)

    def test_mutation_and_transfer_are_detected(self) -> None:
        mutation = self.verifier.record_interaction(
            "inspection",
            self.canary,
            representation={**REPRESENTATION, "scope": "real-admin"},
            mutation_diff={"scope": ["synthetic-admin", "real-admin"]},
            now_ms=NOW_MS,
        )
        self.assertEqual(mutation["mutation_diff"]["scope"][1], "real-admin")
        transferred = ActionRequest(
            "transfer", "other-session", "agent-a", "object.read", "decoy-cache",
            "other-executor", {}, "transfer",
        )
        self.verifier.record_interaction(
            "redemption", self.canary, request=transferred, now_ms=NOW_MS
        )
        event_types = [event["event_type"] for event in self.recorder.events()]
        self.assertEqual(event_types, [
            "canary.mutation", "denial.evaluated", "canary.transfer", "denial.evaluated",
        ])

    def test_canary_cannot_be_converted_to_real_capability_or_collide(self) -> None:
        with self.assertRaisesRegex(ValidationError, "envelope"):
            IssuedCapability.from_dict(self.canary.to_dict())
        self.assertTrue(canary_ids_do_not_overlap(
            ["cap_0123456789abcdef01234567"], [self.canary.claims.canary_id]
        ))

    def test_response_policy_is_strictly_subtractive(self) -> None:
        policy = CanaryResponsePolicy(("deny", "remove-tools", "require-reattestation"))
        self.assertEqual(policy.actions[0], "deny")
        with self.assertRaisesRegex(ValueError, "subtractive"):
            CanaryResponsePolicy(("deny", "add-tool"))

    def test_cross_tenant_spoof_cannot_emit_an_event_for_victim(self) -> None:
        foreign = self.authority.issue(
            campaign_id="attacker-campaign",
            session_id="attacker-session",
            workload_id="attacker-executor",
            tenant="victim-tenant",
            environment="test-range",
            seed_location="decoy",
            policy_version="policy-v1",
            representation=REPRESENTATION,
            now_ms=NOW_MS,
            enabled=True,
        )
        with self.assertRaisesRegex(CanaryError, "tenant"):
            self.verifier.record_interaction("discovery", foreign, now_ms=NOW_MS)
        self.assertEqual(self.recorder.events(), [])

    def test_positive_control_probe_discovers_then_attempts_canary(self) -> None:
        self.verifier.record_interaction("discovery", self.canary, now_ms=NOW_MS)
        with self.assertRaisesRegex(CanaryError, "cannot be redeemed"):
            self.verifier.redeem(self.canary, self.request, now_ms=NOW_MS)
        events = self.recorder.events()
        self.assertEqual([item["event_type"] for item in events], [
            "canary.discovery", "denial.evaluated", "canary.redemption", "denial.evaluated"
        ])
        canary_events = [item for item in events if item["event_type"].startswith("canary.")]
        self.assertTrue(all(item["payload"]["campaign_id"] == "campaign-positive-control" for item in canary_events))
        self.assertTrue(all(item["payload"]["evidence_hash"] for item in canary_events))

    def test_legitimate_default_harness_has_no_canary_seed(self) -> None:
        self.assertFalse(any(
            event["event_type"].startswith("canary.") for event in self.recorder.events()
        ))
        self.assertNotEqual(digest(self.canary.claims.to_dict()), self.canary.claims.representation_digest)

    def test_every_trusted_canary_path_emits_a_signed_denial_certificate(self) -> None:
        builder = DenialCertificateBuilder(self.recorder, b"canary-denial-signer-key-material!!")
        verifier = CanaryVerifier(
            self.authority.public_key_pem, self.authority.key_id, self.recorder,
            tenant="tenant-a", environment="test-range", clock_ms=lambda: NOW_MS,
            denial_certificate_builder=builder,
        )
        verifier.record_interaction("discovery", self.canary, now_ms=NOW_MS)
        verifier.record_interaction(
            "inspection", self.canary, representation={"scope": "changed"}, now_ms=NOW_MS
        )
        transferred = ActionRequest(
            "transfer-cert", "other-session", "agent-a", "object.read", "decoy-cache",
            "other-executor", {}, "transfer",
        )
        verifier.record_interaction("transfer", self.canary, request=transferred, now_ms=NOW_MS)
        with self.assertRaises(CanaryError):
            verifier.redeem(self.canary, self.request, now_ms=NOW_MS)
        certificates = [
            event for event in self.recorder.events()
            if event["event_type"] == "denial.evaluated"
        ]
        self.assertEqual(len(certificates), 4)
        self.assertTrue(all(event["payload"]["effect_state"] == "denied-before-effect" for event in certificates))

    def test_ambiguous_canary_outcome_is_not_known_no_effect(self) -> None:
        builder = DenialCertificateBuilder(self.recorder, b"canary-ambiguous-signer-key-mat!!")
        verifier = CanaryVerifier(
            self.authority.public_key_pem, self.authority.key_id, self.recorder,
            tenant="tenant-a", environment="test-range", clock_ms=lambda: NOW_MS,
            denial_certificate_builder=builder,
        )
        verifier.record_interaction(
            "redemption", self.canary, request=self.request, now_ms=NOW_MS,
            effect_state="reconciliation-required",
        )
        denial = [e for e in self.recorder.events() if e["event_type"] == "denial.evaluated"][0]
        self.assertEqual(denial["payload"]["effect_state"], "reconciliation-required")
        self.assertIsNone(denial["payload"]["no_authorized_effect_committed"])

    def test_certificate_generation_failure_fails_closed_and_records_event(self) -> None:
        builder = DenialCertificateBuilder(self.recorder, b"canary-failure-signer-key-material")
        verifier = CanaryVerifier(
            self.authority.public_key_pem, self.authority.key_id, self.recorder,
            tenant="tenant-a", environment="test-range", clock_ms=lambda: NOW_MS,
            denial_certificate_builder=builder,
            denial_certificate_context={"policy_digest": "not-a-digest"},
        )
        with self.assertRaisesRegex(CanaryError, "certificate generation failed"):
            verifier.record_interaction("discovery", self.canary, now_ms=NOW_MS)
        self.assertTrue(any(e["event_type"] == "canary.certificate-failure" for e in self.recorder.events()))


if __name__ == "__main__":
    unittest.main()
