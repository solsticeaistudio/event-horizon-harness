from __future__ import annotations

import copy
import unittest

from event_horizon.broker import CapabilityBroker, CapabilityError, CapabilityVerifier
from event_horizon.replay_state import InMemoryCapabilityConsumptionStore
from event_horizon.canonical import digest
from event_horizon.models import ActionRequest, ValidationError
from event_horizon.task_policy import ProviderTrustState
from scripts.capability_fixture_support import authority_context, issue_options, verify_options


NOW = 1_700_000_000.0


def request(**changes):
    payload = {
        "request_id": "trust-request",
        "session_id": "trust-session",
        "agent_id": "trust-agent",
        "operation": "object.read",
        "resource_id": "trust-resource",
        "executor_id": "trust-executor",
        "arguments": {"length": 1},
        "purpose": "authoritative trust regression",
    }
    payload.update(changes)
    return ActionRequest.from_dict(payload)


def redigest_attestation(attestation, **changes):
    changed = copy.deepcopy(attestation)
    changed.update(changes)
    changed.pop("resultDigest", None)
    changed["resultDigest"] = digest(changed)
    return changed


class AuthoritativeTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = request()
        self.authority = authority_context(self.request, NOW)
        self.broker = CapabilityBroker(
            b"authoritative-trust-regression-key",
            ttl_seconds=60,
            consumption_store=InMemoryCapabilityConsumptionStore(),
        )
        self.capability = self.broker.issue(
            self.request,
            now=NOW,
            max_output_bytes=1_024,
            **issue_options(self.authority),
        )

    def verify(self, *, action=None, capability=None, **changes):
        options = {**verify_options(self.authority), **changes}
        verifier = CapabilityVerifier(
            self.broker.public_key_pem, self.broker.key_id, InMemoryCapabilityConsumptionStore()
        )
        return verifier.verify_and_consume(
            capability or self.capability,
            action or self.request,
            now=NOW,
            **options,
        )

    def test_self_asserted_privileged_tier_is_contradictory(self) -> None:
        forged = redigest_attestation(
            self.authority["attestation"], trustLevel="hardware"
        )
        with self.assertRaisesRegex(CapabilityError, "contradictory"):
            self.verify(attestation=forged)

    def test_missing_or_malformed_provider_evidence_fails_closed(self) -> None:
        with self.assertRaisesRegex(CapabilityError, "authority context"):
            self.verify(attestation={})
        bad = copy.deepcopy(self.authority["attestation"])
        bad["resultDigest"] = "0" * 64
        with self.assertRaisesRegex(CapabilityError, "digest"):
            self.verify(attestation=bad)

    def test_provider_proof_key_and_bundle_substitution_fail(self) -> None:
        for changed in (
            redigest_attestation(self.authority["attestation"], keyId="attacker-key"),
            redigest_attestation(self.authority["attestation"], bundleDigest="9" * 64),
        ):
            with self.subTest(changed=changed["keyId"]):
                with self.assertRaisesRegex(CapabilityError, "binding mismatch"):
                    self.verify(attestation=changed)

    def test_expired_and_stale_attestation_fail(self) -> None:
        stale = redigest_attestation(
            self.authority["attestation"],
            verifiedAt="2023-11-14T21:00:00.000Z",
            nonceExpiresAt="2023-11-14T21:30:00.000Z",
        )
        with self.assertRaisesRegex(CapabilityError, "expired"):
            self.verify(attestation=stale)

    def test_wrong_workload_tenant_environment_audience_and_policy_fail(self) -> None:
        cases = (
            ({"action": request(executor_id="other-executor")}, "executor_id"),
            ({"tenant": "other-tenant"}, "current_tenant"),
            ({"environment": "production"}, "current_environment"),
            ({"audience": "other-service"}, "audience"),
            ({"policy_digest": "8" * 64}, "policy_digest"),
            ({"verifier_policy_digest": "7" * 64}, "current_verifier_policy_digest"),
        )
        for changes, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(CapabilityError, expected):
                    self.verify(**changes)

    def test_trust_downgrade_denies_and_upgrade_does_not_expand_old_capability(self) -> None:
        hardware = authority_context(
            self.request,
            NOW,
            trust_level="hardware",
            method="tpm2",
            required_trust="hardware",
        )
        hardware_capability = self.broker.issue(
            self.request,
            now=NOW,
            max_output_bytes=1_024,
            **issue_options(hardware),
        )
        with self.assertRaisesRegex(CapabilityError, "below the signed constraint"):
            self.verify(
                capability=hardware_capability,
                **verify_options(self.authority),
            )
        with self.assertRaisesRegex(CapabilityError, "binding mismatch"):
            self.verify(**verify_options(hardware))

    def test_contradictory_trust_state_and_missing_trust_at_issuance_fail(self) -> None:
        with self.assertRaisesRegex(ValidationError, "conservative"):
            ProviderTrustState(
                requested_trust="hardware",
                observed_trust="simulated",
                provider_attested_trust="simulated",
                effective_trust="hardware",
                method="simulator",
                key_id="fixture",
                attestation_digest="1" * 64,
                bundle_digest="2" * 64,
                verifier_policy_digest="3" * 64,
                verified_at_ms=1,
                expires_at_ms=2,
            )
        options = issue_options(self.authority)
        options["trust_state"] = None
        with self.assertRaisesRegex(CapabilityError, "provider-derived trust"):
            self.broker.issue(
                self.request,
                now=NOW,
                max_output_bytes=1_024,
                **options,
            )

    def test_task_fingerprint_and_capability_copy_are_bound(self) -> None:
        with self.assertRaisesRegex(CapabilityError, "request_digest"):
            self.verify(action=request(purpose="changed task semantics"))
        with self.assertRaisesRegex(CapabilityError, "agent_id"):
            self.verify(action=request(agent_id="other-agent"))


if __name__ == "__main__":
    unittest.main()
