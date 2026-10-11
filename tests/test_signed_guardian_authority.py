"""Opt-in signer-role security contract: coordinator approval forgery tests."""
from __future__ import annotations

import copy
import time
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.broker import CapabilityBroker, CapabilityVerifier
from event_horizon.component_ids import (
    REQUIRED_GUARDIANS, STATIC_POLICY_GUARDIAN,
    EXECUTOR_ATTESTATION_GUARDIAN,
)
from event_horizon.models import ActionRequest, GuardianDecision
from event_horizon.policy import OperationRule, StaticPolicy
from event_horizon.signed_guardian_authority import (
    GuardianAuthorityError, GuardianSigningKey,
    PinnedGuardianCapabilityIssuer, PinnedGuardianVerifier,
    SignedGuardianApproval,
)
from scripts.capability_fixture_support import (
    authority_context, verify_options,
)


class SignedGuardianSignerTests(unittest.TestCase):
    def setUp(self):
        self.request = ActionRequest(
            "signed-vote", "guardian-session", "attacker-agent",
            "object.read", "synthetic-dataset", "exec-1",
            {"offset": 0, "length": 5}, "synthetic signed decision test",
        )
        self.context = authority_context(self.request, time.time())
        self.policy = StaticPolicy(
            policy_id="fixture-policy-v1",
            operations={
                "object.read": OperationRule(
                    resources=frozenset({"synthetic-dataset"}),
                    allowed_argument_keys=frozenset({"offset", "length"}),
                    max_output_bytes=4096,
                ),
            },
            allowed_agents=frozenset({"attacker-agent"}),
            allowed_executors=frozenset({"exec-1"}),
        )
        self.assertEqual(self.context["policy_digest"], self.policy.policy_digest)
        self.keys = {
            identity: GuardianSigningKey(identity, Ed25519PrivateKey.generate())
            for identity in sorted(REQUIRED_GUARDIANS)
        }
        self.verifier = PinnedGuardianVerifier({
            identity: key.public_key_pem
            for identity, key in self.keys.items()
        })
        self.broker = CapabilityBroker(ttl_seconds=60)
        self.signer = PinnedGuardianCapabilityIssuer(
            broker=self.broker, static_policy=self.policy,
            verifier=self.verifier,
        )

    def decisions(self, *, request=None):
        action = request or self.request
        result = {
            identity: GuardianDecision(
                identity, True, "approved in independent synthetic lab",
                request_digest=action.request_digest,
            )
            for identity in REQUIRED_GUARDIANS
        }
        result[STATIC_POLICY_GUARDIAN] = self.policy.evaluate(action)
        result[EXECUTOR_ATTESTATION_GUARDIAN] = GuardianDecision(
            EXECUTOR_ATTESTATION_GUARDIAN, True,
            "executor measurement independently accepted by test guardian",
            {
                "device_id": action.executor_id,
                "measurement": self.context["executor_measurement"],
                "provider_trust_state": self.context["trust_state"].to_dict(),
                "attestation_result": dict(self.context["attestation"]),
            },
            action.request_digest,
        )
        return result

    def signed(self, challenge, *, decisions=None, keys=None):
        decisions = decisions or self.decisions()
        keys = keys or self.keys
        return [
            keys[name].approve(
                decisions[name], challenge=challenge,
                policy_digest=self.policy.policy_digest,
            )
            for name in sorted(REQUIRED_GUARDIANS)
        ]

    def test_legitimate_approved_signed_guardians_issue_exact_authority(self):
        challenge = self.signer.new_challenge(self.request)
        votes = self.signed(challenge)
        capability = self.signer.issue(
            self.request, challenge, votes, self.context["compiled_ceiling"],
        )
        self.assertEqual(capability.claims.operation, "object.read")
        self.assertEqual(capability.claims.max_output_bytes, 4096)
        self.assertEqual(capability.claims.policy_digest, self.policy.policy_digest)
        verifier = CapabilityVerifier(self.broker.public_key_pem, self.broker.key_id)
        claims = verifier.verify_and_consume(
            capability, self.request, **verify_options(self.context),
        )
        self.assertEqual(claims.capability_id, capability.claims.capability_id)
        with self.assertRaises(GuardianAuthorityError):
            self.signer.issue(
                self.request, challenge, votes, self.context["compiled_ceiling"],
            )

    def test_coordinator_cannot_forge_guardian_unanimity(self):
        challenge = self.signer.new_challenge(self.request)
        attacker = GuardianSigningKey(
            STATIC_POLICY_GUARDIAN, Ed25519PrivateKey.generate(),
        )
        keys = {**self.keys, STATIC_POLICY_GUARDIAN: attacker}
        with self.assertRaises(GuardianAuthorityError):
            self.signer.issue(
                self.request, challenge, self.signed(challenge, keys=keys),
                self.context["compiled_ceiling"],
            )

    def test_missing_duplicate_and_unsigned_approvals_veto(self):
        for kind in ("missing", "duplicate", "unsigned"):
            with self.subTest(kind=kind):
                challenge = self.signer.new_challenge(self.request)
                votes = self.signed(challenge)
                if kind == "missing":
                    votes.pop()
                elif kind == "duplicate":
                    votes[1] = votes[0]
                else:
                    votes[1] = SignedGuardianApproval(
                        votes[1].payload, "A" * 86,
                    )
                with self.assertRaises(GuardianAuthorityError):
                    self.signer.issue(
                        self.request, challenge, votes,
                        self.context["compiled_ceiling"],
                    )

    def test_challenge_is_fresh_consumed_and_request_bound(self):
        previous = self.signer.new_challenge(self.request)
        wrong_request = ActionRequest(
            "signed-vote", "other-session", "attacker-agent",
            "object.read", "synthetic-dataset", "exec-1",
            {"offset": 0, "length": 5}, "synthetic signed decision test",
        )
        with self.assertRaises(GuardianAuthorityError):
            self.signer.issue(
                wrong_request, previous, self.signed(previous),
                self.context["compiled_ceiling"],
            )
        with self.assertRaises(GuardianAuthorityError):
            self.signer.issue(
                self.request, previous, self.signed(previous),
                self.context["compiled_ceiling"],
            )

    def test_valid_signature_over_swapped_request_is_rejected(self):
        challenge = self.signer.new_challenge(self.request)
        votes = self.signed(challenge)
        attacker = self.keys[STATIC_POLICY_GUARDIAN]
        wrong = ActionRequest(
            "signed-vote", "swapped-session", "attacker-agent",
            "object.read", "synthetic-dataset", "exec-1",
            {"offset": 0, "length": 5}, "synthetic signed decision test",
        )
        votes[0] = attacker.approve(
            self.policy.evaluate(wrong),
            challenge=challenge, policy_digest=self.policy.policy_digest,
        ) if votes[0].payload["guardian"] == STATIC_POLICY_GUARDIAN else votes[0]
        # Every signed decision must match the exact requested digest.
        with self.assertRaises(GuardianAuthorityError):
            self.signer.issue(
                self.request, challenge, votes,
                self.context["compiled_ceiling"],
            )

    def test_policy_ceiling_independently_deny_by_default(self):
        prohibited = ActionRequest(
            "signed-vote", "guardian-session", "attacker-agent",
            "network.connect", "internet", "exec-1",
            {}, "unapproved operation",
        )
        challenge = self.signer.new_challenge(prohibited)
        decisions = self.decisions(request=prohibited)
        # Even if all signed decision envelopes were forged as approval by
        # all private keys in this *test only*, the signer recomputes policy.
        decisions[STATIC_POLICY_GUARDIAN] = GuardianDecision(
            STATIC_POLICY_GUARDIAN, True, "allowed", {
                "policy_digest": self.policy.policy_digest,
                "max_output_bytes": 4096,
            }, prohibited.request_digest,
        )
        approvals = self.signed(challenge, decisions=decisions)
        with self.assertRaises(GuardianAuthorityError):
            self.signer.issue(
                prohibited, challenge, approvals,
                self.context["compiled_ceiling"],
            )

    def test_trust_state_and_signed_attestation_must_match(self):
        challenge = self.signer.new_challenge(self.request)
        decisions = self.decisions()
        attest = decisions[EXECUTOR_ATTESTATION_GUARDIAN]
        tampered = dict(attest.evidence)
        synthetic = dict(tampered["attestation_result"])
        synthetic["deviceId"] = "not-exec-1"
        tampered["attestation_result"] = synthetic
        decisions[EXECUTOR_ATTESTATION_GUARDIAN] = GuardianDecision(
            attest.guardian, True, attest.reason, tampered,
            attest.request_digest,
        )
        with self.assertRaises(GuardianAuthorityError):
            self.signer.issue(
                self.request, challenge, self.signed(challenge, decisions=decisions),
                self.context["compiled_ceiling"],
            )

    def test_key_identity_must_be_unique_across_guardians(self):
        common = Ed25519PrivateKey.generate()
        pem = GuardianSigningKey(
            STATIC_POLICY_GUARDIAN, common,
        ).public_key_pem
        with self.assertRaises(ValueError):
            PinnedGuardianVerifier({guardian: pem for guardian in REQUIRED_GUARDIANS})

    def test_compiled_ceiling_must_be_independently_policy_bound(self):
        challenge = self.signer.new_challenge(self.request)
        altered = replace(self.context["compiled_ceiling"], policy_version="coordinator-policy")
        with self.assertRaises((GuardianAuthorityError, ValueError)):
            self.signer.issue(
                self.request, challenge, self.signed(challenge), altered,
            )


if __name__ == "__main__":
    unittest.main()
