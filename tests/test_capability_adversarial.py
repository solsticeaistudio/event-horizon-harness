from __future__ import annotations

import copy
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.broker import CapabilityBroker, CapabilityError, CapabilityVerifier
from event_horizon.canonical import CanonicalizationError, digest, strict_json_loads
from event_horizon.guardians import GuardianQuorum
from event_horizon.replay_state import InMemoryCapabilityConsumptionStore
from event_horizon.models import ActionRequest, GuardianDecision, IssuedCapability, ValidationError
from scripts.verify_capability_vectors import verify_vector
from scripts.capability_fixture_support import authority_context, issue_options, verify_options


FIXED_NOW = 1_700_000_000.0


def request_payload(**overrides):
    payload = {
        "request_id": "vector-request",
        "session_id": "vector-session",
        "agent_id": "attacker-agent",
        "operation": "object.read",
        "resource_id": "target-source",
        "executor_id": "exec-1",
        "arguments": {"length": 10, "offset": 0},
        "purpose": "capability verification",
    }
    payload.update(overrides)
    return payload


class CapabilityAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.broker = CapabilityBroker(
            b"capability-adversarial-fixture-key",
            ttl_seconds=60,
            consumption_store=InMemoryCapabilityConsumptionStore(),
        )
        self.request = ActionRequest.from_dict(request_payload())
        self.authority = authority_context(self.request, FIXED_NOW)
        self.context = verify_options(self.authority)
        self.capability = self.broker.issue(
            self.request,
            **issue_options(self.authority),
            max_output_bytes=4096,
            now=FIXED_NOW,
        )

    def verifier(self) -> CapabilityVerifier:
        return CapabilityVerifier(
            self.broker.public_key_pem, self.broker.key_id, InMemoryCapabilityConsumptionStore()
        )

    def verify(self, capability=None, request=None, *, verifier=None, now=FIXED_NOW, **context):
        return (verifier or self.verifier()).verify_and_consume(
            capability or self.capability,
            request or self.request,
            **{**self.context, **context},
            now=now,
        )

    def mutated_capability(self, mutate):
        payload = copy.deepcopy(self.capability.to_dict())
        mutate(payload)
        return IssuedCapability.from_dict(payload)

    def test_duplicate_json_keys_and_trailing_data_are_rejected(self):
        with self.assertRaisesRegex(CanonicalizationError, "duplicate"):
            strict_json_loads('{"request_id":"a","request_id":"b"}')
        with self.assertRaisesRegex(CanonicalizationError, "trailing"):
            strict_json_loads('{"request_id":"a"} trailing')

    def test_unknown_request_capability_and_nested_numeric_values_are_rejected(self):
        with self.assertRaisesRegex(ValidationError, "unknown"):
            ActionRequest.from_dict(request_payload(unknown=True))
        envelope = self.capability.to_dict()
        envelope["unknown"] = True
        with self.assertRaisesRegex(ValidationError, "envelope"):
            IssuedCapability.from_dict(envelope)
        claims = self.capability.to_dict()
        claims["claims"]["unknown"] = True
        with self.assertRaisesRegex(ValidationError, "claim fields"):
            IssuedCapability.from_dict(claims)
        with self.assertRaisesRegex(ValidationError, "floating-point"):
            ActionRequest.from_dict(request_payload(arguments={"length": 1.0}))
        with self.assertRaisesRegex(ValidationError, "floating-point"):
            # Negative zero is a float form; the integer-only numeric domain
            # rejects every floating-point representation.
            ActionRequest.from_dict(request_payload(arguments={"length": -0.0}))
        with self.assertRaisesRegex(ValidationError, "interoperable"):
            ActionRequest.from_dict(request_payload(arguments={"length": 2**60}))

    def test_unicode_normalization_is_rejected_instead_of_silently_normalized(self):
        with self.assertRaisesRegex(ValidationError, "Unicode NFC"):
            ActionRequest.from_dict(request_payload(purpose="e\u0301"))

    def test_key_order_and_nested_reordering_have_one_digest(self):
        left = {"z": {"b": 2, "a": 1}, "a": [3, {"d": 4, "c": 5}]}
        right = {"a": [3, {"c": 5, "d": 4}], "z": {"a": 1, "b": 2}}
        self.assertEqual(digest(left), digest(right))

    def test_ambiguous_numeric_representations_and_noncanonical_order_are_rejected(self):
        for payload in ('{"n":1.0}', '{"n":1e0}', '{"n":-0}'):
            with self.subTest(payload=payload):
                with self.assertRaises(CanonicalizationError):
                    strict_json_loads(payload, require_canonical=True)
        with self.assertRaisesRegex(CanonicalizationError, "canonical form"):
            strict_json_loads('{"z":{"b":2,"a":1},"a":0}', require_canonical=True)

    def test_malformed_lengths_algorithm_and_signature_substitution_fail(self):
        with self.assertRaisesRegex(ValidationError, "UTF-8 bytes"):
            ActionRequest.from_dict(request_payload(session_id="x" * 257))
        algorithm = self.capability.to_dict()
        algorithm["algorithm"] = "EdDSA"
        with self.assertRaisesRegex(ValidationError, "algorithm"):
            IssuedCapability.from_dict(algorithm)
        signature = self.mutated_capability(lambda value: value.__setitem__("signature", "A" * 86))
        with self.assertRaisesRegex(CapabilityError, "signature"):
            self.verify(signature)

    def test_public_key_substitution_is_rejected_at_verifier_configuration(self):
        other = Ed25519PrivateKey.generate().public_key()
        with self.assertRaisesRegex(ValueError, "does not match"):
            CapabilityVerifier(other, self.broker.key_id, InMemoryCapabilityConsumptionStore())

    def test_request_argument_executor_measurement_session_and_policy_mutation_fail(self):
        mutations = [
            (ActionRequest.from_dict(request_payload(resource_id="public-evidence")), {}, "resource_id"),
            (ActionRequest.from_dict(request_payload(arguments={"length": 11, "offset": 0})), {}, "arguments_digest"),
            (ActionRequest.from_dict(request_payload(executor_id="exec-2")), {}, "executor_id"),
            (ActionRequest.from_dict(request_payload(session_id="other-session")), {}, "session_id"),
            (self.request, {"executor_measurement": "9" * 64}, "executor_measurement"),
            (self.request, {"device_id": "exec-2"}, "device_id"),
            (self.request, {"policy_digest": "8" * 64}, "policy_digest"),
        ]
        for changed_request, context, expected in mutations:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(CapabilityError, expected):
                    self.verify(request=changed_request, **context)

    def test_signed_claim_mutation_and_signer_key_substitution_fail(self):
        changed = self.mutated_capability(
            lambda value: value["claims"].__setitem__("executor_measurement", "9" * 64)
        )
        with self.assertRaisesRegex(CapabilityError, "signature"):
            self.verify(changed)
        changed_key = self.capability.to_dict()
        changed_key["key_id"] = "ed25519:" + "0" * 32
        parsed = IssuedCapability.from_dict(changed_key)
        with self.assertRaisesRegex(CapabilityError, "signing key"):
            self.verify(parsed)

    def test_expiration_boundary_and_clock_skew_are_fail_closed(self):
        at_expiration = self.capability.claims.expires_at / 1000
        with self.assertRaisesRegex(CapabilityError, "expired"):
            self.verify(now=at_expiration)
        with self.assertRaisesRegex(CapabilityError, "clock skew"):
            self.verify(now=FIXED_NOW - 5.001)
        self.assertEqual(self.verify(now=FIXED_NOW - 5).capability_id, self.capability.claims.capability_id)

    def test_concurrent_replay_allows_exactly_one_consumer(self):
        verifier = self.verifier()
        barrier = threading.Barrier(32)

        def attempt():
            barrier.wait()
            try:
                self.verify(verifier=verifier)
                return True
            except CapabilityError:
                return False

        with ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(lambda _index: attempt(), range(32)))
        self.assertEqual(sum(results), 1)

    def test_request_snapshot_prevents_time_of_check_time_of_use_mutation(self):
        source = request_payload(arguments={"range": {"end": 10, "start": 0}})
        request = ActionRequest.from_dict(source)
        source["executor_id"] = "exec-2"
        source["arguments"]["range"]["end"] = 999
        self.assertEqual(request.executor_id, "exec-1")
        self.assertEqual(request.canonical_payload()["arguments"]["range"]["end"], 10)
        with self.assertRaises(TypeError):
            request.arguments["new"] = True

    def test_guardian_response_swapping_and_stale_approval_are_denied(self):
        class SwappedGuardian:
            name = "swapped"

            def evaluate(self, _request):
                return GuardianDecision("different-guardian", True, "swapped", request_digest="0" * 64)

        class StaleGuardian:
            name = "stale"

            def evaluate(self, _request):
                return GuardianDecision(self.name, True, "old approval", request_digest="f" * 64)

        decisions = GuardianQuorum([SwappedGuardian(), StaleGuardian()]).evaluate(self.request)
        self.assertTrue(all(not decision.allowed for decision in decisions))
        self.assertEqual(
            sum("binding or schema mismatch" in decision.reason for decision in decisions),
            2,
        )

    def test_fixed_public_vectors_match_their_expected_results(self):
        vector_dir = Path(__file__).resolve().parents[1] / "test-vectors"
        expected_names = {
            "valid-capability.json", "modified-arguments.json", "wrong-executor.json",
            "wrong-measurement.json", "expired-capability.json", "replayed-capability.json",
            "unknown-field.json", "invalid-signature.json",
        }
        paths = sorted(vector_dir.glob("*.json"))
        self.assertEqual({path.name for path in paths}, expected_names)
        for path in paths:
            with self.subTest(vector=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                actual_valid, actual_reason = verify_vector(payload)
                self.assertIs(actual_valid, payload["expected"]["valid"])
                self.assertIn(payload["expected"]["reason"], actual_reason)


if __name__ == "__main__":
    unittest.main()
