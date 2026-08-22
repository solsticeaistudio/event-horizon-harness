from __future__ import annotations

import copy
import unittest
import unicodedata

from hypothesis import HealthCheck, given, settings, strategies as st

from event_horizon.broker import CapabilityBroker, CapabilityError, CapabilityVerifier
from event_horizon.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalizationError,
    canonical_bytes,
    digest,
    strict_json_loads,
)
from event_horizon.models import ActionRequest, CapabilityClaims, IssuedCapability, ValidationError
from event_horizon.replay_state import InMemoryCapabilityConsumptionStore
from scripts.capability_fixture_support import authority_context, issue_options, verify_options


FIXED_NOW = 1_700_000_000.0


canonical_text = st.text(
    alphabet=st.characters(exclude_categories=("Cs",)),
    max_size=32,
).filter(lambda value: unicodedata.normalize("NFC", value) == value)
canonical_keys = canonical_text.filter(bool)
canonical_scalars = st.one_of(
    st.none(), st.booleans(), st.integers(-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER), canonical_text
)
canonical_json = st.recursive(
    canonical_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=12),
        st.dictionaries(canonical_keys, children, max_size=12),
    ),
    max_leaves=40,
)


def request_payload(arguments=None, **overrides):
    value = {
        "request_id": "property-request",
        "session_id": "property-session",
        "agent_id": "attacker-agent",
        "operation": "object.read",
        "resource_id": "target-source",
        "executor_id": "exec-1",
        "arguments": {"length": 1, "offset": 0} if arguments is None else arguments,
        "purpose": "property test",
    }
    value.update(overrides)
    return value


class CanonicalProtocolProperties(unittest.TestCase):
    @settings(
        max_examples=150, deadline=None,
        suppress_health_check=(HealthCheck.filter_too_much,), derandomize=True,
    )
    @given(canonical_json)
    def test_canonical_round_trip_is_exact_and_stable(self, value) -> None:
        encoded = canonical_bytes(value)
        self.assertEqual(strict_json_loads(encoded, require_canonical=True), value)
        self.assertEqual(canonical_bytes(strict_json_loads(encoded)), encoded)

    @settings(
        max_examples=150, deadline=None,
        suppress_health_check=(HealthCheck.filter_too_much,), derandomize=True,
    )
    @given(st.dictionaries(canonical_keys, canonical_scalars, min_size=1, max_size=32))
    def test_object_insertion_order_cannot_change_digest(self, value) -> None:
        reversed_value = dict(reversed(tuple(value.items())))
        self.assertEqual(digest(value), digest(reversed_value))
        self.assertEqual(canonical_bytes(value), canonical_bytes(reversed_value))

    @settings(
        max_examples=150, deadline=None,
        suppress_health_check=(HealthCheck.filter_too_much,), derandomize=True,
    )
    @given(st.dictionaries(canonical_keys, canonical_json, max_size=20))
    def test_action_request_freezes_bounded_security_json(self, arguments) -> None:
        request = ActionRequest.from_dict(request_payload(arguments=arguments))
        snapshot = request.canonical_payload()
        self.assertEqual(ActionRequest.from_dict(snapshot).request_digest, request.request_digest)

    def test_malformed_encoding_size_depth_and_ambiguity_fail_closed(self) -> None:
        invalid = (
            b'\xff', b'{"a":1} trailing', b'{"a":1,"a":2}', b'{"n":1.0}',
            b'{"n":1e0}', b'{"n":NaN}', b'{"n":9007199254740992}',
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(CanonicalizationError):
                    strict_json_loads(payload, require_canonical=True)
        nested = None
        for _ in range(10):
            nested = [nested]
        with self.assertRaisesRegex(CanonicalizationError, "nesting"):
            canonical_bytes(nested)
        with self.assertRaisesRegex(CanonicalizationError, "item limit"):
            canonical_bytes(list(range(257)))
        with self.assertRaisesRegex(CanonicalizationError, "string"):
            canonical_bytes("x" * 16_385)
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"unsupported": {1, 2}})


class SignedCapabilityFieldProperties(unittest.TestCase):
    def setUp(self) -> None:
        self.broker = CapabilityBroker(
            b"property-capability-key-no-authority",
            ttl_seconds=60,
            consumption_store=InMemoryCapabilityConsumptionStore(),
        )
        self.request = ActionRequest.from_dict(request_payload())
        self.authority = authority_context(self.request, FIXED_NOW)
        self.context = verify_options(self.authority)
        self.capability = self.broker.issue(
            self.request,
            **issue_options(self.authority),
            max_output_bytes=4_096,
            now=FIXED_NOW,
        )

    def test_mutating_every_signed_security_field_is_rejected(self) -> None:
        for field in sorted(CapabilityClaims.ALLOWED_FIELDS):
            with self.subTest(field=field):
                self._assert_field_mutation_rejected(field)

    def _assert_field_mutation_rejected(self, field: str) -> None:
        envelope = copy.deepcopy(self.capability.to_dict())
        claims = envelope["claims"]
        current = claims[field]
        if field == "compiled_ceiling":
            claims[field]["maximum_read_bytes"] += 1
        elif field == "capability_id":
            claims[field] = "cap_ffffffffffffffffffffffff"
        elif field == "signer_key_id":
            claims[field] = "ed25519:" + "0" * 32
        elif field in {
            "requested_trust", "provider_attested_trust", "effective_trust",
            "signed_trust_constraint",
        }:
            claims[field] = "software" if current != "software" else "simulated"
        elif isinstance(current, int):
            claims[field] = current + 1
        elif isinstance(current, str) and len(current) == 64:
            claims[field] = ("0" if current[0] != "0" else "1") + current[1:]
        elif isinstance(current, str):
            claims[field] = current + "-mutated"
        else:  # pragma: no cover - schema exhaustiveness guard
            self.fail(f"unhandled capability field {field}")
        try:
            mutated = IssuedCapability.from_dict(envelope)
        except ValidationError:
            return
        verifier = CapabilityVerifier(
            self.broker.public_key_pem, self.broker.key_id, InMemoryCapabilityConsumptionStore()
        )
        with self.assertRaises(CapabilityError):
            verifier.verify_and_consume(
                mutated, self.request, **self.context, now=FIXED_NOW
            )


if __name__ == "__main__":
    unittest.main()
