"""Pinned, independently signed guardian approvals for an isolated signer role.

This module establishes a cryptographic signing CONTRACT; the caller must
deploy the guardian keys and the capability signer in different trust domains
for coordinator-compromise tolerance. Running these objects in one process
does NOT isolate the secrets against compromise of that process.

The existing unsigned GuardianQuorum path remains available for research and
compatibility. A strict signer's trusted entrypoint MUST use this facade,
not expose CapabilityBroker.issue to the coordinator.
"""
from __future__ import annotations

import base64
import re
import secrets
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .broker import CapabilityBroker, capability_key_id
from .canonical import canonical_bytes, digest
from .component_ids import (
    REQUIRED_GUARDIANS, EXECUTOR_ATTESTATION_GUARDIAN, STATIC_POLICY_GUARDIAN,
)
from .models import ActionRequest, GuardianDecision, IssuedCapability
from .policy import StaticPolicy
from .task_policy import CompiledTaskPolicyCeiling, ProviderTrustState

SCHEMA = "event-horizon.guardian-approval.v1"
DOMAIN = b"event-horizon/guardian-approval/v1\0"
CHALLENGE_RE = re.compile(r"^[0-9a-f]{32}$")
REQUIRED_PAYLOAD_FIELDS = frozenset({
    "schema", "challenge", "guardian", "request_digest",
    "policy_digest", "allowed", "reason", "evidence", "key_id",
})


class GuardianAuthorityError(PermissionError):
    pass


def _decision_payload(
    decision: GuardianDecision, challenge: str,
    policy_digest: str, key_id: str,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "challenge": challenge,
        "guardian": decision.guardian,
        "request_digest": decision.request_digest,
        "policy_digest": policy_digest,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "evidence": dict(decision.evidence),
        "key_id": key_id,
    }


@dataclass(frozen=True)
class SignedGuardianApproval:
    payload: Mapping[str, Any]
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {"payload": dict(self.payload), "signature": self.signature}


class GuardianSigningKey:
    """One guardian's own signing key; must never be placed on coordinator."""

    def __init__(self, identity: str, key: Ed25519PrivateKey):
        if identity not in REQUIRED_GUARDIANS:
            raise ValueError("unknown required guardian identity")
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("guardian signing key must be Ed25519")
        self.identity = identity
        self._key = key
        self.key_id = capability_key_id(key.public_key())

    @property
    def public_key_pem(self) -> str:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def approve(
        self, decision: GuardianDecision, *, challenge: str,
        policy_digest: str,
    ) -> SignedGuardianApproval:
        if decision.guardian != self.identity or not CHALLENGE_RE.fullmatch(challenge):
            raise GuardianAuthorityError("guardian identity or challenge invalid")
        if not decision.request_digest or not isinstance(decision.allowed, bool):
            raise GuardianAuthorityError("guardian decision invalid")
        payload = _decision_payload(decision, challenge, policy_digest, self.key_id)
        signature = base64.urlsafe_b64encode(
            self._key.sign(DOMAIN + canonical_bytes(payload))
        ).decode("ascii").rstrip("=")
        return SignedGuardianApproval(payload, signature)


class PinnedGuardianVerifier:
    """Signer-pinned public keys; no coordinator-provided key discovery."""

    def __init__(self, public_keys: Mapping[str, str]):
        if not isinstance(public_keys, Mapping) or set(public_keys) != REQUIRED_GUARDIANS:
            raise ValueError("all four required guardian identity keys must be pinned")
        keys: dict[str, Ed25519PublicKey] = {}
        ids: dict[str, str] = {}
        for identity, pem in public_keys.items():
            key = serialization.load_pem_public_key(pem.encode("ascii"))
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("guardian identity requires Ed25519")
            keys[identity] = key
            ids[identity] = capability_key_id(key)
        if len(set(ids.values())) != len(ids):
            raise ValueError("one private key cannot impersonate multiple guardians")
        self._keys = keys
        self.key_ids = ids

    def verify_all(
        self, request: ActionRequest, challenge: str, policy_digest: str,
        approvals: Sequence[SignedGuardianApproval],
    ) -> dict[str, GuardianDecision]:
        if not CHALLENGE_RE.fullmatch(challenge):
            raise GuardianAuthorityError("invalid signer-issued challenge")
        if not isinstance(approvals, (list, tuple)) or len(approvals) != len(REQUIRED_GUARDIANS):
            raise GuardianAuthorityError("every required guardian must approve exactly once")
        verified: dict[str, GuardianDecision] = {}
        for envelope in approvals:
            if not isinstance(envelope, SignedGuardianApproval):
                raise GuardianAuthorityError("unsigned or malformed guardian approval")
            payload = envelope.payload
            if not isinstance(payload, Mapping) or set(payload) != REQUIRED_PAYLOAD_FIELDS:
                raise GuardianAuthorityError("guardian payload fields invalid")
            identity = payload["guardian"]
            if (not isinstance(identity, str) or identity not in self._keys
                    or identity in verified or payload["schema"] != SCHEMA
                    or payload["challenge"] != challenge
                    or payload["policy_digest"] != policy_digest
                    or payload["request_digest"] != request.request_digest
                    or payload["key_id"] != self.key_ids[identity]
                    or type(payload["allowed"]) is not bool
                    or not isinstance(payload["reason"], str)
                    or not payload["reason"]
                    or not isinstance(payload["evidence"], Mapping)):
                raise GuardianAuthorityError("guardian signature identity or binding mismatch")
            try:
                signature = base64.urlsafe_b64decode(envelope.signature + "==")
                if len(signature) != 64 or base64.urlsafe_b64encode(signature).decode().rstrip("=") != envelope.signature:
                    raise ValueError("noncanonical signature")
                self._keys[identity].verify(
                    signature, DOMAIN + canonical_bytes(payload),
                )
            except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
                raise GuardianAuthorityError("guardian signature verification failed") from exc
            if payload["allowed"] is not True:
                raise GuardianAuthorityError("guardian veto")
            verified[identity] = GuardianDecision(
                identity, True, payload["reason"],
                dict(payload["evidence"]), request.request_digest,
            )
        if set(verified) != REQUIRED_GUARDIANS:
            raise GuardianAuthorityError("missing required guardian")
        return verified


class PinnedGuardianCapabilityIssuer:
    """An opt-in capability issuer for an independently deployed signer role.

    A coordinator can provide requests and signed envelopes, but cannot
    select verification keys, forge decision bits or choose output limits.
    This facade does NOT establish OS/process separation on its own.
    """

    def __init__(
        self, *, broker: CapabilityBroker, static_policy: StaticPolicy,
        verifier: PinnedGuardianVerifier, challenge_ttl_seconds: float = 15.0,
    ):
        if not 0 < challenge_ttl_seconds <= 60:
            raise ValueError("signer challenge TTL invalid")
        self._broker = broker
        self.policy = static_policy
        self.verifier = verifier
        self.ttl = challenge_ttl_seconds
        self._pending: dict[str, tuple[str, float]] = {}
        self._lock = threading.RLock()

    def new_challenge(self, request: ActionRequest) -> str:
        if not isinstance(request, ActionRequest):
            raise GuardianAuthorityError("invalid signer challenge request")
        nonce = secrets.token_hex(16)
        with self._lock:
            self._pending[nonce] = (request.request_digest, time.monotonic() + self.ttl)
        return nonce

    def issue(
        self, request: ActionRequest, challenge: str,
        approvals: Sequence[SignedGuardianApproval],
        compiled_ceiling: CompiledTaskPolicyCeiling,
    ) -> IssuedCapability:
        if not isinstance(request, ActionRequest) or not isinstance(challenge, str):
            raise GuardianAuthorityError("signer request invalid")
        with self._lock:
            state = self._pending.pop(challenge, None)
        if state is None or state[0] != request.request_digest or time.monotonic() > state[1]:
            raise GuardianAuthorityError("expired/replayed or swapped signer challenge")
        decisions = self.verifier.verify_all(
            request, challenge, self.policy.policy_digest, approvals,
        )
        independently_evaluated = self.policy.evaluate(request)
        if not independently_evaluated.allowed:
            raise GuardianAuthorityError("signer local policy independently vetoed request")
        static = decisions[STATIC_POLICY_GUARDIAN]
        if (_decision_payload(static, challenge, self.policy.policy_digest, self.verifier.key_ids[STATIC_POLICY_GUARDIAN])
                != _decision_payload(independently_evaluated, challenge, self.policy.policy_digest, self.verifier.key_ids[STATIC_POLICY_GUARDIAN])):
            raise GuardianAuthorityError("guardian's signed static policy disagrees with independent signer policy")
        # A compromised coordinator cannot smuggle an enlarged ceiling.
        if not isinstance(compiled_ceiling, CompiledTaskPolicyCeiling):
            raise GuardianAuthorityError("compiled authority ceiling invalid")
        compiled_ceiling.verify_integrity()
        if not compiled_ceiling.permits(request):
            raise GuardianAuthorityError("compiled ceiling rejects requested operation")
        if compiled_ceiling.policy_version != self.policy.policy_id:
            # The compiled ceiling actually binds an immutable compiler policy
            # version, not a coordinator-provided authorization string.
            raise GuardianAuthorityError("compiled ceiling policy version mismatch")
        for action in compiled_ceiling.actions:
            rule = self.policy.operations.get(action)
            if rule is None:
                raise GuardianAuthorityError("compiled ceiling includes unapproved action")
            if not set(compiled_ceiling.action_resources.get(action, ())).issubset(rule.resources):
                raise GuardianAuthorityError("compiled ceiling widened resources")
            if not set(compiled_ceiling.argument_constraints.get(action, ())).issubset(rule.allowed_argument_keys):
                raise GuardianAuthorityError("compiled ceiling widened arguments")
        if compiled_ceiling.network_destinations and "network.connect" not in self.policy.operations:
            raise GuardianAuthorityError("compiled ceiling requested network without policy")
        attestation = decisions[EXECUTOR_ATTESTATION_GUARDIAN].evidence
        if (attestation.get("device_id") != request.executor_id
                or not isinstance(attestation.get("measurement"), str)
                or not isinstance(attestation.get("provider_trust_state"), Mapping)):
            raise GuardianAuthorityError("signed executor identity/attestation missing")
        try:
            trust = ProviderTrustState.from_dict(attestation["provider_trust_state"])
            observed_attestation = attestation.get("attestation_result")
            if not isinstance(observed_attestation, Mapping):
                raise GuardianAuthorityError("signed attestation result missing")
            expected_trust = ProviderTrustState.from_attestation(\n                observed_attestation, requested_trust=trust.requested_trust,\n            )
            if trust.to_dict() != expected_trust.to_dict():
                raise GuardianAuthorityError("guardian trust assertion mismatches signed attestation evidence")
        except (TypeError, ValueError) as exc:
            raise GuardianAuthorityError("invalid guardian attestation binding") from exc
        signed_state = digest([
            {
                "guardian": key,
                "signature": next(a.signature for a in approvals if a.payload["guardian"] == key),
                "payload": next(dict(a.payload) for a in approvals if a.payload["guardian"] == key),
            }
            for key in sorted(REQUIRED_GUARDIANS)
        ])
        return self._broker.issue(
            request,
            device_id=attestation["device_id"],
            executor_measurement=attestation["measurement"],
            trust_state=trust,
            compiled_ceiling=compiled_ceiling,
            policy_digest=self.policy.policy_digest,
            max_output_bytes=independently_evaluated.evidence["max_output_bytes"],
            guardian_state_digest=signed_state,
        )
