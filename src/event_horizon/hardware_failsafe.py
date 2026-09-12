from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .hardware_backends import (
    HardwareBackend,
    HardwareFailSafeError,
    MockHardwareBackend,
)


MESSAGE_SCHEMA = "event-horizon.hardware-failsafe.v1"
ACTIONS = frozenset({"heartbeat", "kill", "rearm", "rotate-key"})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{32}$")


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


@dataclass(frozen=True)
class HeartbeatChallenge:
    device_id: str
    challenge_id: int
    nonce: str
    issued_at_ms: int
    expires_at_ms: int

    def __post_init__(self) -> None:
        if not self.device_id or type(self.challenge_id) is not int or self.challenge_id < 1:
            raise HardwareFailSafeError("heartbeat challenge identity is invalid")
        if not re.fullmatch(r"[0-9a-f]{32}", self.nonce):
            raise HardwareFailSafeError("heartbeat challenge nonce is malformed")
        if not self.issued_at_ms < self.expires_at_ms:
            raise HardwareFailSafeError("heartbeat challenge lifetime is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class SignedHeartbeat:
    claims: Mapping[str, Any]
    signature: str
    algorithm: str = "Ed25519"

    CLAIM_FIELDS = frozenset({
        "schema", "device_id", "challenge_id", "challenge_nonce", "sequence",
        "issued_at_ms", "expires_at_ms", "policy_version", "evidence_chain_digest",
        "action", "action_payload", "key_id",
    })

    def __post_init__(self) -> None:
        if not isinstance(self.claims, Mapping) or set(self.claims) != self.CLAIM_FIELDS:
            raise HardwareFailSafeError("heartbeat claims are malformed")
        if self.algorithm != "Ed25519" or not re.fullmatch(r"[A-Za-z0-9_-]{86}", self.signature):
            raise HardwareFailSafeError("heartbeat signature envelope is malformed")
        canonical_bytes(self.claims)

    def to_dict(self) -> dict[str, Any]:
        return {"algorithm": self.algorithm, "claims": dict(self.claims), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignedHeartbeat":
        if not isinstance(value, Mapping) or set(value) != {"algorithm", "claims", "signature"}:
            raise HardwareFailSafeError("heartbeat envelope is malformed")
        return cls(value["claims"], value["signature"], value["algorithm"])


class FailSafeHostClient:
    def __init__(
        self,
        device_id: str,
        signing_key: bytes | Ed25519PrivateKey,
        *,
        initial_sequence: int = 0,
    ):
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes) and len(signing_key) >= 32:
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        else:
            raise ValueError("heartbeat signing seed is invalid")
        if not device_id or type(initial_sequence) is not int or initial_sequence < 0:
            raise ValueError("heartbeat client identity or sequence is invalid")
        self.device_id = device_id
        self._sequence = initial_sequence
        self.public_key = self._private_key.public_key()
        self.key_id = key_id(self.public_key)

    @property
    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def sequence(self) -> int:
        return self._sequence

    def respond(
        self,
        challenge: HeartbeatChallenge,
        *,
        now_ms: int,
        policy_version: str,
        evidence_chain_digest: str,
        action: str = "heartbeat",
        action_payload: Mapping[str, Any] | None = None,
        lifetime_ms: int = 1_000,
    ) -> SignedHeartbeat:
        self._sequence += 1
        claims = {
            "schema": MESSAGE_SCHEMA,
            "device_id": self.device_id,
            "challenge_id": challenge.challenge_id,
            "challenge_nonce": challenge.nonce,
            "sequence": self._sequence,
            "issued_at_ms": now_ms,
            "expires_at_ms": now_ms + lifetime_ms,
            "policy_version": policy_version,
            "evidence_chain_digest": evidence_chain_digest,
            "action": action,
            "action_payload": dict(action_payload or {}),
            "key_id": self.key_id,
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(claims))
        ).rstrip(b"=").decode("ascii")
        return SignedHeartbeat(claims, signature)


class HardwareFailSafeSimulator:
    """Independent-switch state machine. Restart always begins tripped.
    
    Supports optional hardware backend for physical kill switch integration.
    """

    def __init__(
        self,
        *,
        device_id: str,
        trusted_public_key_pem: str,
        expected_policy_version: str,
        expected_evidence_digest: str,
        heartbeat_timeout_ms: int = 2_000,
        nonce_factory: Callable[[], str] | None = None,
        hardware_backend: Optional[HardwareBackend] = None,
    ):
        try:
            public = serialization.load_pem_public_key(trusted_public_key_pem.encode("ascii"))
        except (TypeError, ValueError) as exc:
            raise ValueError("fail-safe public key is invalid") from exc
        if not isinstance(public, Ed25519PublicKey) or not device_id or not expected_policy_version:
            raise ValueError("fail-safe enrollment is invalid")
        if not _DIGEST.fullmatch(expected_evidence_digest):
            raise ValueError("fail-safe evidence digest is invalid")
        if type(heartbeat_timeout_ms) is not int or not 100 <= heartbeat_timeout_ms <= 60_000:
            raise ValueError("heartbeat timeout is invalid")
        self.device_id = device_id
        self._public_key = public
        self.active_key_id = key_id(public)
        self.expected_policy_version = expected_policy_version
        self.expected_evidence_digest = expected_evidence_digest
        self.heartbeat_timeout_ms = heartbeat_timeout_ms
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(16))
        self.state = "tripped"
        self.trip_reason = "microcontroller-restart"
        self.last_sequence = 0
        self.last_valid_heartbeat_ms: int | None = None
        self._challenge_counter = 0
        self._pending: HeartbeatChallenge | None = None
        
        # Hardware backend for physical kill switch
        self._hardware_backend = hardware_backend or MockHardwareBackend()

    def issue_challenge(self, now_ms: int, *, lifetime_ms: int = 1_000) -> HeartbeatChallenge:
        self._challenge_counter += 1
        challenge = HeartbeatChallenge(
            self.device_id, self._challenge_counter, self._nonce_factory(),
            now_ms, now_ms + lifetime_ms,
        )
        self._pending = challenge
        return challenge

    def _trip(self, reason: str) -> None:
        self.state = "tripped"
        self.trip_reason = reason
        
        # Trigger hardware kill switch if available
        try:
            self._hardware_backend.trigger_kill(reason)
        except Exception:
            # Hardware failure doesn't change the tripped state
            # but should be logged
            pass

    def receive(
        self,
        message: SignedHeartbeat | Mapping[str, Any],
        *,
        now_ms: int,
        trusted_rearm: bool = False,
    ) -> str:
        try:
            parsed = message if isinstance(message, SignedHeartbeat) else SignedHeartbeat.from_dict(message)
            claims = dict(parsed.claims)
            challenge = self._pending
            if challenge is None:
                raise HardwareFailSafeError("no outstanding heartbeat challenge")
            if claims["schema"] != MESSAGE_SCHEMA or claims["device_id"] != self.device_id:
                raise HardwareFailSafeError("heartbeat device or schema mismatch")
            if claims["key_id"] != self.active_key_id or not _KEY_ID.fullmatch(claims["key_id"]):
                raise HardwareFailSafeError("heartbeat key identity mismatch")
            if (
                claims["challenge_id"] != challenge.challenge_id
                or claims["challenge_nonce"] != challenge.nonce
            ):
                raise HardwareFailSafeError("heartbeat challenge mismatch")
            if now_ms >= challenge.expires_at_ms:
                raise HardwareFailSafeError("heartbeat challenge expired")
            if any(type(claims[name]) is not int for name in ("sequence", "issued_at_ms", "expires_at_ms")):
                raise HardwareFailSafeError("heartbeat counters are malformed")
            if claims["sequence"] <= self.last_sequence:
                raise HardwareFailSafeError("heartbeat sequence is stale or replayed")
            if now_ms < claims["issued_at_ms"] - 1_000 or now_ms >= claims["expires_at_ms"]:
                raise HardwareFailSafeError("heartbeat freshness check failed")
            if claims["policy_version"] != self.expected_policy_version:
                raise HardwareFailSafeError("heartbeat policy mismatch")
            if claims["evidence_chain_digest"] != self.expected_evidence_digest:
                raise HardwareFailSafeError("heartbeat evidence digest mismatch")
            if claims["action"] not in ACTIONS or not isinstance(claims["action_payload"], Mapping):
                raise HardwareFailSafeError("heartbeat action is malformed")
            try:
                raw = base64.urlsafe_b64decode(parsed.signature + "==")
                self._public_key.verify(raw, canonical_bytes(claims))
            except (InvalidSignature, ValueError) as exc:
                raise HardwareFailSafeError("heartbeat signature is invalid") from exc
            self._pending = None
            self.last_sequence = claims["sequence"]
            action = claims["action"]
            if action == "kill":
                reason = claims["action_payload"].get("reason", "explicit-trusted-kill")
                self._trip(str(reason)[:128])
            elif action == "rearm":
                if not trusted_rearm:
                    raise HardwareFailSafeError("re-arm requires an explicit trusted procedure")
                self.state = "armed"
                self.trip_reason = ""
                self.last_valid_heartbeat_ms = now_ms
            elif action == "rotate-key":
                self._rotate(claims["action_payload"])
            elif self.state == "armed":
                self.last_valid_heartbeat_ms = now_ms
            return self.state
        except Exception as exc:
            self._pending = None
            self._trip(type(exc).__name__)
            if isinstance(exc, HardwareFailSafeError):
                raise
            raise HardwareFailSafeError("heartbeat validation failed closed") from exc

    def _rotate(self, payload: Mapping[str, Any]) -> None:
        if set(payload) != {"new_key_id", "new_public_key_pem"}:
            raise HardwareFailSafeError("key rotation payload is malformed")
        try:
            public = serialization.load_pem_public_key(payload["new_public_key_pem"].encode("ascii"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise HardwareFailSafeError("rotated public key is invalid") from exc
        if not isinstance(public, Ed25519PublicKey) or key_id(public) != payload["new_key_id"]:
            raise HardwareFailSafeError("rotated public key identity mismatch")
        self._public_key = public
        self.active_key_id = payload["new_key_id"]

    def tick(self, now_ms: int) -> str:
        if (
            self.state == "armed"
            and (self.last_valid_heartbeat_ms is None
                 or now_ms - self.last_valid_heartbeat_ms >= self.heartbeat_timeout_ms)
        ):
            self._trip("heartbeat-timeout")
        return self.state

    def get_hardware_status(self) -> Mapping[str, Any]:
        """Get status of the hardware backend."""
        return self._hardware_backend.get_status()

    def test_hardware(self) -> bool:
        """Test the hardware backend."""
        return self._hardware_backend.test_kill_circuit()

    def close(self) -> None:
        """Close the hardware backend."""
        if hasattr(self._hardware_backend, 'close'):
            self._hardware_backend.close()
