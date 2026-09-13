from __future__ import annotations

import base64
import hashlib
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes
from .recorder import ExternalRecorder


MESSAGE_SCHEMA = "event-horizon.emergency-stop.v1"
ACTIONS = frozenset({"kill", "rearm", "rotate-key", "revoke-authority", "revoke-external-effects"})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{32}$")


class EmergencyStopError(PermissionError):
    pass


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


@dataclass(frozen=True)
class EmergencyStopChallenge:
    component_id: str
    challenge_id: int
    nonce: str
    issued_at_ms: int
    expires_at_ms: int

    def __post_init__(self) -> None:
        if not self.component_id or type(self.challenge_id) is not int or self.challenge_id < 1:
            raise EmergencyStopError("emergency stop challenge identity is invalid")
        if not re.fullmatch(r"[0-9a-f]{32}", self.nonce):
            raise EmergencyStopError("emergency stop challenge nonce is malformed")
        if not self.issued_at_ms < self.expires_at_ms:
            raise EmergencyStopError("emergency stop challenge lifetime is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class SignedEmergencyAction:
    claims: Mapping[str, Any]
    signature: str
    algorithm: str = "Ed25519"

    CLAIM_FIELDS = frozenset({
        "schema", "component_id", "challenge_id", "challenge_nonce", "sequence",
        "issued_at_ms", "expires_at_ms", "action", "action_payload", "key_id",
    })

    def __post_init__(self) -> None:
        if not isinstance(self.claims, Mapping) or set(self.claims) != self.CLAIM_FIELDS:
            raise EmergencyStopError("emergency action claims are malformed")
        if self.algorithm != "Ed25519" or not re.fullmatch(r"[A-Za-z0-9_-]{86}", self.signature):
            raise EmergencyStopError("emergency action signature envelope is malformed")
        canonical_bytes(self.claims)

    def to_dict(self) -> dict[str, Any]:
        return {"algorithm": self.algorithm, "claims": dict(self.claims), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignedEmergencyAction":
        if not isinstance(value, Mapping) or set(value) != {"algorithm", "claims", "signature"}:
            raise EmergencyStopError("emergency action envelope is malformed")
        return cls(value["claims"], value["signature"], value["algorithm"])


@dataclass
class EmergencyStopController:
    """Independent emergency stop controller that can revoke authority and external effects."""

    component_id: str
    recorder: ExternalRecorder
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _state: str = field(default="armed", init=False)
    _trip_reason: str = field(default="", init=False)
    _sequence: int = field(default=0, init=False)
    _last_valid_ms: int = field(default=None, init=False)
    _challenge_counter: int = field(default=0, init=False)
    _pending_challenge: 'EmergencyStopChallenge' = field(default=None, init=False)
    _authorized_keys: dict[str, Ed25519PublicKey] = field(default_factory=dict, init=False)
    _trusted_rearm_keys: set[str] = field(default_factory=set, init=False)
    _revoked_authorities: set[str] = field(default_factory=set, init=False)
    _revoked_external_effects: set[str] = field(default_factory=set, init=False)
    _timeout_ms: int = field(default=2_000, init=False)
    _nonce_factory: Callable[[], str] = field(default_factory=lambda: secrets.token_hex(16), init=False)

    def __post_init__(self) -> None:
        if not self.component_id:
            raise EmergencyStopError("component_id is required")
        self._state = "tripped"
        self._trip_reason = "controller-restart"

    def enroll_key(
        self,
        key_id_str: str,
        public_key_pem: str,
        *,
        trusted_for_rearm: bool = False,
        actor: str = "operator",
    ) -> None:
        """Enroll a public key for emergency stop operations."""
        if not _KEY_ID.fullmatch(key_id_str):
            raise EmergencyStopError("key_id format is invalid")
        try:
            public = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            if not isinstance(public, Ed25519PublicKey):
                raise EmergencyStopError("public key must be Ed25519")
            if key_id(public) != key_id_str:
                raise EmergencyStopError("key_id does not match public key")
        except Exception as exc:
            raise EmergencyStopError(f"invalid public key: {exc}") from exc

        with self._lock:
            if key_id_str in self._authorized_keys:
                raise EmergencyStopError(f"key {key_id_str} already enrolled")
            self._authorized_keys[key_id_str] = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            if trusted_for_rearm:
                self._trusted_rearm_keys.add(key_id_str)
            self.recorder.append("emergency_stop.key_enrolled", {
                "key_id": key_id_str,
                "component_id": self.component_id,
                "trusted_for_rearm": trusted_for_rearm,
                "actor": actor,
            })

    def revoke_key(self, key_id_str: str, *, actor: str = "operator") -> None:
        """Revoke an enrolled key."""
        with self._lock:
            if key_id_str not in self._authorized_keys:
                raise EmergencyStopError(f"key {key_id_str} not enrolled")
            del self._authorized_keys[key_id_str]
            self._trusted_rearm_keys.discard(key_id_str)
            self.recorder.append("emergency_stop.key_revoked", {
                "key_id": key_id_str,
                "component_id": self.component_id,
                "actor": actor,
            })

    def issue_challenge(self, now_ms: int, *, lifetime_ms: int = 1_000) -> 'EmergencyStopChallenge':
        """Issue a new challenge for emergency action."""
        with self._lock:
            self._challenge_counter += 1
            challenge = EmergencyStopChallenge(
                self.component_id,
                self._challenge_counter,
                secrets.token_hex(16),
                now_ms,
                now_ms + lifetime_ms,
            )
            self._pending_challenge = challenge
            return challenge

    def receive_action(
        self,
        action: 'SignedEmergencyAction',
        *,
        now_ms: int,
        trusted_operator: bool = False,
    ) -> str:
        """Receive and validate an emergency action."""
        with self._lock:
            try:
                parsed = action if isinstance(action, SignedEmergencyAction) else SignedEmergencyAction.from_dict(action)
                claims = dict(parsed.claims)
                challenge = self._pending_challenge
                if challenge is None:
                    raise EmergencyStopError("no outstanding challenge")
                if claims["schema"] != MESSAGE_SCHEMA or claims["component_id"] != self.component_id:
                    raise EmergencyStopError("component or schema mismatch")
                if claims["key_id"] not in self._authorized_keys:
                    raise EmergencyStopError("action key not authorized")
                if claims["challenge_id"] != challenge.challenge_id or claims["challenge_nonce"] != challenge.nonce:
                    raise EmergencyStopError("challenge mismatch")
                if now_ms >= challenge.expires_at_ms:
                    raise EmergencyStopError("challenge expired")
                if claims["sequence"] <= self._sequence:
                    raise EmergencyStopError("stale or replayed sequence")
                if now_ms < claims["issued_at_ms"] - 1_000 or now_ms >= claims["expires_at_ms"]:
                    raise EmergencyStopError("freshness check failed")
                if claims["action"] not in ACTIONS:
                    raise EmergencyStopError("invalid action")

                try:
                    public_key = self._authorized_keys[claims["key_id"]]
                    raw = base64.urlsafe_b64decode(parsed.signature + "==")
                    public_key.verify(raw, canonical_bytes(dict(claims)))
                except (InvalidSignature, ValueError) as exc:
                    raise EmergencyStopError("invalid signature") from exc

                self._pending_challenge = None
                self._sequence = claims["sequence"]
                action = claims["action"]
                payload = dict(claims["action_payload"])

                if action == "kill":
                    self._trip(payload.get("reason", "explicit-kill"))
                elif action == "rearm":
                    if not trusted_operator:
                        raise EmergencyStopError("rearm requires trusted operator")
                    self._state = "armed"
                    self._trip_reason = ""
                elif action == "revoke-authority":
                    authority_id = payload.get("authority_id")
                    if not authority_id:
                        raise EmergencyStopError("revoke-authority requires authority_id")
                    self._revoked_authorities.add(authority_id)
                    self.recorder.append("emergency_stop.authority_revoked", {
                        "component_id": self.component_id,
                        "authority_id": authority_id,
                        "revoked_at_ms": int(time.time() * 1000),
                    })
                elif action == "revoke-external-effects":
                    effect_id = payload.get("effect_id")
                    if not effect_id:
                        raise EmergencyStopError("revoke-external-effects requires effect_id")
                    self._revoked_external_effects.add(effect_id)
                    self.recorder.append("emergency_stop.external_effect_revoked", {
                        "component_id": self.component_id,
                        "effect_id": effect_id,
                        "revoked_at_ms": int(time.time() * 1000),
                    })

                return self._state
            except Exception as exc:
                self._pending_challenge = None
                self._trip(type(exc).__name__)
                if isinstance(exc, EmergencyStopError):
                    raise
                raise EmergencyStopError("validation failed closed") from exc

    def _trip(self, reason: str) -> None:
        with self._lock:
            self._state = "tripped"
            self._trip_reason = reason[:256]
            self.recorder.append("emergency_stop.tripped", {
                "component_id": self.component_id,
                "reason": self._trip_reason,
                "revoked_authorities": list(self._revoked_authorities),
                "revoked_external_effects": list(self._revoked_external_effects),
            })

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def trip_reason(self) -> str:
        with self._lock:
            return self._trip_reason

    def is_authority_revoked(self, authority_id: str) -> bool:
        with self._lock:
            return authority_id in self._revoked_authorities

    def is_external_effect_revoked(self, effect_id: str) -> bool:
        with self._lock:
            return effect_id in self._revoked_external_effects

    def get_revoked_authorities(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._revoked_authorities)

    def get_revoked_external_effects(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._revoked_external_effects)