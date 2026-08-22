from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes


STATEMENT_SCHEMA = "event-horizon.signed-statement.v1"
STATEMENT_ALGORITHM = "Ed25519"

# Domain separation: every statement type is signed under an explicit
# purpose-bound domain string so a signature over one class of object can
# never be interpreted as another class of object.
DOMAIN_PREFIX = "EVENT_HORIZON"

TYPE_VERIFIER_ATTESTATION = "verifier-attestation"
TYPE_GUARDIAN_DECISION = "guardian-decision"
TYPE_EXECUTION_RECEIPT = "execution-receipt"
TYPE_RECORDER_CHECKPOINT = "recorder-checkpoint"
TYPE_TEARDOWN_ATTESTATION = "teardown-attestation"

STATEMENT_TYPES = frozenset({
    TYPE_VERIFIER_ATTESTATION,
    TYPE_GUARDIAN_DECISION,
    TYPE_EXECUTION_RECEIPT,
    TYPE_RECORDER_CHECKPOINT,
    TYPE_TEARDOWN_ATTESTATION,
})

_STATEMENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{32}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_ENVELOPE_FIELDS = {
    "statement_schema",
    "statement_type",
    "statement_version",
    "domain",
    "key_id",
    "issued_at",
    "subject",
    "payload",
    "signature",
}


class StatementError(ValueError):
    pass


def statement_domain(statement_type: str, version: int) -> str:
    if _STATEMENT_TYPE_RE.fullmatch(statement_type) is None:
        raise StatementError("statement type is invalid")
    if type(version) is not int or not 1 <= version <= 9_999:
        raise StatementError("statement version is invalid")
    return f"{DOMAIN_PREFIX}/{statement_type.upper().replace('-', '_')}/v{version}"


def key_id_for_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


def _load_private(value: bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes) and len(value) >= 32:
        return Ed25519PrivateKey.from_private_bytes(value[:32])
    raise StatementError("statement signing key must be Ed25519")


def _load_public(value: str | Ed25519PublicKey) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    try:
        key = serialization.load_pem_public_key(value.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise StatementError("statement verification key is malformed") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise StatementError("statement verification key must be Ed25519")
    return key


@dataclass(frozen=True)
class SignedStatement:
    """A typed, domain-separated statement signed by one trusted actor."""

    statement_type: str
    statement_version: int
    subject: str
    payload: Mapping[str, Any]
    issued_at: float
    key_id: str
    signature: str
    algorithm: str = STATEMENT_ALGORITHM

    def unsigned(self) -> dict[str, Any]:
        return {
            "statement_schema": STATEMENT_SCHEMA,
            "statement_type": self.statement_type,
            "statement_version": self.statement_version,
            "domain": statement_domain(self.statement_type, self.statement_version),
            "key_id": self.key_id,
            "issued_at": self.issued_at,
            "subject": self.subject,
            "payload": dict(self.payload),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned(), "signature": self.signature}

    @classmethod
    def from_dict(cls, envelope: Mapping[str, Any]) -> "SignedStatement":
        if not isinstance(envelope, Mapping) or set(envelope) != _ENVELOPE_FIELDS:
            raise StatementError("signed statement fields are invalid")
        if envelope["statement_schema"] != STATEMENT_SCHEMA:
            raise StatementError("signed statement schema is unsupported")
        statement_type = envelope["statement_type"]
        version = envelope["statement_version"]
        if (
            not isinstance(statement_type, str)
            or statement_type not in STATEMENT_TYPES
            or type(version) is not int
        ):
            raise StatementError("signed statement type or version is invalid")
        expected_domain = statement_domain(statement_type, version)
        if envelope["domain"] != expected_domain:
            raise StatementError("signed statement domain does not match its type and version")
        if not isinstance(envelope["subject"], str) or not envelope["subject"] or len(envelope["subject"]) > 256:
            raise StatementError("signed statement subject is invalid")
        if not isinstance(envelope["payload"], dict):
            raise StatementError("signed statement payload must be an object")
        issued_at = envelope["issued_at"]
        if type(issued_at) is not int or issued_at < 0:
            raise StatementError("signed statement issuance time must be integer Unix milliseconds")
        key_id = envelope["key_id"]
        signature = envelope["signature"]
        if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
            raise StatementError("signed statement key identity is malformed")
        if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
            raise StatementError("signed statement signature is malformed")
        return cls(
            statement_type=statement_type,
            statement_version=version,
            subject=envelope["subject"],
            payload=envelope["payload"],
            issued_at=issued_at,
            key_id=key_id,
            signature=signature,
        )


class StatementSigner:
    """Signs typed statements on behalf of exactly one trusted actor."""

    def __init__(
        self,
        signing_key: bytes | Ed25519PrivateKey,
        *,
        subject: str,
    ) -> None:
        self._private_key = _load_private(signing_key)
        public_key = self._private_key.public_key()
        self.public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.key_id = key_id_for_public_key(public_key)
        if not isinstance(subject, str) or not 0 < len(subject) <= 256:
            raise StatementError("statement signer subject is invalid")
        self.subject = subject

    def sign(
        self,
        statement_type: str,
        payload: Mapping[str, Any],
        *,
        version: int = 1,
        now: float | None = None,
    ) -> SignedStatement:
        if now is None:
            issued_at: int = time.time_ns() // 1_000_000
        elif isinstance(now, bool) or not isinstance(now, (int, float)):
            raise StatementError("statement issuance time is invalid")
        else:
            issued_at = int(now)
        if issued_at < 0:
            raise StatementError("statement issuance time is invalid")
        statement = SignedStatement(
            statement_type=statement_type,
            statement_version=version,
            subject=self.subject,
            payload=dict(payload),
            issued_at=issued_at,
            key_id=self.key_id,
            signature="",
        )
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(statement.unsigned()))
        ).rstrip(b"=").decode("ascii")
        return SignedStatement(
            statement_type=statement.statement_type,
            statement_version=statement.statement_version,
            subject=statement.subject,
            payload=statement.payload,
            issued_at=statement.issued_at,
            key_id=statement.key_id,
            signature=signature,
        )


class StatementVerifier:
    """Verifies statements from independently trusted actors.

    Trust is pinned to specific public keys supplied out of band. The map keys
    are caller-chosen slot names; statements are accepted only when their
    ``key_id`` matches the derived identity of one of those pinned keys.
    """

    def __init__(
        self,
        trusted_public_keys: Mapping[str, str | Ed25519PublicKey],
    ) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        for slot, value in trusted_public_keys.items():
            if not isinstance(slot, str) or not slot:
                raise StatementError("trusted statement key slot name is invalid")
            key = _load_public(value)
            self._keys[key_id_for_public_key(key)] = key

    @property
    def trusted_key_ids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def verify(
        self,
        envelope: Mapping[str, Any],
        *,
        expected_type: str | None = None,
        expected_subject: str | None = None,
    ) -> SignedStatement:
        statement = SignedStatement.from_dict(envelope)
        if expected_type is not None and statement.statement_type != expected_type:
            raise StatementError("signed statement type does not match expectation")
        if expected_subject is not None and statement.subject != expected_subject:
            raise StatementError("signed statement subject does not match expectation")
        key = self._keys.get(statement.key_id)
        if key is None:
            raise StatementError("signed statement key is not trusted")
        signature = base64.urlsafe_b64decode(statement.signature + "=" * (-len(statement.signature) % 4))
        try:
            key.verify(signature, canonical_bytes(statement.unsigned()))
        except InvalidSignature as exc:
            raise StatementError("signed statement signature is invalid") from exc
        return statement
