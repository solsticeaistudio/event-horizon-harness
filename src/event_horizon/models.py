from __future__ import annotations

import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import CanonicalizationError, canonical_bytes, digest


class ValidationError(ValueError):
    pass


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^ed25519:[0-9a-f]{32}$")
_CAPABILITY_ID_RE = re.compile(r"^cap_[0-9a-f]{24}$")


def _validated_text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValidationError(f"{name} must be a non-empty string <= {maximum} UTF-8 bytes")
    try:
        canonical_bytes(value)
    except CanonicalizationError as exc:
        raise ValidationError(f"{name} is not canonical: {exc}") from exc
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _validate_security_json(value: Any) -> None:
    if isinstance(value, float):
        raise ValidationError("floating-point request values are not permitted")
    if isinstance(value, Mapping):
        for item in value.values():
            _validate_security_json(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_security_json(item)


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True)
class ActionRequest:
    request_id: str
    session_id: str
    agent_id: str
    operation: str
    resource_id: str
    executor_id: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    purpose: str = ""

    ALLOWED_FIELDS = frozenset({
        "request_id", "session_id", "agent_id", "operation", "resource_id",
        "executor_id", "arguments", "purpose"
    })

    def __post_init__(self) -> None:
        for name in ("request_id", "session_id", "agent_id", "operation", "resource_id", "executor_id"):
            _validated_text(getattr(self, name), name, 256)
        if not isinstance(self.purpose, str) or len(self.purpose.encode("utf-8")) > 1024:
            raise ValidationError("purpose must be a string <= 1024 UTF-8 bytes")
        try:
            canonical_bytes(self.purpose)
            canonical_bytes(self.arguments)
        except CanonicalizationError as exc:
            raise ValidationError(f"request is not canonical: {exc}") from exc
        if not isinstance(self.arguments, Mapping):
            raise ValidationError("arguments must be an object")
        _validate_security_json(self.arguments)
        object.__setattr__(self, "arguments", _freeze_json(self.arguments))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ActionRequest":
        if not isinstance(payload, Mapping):
            raise ValidationError("request must be an object")
        unknown = set(payload) - cls.ALLOWED_FIELDS
        missing = cls.ALLOWED_FIELDS - set(payload)
        if unknown or missing:
            raise ValidationError(f"invalid request fields; unknown={sorted(unknown)}, missing={sorted(missing)}")
        arguments = payload["arguments"]
        if not isinstance(arguments, Mapping):
            raise ValidationError("arguments must be an object")
        return cls(
            request_id=payload["request_id"],
            session_id=payload["session_id"],
            agent_id=payload["agent_id"],
            operation=payload["operation"],
            resource_id=payload["resource_id"],
            executor_id=payload["executor_id"],
            arguments=arguments,
            purpose=payload["purpose"],
        )

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "operation": self.operation,
            "resource_id": self.resource_id,
            "executor_id": self.executor_id,
            "arguments": _thaw_json(self.arguments),
            "purpose": self.purpose,
        }

    @property
    def request_digest(self) -> str:
        return digest(self.canonical_payload())


@dataclass(frozen=True)
class GuardianDecision:
    guardian: str
    allowed: bool
    reason: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    request_digest: str = ""


@dataclass(frozen=True)
class CapabilityClaims:
    capability_id: str
    issued_at: int
    expires_at: int
    session_id: str
    agent_id: str
    executor_id: str
    device_id: str
    executor_measurement: str
    attestation_digest: str
    attestation_bundle_digest: str
    verifier_policy_digest: str
    task_id: str
    task_fingerprint: str
    tenant: str
    environment: str
    audience: str
    requested_trust: str
    provider_attested_trust: str
    effective_trust: str
    signed_trust_constraint: str
    attestation_method: str
    attestation_key_id: str
    compiled_ceiling: Mapping[str, Any]
    compiled_ceiling_digest: str
    guardian_state_digest: str
    decay_profile_id: str
    decay_profile_version: str
    decay_profile_digest: str
    initial_authority_digest: str
    refresh_requirements_digest: str
    operation: str
    resource_id: str
    arguments_digest: str
    request_digest: str
    max_output_bytes: int
    invocation_limit: int = 1
    signer_key_id: str = ""
    policy_digest: str = ""

    ALLOWED_FIELDS = frozenset({
        'capability_id', 'issued_at', 'expires_at', 'session_id', 'agent_id',
        'executor_id', 'device_id', 'executor_measurement', 'attestation_digest',
        'attestation_bundle_digest', 'verifier_policy_digest', 'task_id',
        'task_fingerprint', 'tenant', 'environment', 'audience', 'requested_trust',
        'provider_attested_trust', 'effective_trust', 'signed_trust_constraint',
        'attestation_method', 'attestation_key_id', 'compiled_ceiling',
        'compiled_ceiling_digest', 'guardian_state_digest', 'decay_profile_id',
        'decay_profile_version', 'decay_profile_digest', 'initial_authority_digest',
        'refresh_requirements_digest', 'operation',
        'resource_id', 'arguments_digest', 'request_digest', 'max_output_bytes',
        'invocation_limit', 'policy_digest', 'signer_key_id',
    })

    def __post_init__(self) -> None:
        if not _CAPABILITY_ID_RE.fullmatch(self.capability_id):
            raise ValidationError("capability_id is malformed")
        for name in (
            "session_id", "agent_id", "executor_id", "device_id", "task_id", "tenant",
            "environment", "audience", "attestation_method", "attestation_key_id",
            "decay_profile_id", "decay_profile_version", "operation", "resource_id",
        ):
            _validated_text(getattr(self, name), name, 256)
        for name in (
            "executor_measurement", "attestation_digest", "attestation_bundle_digest",
            "verifier_policy_digest", "task_fingerprint", "compiled_ceiling_digest",
            "guardian_state_digest", "decay_profile_digest", "initial_authority_digest",
            "refresh_requirements_digest", "arguments_digest", "request_digest",
            "policy_digest",
        ):
            if not isinstance(getattr(self, name), str) or not _DIGEST_RE.fullmatch(getattr(self, name)):
                raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
        trust_tiers = {"simulated", "software", "hardware"}
        for name in (
            "requested_trust", "provider_attested_trust", "effective_trust",
            "signed_trust_constraint",
        ):
            if getattr(self, name) not in trust_tiers:
                raise ValidationError(f"{name} is not a supported trust tier")
        if not isinstance(self.compiled_ceiling, Mapping):
            raise ValidationError("compiled_ceiling must be an object")
        _validate_security_json(self.compiled_ceiling)
        try:
            canonical_bytes(self.compiled_ceiling)
        except CanonicalizationError as exc:
            raise ValidationError(f"compiled ceiling is not canonical: {exc}") from exc
        if self.compiled_ceiling.get("compiled_digest") != self.compiled_ceiling_digest:
            raise ValidationError("compiled ceiling digest mismatch")
        object.__setattr__(self, "compiled_ceiling", _freeze_json(self.compiled_ceiling))
        if not isinstance(self.signer_key_id, str) or not _KEY_ID_RE.fullmatch(self.signer_key_id):
            raise ValidationError("signer_key_id is malformed")
        if type(self.issued_at) is not int or type(self.expires_at) is not int:
            raise ValidationError("capability timestamps must be integer Unix milliseconds")
        if not 0 < self.expires_at - self.issued_at <= 300_000:
            raise ValidationError("capability lifetime is invalid")
        if type(self.max_output_bytes) is not int or not 0 < self.max_output_bytes <= 1_048_576:
            raise ValidationError("invalid capability output limit")
        if type(self.invocation_limit) is not int or self.invocation_limit != 1:
            raise ValidationError("only one-use capabilities are supported")

    def to_dict(self) -> dict[str, Any]:
        return {
            name: _thaw_json(getattr(self, name))
            for name in self.__dataclass_fields__
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> 'CapabilityClaims':
        if not isinstance(payload, Mapping):
            raise ValidationError('capability claims must be an object')
        unknown = set(payload) - cls.ALLOWED_FIELDS
        missing = cls.ALLOWED_FIELDS - set(payload)
        if unknown or missing:
            raise ValidationError(
                f'invalid capability claim fields; unknown={sorted(unknown)}, missing={sorted(missing)}'
            )
        string_fields = cls.ALLOWED_FIELDS - {
            'issued_at', 'expires_at', 'max_output_bytes', 'invocation_limit',
            'compiled_ceiling',
        }
        if any(not isinstance(payload[name], str) or not payload[name] for name in string_fields):
            raise ValidationError('capability string claims must be non-empty strings')
        return cls(**dict(payload))


@dataclass(frozen=True)
class IssuedCapability:
    claims: CapabilityClaims
    signature: str
    key_id: str
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        if self.algorithm != "Ed25519":
            raise ValidationError("capability algorithm must be Ed25519")
        if not isinstance(self.key_id, str) or not _KEY_ID_RE.fullmatch(self.key_id):
            raise ValidationError("capability key_id is malformed")
        if not isinstance(self.signature, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", self.signature):
            raise ValidationError("capability signature is not canonical Ed25519 base64url")

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "claims": self.claims.to_dict(),
            "signature": self.signature,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> 'IssuedCapability':
        if not isinstance(payload, Mapping) or set(payload) != {'algorithm', 'claims', 'signature', 'key_id'}:
            raise ValidationError('capability envelope fields are invalid')
        return cls(
            CapabilityClaims.from_dict(payload['claims']),
            payload['signature'],
            payload['key_id'],
            payload['algorithm'],
        )


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    operation: str
    resource_id: str
    output: Any = None
    output_bytes: int = 0
    error: str | None = None
    effect_state: str = "unknown"
    receipt: Mapping[str, Any] | None = None
