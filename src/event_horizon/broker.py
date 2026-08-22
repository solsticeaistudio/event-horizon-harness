from __future__ import annotations

import base64
import hashlib
import math
import re
import secrets
import time
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest
from .models import ActionRequest, CapabilityClaims, IssuedCapability
from .replay_state import CapabilityConsumptionStore
from .task_policy import (
    CompiledTaskPolicyCeiling,
    ProviderTrustState,
    TRUST_ORDER,
)
from .trust_decay import DecayEngine, DecayError, decay_profile_for_ceiling


class CapabilityError(PermissionError):
    pass


def capability_key_id(public_key: Ed25519PublicKey) -> str:
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"


def _strict_signature(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", value):
        raise CapabilityError("malformed capability signature")
    try:
        signature = base64.urlsafe_b64decode(value + "==")
    except (ValueError, TypeError) as exc:
        raise CapabilityError("malformed capability signature") from exc
    if len(signature) != 64 or base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != value:
        raise CapabilityError("malformed capability signature")
    return signature


def _now_ms(now: float | None) -> int:
    seconds = time.time() if now is None else now
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or not math.isfinite(seconds):
        raise CapabilityError("verification clock is invalid")
    return int(seconds * 1000)


def _verified_claims(
    public_key: Ed25519PublicKey,
    expected_key_id: str,
    capability: IssuedCapability,
    request: ActionRequest,
    *,
    executor_measurement: str,
    device_id: str,
    attestation: Mapping[str, Any],
    verifier_policy_digest: str,
    policy_digest: str,
    audience: str,
    tenant: str,
    environment: str,
    now: float | None,
) -> CapabilityClaims:
    try:
        parsed = IssuedCapability.from_dict(capability.to_dict())
    except (TypeError, ValueError) as exc:
        raise CapabilityError(f"malformed capability: {exc}") from exc
    claims = parsed.claims
    if parsed.algorithm != "Ed25519":
        raise CapabilityError("unsupported capability algorithm")
    if parsed.key_id != expected_key_id or claims.signer_key_id != expected_key_id:
        raise CapabilityError("unknown capability signing key")
    try:
        public_key.verify(_strict_signature(parsed.signature), canonical_bytes(claims.to_dict()))
    except InvalidSignature as exc:
        raise CapabilityError("invalid capability signature") from exc

    current_ms = _now_ms(now)
    if current_ms < claims.issued_at - 5_000:
        raise CapabilityError("capability issued beyond allowed clock skew")
    if current_ms >= claims.expires_at:
        raise CapabilityError("capability expired")

    request_payload = request.canonical_payload()
    reconstructed_request_digest = digest(request_payload)
    reconstructed_arguments_digest = digest(request_payload["arguments"])
    request_bindings = {
        "session_id": (claims.session_id, request.session_id),
        "agent_id": (claims.agent_id, request.agent_id),
        "executor_id": (claims.executor_id, request.executor_id),
        "operation": (claims.operation, request.operation),
        "resource_id": (claims.resource_id, request.resource_id),
        "arguments_digest": (claims.arguments_digest, reconstructed_arguments_digest),
        "request_digest": (claims.request_digest, reconstructed_request_digest),
    }
    request_mismatches = [
        name for name, pair in request_bindings.items() if pair[0] != pair[1]
    ]
    if request_mismatches:
        raise CapabilityError(f"capability binding mismatch: {sorted(request_mismatches)}")

    try:
        current_trust = ProviderTrustState.from_attestation(
            attestation,
            requested_trust=claims.requested_trust,
        )
        compiled = CompiledTaskPolicyCeiling.from_dict(claims.compiled_ceiling)
        decay_profile = decay_profile_for_ceiling(
            compiled,
            version=claims.decay_profile_version,
            issued_at_ms=claims.issued_at,
            expires_at_ms=claims.expires_at,
        )
    except (TypeError, ValueError) as exc:
        raise CapabilityError(f"current authority context is invalid: {exc}") from exc
    measurements = attestation.get("measurements")
    if not isinstance(measurements, Mapping):
        raise CapabilityError("current attestation measurements are invalid")
    nonce_context = attestation.get("nonceContext")
    expected_nonce_context = {
        "deviceId": request.executor_id,
        "executorId": request.executor_id,
        "sessionId": request.session_id,
        "purpose": request.purpose,
    }
    if nonce_context != expected_nonce_context:
        raise CapabilityError("current attestation nonce context mismatch")
    if current_ms >= current_trust.expires_at_ms:
        raise CapabilityError("current provider attestation expired")
    if TRUST_ORDER[current_trust.effective_trust] < TRUST_ORDER[claims.signed_trust_constraint]:
        raise CapabilityError("current provider trust is below the signed constraint")
    if not compiled.permits(request):
        raise CapabilityError("compiled task policy ceiling does not permit the request")

    bindings = {
        "session_id": (claims.session_id, request.session_id),
        "agent_id": (claims.agent_id, request.agent_id),
        "executor_id": (claims.executor_id, request.executor_id),
        "device_id": (claims.device_id, device_id),
        "executor_measurement": (claims.executor_measurement, executor_measurement),
        "current_attested_device": (device_id, str(attestation.get("deviceId", ""))),
        "current_attested_measurement": (
            executor_measurement,
            str(measurements.get("executor", "")),
        ),
        "attestation_digest": (claims.attestation_digest, current_trust.attestation_digest),
        "attestation_bundle_digest": (
            claims.attestation_bundle_digest,
            current_trust.bundle_digest,
        ),
        "verifier_policy_digest": (
            claims.verifier_policy_digest,
            current_trust.verifier_policy_digest,
        ),
        "current_verifier_policy_digest": (
            current_trust.verifier_policy_digest,
            verifier_policy_digest,
        ),
        "attestation_method": (claims.attestation_method, current_trust.method),
        "attestation_key_id": (claims.attestation_key_id, current_trust.key_id),
        "provider_attested_trust": (
            claims.provider_attested_trust,
            current_trust.provider_attested_trust,
        ),
        "effective_trust": (claims.effective_trust, current_trust.effective_trust),
        "policy_digest": (claims.policy_digest, policy_digest),
        "audience": (claims.audience, audience),
        "current_tenant": (claims.tenant, tenant),
        "current_environment": (claims.environment, environment),
        "task_id": (claims.task_id, compiled.task_id),
        "task_fingerprint": (claims.task_fingerprint, compiled.task_fingerprint),
        "tenant": (claims.tenant, compiled.tenant),
        "environment": (claims.environment, compiled.environment),
        "compiled_ceiling_digest": (
            claims.compiled_ceiling_digest,
            compiled.compiled_digest,
        ),
        "decay_profile_id": (claims.decay_profile_id, compiled.decay_profile),
        "decay_profile_digest": (claims.decay_profile_digest, decay_profile.profile_digest),
        "initial_authority_digest": (
            claims.initial_authority_digest,
            decay_profile.initial_authority.authority_digest,
        ),
        "refresh_requirements_digest": (
            claims.refresh_requirements_digest,
            digest(list(decay_profile.refresh_requirements)),
        ),
        "compiled_subject": (claims.agent_id, compiled.subject_id),
        "compiled_workload": (claims.executor_id, compiled.workload_identity),
        "compiled_attestation": (
            claims.attestation_digest,
            compiled.provider_attestation_digest,
        ),
        "compiled_bundle": (
            claims.attestation_bundle_digest,
            compiled.provider_bundle_digest,
        ),
        "compiled_attestation_method": (
            claims.attestation_method,
            compiled.provider_method,
        ),
        "compiled_attestation_key": (
            claims.attestation_key_id,
            compiled.provider_key_id,
        ),
        "compiled_trust": (claims.effective_trust, compiled.provider_trust),
        "signer_key_id": (claims.signer_key_id, parsed.key_id),
        "operation": (claims.operation, request.operation),
        "resource_id": (claims.resource_id, request.resource_id),
        "arguments_digest": (claims.arguments_digest, reconstructed_arguments_digest),
        "request_digest": (claims.request_digest, reconstructed_request_digest),
    }
    mismatches = [name for name, pair in bindings.items() if pair[0] != pair[1]]
    if mismatches:
        raise CapabilityError(f"capability binding mismatch: {sorted(mismatches)}")
    return claims


def _consume_once(
    store: CapabilityConsumptionStore,
    claims: CapabilityClaims,
    now: float | None,
) -> None:
    try:
        accepted = store.consume(
            claims.capability_id,
            digest(claims.to_dict()),
            claims.expires_at,
            _now_ms(now),
        )
    except Exception as exc:
        raise CapabilityError("capability replay state unavailable") from exc
    if not accepted:
        raise CapabilityError("capability replay detected")


class CapabilityVerifier:
    """Public-key-only verifier with injected one-use consumption state.

    The consumption store is required: a one-use capability primitive must
    never silently fall back to volatile replay state. Tests may inject
    ``InMemoryCapabilityConsumptionStore`` explicitly; production call sites
    must inject durable shared state.
    """

    def __init__(
        self,
        public_key: str | bytes | Ed25519PublicKey,
        key_id: str,
        consumption_store: CapabilityConsumptionStore,
        decay_engine: DecayEngine | None = None,
    ):
        if not hasattr(consumption_store, "consume"):
            raise TypeError(
                "capability replay store is required; inject a durable "
                "CapabilityConsumptionStore (volatile in-memory stores are "
                "development-only)"
            )
        if isinstance(public_key, Ed25519PublicKey):
            loaded = public_key
        else:
            encoded = public_key.encode("ascii") if isinstance(public_key, str) else public_key
            loaded = serialization.load_pem_public_key(encoded)
        if not isinstance(loaded, Ed25519PublicKey):
            raise TypeError("capability verification key must be Ed25519")
        actual_key_id = capability_key_id(loaded)
        if key_id != actual_key_id:
            raise ValueError("capability key_id does not match the supplied public key")
        self._public_key = loaded
        self.key_id = actual_key_id
        self.consumption_store = consumption_store
        self.decay_engine = decay_engine or DecayEngine()

    def verify_and_consume(
        self,
        capability: IssuedCapability,
        request: ActionRequest,
        *,
        executor_measurement: str,
        device_id: str,
        attestation: Mapping[str, Any],
        verifier_policy_digest: str,
        policy_digest: str,
        audience: str = "effect-executor",
        tenant: str = "default",
        environment: str = "synthetic",
        now: float | None = None,
    ) -> CapabilityClaims:
        claims = _verified_claims(
            self._public_key, self.key_id, capability, request,
            executor_measurement=executor_measurement,
            device_id=device_id,
            attestation=attestation,
            verifier_policy_digest=verifier_policy_digest,
            policy_digest=policy_digest,
            audience=audience,
            tenant=tenant,
            environment=environment,
            now=now,
        )
        _consume_once(self.consumption_store, claims, now)
        try:
            self.decay_engine.authorize(
                claims.capability_id,
                decay_profile_for_ceiling(
                    CompiledTaskPolicyCeiling.from_dict(claims.compiled_ceiling),
                    version=claims.decay_profile_version,
                    issued_at_ms=claims.issued_at,
                    expires_at_ms=claims.expires_at,
                ),
                request,
                issued_at_ms=claims.issued_at,
                now_ms=_now_ms(now),
            )
        except (TypeError, ValueError, DecayError) as exc:
            raise CapabilityError(f"current decay authority denied redemption: {exc}") from exc
        return claims


class CapabilityBroker:
    """External capability signer and one-use verifier.

    The private key belongs outside the hostile execution environment. The
    executor needs only the Ed25519 public key. Production call sites must
    inject replay state shared by every replica in the same consumption domain.
    """

    def __init__(
        self,
        signing_key: bytes | Ed25519PrivateKey | None = None,
        key_id: str | None = None,
        ttl_seconds: float = 10.0,
        consumption_store: CapabilityConsumptionStore | None = None,
        decay_engine: DecayEngine | None = None,
    ):
        if not hasattr(consumption_store, "consume"):
            raise TypeError(
                "capability replay store is required; inject a durable "
                "CapabilityConsumptionStore (volatile in-memory stores are "
                "development-only)"
            )
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes):
            if len(signing_key) < 32:
                raise ValueError("signing key seed must be at least 32 bytes")
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        elif signing_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise TypeError("unsupported signing key")
        self._public_key = self._private_key.public_key()
        actual_key_id = capability_key_id(self._public_key)
        if key_id is not None and key_id != actual_key_id:
            raise ValueError("explicit capability key_id does not match the signing key")
        self.key_id = actual_key_id
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool) or not math.isfinite(ttl_seconds):
            raise ValueError("capability TTL must be finite")
        if not 0 < ttl_seconds <= 300:
            raise ValueError("capability TTL must be greater than zero and at most 300 seconds")
        self.ttl_seconds = ttl_seconds
        self.consumption_store = consumption_store
        self.decay_engine = decay_engine or DecayEngine()

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def issue(
        self,
        request: ActionRequest,
        *,
        device_id: str,
        executor_measurement: str,
        trust_state: ProviderTrustState,
        compiled_ceiling: CompiledTaskPolicyCeiling,
        policy_digest: str,
        max_output_bytes: int,
        guardian_state_digest: str,
        audience: str = "effect-executor",
        decay_profile_version: str = "v1",
        now: float | None = None,
    ) -> IssuedCapability:
        issued_at = _now_ms(now)
        ttl_ms = max(1, math.ceil(self.ttl_seconds * 1000))
        if not isinstance(trust_state, ProviderTrustState):
            raise CapabilityError("provider-derived trust is required for capability issuance")
        if not isinstance(compiled_ceiling, CompiledTaskPolicyCeiling):
            raise CapabilityError("compiled task policy ceiling is required for capability issuance")
        try:
            compiled_ceiling.verify_integrity()
        except (TypeError, ValueError) as exc:
            raise CapabilityError(f"compiled task policy ceiling is invalid: {exc}") from exc
        if not compiled_ceiling.permits(request):
            raise CapabilityError("compiled task policy ceiling does not permit the request")
        if compiled_ceiling.policy_version == "" or not policy_digest:
            raise CapabilityError("current policy authority is unavailable")
        if compiled_ceiling.provider_attestation_digest != trust_state.attestation_digest:
            raise CapabilityError("compiled ceiling attestation binding mismatch")
        if compiled_ceiling.provider_bundle_digest != trust_state.bundle_digest:
            raise CapabilityError("compiled ceiling bundle binding mismatch")
        if compiled_ceiling.provider_key_id != trust_state.key_id:
            raise CapabilityError("compiled ceiling provider key binding mismatch")
        if compiled_ceiling.provider_method != trust_state.method:
            raise CapabilityError("compiled ceiling provider method binding mismatch")
        if compiled_ceiling.provider_trust != trust_state.effective_trust:
            raise CapabilityError("compiled ceiling provider trust binding mismatch")
        if issued_at >= trust_state.expires_at_ms:
            raise CapabilityError("provider-derived trust has expired")
        if not re.fullmatch(r"[0-9a-f]{64}", guardian_state_digest):
            raise CapabilityError("guardian state digest is invalid")
        request_payload = request.canonical_payload()
        request_digest = digest(request_payload)
        arguments_digest = digest(request_payload["arguments"])
        expires_at = min(issued_at + ttl_ms, compiled_ceiling.expires_at_ms)
        try:
            decay_profile = decay_profile_for_ceiling(
                compiled_ceiling,
                version=decay_profile_version,
                issued_at_ms=issued_at,
                expires_at_ms=expires_at,
            )
        except (TypeError, ValueError) as exc:
            raise CapabilityError(f"decay profile is invalid: {exc}") from exc
        claims = CapabilityClaims(
            capability_id=f"cap_{secrets.token_hex(12)}",
            issued_at=issued_at,
            expires_at=expires_at,
            session_id=request.session_id,
            agent_id=request.agent_id,
            executor_id=request.executor_id,
            device_id=device_id,
            executor_measurement=executor_measurement,
            attestation_digest=trust_state.attestation_digest,
            attestation_bundle_digest=trust_state.bundle_digest,
            verifier_policy_digest=trust_state.verifier_policy_digest,
            task_id=compiled_ceiling.task_id,
            task_fingerprint=compiled_ceiling.task_fingerprint,
            tenant=compiled_ceiling.tenant,
            environment=compiled_ceiling.environment,
            audience=audience,
            requested_trust=trust_state.requested_trust,
            provider_attested_trust=trust_state.provider_attested_trust,
            effective_trust=trust_state.effective_trust,
            signed_trust_constraint=compiled_ceiling.required_trust_tier,
            attestation_method=trust_state.method,
            attestation_key_id=trust_state.key_id,
            compiled_ceiling=compiled_ceiling.to_dict(),
            compiled_ceiling_digest=compiled_ceiling.compiled_digest,
            guardian_state_digest=guardian_state_digest,
            decay_profile_id=compiled_ceiling.decay_profile,
            decay_profile_version=decay_profile_version,
            decay_profile_digest=decay_profile.profile_digest,
            initial_authority_digest=decay_profile.initial_authority.authority_digest,
            refresh_requirements_digest=digest(list(decay_profile.refresh_requirements)),
            operation=request.operation,
            resource_id=request.resource_id,
            arguments_digest=arguments_digest,
            request_digest=request_digest,
            max_output_bytes=max_output_bytes,
            invocation_limit=1,
            policy_digest=policy_digest,
            signer_key_id=self.key_id,
        )
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(claims.to_dict()))
        ).rstrip(b"=").decode("ascii")
        return IssuedCapability(claims=claims, signature=signature, key_id=self.key_id)

    def verify_and_consume(
        self,
        capability: IssuedCapability,
        request: ActionRequest,
        *,
        executor_measurement: str,
        device_id: str,
        attestation: Mapping[str, Any],
        verifier_policy_digest: str,
        policy_digest: str,
        audience: str = "effect-executor",
        tenant: str = "default",
        environment: str = "synthetic",
        now: float | None = None,
    ) -> CapabilityClaims:
        claims = _verified_claims(
            self._public_key, self.key_id, capability, request,
            executor_measurement=executor_measurement,
            device_id=device_id,
            attestation=attestation,
            verifier_policy_digest=verifier_policy_digest,
            policy_digest=policy_digest,
            audience=audience,
            tenant=tenant,
            environment=environment,
            now=now,
        )
        _consume_once(self.consumption_store, claims, now)
        try:
            self.decay_engine.authorize(
                claims.capability_id,
                decay_profile_for_ceiling(
                    CompiledTaskPolicyCeiling.from_dict(claims.compiled_ceiling),
                    version=claims.decay_profile_version,
                    issued_at_ms=claims.issued_at,
                    expires_at_ms=claims.expires_at,
                ),
                request,
                issued_at_ms=claims.issued_at,
                now_ms=_now_ms(now),
            )
        except (TypeError, ValueError, DecayError) as exc:
            raise CapabilityError(f"current decay authority denied redemption: {exc}") from exc
        return claims
