from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .broker import CapabilityBroker, CapabilityVerifier
from .canary import CanaryCapability, CanaryError, CanaryVerifier
from .canonical import digest
from .chaos import DeterministicFaultInjector
from .effect_gateway import (
    EffectGateway,
    EffectGatewayError,
    EffectRequest,
    GATEWAY_COMMITTED,
    GATEWAY_CONFIRMED_NOT_COMMITTED,
    GATEWAY_INDETERMINATE,
    ProviderAdapter,
    ProviderResult,
    make_effect_request,
)
from .execution_state import (
    CapabilityExecutionTracker,
    ExecutionState,
    ExecutionStateError,
    InMemoryExecutionStateStore,
)
from .models import ActionRequest, ExecutionResult, IssuedCapability
from .recorder import ExternalRecorder
from .statements import StatementSigner, TYPE_EXECUTION_RECEIPT


# Operations whose handlers are architecturally declared pure. Any operation
# not listed here MUST be treated as potentially effectful: once its handler is
# invoked, absence of an external effect cannot be inferred from a local
# failure signal.
PURE_OPERATIONS = frozenset({"object.read"})

_CANARY_OUTPUT_LIMIT_BYTES = 4_096


class LocalHandlerProvider:
    """Provider adapter wrapping a local handler as a governed provider.

    The adapter records outcomes keyed by the immutable idempotency identity,
    so gateway retries and reconciliations observe exactly-one execution even
    though the "provider" is in-process. Production adapters wrap remote
    systems; :class:`SimulatedEffectProvider` models their failure modes.
    """

    def __init__(self, invoke: Callable[[], Any], *, provider_id: str = "local-handler") -> None:
        self.invoke = invoke
        self.provider_id = provider_id
        self.records: dict[str, dict[str, Any]] = {}
        self.last_output: Any = None

    def execute(
        self, effect_request: Mapping[str, Any], idempotency_key: str
    ) -> ProviderResult:
        record = self.records.get(idempotency_key)
        if record is not None and record["executed"] and record.get("receipt_digest"):
            # Idempotent replay of the same logical effect.
            self.last_output = record.get("output")
            return ProviderResult(
                state="committed",
                receipt_digest=record["receipt_digest"],
                detail={"duplicate": True},
            )
        try:
            output = self.invoke()
        except Exception as exc:
            self.records[idempotency_key] = {
                "executed": True,
                "output": None,
                "error": f"{type(exc).__name__}: {exc}",
            }
            raise
        receipt_digest = digest({
            "provider": self.provider_id,
            "idempotency_key": idempotency_key,
            "output": output,
        })
        self.records[idempotency_key] = {
            "executed": True,
            "output": output,
            "receipt_digest": receipt_digest,
        }
        self.last_output = output
        return ProviderResult(state="committed", receipt_digest=receipt_digest)

    def reconcile(self, idempotency_key: str) -> ProviderResult:
        record = self.records.get(idempotency_key)
        if record is None:
            return ProviderResult(
                state="confirmed-not-executed",
                detail={"reason": "no such execution"},
            )
        if record.get("error") and not record.get("receipt_digest"):
            return ProviderResult(state="unknown", detail={"reason": record["error"]})
        return ProviderResult(
            state="committed",
            receipt_digest=record.get("receipt_digest"),
            detail={"reconciled": True},
        )


def _governed_execution_id(capability_id: str, request_digest: str) -> str:
    material = hashlib.sha256(f"{capability_id}:{request_digest}".encode("utf-8")).hexdigest()
    return f"exec_{material[:32]}"


def _governed_effect_id(capability_id: str, request_digest: str) -> str:
    """Deterministic logical-effect identity for one capability execution.

    Retryable: the same capability execution always maps to the same effect.
    Distinct capabilities (or distinct requests) map to distinct effects, so
    intentionally repeating identical semantics under a fresh one-use
    capability is a genuinely new logical effect.
    """
    material = hashlib.sha256(f"{capability_id}:{request_digest}".encode("utf-8")).hexdigest()
    return f"eff_{material[32:64]}"


@dataclass
class SacrificialExecutor:
    executor_id: str
    device_id: str
    measurement: str
    verifier_policy_digest: str
    policy_digest: str
    broker: CapabilityBroker | CapabilityVerifier
    recorder: ExternalRecorder
    tenant: str = "default"
    environment: str = "synthetic"
    canary_verifier: CanaryVerifier | None = None
    fault_injector: DeterministicFaultInjector | None = None
    objects: dict[str, Any] = field(default_factory=dict)
    compute_profiles: dict[str, Callable[[dict[str, Any]], Any]] = field(default_factory=dict)
    statement_signer: StatementSigner | None = None
    execution_tracker: CapabilityExecutionTracker | None = None
    effect_gateway: EffectGateway | None = None
    effect_provider: ProviderAdapter | None = None
    deployment_id: str = "local-dev"
    run_namespace: str | None = None
    provider_scope: str = "default"

    def __post_init__(self) -> None:
        # Process-scoped duplicate-execution detection fallback. Production
        # deployments must inject a tracker backed by SqliteExecutionStateStore
        # so lifecycle state survives restarts. This fallback is scoped to this
        # single executor object and is never shared across processes.
        if self.execution_tracker is None:
            self.execution_tracker = CapabilityExecutionTracker(
                InMemoryExecutionStateStore(),
                namespace=f"executor:{self.executor_id}"[:127].lower(),
            )
        if (
            self.effect_gateway is not None
            and (not isinstance(self.run_namespace, str) or not self.run_namespace)
        ):
            # Governed effects bind to a run namespace; without one the
            # gateway request would be unattributable. Fail closed.
            raise ExecutionStateError(
                "governed effects require an explicit executor run_namespace"
            )

    def execute(
        self,
        request: ActionRequest,
        capability: IssuedCapability | CanaryCapability,
        attestation: Mapping[str, Any],
    ) -> ExecutionResult:
        tracker = self.execution_tracker
        assert tracker is not None
        claims = getattr(capability, "claims", None)
        capability_id = getattr(claims, "capability_id", None) or getattr(
            claims, "canary_id", None
        )
        if not isinstance(capability_id, str) or not capability_id:
            return ExecutionResult(
                False,
                request.operation,
                request.resource_id,
                error="malformed capability identifier",
                effect_state="not_attempted",
            )
        try:
            tracker.begin(capability_id, details={
                "request_digest": request.request_digest,
                "session_id": request.session_id,
            })
        except ExecutionStateError as exc:
            return self._deny_before_dispatch(
                request,
                capability_id,
                f"duplicate execution attempt rejected: {exc}",
            )

        try:
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.before-validation")
            max_output_bytes = self._authorize(request, capability, attestation, tracker, capability_id)
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.after-validation")
            tracker.transition(capability_id, ExecutionState.INTENT_RECORDED, details={
                "request_digest": request.request_digest,
                "operation": request.operation,
            })
            governed = (
                self.effect_gateway is not None
                and request.operation not in PURE_OPERATIONS
            )
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.before-effect")
            if governed:
                return self._governed_dispatch(
                    request, capability, capability_id, tracker, max_output_bytes
                )
            tracker.transition(capability_id, ExecutionState.DISPATCHED, details={
                "request_digest": request.request_digest,
            })
        except Exception as exc:
            # Failure strictly before the dispatch boundary: no provider was
            # invoked, so "not committed" is positively provable here.
            return self._deny_before_dispatch(request, capability_id, str(exc), exc=exc)

        # ---- effect boundary -------------------------------------------------
        # Past DISPATCHED the outcome of a potentially effectful handler cannot
        # be refuted locally. Only positive evidence upgrades certainty.
        try:
            output = self._invoke_handler(request)
            return self._finish_success(
                request, capability, capability_id, tracker,
                output, max_output_bytes,
            )
        except Exception as exc:
            confirmed = tracker.load(capability_id) is ExecutionState.EFFECT_CONFIRMED
            return self._resolve_post_boundary_failure(
                request,
                capability_id,
                exc,
                confirmed=confirmed,
            )

    def _finish_success(
        self,
        request: ActionRequest,
        capability: IssuedCapability | CanaryCapability,
        capability_id: str,
        tracker: CapabilityExecutionTracker,
        output: Any,
        max_output_bytes: int,
        *,
        extra_evidence: Mapping[str, Any] | None = None,
    ) -> ExecutionResult:
        """Shared post-provider success pipeline: validate -> confirm ->
        evidence -> reconcile -> close."""
        # No ``default=str`` fallback: an unserializable result must be
        # treated as a post-effect failure, never silently stringified.
        encoded = json.dumps(output, sort_keys=True).encode("utf-8")
        if len(encoded) > max_output_bytes:
            raise PermissionError("result exceeds capability output envelope")
        tracker.transition(capability_id, ExecutionState.EFFECT_CONFIRMED, details={
            "output_bytes": len(encoded),
        })
        if self.fault_injector is not None:
            self.fault_injector.hit("executor.after-effect")
            self.fault_injector.hit("executor.before-evidence-record")
        receipt = self._sign_receipt(capability, request, "committed", encoded)
        evidence_payload = {
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "session_id": request.session_id,
            "capability_id": capability_id,
            "success": True,
            "output_bytes": len(encoded),
            "receipt": receipt,
        }
        if extra_evidence:
            evidence_payload.update(extra_evidence)
        event_hash = self._append_evidence("execution.completed", evidence_payload)
        if event_hash is None:
            # The effect committed but durable evidence did not persist.
            # Leave the lifecycle unresolved; certification is blocked until
            # reconciliation records positive evidence.
            tracker.transition(capability_id, ExecutionState.INDETERMINATE, details={
                "reason": "execution evidence persistence failed after a committed effect",
            })
            return ExecutionResult(
                True,
                request.operation,
                request.resource_id,
                output,
                len(encoded),
                error="effect committed but execution evidence could not be recorded",
                effect_state="committed",
                receipt=receipt,
            )
        tracker.reconcile(
            capability_id,
            resolution="committed",
            evidence_digest=digest({"event_hash": event_hash}),
        )
        tracker.close(capability_id, evidence_digest=digest({"event_hash": event_hash}))
        if self.fault_injector is not None:
            self.fault_injector.hit("executor.after-evidence-record")
            self.fault_injector.hit("executor.before-response")
        return ExecutionResult(
            True,
            request.operation,
            request.resource_id,
            output,
            len(encoded),
            effect_state="committed",
            receipt=receipt,
        )

    def _authorize(
        self,
        request: ActionRequest,
        capability: IssuedCapability | CanaryCapability,
        attestation: Mapping[str, Any],
        tracker: CapabilityExecutionTracker,
        capability_id: str,
    ) -> int:
        if isinstance(capability, CanaryCapability):
            if self.canary_verifier is None:
                raise CanaryError("canary verification boundary is unavailable")
            self.canary_verifier.redeem(capability, request)
            return _CANARY_OUTPUT_LIMIT_BYTES
        assert isinstance(capability, IssuedCapability)
        claims = self.broker.verify_and_consume(
            capability,
            request,
            executor_measurement=self.measurement,
            device_id=self.device_id,
            attestation=attestation,
            verifier_policy_digest=self.verifier_policy_digest,
            policy_digest=self.policy_digest,
            tenant=self.tenant,
            environment=self.environment,
        )
        tracker.transition(capability_id, ExecutionState.AUTHORIZED, details={
            "request_digest": request.request_digest,
        })
        tracker.transition(capability_id, ExecutionState.CONSUMED, details={
            "consumption": "verify-and-consume",
        })
        return claims.max_output_bytes

    def _invoke_handler(self, request: ActionRequest) -> Any:
        if request.operation == "object.read":
            if request.resource_id not in self.objects:
                raise KeyError("object not found")
            return self.objects[request.resource_id]
        if request.operation == "compute.run":
            fn = self.compute_profiles.get(request.resource_id)
            if fn is None:
                raise KeyError("compute profile not found")
            return fn(dict(request.arguments))
        raise PermissionError("executor has no implementation for operation")

    def _governed_dispatch(
        self,
        request: ActionRequest,
        capability: IssuedCapability | CanaryCapability,
        capability_id: str,
        tracker: CapabilityExecutionTracker,
        max_output_bytes: int,
    ) -> ExecutionResult:
        """Route a potentially effectful operation through the Effect Gateway.

        Sequence: durable gateway intent -> lifecycle DISPATCHED -> mediated
        provider invocation -> outcome mapping. The gateway's signed intent
        and receipt statements exist independently of this executor's own
        output, so certificates can corroborate or contradict executor claims.
        """
        assert self.effect_gateway is not None
        effect_request = make_effect_request(
            deployment_id=self.deployment_id,
            environment=self.environment,
            run_id=self.run_namespace or f"session:{request.session_id}",
            session_id=request.session_id,
            capability_id=capability_id,
            request_digest=request.request_digest,
            operation=request.operation,
            arguments_digest=digest(dict(request.arguments)),
            policy_digest=self.policy_digest,
            executor_identity=self.executor_id,
            execution_id=_governed_execution_id(capability_id, request.request_digest),
            effect_id=_governed_effect_id(capability_id, request.request_digest),
            provider_scope=self.provider_scope,
        )
        provider = self.effect_provider or LocalHandlerProvider(
            lambda: self._invoke_handler(request)
        )
        # Durable intent exists before the lifecycle crosses DISPATCHED.
        self.effect_gateway.begin_effect(effect_request)
        tracker.transition(capability_id, ExecutionState.DISPATCHED, details={
            "request_digest": request.request_digest,
            "governed": True,
        })
        record = self.effect_gateway.dispatch(effect_request, provider)
        state = record["state"]

        if state == GATEWAY_COMMITTED:
            # Positive provider outcome: reconcile immediately so the durable
            # record becomes terminal and carries a signed reconciliation
            # statement. A store failure here leaves the effect unresolved by
            # design; certification stays blocked until it is resolved.
            try:
                record = self.effect_gateway.reconcile(effect_request, provider)
            except EffectGatewayError:
                pass
            try:
                output = provider.last_output
                encoded = json.dumps(output, sort_keys=True).encode("utf-8")
                if len(encoded) > max_output_bytes:
                    raise PermissionError("result exceeds capability output envelope")
            except Exception as exc:
                return self._resolve_post_boundary_failure(
                    request, capability_id, exc, confirmed=False
                )
            return self._finish_success(
                request, capability, capability_id, tracker,
                output, max_output_bytes,
                extra_evidence={
                    "effect_gateway": {
                        "execution_id": effect_request.execution_id,
                        "idempotency_key": effect_request.idempotency_key,
                        "gateway_state": state,
                        "resolution": record.get("resolution"),
                    },
                    "provider_receipt_digest": record.get("provider_receipt_digest"),
                },
            )
        if state == GATEWAY_CONFIRMED_NOT_COMMITTED:
            # The provider positively proved non-execution for this identity.
            tracker.reconcile(
                capability_id,
                resolution="confirmed_not_committed",
                evidence_digest=digest({
                    "gateway_state": state,
                    "idempotency_key": effect_request.idempotency_key,
                }),
                positive_provider_proof=True,
            )
            tracker.close(
                capability_id,
                evidence_digest=digest({"resolution": "confirmed_not_committed"}),
            )
            self._append_evidence("execution.denied", {
                "request_id": request.request_id,
                "request_digest": request.request_digest,
                "session_id": request.session_id,
                "capability_id": capability_id,
                "effect_state": "not_committed",
                "effect_gateway_state": state,
            })
            return ExecutionResult(
                False,
                request.operation,
                request.resource_id,
                error="mediated effect was positively not executed by the provider",
                effect_state="not_committed",
            )
        # GATEWAY_INDETERMINATE (or any unresolved outcome): uncertainty must
        # survive; reconciliation happens out of band against the gateway.
        exc = EffectGatewayError(
            f"mediated dispatch ended {state}; reconciliation required"
        )
        result = self._resolve_post_boundary_failure(
            request, capability_id, exc, confirmed=False
        )
        return ExecutionResult(
            result.success,
            result.operation,
            result.resource_id,
            error=result.error,
            effect_state=result.effect_state,
        )

    def _resolve_post_boundary_failure(
        self,
        request: ActionRequest,
        capability_id: str,
        exc: Exception,
        *,
        confirmed: bool,
    ) -> ExecutionResult:
        tracker = self.execution_tracker
        assert tracker is not None
        current = tracker.load(capability_id)
        if current in {ExecutionState.CLOSED, ExecutionState.DENIED}:
            return ExecutionResult(
                False,
                request.operation,
                request.resource_id,
                error=f"indeterminate effect state: {exc}",
                effect_state="possibly_committed",
            )
        if current is ExecutionState.DISPATCHED:
            tracker.transition(capability_id, ExecutionState.EFFECT_UNKNOWN, details={
                "error_type": type(exc).__name__,
            })
            current = ExecutionState.EFFECT_UNKNOWN
        if request.operation in PURE_OPERATIONS:
            # Declared-pure handlers touch no external system: a local failure
            # is positive proof that no effect occurred.
            tracker.reconcile(
                capability_id,
                resolution="confirmed_not_committed",
                evidence_digest=digest({
                    "error_type": type(exc).__name__,
                    "purity": request.operation,
                }),
                declared_pure=True,
            )
            tracker.close(
                capability_id,
                evidence_digest=digest({"resolution": "confirmed_not_committed"}),
            )
            self._append_evidence("execution.denied", {
                "request_id": request.request_id,
                "request_digest": request.request_digest,
                "session_id": request.session_id,
                "capability_id": capability_id,
                "error_type": type(exc).__name__,
                "error": str(exc)[:512],
                "effect_state": "not_committed",
            })
            return ExecutionResult(
                False,
                request.operation,
                request.resource_id,
                error=str(exc),
                effect_state="not_committed",
            )
        # Potentially effectful handler already invoked (or output validation
        # failed after it returned): the failure signal itself carries no proof
        # about the provider. Uncertainty is preserved until reconciliation.
        if confirmed and current is not ExecutionState.EFFECT_CONFIRMED:
            raise ExecutionStateError("lifecycle diverged after effect confirmation")
        tracker.transition(capability_id, ExecutionState.INDETERMINATE, details={
            "error_type": type(exc).__name__,
        })
        self._append_evidence("execution.indeterminate", {
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "session_id": request.session_id,
            "capability_id": capability_id,
            "error_type": type(exc).__name__,
            "error": str(exc)[:512],
            "effect_state": "possibly_committed",
        })
        tracker.reconcile(
            capability_id,
            resolution="indeterminate",
            evidence_digest=digest({"error_type": type(exc).__name__}),
        )
        tracker.close(capability_id, evidence_digest=digest({"resolution": "indeterminate"}))
        return ExecutionResult(
            False,
            request.operation,
            request.resource_id,
            error=f"indeterminate effect state: {exc}",
            effect_state="possibly_committed",
        )

    def _deny_before_dispatch(
        self,
        request: ActionRequest,
        capability_id: str,
        message: str,
        *,
        exc: Exception | None = None,
    ) -> ExecutionResult:
        tracker = self.execution_tracker
        assert tracker is not None
        current = tracker.load(capability_id)
        try:
            if current is ExecutionState.ISSUED:
                tracker.transition(capability_id, ExecutionState.DENIED, details={
                    "error_type": type(exc).__name__ if exc else "Denied",
                })
            elif current is not None and current not in {ExecutionState.CLOSED, ExecutionState.DENIED}:
                # Consumption already occurred before the failure: the replay
                # store owns that decision, but this attempt produced no effect.
                tracker.reconcile(
                    capability_id,
                    resolution="confirmed_not_committed",
                    evidence_digest=digest({"denied_before_dispatch": True}),
                )
                tracker.close(
                    capability_id,
                    evidence_digest=digest({"resolution": "confirmed_not_committed"}),
                )
        except ExecutionStateError:
            pass
        self._append_evidence("execution.denied", {
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "session_id": request.session_id,
            "capability_id": capability_id,
            "error_type": type(exc).__name__ if exc else "Denied",
            "error": message[:512],
            "effect_state": "not_committed",
        })
        return ExecutionResult(
            False,
            request.operation,
            request.resource_id,
            error=message,
            effect_state="not_committed",
        )

    def _sign_receipt(
        self,
        capability: IssuedCapability | CanaryCapability,
        request: ActionRequest,
        effect_state: str,
        encoded_output: bytes,
    ) -> dict[str, Any] | None:
        if self.statement_signer is None:
            return None
        payload = {
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "session_id": request.session_id,
            "capability_id": getattr(getattr(capability, "claims", None), "capability_id", ""),
            "capability_envelope_digest": digest(capability.to_dict()),
            "operation": request.operation,
            "resource_id": request.resource_id,
            "effect_state": effect_state,
            "output_digest": digest(encoded_output.decode("utf-8")),
            "output_bytes": len(encoded_output),
        }
        return self.statement_signer.sign(TYPE_EXECUTION_RECEIPT, payload).to_dict()

    def _append_evidence(self, event_type: str, payload: dict[str, Any]) -> str | None:
        try:
            record = self.recorder.append(event_type, payload)
        except Exception:
            # Evidence persistence failing after an effect must never upgrade
            # certainty; callers observe the ambiguous effect state regardless.
            return None
        if not isinstance(record, Mapping):
            return None
        event_hash = record.get("event_hash")
        return event_hash if isinstance(event_hash, str) else None
