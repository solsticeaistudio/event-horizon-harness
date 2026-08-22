from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .broker import CapabilityBroker, CapabilityVerifier
from .canary import CanaryCapability, CanaryError, CanaryVerifier
from .canonical import digest
from .chaos import DeterministicFaultInjector
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
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.before-effect")
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
        confirmed = False
        output = None
        encoded = b""
        receipt: dict[str, Any] | None = None
        try:
            output = self._invoke_handler(request)
            # No ``default=str`` fallback: an unserializable result must be
            # treated as a post-effect failure, never silently stringified.
            encoded = json.dumps(output, sort_keys=True).encode("utf-8")
            if len(encoded) > max_output_bytes:
                raise PermissionError("result exceeds capability output envelope")
            tracker.transition(capability_id, ExecutionState.EFFECT_CONFIRMED, details={
                "output_bytes": len(encoded),
            })
            confirmed = True
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.after-effect")
                self.fault_injector.hit("executor.before-evidence-record")
            receipt = self._sign_receipt(capability, request, "committed", encoded)
            event_hash = self._append_evidence("execution.completed", {
                "request_id": request.request_id,
                "request_digest": request.request_digest,
                "session_id": request.session_id,
                "capability_id": capability_id,
                "success": True,
                "output_bytes": len(encoded),
                "receipt": receipt,
            })
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
        except Exception as exc:
            return self._resolve_post_boundary_failure(
                request,
                capability_id,
                exc,
                confirmed=confirmed,
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
