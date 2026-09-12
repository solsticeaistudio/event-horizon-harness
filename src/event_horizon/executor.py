from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .broker import CapabilityBroker, CapabilityVerifier
from .canary import CanaryCapability, CanaryError, CanaryVerifier
from .chaos import DeterministicFaultInjector
from .models import ActionRequest, ExecutionResult, IssuedCapability
from .recorder import ExternalRecorder


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

    def execute(
        self,
        request: ActionRequest,
        capability: IssuedCapability | CanaryCapability,
        attestation: Mapping[str, Any],
    ) -> ExecutionResult:
        effect_state = "not-started"
        evidence_recorded = False
        try:
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.before-validation")
            if isinstance(capability, CanaryCapability):
                if self.canary_verifier is None:
                    raise CanaryError("canary verification boundary is unavailable")
                self.canary_verifier.redeem(capability, request)
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
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.after-validation")
                self.fault_injector.hit("executor.before-effect")
            if request.operation == "object.read":
                if request.resource_id not in self.objects:
                    raise KeyError("object not found")
                effect_state = "possibly-committed"
                output = self.objects[request.resource_id]
            elif request.operation == "compute.run":
                fn = self.compute_profiles.get(request.resource_id)
                if fn is None:
                    raise KeyError("compute profile not found")
                arguments = dict(request.arguments)
                # A callback may commit an effect before returning or raising.
                effect_state = "possibly-committed"
                output = fn(arguments)
            else:
                raise PermissionError("executor has no implementation for operation")
            encoded = json.dumps(output, sort_keys=True, default=str).encode("utf-8")
            if len(encoded) > claims.max_output_bytes:
                raise PermissionError("result exceeds capability output envelope")
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.after-effect")
                self.fault_injector.hit("executor.before-evidence-record")
            self.recorder.append("execution.completed", {
                "request_id": request.request_id,
                "capability_id": claims.capability_id,
                "success": True,
                "output_bytes": len(encoded),
                "effect_state": "completed",
            })
            evidence_recorded = True
            effect_state = "completed"
            if self.fault_injector is not None:
                self.fault_injector.hit("executor.after-evidence-record")
                self.fault_injector.hit("executor.before-response")
            return ExecutionResult(
                True, request.operation, request.resource_id, output, len(encoded),
                effect_state=effect_state,
            )
        except Exception as exc:
            event_type = "execution.denied" if effect_state == "not-started" else "execution.indeterminate"
            if not evidence_recorded:
                try:
                    self.recorder.append(event_type, {
                        "request_id": request.request_id,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "effect_state": effect_state,
                    })
                except Exception:
                    pass
            error = (
                f"indeterminate effect state: {exc}" if effect_state != "not-started" else str(exc)
            )
            return ExecutionResult(
                False, request.operation, request.resource_id, error=error,
                effect_state=effect_state,
            )
