"""Narrow host-side dataset reader; never runs inside the hostile guest."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .broker import CapabilityVerifier
from .executor import SacrificialExecutor
from .models import ActionRequest, ExecutionResult, IssuedCapability
from .replay_state import SqliteCapabilityConsumptionStore
from .trust_decay import DecayEngine, SqliteDecayStateStore


class DatasetEffectBoundary:
    """A session-bound endpoint with no mint, reset, refresh, or arbitrary I/O API.

    The transport supplies an authenticated VM principal; public attestation and
    policy context are provisioned by the host, never accepted from the guest.
    """

    def __init__(self, config: dict[str, Any], recorder: Any):
        self.config = config
        self.recorder = recorder
        self.active = True
        context = config["verification_context"]
        self.consumption_store = SqliteCapabilityConsumptionStore(
            config["replay_database"], namespace=config["session_id"], domain="external-effect",
        )
        self.decay_store = SqliteDecayStateStore(config["decay_database"])
        self.executor = SacrificialExecutor(
            executor_id=context["device_id"], device_id=context["device_id"],
            measurement=context["executor_measurement"],
            verifier_policy_digest=context["verifier_policy_digest"],
            policy_digest=context["policy_digest"],
            broker=CapabilityVerifier(
                config["public_key_pem"], config["key_id"],
                self.consumption_store, DecayEngine(self.decay_store),
            ),
            recorder=recorder, tenant=context["tenant"], environment=context["environment"],
        )

    def close(self) -> None:
        self.active = False
        self.decay_store.close()
        self.consumption_store.close()

    def execute(self, message: dict[str, Any], *, peer_uid: int) -> dict[str, Any]:
        try:
            if not self.active or peer_uid != self.config["vm_uid"]:
                raise PermissionError("inactive session or wrong transport principal")
            if set(message) != {"request", "capability"}:
                raise ValueError("invalid effect envelope")
            request = ActionRequest.from_dict(message["request"])
            if request.session_id != self.config["session_id"]:
                raise PermissionError("cross-session request")
            if request.operation != "object.read" or request.resource_id != self.config.get("resource_id", "synthetic-dataset"):
                raise PermissionError("unsupported effect")
            if set(request.arguments) != {"offset", "length"}:
                raise ValueError("invalid dataset range")
            offset, length = request.arguments["offset"], request.arguments["length"]
            if type(offset) is not int or type(length) is not int or not (
                0 <= offset < len(self.config["dataset"]) and 0 < length <= 512
                and offset + length <= len(self.config["dataset"])
            ):
                raise ValueError("dataset range exceeds service ceiling")
            capability = IssuedCapability.from_dict(message["capability"])
        except (ValueError, TypeError, KeyError, PermissionError):
            result = ExecutionResult(False, "object.read", "synthetic-dataset",
                                     error="request denied", effect_state="not-started")
            self.recorder.append("execution.denied", {"effect_state": "not-started", "source": "effect-boundary"})
            return asdict(result)
        # Single-threaded service: no callback registration, dynamic paths, URLs,
        # guest-selected attestation, or mutable policy/context interfaces.
        self.executor.objects = {request.resource_id: self.config["dataset"][offset:offset + length]}
        return asdict(self.executor.execute(
            request, capability, self.config["verification_context"]["attestation"],
        ))
