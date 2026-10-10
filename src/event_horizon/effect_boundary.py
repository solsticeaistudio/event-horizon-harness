"""Host-owned dataset boundary for Firecracker and the package worker lab.

The VM controls the request payload, not the authority store, verifier keys,
effect handler, attestation context, or database credentials. Authorization
and effect dispatch happen in the trusted host service.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .authority_backends import EtcdGatewayConfig
from .broker import CapabilityVerifier
from .models import ActionRequest, ExecutionResult, IssuedCapability
from .trusted_effect_gateway import TrustedEffectGateway, select_consumption_store
from .trust_decay import DecayEngine, SqliteDecayStateStore


class DatasetEffectBoundary:
    """Session-bound, transport-UID constrained read endpoint.

    The selected authority backend lives only in this host-side service.
    The guest protocol is limited to `{"request", "capability"}` and
    cannot select backend, caller identity, policy, or effect callback.
    """

    def __init__(self, config: dict[str, Any], recorder: Any):
        self.config = config
        self.recorder = recorder
        self.active = True
        context = config["verification_context"]
        self.backend = config.get("authority_backend", "sqlite")
        opts: dict[str, Any] = {
            "backend": self.backend,
            "namespace": config["session_id"],
            "domain": "external-effect",
        }
        if self.backend == "sqlite":
            if "etcd_gateway" in config or "etcd_cluster_id" in config:
                raise ValueError("SQLite mode cannot inherit etcd configuration")
            opts["sqlite_path"] = config["replay_database"]
        elif self.backend == "etcd":
            etcd_fields = config.get("etcd_gateway")
            if not isinstance(etcd_fields, dict):
                raise ValueError("etcd authority requires host-only transport configuration")
            opts["etcd_config"] = EtcdGatewayConfig(**etcd_fields)
            opts["expected_cluster_id"] = config["etcd_cluster_id"]
        else:
            raise ValueError("unknown authority backend; no local fallback")
        self.consumption_store = select_consumption_store(**opts)
        self.decay_store = SqliteDecayStateStore(config["decay_database"])
        self.gateway = TrustedEffectGateway(
            CapabilityVerifier(
                config["public_key_pem"], config["key_id"],
                self.consumption_store, DecayEngine(self.decay_store),
            ),
            {"object.read": self._read_dataset},
            recorder,
            event_prefix="execution",
            tenant=context["tenant"],
            environment=context["environment"],
        )

    def _read_dataset(self, request: ActionRequest) -> str:
        offset, length = request.arguments["offset"], request.arguments["length"]
        return self.config["dataset"][offset:offset + length]

    def close(self) -> None:
        self.active = False
        self.decay_store.close()
        close = getattr(self.consumption_store, "close", None)
        if close is not None:
            close()

    def execute(self, message: dict[str, Any], *, peer_uid: int) -> dict[str, Any]:
        try:
            if not self.active or peer_uid != self.config["vm_uid"]:
                raise PermissionError("inactive session or wrong transport principal")
            if not isinstance(message, dict) or set(message) != {"request", "capability"}:
                raise ValueError("invalid effect envelope")
            request = ActionRequest.from_dict(message["request"])
            if request.session_id != self.config["session_id"]:
                raise PermissionError("cross-session request")
            if (request.operation != "object.read"
                    or request.resource_id != self.config.get("resource_id", "synthetic-dataset")):
                raise PermissionError("unsupported effect")
            if set(request.arguments) != {"offset", "length"}:
                raise ValueError("invalid dataset range")
            offset, length = request.arguments["offset"], request.arguments["length"]
            if (type(offset) is not int or type(length) is not int
                    or not (0 <= offset < len(self.config["dataset"])
                            and 0 < length <= 512
                            and offset + length <= len(self.config["dataset"]))):
                raise ValueError("dataset range exceeds service ceiling")
            capability = IssuedCapability.from_dict(message["capability"])
        except (ValueError, TypeError, KeyError, PermissionError):
            result = ExecutionResult(
                False, "object.read", self.config.get("resource_id", "synthetic-dataset"),
                error="request denied", effect_state="not-started",
            )
            self.recorder.append("execution.denied", {
                "effect_state": "not-started", "source": "effect-boundary",
            })
            return asdict(result)
        context = self.config["verification_context"]
        decision = self.gateway.execute(
            request, capability, context["attestation"],
            executor_measurement=context["executor_measurement"],
            device_id=context["device_id"],
            verifier_policy_digest=context["verifier_policy_digest"],
            policy_digest=context["policy_digest"],
        )
        return asdict(ExecutionResult(
            decision.accepted, request.operation, request.resource_id,
            output=decision.output, output_bytes=decision.output_bytes,
            error=decision.error_class, effect_state=decision.effect_state,
        ))
