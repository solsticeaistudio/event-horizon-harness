"""Trusted effect gateway: verify, consume authority, then invoke a trusted effect.

This gateway belongs in an *independent trusted host process*, never in the
compromised executor. Only the gateway has the authority store connection
(Option A SQLite or Option B etcd). The untrusted workload holds neither
database path nor etcd credentials.

This Python class models the enforcement sequence and has fault tests. It
does not expose a hardened HTTP endpoint or establish OS-process isolation.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable, Mapping, Protocol

from .broker import CapabilityVerifier
from .models import ActionRequest, IssuedCapability
from .replay_state import CapabilityConsumptionStore


class EvidenceSink(Protocol):
    def append(self, event_type: str, payload: Mapping[str, Any]) -> Any: ...


@dataclass(frozen=True)
class GatewayDecision:
    accepted: bool
    effect_state: str
    error_class: str | None = None
    output: Any = None
    output_bytes: int = 0


class TrustedEffectGateway:
    """Authorize exactly one remote effect after EHH signature and replay checks.

    The gateway is the *only* holder of externally usable credentials in
    the intended topology. Its callback is a trusted integration, NOT
    attacker-provided Python code. An uncertain effect fails without retry.
    """

    def __init__(
        self,
        verifier: CapabilityVerifier,
        effects: Mapping[str, Callable[[ActionRequest], Any]],
        recorder: EvidenceSink,
        *,
        event_prefix: str = "gateway",
        tenant: str = "default",
        environment: str = "synthetic",
    ):
        if event_prefix not in {"gateway", "execution"}:
            raise ValueError("unrecognized evidence event namespace")
        self.event_prefix = event_prefix
        self.tenant = tenant
        self.environment = environment
        if not effects or any(not isinstance(name, str) or not callable(fn)
                              for name, fn in effects.items()):
            raise ValueError("gateway must have explicit trusted effect handlers")
        self.verifier = verifier
        self.effects = dict(effects)
        self.recorder = recorder

    def _record_denial(self, request: ActionRequest, error_class: str) -> None:
        # A recorder outage must never weaken the authority decision.
        try:
            self.recorder.append(f"{self.event_prefix}.denied", {
                "request_id": request.request_id,
                "error_class": error_class,
                "effect_state": "not-started",
            })
        except Exception:
            pass

    def execute(
        self,
        request: ActionRequest,
        capability: IssuedCapability,
        attestation: Mapping[str, Any],
        *,
        executor_measurement: str,
        device_id: str,
        verifier_policy_digest: str,
        policy_digest: str,
        now: float | None = None,
    ) -> GatewayDecision:
        # Only host-defined actions are dispatched. Neither tools nor effect
        # callbacks may be supplied by the untrusted workload.
        handler = self.effects.get(request.operation)
        if handler is None:
            self._record_denial(request, "unsupported-operation")
            return GatewayDecision(False, "not-started", "unsupported-operation")
        try:
            claims = self.verifier.verify_and_consume(
                capability, request,
                executor_measurement=executor_measurement,
                device_id=device_id,
                attestation=attestation,
                verifier_policy_digest=verifier_policy_digest,
                policy_digest=policy_digest,
                tenant=self.tenant,
                environment=self.environment,
                now=now,
            )
        except Exception:
            # Unknown/ambiguous consumption outcomes are not retried.
            self._record_denial(request, "authority-denied")
            return GatewayDecision(False, "not-started", "authority-denied")
        try:
            self.recorder.append(f"{self.event_prefix}.authorized", {
                "request_id": request.request_id,
                "request_digest": request.request_digest,
                "capability_id": capability.claims.capability_id,
            })
        except Exception:
            return GatewayDecision(False, "not-started", "evidence-unavailable")
        try:
            output = handler(request)
            encoded = json.dumps(
                output, sort_keys=True, default=str,
            ).encode("utf-8")
            if len(encoded) > claims.max_output_bytes:
                raise PermissionError("result exceeds signed capability output ceiling")
        except Exception:
            # An effect callback may have committed before raising.
            try:
                self.recorder.append(f"{self.event_prefix}.indeterminate", {
                    "request_id": request.request_id,
                    "effect_state": "possibly-committed",
                })
            except Exception:
                pass
            return GatewayDecision(False, "possibly-committed", "effect-indeterminate")
        try:
            self.recorder.append(f"{self.event_prefix}.completed", {
                "request_id": request.request_id,
                "capability_id": claims.capability_id,
                "success": True,
                "output_bytes": len(encoded),
                "effect_state": "completed",
            })
        except Exception:
            return GatewayDecision(False, "possibly-committed", "evidence-indeterminate")
        return GatewayDecision(True, "completed", output=output, output_bytes=len(encoded))

def select_consumption_store(
    *,
    backend: str,
    namespace: str,
    domain: str,
    sqlite_path: str | None = None,
    etcd_config=None,
    expected_cluster_id: str | None = None,
) -> CapabilityConsumptionStore:
    """Explicitly select an authority backend in a trusted process.

    No automatic fallback. Never serialize the resulting transport or etcd
    credentials into the executor's configuration.
    """
    from .authority_backends import local_authority, etcd_authority
    if backend == "sqlite":
        if sqlite_path is None or etcd_config is not None:
            raise ValueError("SQLite authority requires path and no etcd config")
        return local_authority(sqlite_path, namespace=namespace, domain=domain)
    if backend == "etcd":
        if sqlite_path is not None or etcd_config is None or not expected_cluster_id:
            raise ValueError("etcd authority requires pinned cluster and no SQLite path")
        return etcd_authority(
            etcd_config, expected_cluster_id=expected_cluster_id,
            namespace=namespace, domain=domain,
        )
    raise ValueError("unknown trusted authority backend; refusing fallback")
