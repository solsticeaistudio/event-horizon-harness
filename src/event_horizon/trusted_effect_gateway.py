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
    ):
        if not effects or any(not isinstance(name, str) or not callable(fn)
                              for name, fn in effects.items()):
            raise ValueError("gateway must have explicit trusted effect handlers")
        self.verifier = verifier
        self.effects = dict(effects)
        self.recorder = recorder

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
        # No arbitrary network target, command or caller-supplied callback.
        # Refuse to consume authority for unsupported effects.
        handler = self.effects.get(request.operation)
        if handler is None:
            return GatewayDecision(False, "not-started", "unsupported-operation")
        try:
            self.verifier.verify_and_consume(
                capability, request,
                executor_measurement=executor_measurement,
                device_id=device_id,
                attestation=attestation,
                verifier_policy_digest=verifier_policy_digest,
                policy_digest=policy_digest,
                now=now,
            )
        except Exception:
            # Never turn unavailable/ambiguous replay into permission.
            return GatewayDecision(False, "not-started", "authority-denied")
        # A missing recorder cannot authorize an effect either.
        try:
            self.recorder.append("gateway.authorized", {
                "request_id": request.request_id,
                "request_digest": request.request_digest,
                "capability_id": capability.claims.capability_id,
            })
        except Exception:
            return GatewayDecision(False, "not-started", "evidence-unavailable")
        try:
            output = handler(request)
        except Exception:
            # A side effect may have happened before the handler threw.
            try:
                self.recorder.append("gateway.indeterminate", {
                    "request_id": request.request_id,
                    "effect_state": "possibly-committed",
                })
            except Exception:
                pass
            return GatewayDecision(False, "possibly-committed", "effect-indeterminate")
        try:
            self.recorder.append("gateway.completed", {
                "request_id": request.request_id,
                "effect_state": "completed",
            })
        except Exception:
            return GatewayDecision(False, "possibly-committed", "evidence-indeterminate")
        return GatewayDecision(True, "completed", output=output)


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
