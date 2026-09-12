from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping


FaultDisposition = Literal["deny", "safe-retry", "reconcile", "indeterminate", "halt"]


FAULT_DISPOSITIONS: Mapping[str, FaultDisposition] = {
    "signer.before-authorization": "deny",
    "signer.after-authorization": "deny",
    "signer.before-signing": "deny",
    "signer.after-signing": "safe-retry",
    "signer.before-returning": "safe-retry",
    "policy-synthesizer.before-synthesis": "deny",
    "policy-synthesizer.during-synthesis": "deny",
    "policy-synthesizer.malformed-output": "deny",
    "policy-synthesizer.timeout": "deny",
    "policy-synthesizer.unavailable": "deny",
    "policy-synthesizer.compromised-over-broad-output": "deny",
    "policy-compiler.before-validation": "deny",
    "policy-compiler.during-intersection": "deny",
    "policy-compiler.before-ceiling-commit": "deny",
    "policy-compiler.after-ceiling-commit": "safe-retry",
    "executor.before-validation": "deny",
    "executor.after-validation": "deny",
    "executor.before-effect": "deny",
    "executor.after-effect": "indeterminate",
    "executor.before-evidence-record": "indeterminate",
    "executor.after-evidence-record": "reconcile",
    "executor.before-response": "reconcile",
    "recorder.before-append": "indeterminate",
    "recorder.during-append": "indeterminate",
    "recorder.after-append": "reconcile",
    "recorder.before-flush": "indeterminate",
    "recorder.after-flush": "reconcile",
    "recorder.during-checkpoint": "halt",
    "recorder.during-integrity-validation": "halt",
    "capability-store.before-consumption": "deny",
    "capability-store.during-atomic-consumption": "reconcile",
    "capability-store.after-consumption": "reconcile",
    "capability-store.before-durable-commit": "reconcile",
    "capability-store.after-durable-commit": "reconcile",
    "guardian.before-scoring": "deny",
    "guardian.after-scoring": "deny",
    "guardian.during-state-update": "deny",
    "guardian.during-forced-reduction": "deny",
    "attestation.timeout": "deny",
    "attestation.malformed-response": "deny",
    "attestation.contradictory-response": "deny",
    "attestation.stale-response": "deny",
    "attestation.invalid-signature": "deny",
    "attestation.restart": "deny",
    "network.dropped-request": "safe-retry",
    "network.dropped-response": "reconcile",
    "network.duplication": "reconcile",
    "network.reordering": "deny",
    "network.delay": "deny",
    "network.partition": "deny",
    "process.crash-during-effect": "indeterminate",
    "process.crash-after-effect": "reconcile",
    "process.crash-before-evidence": "indeterminate",
    "process.crash-after-evidence": "reconcile",
    "clock.change-during-execution": "deny",
    "clock.change-during-redemption": "deny",
    "policy.stale-at-issuance": "deny",
    "policy.stale-at-redemption": "deny",
    "storage.rollback-detected": "halt",
    "storage.corruption-detected": "halt",
}

EFFECT_COMMITTED_POINTS = frozenset({
    "executor.after-effect", "executor.before-evidence-record",
    "executor.after-evidence-record", "executor.before-response",
    "recorder.before-append", "recorder.during-append", "recorder.after-append",
    "recorder.before-flush", "recorder.after-flush",
    "network.dropped-response",
    "process.crash-after-effect",
    "process.crash-after-evidence",
})


class InjectedFault(RuntimeError):
    def __init__(self, point: str, disposition: FaultDisposition):
        super().__init__(f"deterministic fault at {point}: {disposition}")
        self.point = point
        self.disposition = disposition


class DeterministicFaultInjector:
    """Explicit test-only injector. Production construction cannot enable faults."""

    def __init__(
        self,
        configured_hits: Mapping[str, int] | None = None,
        *,
        enabled: bool = False,
        environment: str = "production",
    ):
        if enabled and environment != "test":
            raise PermissionError("fault injection can be enabled only in the test environment")
        configured = dict(configured_hits or {})
        unknown = set(configured) - set(FAULT_DISPOSITIONS)
        if unknown or any(type(value) is not int or value < 1 for value in configured.values()):
            raise ValueError(f"fault plan is malformed or unknown: {sorted(unknown)}")
        self.configured_hits = configured
        self.enabled = enabled
        self._counts: dict[str, int] = {}

    def hit(self, point: str) -> None:
        if point not in FAULT_DISPOSITIONS:
            raise ValueError(f"unknown fault injection point: {point}")
        self._counts[point] = self._counts.get(point, 0) + 1
        if self.enabled and self.configured_hits.get(point) == self._counts[point]:
            raise InjectedFault(point, FAULT_DISPOSITIONS[point])


@dataclass(frozen=True)
class ChaosResult:
    fault_point: str
    disposition: FaultDisposition
    authority_issued: bool
    capability_consumed: bool
    effect_state: str
    evidence_state: str
    retry_permitted: bool

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class DeterministicChaosHarness:
    """Trusted state classifier for named failure points and ambiguous outcomes."""

    def run(self, fault_point: str) -> ChaosResult:
        if fault_point not in FAULT_DISPOSITIONS:
            raise ValueError("unknown chaos point")
        disposition = FAULT_DISPOSITIONS[fault_point]
        authority_issued = fault_point.startswith("executor.") or fault_point.startswith(
            ("recorder.", "capability-store.", "network.")
        )
        consumed = fault_point in {
            "capability-store.after-consumption", "capability-store.before-durable-commit",
            "capability-store.after-durable-commit",
        } or fault_point in EFFECT_COMMITTED_POINTS or fault_point.startswith("executor.")
        effect_state = "committed" if fault_point in EFFECT_COMMITTED_POINTS else "not-committed"
        if disposition in {"indeterminate", "reconcile"} and effect_state != "committed":
            effect_state = "indeterminate"
        evidence_state = (
            "recorded" if fault_point in {"executor.after-evidence-record", "executor.before-response",
                                           "recorder.after-append", "recorder.after-flush"}
            else "missing-or-uncertain" if effect_state != "not-committed" else "denial-required"
        )
        retry_permitted = disposition == "safe-retry" and effect_state == "not-committed"
        return ChaosResult(
            fault_point, disposition, authority_issued, consumed, effect_state,
            evidence_state, retry_permitted,
        )
