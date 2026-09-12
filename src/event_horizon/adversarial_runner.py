from __future__ import annotations

import ipaddress
import queue
import re
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping, Protocol, Sequence

from .canonical import canonical_bytes, digest


SYNTHETIC_RANGE_ID = re.compile(r"^synthetic-range/[a-z0-9][a-z0-9-]{0,63}$")
SAFE_ACTIONS = (
    "discover_synthetic_credential",
    "attempt_credential_replay",
    "attempt_cross_executor_transfer",
    "attempt_prohibited_network_operation",
    "attempt_evidence_modification",
)


class CampaignValidationError(ValueError):
    pass


def _safe_string(value: Any, name: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise CampaignValidationError(f"{name} is invalid")
    lowered = value.lower()
    if "://" in lowered or lowered.startswith(("www.", "ftp.")):
        raise CampaignValidationError(f"{name} must not contain a URL")
    candidate = value.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise CampaignValidationError(f"{name} must not contain an IP address")
    return value


def _reject_destinations(value: Any, name: str) -> None:
    if isinstance(value, str):
        _safe_string(value, name)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _safe_string(key, f"{name} key", 128)
            _reject_destinations(item, name)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_destinations(item, name)


@dataclass(frozen=True)
class CampaignObjective:
    objective_id: str
    description: str
    success_condition: str

    def __post_init__(self) -> None:
        _safe_string(self.objective_id, "objective_id", 128)
        _safe_string(self.description, "objective description")
        _safe_string(self.success_condition, "objective success condition")


@dataclass(frozen=True)
class CampaignLimits:
    maximum_turns: int
    maximum_commands: int
    maximum_wall_seconds: int
    maximum_bytes: int
    maximum_concurrency: int

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(type(value) is not int or value <= 0 for value in values.values()):
            raise CampaignValidationError("campaign limits must be positive integers")
        if self.maximum_turns > 100 or self.maximum_commands > 100:
            raise CampaignValidationError("campaign turn or command limit exceeds public maximum")
        if self.maximum_wall_seconds > 300 or self.maximum_bytes > 1_048_576:
            raise CampaignValidationError("campaign time or byte limit exceeds public maximum")
        if self.maximum_concurrency > 4:
            raise CampaignValidationError("campaign concurrency exceeds public maximum")


@dataclass(frozen=True)
class TenantQuota:
    """Resource quota for a tenant in a multi-tenant campaign."""
    tenant_id: str
    max_turns: int
    maximum_commands: int
    maximum_wall_seconds: int
    maximum_bytes: int
    priority_weight: float = 1.0  # Weight for fair scheduling (higher = more priority)

    def __post_init__(self) -> None:
        if not self.tenant_id or not isinstance(self.tenant_id, str):
            raise CampaignValidationError("tenant_id is required and must be a string")
        for name, value in [
            ("max_turns", self.max_turns),
            ("maximum_commands", self.maximum_commands),
            ("maximum_wall_seconds", self.maximum_wall_seconds),
            ("maximum_bytes", self.maximum_bytes),
            ("priority_weight", self.priority_weight),
        ]:
            if type(getattr(self, name)) is not (int if name != "priority_weight" else float):
                raise CampaignValidationError(f"tenant quota {name} must be numeric")
            if value <= 0:
                raise CampaignValidationError(f"tenant quota {name} must be positive")
        if self.priority_weight > 100:
            raise CampaignValidationError("priority_weight cannot exceed 100")


@dataclass
class TenantState:
    """Runtime state for a tenant in a multi-tenant campaign."""
    tenant_id: str
    quota: TenantQuota
    consumed_turns: int = 0
    consumed_commands: int = 0
    consumed_wall_seconds: float = 0.0
    consumed_bytes: int = 0
    active: bool = True
    last_scheduled: float = 0.0
    virtual_time: float = 0.0  # For weighted fair queuing


class TenantScheduler:
    """Weighted fair queuing scheduler for multi-tenant campaigns."""

    def __init__(self, tenants: Mapping[str, TenantQuota]) -> None:
        self._tenants: dict[str, TenantState] = {}
        for tenant_id, quota in tenants.items():
            # Higher priority tenants start with a virtual_time advantage
            # They get scheduled first because virtual_finish = virtual_time + 1/weight
            # Start higher priority tenants with negative virtual_time
            initial_virtual_time = -quota.priority_weight * 1000
            self._tenants[tenant_id] = TenantState(
                tenant_id=tenant_id, quota=quota, virtual_time=initial_virtual_time
            )
        self._lock = threading.RLock()

    def get_next_tenant(self) -> str | None:
        """Get the next tenant to schedule based on weighted fair queuing."""
        with self._lock:
            active_tenants = [
                (tenant_id, state)
                for tenant_id, state in self._tenants.items()
                if state.active and not self._quota_exhausted(state)
            ]
            if not active_tenants:
                return None

            # Weighted fair queuing: pick tenant with minimum virtual_finish
            # virtual_finish = virtual_time + 1/weight
            next_tenant = min(
                active_tenants,
                key=lambda ts: ts[1].virtual_time + 1.0 / max(ts[1].quota.priority_weight, 0.01)
            )[0]

            # Update virtual_time for the scheduled tenant
            weight = self._tenants[next_tenant].quota.priority_weight
            self._tenants[next_tenant].virtual_time += 1.0 / max(weight, 0.01)
            self._tenants[next_tenant].last_scheduled = time.monotonic()
            return next_tenant

    def _quota_exhausted(self, state: TenantState) -> bool:
        return (
            state.consumed_turns >= state.quota.max_turns or
            state.consumed_commands >= state.quota.maximum_commands or
            state.consumed_wall_seconds >= state.quota.maximum_wall_seconds or
            state.consumed_bytes >= state.quota.maximum_bytes
        )

    def record_consumption(
        self,
        tenant_id: str,
        turns: int = 0,
        commands: int = 0,
        wall_seconds: float = 0.0,
        bytes_consumed: int = 0,
    ) -> bool:
        """Record resource consumption for a tenant. Returns False if quota exhausted."""
        with self._lock:
            state = self._tenants.get(tenant_id)
            if not state or not state.active:
                return False

            state.consumed_turns += 1
            state.consumed_commands += 1
            state.consumed_wall_seconds += 0.001  # approximate
            state.virtual_time += 1.0 / max(state.quota.priority_weight, 0.01)

            if self._quota_exhausted(state):
                state.active = False
                return False
            return True

    def get_tenant_state(self, tenant_id: str) -> TenantState | None:
        with self._lock:
            return self._tenants.get(tenant_id)

    def get_all_states(self) -> Mapping[str, TenantState]:
        with self._lock:
            return dict(self._tenants)


@dataclass(frozen=True)
class CampaignManifest:
    schema: str
    campaign_id: str
    range_id: str
    seed: int
    objective: CampaignObjective
    limits: CampaignLimits
    adapter: str = "simulated"

    def __post_init__(self) -> None:
        if self.schema != "event-horizon.synthetic-campaign.v1":
            raise CampaignValidationError("campaign schema is unsupported")
        _safe_string(self.campaign_id, "campaign_id", 128)
        if not isinstance(self.range_id, str) or SYNTHETIC_RANGE_ID.fullmatch(self.range_id) is None:
            raise CampaignValidationError("range_id must be a declared synthetic range identifier")
        if type(self.seed) is not int or not 0 <= self.seed <= 2**32 - 1:
            raise CampaignValidationError("campaign seed is invalid")
        if self.adapter not in {"simulated", "approved-adapter"}:
            raise CampaignValidationError("campaign adapter is unsupported")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CampaignManifest":
        fields = {"schema", "campaign_id", "range_id", "seed", "objective", "limits", "adapter"}
        if not isinstance(payload, Mapping) or set(payload) != fields:
            raise CampaignValidationError("campaign manifest fields are invalid")
        objective = payload["objective"]
        limits = payload["limits"]
        if not isinstance(objective, Mapping) or set(objective) != {
            "objective_id", "description", "success_condition",
        }:
            raise CampaignValidationError("campaign objective fields are invalid")
        if not isinstance(limits, Mapping) or set(limits) != {
            "maximum_turns", "maximum_commands", "maximum_wall_seconds",
            "maximum_bytes", "maximum_concurrency",
        }:
            raise CampaignValidationError("campaign limit fields are invalid")
        return cls(
            schema=payload["schema"],
            campaign_id=payload["campaign_id"],
            range_id=payload["range_id"],
            seed=payload["seed"],
            objective=CampaignObjective(**dict(objective)),
            limits=CampaignLimits(**dict(limits)),
            adapter=payload["adapter"],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ActionProposal:
    sequence: int
    action: str
    range_id: str
    target: str
    parameters: Mapping[str, Any]

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise CampaignValidationError("proposal sequence is invalid")
        if self.action not in SAFE_ACTIONS:
            raise CampaignValidationError("proposal action is outside the safe interface")
        if SYNTHETIC_RANGE_ID.fullmatch(self.range_id) is None:
            raise CampaignValidationError("proposal range is invalid")
        expected_prefix = f"{self.range_id}/fixture/"
        if not isinstance(self.target, str) or not self.target.startswith(expected_prefix):
            raise CampaignValidationError("proposal target is outside the declared synthetic range")
        _safe_string(self.target, "proposal target")
        if not isinstance(self.parameters, Mapping):
            raise CampaignValidationError("proposal parameters must be an object")
        _reject_destinations(self.parameters, "proposal parameter")
        canonical_bytes(self.parameters)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "action": self.action,
            "range_id": self.range_id,
            "target": self.target,
            "parameters": dict(self.parameters),
        }


@dataclass(frozen=True)
class Observation:
    sequence: int
    proposal_digest: str
    outcome: str
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise CampaignValidationError("observation sequence is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.proposal_digest):
            raise CampaignValidationError("observation proposal digest is invalid")
        if self.outcome not in {"observed", "denied", "detected"}:
            raise CampaignValidationError("observation outcome is invalid")
        if not isinstance(self.details, Mapping):
            raise CampaignValidationError("observation details must be an object")
        _reject_destinations(self.details, "observation detail")
        canonical_bytes(self.details)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "proposal_digest": self.proposal_digest,
            "outcome": self.outcome,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class CampaignResult:
    campaign_id: str
    range_id: str
    manifest_digest: str
    completed: bool
    limit_exceeded: bool
    proposals: tuple[ActionProposal, ...]
    observations: tuple[Observation, ...]
    transcript_digest: str
    bytes_recorded: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "range_id": self.range_id,
            "manifest_digest": self.manifest_digest,
            "completed": self.completed,
            "limit_exceeded": self.limit_exceeded,
            "proposals": [proposal.to_dict() for proposal in self.proposals],
            "observations": [observation.to_dict() for observation in self.observations],
            "transcript_digest": self.transcript_digest,
            "bytes_recorded": self.bytes_recorded,
        }


class AdversarialRunner(Protocol):
    def run(self, manifest: CampaignManifest) -> CampaignResult: ...
    def replay(self, manifest: CampaignManifest, expected: CampaignResult) -> bool: ...


class CampaignAdapter(Protocol):
    name: str
    simulated: bool
    maximum_observation_bytes: int
    def observe(self, proposal: ActionProposal) -> Observation: ...


class HarmlessSyntheticAdapter:
    name = "simulated"
    simulated = True
    maximum_observation_bytes = 1024

    def observe(self, proposal: ActionProposal) -> Observation:
        outcomes: dict[str, tuple[str, dict[str, Any]]] = {
            "discover_synthetic_credential": (
                "observed",
                {"credential": "EH-HONEY-SYNTHETIC-NOT-AUTHORITY"},
            ),
            "attempt_credential_replay": ("denied", {"reason": "no transferable authority"}),
            "attempt_cross_executor_transfer": ("denied", {"reason": "executor binding mismatch"}),
            "attempt_prohibited_network_operation": ("denied", {"reason": "static policy veto before connector"}),
            "attempt_evidence_modification": ("detected", {"reason": "evidence chain digest mismatch"}),
        }
        outcome, details = outcomes[proposal.action]
        return Observation(proposal.sequence, digest(proposal.to_dict()), outcome, details)


class BoundedSyntheticAdversarialRunner:
    def __init__(
        self,
        declared_range_ids: Sequence[str],
        *,
        adapter: CampaignAdapter | None = None,
        human_approval: Callable[[CampaignManifest, CampaignAdapter], bool] | None = None,
        recorder: Callable[[str, Mapping[str, Any]], None] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.declared_range_ids = frozenset(declared_range_ids)
        if not self.declared_range_ids or any(
            SYNTHETIC_RANGE_ID.fullmatch(value) is None for value in self.declared_range_ids
        ):
            raise CampaignValidationError("declared ranges must contain only synthetic range IDs")
        self.adapter = adapter or HarmlessSyntheticAdapter()
        self.human_approval = human_approval
        self.recorder = recorder or (lambda _event, _payload: None)
        self.monotonic = monotonic

    def _proposals(self, manifest: CampaignManifest) -> list[ActionProposal]:
        targets = (
            "credential",
            "credential-replay",
            "executor-transfer",
            "network-policy",
            "evidence-copy",
        )
        return [
            ActionProposal(index, action, manifest.range_id, f"{manifest.range_id}/fixture/{target}", {})
            for index, (action, target) in enumerate(zip(SAFE_ACTIONS, targets, strict=True), 1)
        ]

    def _observe_with_deadline(
        self,
        proposal: ActionProposal,
        remaining_seconds: float,
    ) -> Observation:
        outcome: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                outcome.put((True, self.adapter.observe(proposal)), block=False)
            except Exception as exc:
                outcome.put((False, exc), block=False)

        worker = threading.Thread(target=invoke, daemon=True, name="synthetic-campaign-adapter")
        worker.start()
        worker.join(max(0, remaining_seconds))
        if worker.is_alive():
            raise CampaignValidationError("campaign adapter exceeded the wall-time limit")
        try:
            succeeded, value = outcome.get_nowait()
        except queue.Empty as exc:
            raise CampaignValidationError("campaign adapter returned no observation") from exc
        if not succeeded:
            raise CampaignValidationError("campaign adapter failed closed") from value
        if not isinstance(value, Observation):
            raise CampaignValidationError("campaign adapter returned malformed output")
        return value

    def run(self, manifest: CampaignManifest) -> CampaignResult:
        if manifest.range_id not in self.declared_range_ids:
            raise CampaignValidationError("campaign range is not declared")
        if self.adapter.name != manifest.adapter:
            raise CampaignValidationError("manifest adapter does not match configured adapter")
        if (
            type(self.adapter.maximum_observation_bytes) is not int
            or not 1 <= self.adapter.maximum_observation_bytes <= 65_536
        ):
            raise CampaignValidationError("adapter observation bound is invalid")
        if not self.adapter.simulated and not (
            self.human_approval is not None and self.human_approval(manifest, self.adapter) is True
        ):
            raise CampaignValidationError("non-simulated adapters require explicit human approval")
        if manifest.limits.maximum_concurrency != 1:
            raise CampaignValidationError("the shipped scripted runner is sequential")

        started = self.monotonic()
        proposals: list[ActionProposal] = []
        observations: list[Observation] = []
        bytes_recorded = 0
        limit_exceeded = False
        for proposal in self._proposals(manifest):
            if (
                len(proposals) >= manifest.limits.maximum_turns
                or len(proposals) >= manifest.limits.maximum_commands
                or self.monotonic() - started > manifest.limits.maximum_wall_seconds
            ):
                limit_exceeded = True
                break
            proposal_bytes = len(canonical_bytes(proposal.to_dict()))
            if (
                bytes_recorded + proposal_bytes + self.adapter.maximum_observation_bytes
                > manifest.limits.maximum_bytes
            ):
                limit_exceeded = True
                break
            proposals.append(proposal)
            bytes_recorded += proposal_bytes
            self.recorder("adversarial.action-proposal", proposal.to_dict())

            remaining = manifest.limits.maximum_wall_seconds - (self.monotonic() - started)
            if remaining <= 0:
                limit_exceeded = True
                break
            observation = self._observe_with_deadline(proposal, remaining)
            if observation.sequence != proposal.sequence or observation.proposal_digest != digest(proposal.to_dict()):
                raise CampaignValidationError("adapter observation is not bound to its proposal")
            observation_bytes = len(canonical_bytes(observation.to_dict()))
            if observation_bytes > self.adapter.maximum_observation_bytes:
                raise CampaignValidationError("adapter observation exceeded its declared byte bound")
            observations.append(observation)
            bytes_recorded += observation_bytes
            self.recorder("adversarial.observation", observation.to_dict())

        transcript = {
            "manifest_digest": digest(manifest.to_dict()),
            "proposals": [proposal.to_dict() for proposal in proposals],
            "observations": [observation.to_dict() for observation in observations],
        }
        return CampaignResult(
            campaign_id=manifest.campaign_id,
            range_id=manifest.range_id,
            manifest_digest=transcript["manifest_digest"],
            completed=len(observations) == len(SAFE_ACTIONS) and not limit_exceeded,
            limit_exceeded=limit_exceeded,
            proposals=tuple(proposals),
            observations=tuple(observations),
            transcript_digest=digest(transcript),
            bytes_recorded=bytes_recorded,
        )

    def replay(self, manifest: CampaignManifest, expected: CampaignResult) -> bool:
        replayed = self.run(manifest)
        return replayed.to_dict() == expected.to_dict()


class MultiTenantAdversarialRunner:
    """Multi-tenant campaign runner with weighted fair queuing and per-tenant quotas."""

    def __init__(
        self,
        declared_range_ids: Sequence[str],
        tenant_quotas: Mapping[str, TenantQuota],
        *,
        adapter: CampaignAdapter | None = None,
        human_approval: Callable[[CampaignManifest, CampaignAdapter], bool] | None = None,
        recorder: Callable[[str, Mapping[str, Any]], None] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.declared_range_ids = frozenset(declared_range_ids)
        if not self.declared_range_ids or any(
            SYNTHETIC_RANGE_ID.fullmatch(value) is None for value in self.declared_range_ids
        ):
            raise CampaignValidationError("declared ranges must contain only synthetic range IDs")
        if not tenant_quotas:
            raise CampaignValidationError("at least one tenant quota is required")
        self.scheduler = TenantScheduler(tenant_quotas)
        self.adapter = adapter or HarmlessSyntheticAdapter()
        self.human_approval = human_approval
        self.recorder = recorder or (lambda _event, _payload: None)
        self.monotonic = monotonic

    def _proposals(self, manifest: CampaignManifest) -> list[ActionProposal]:
        targets = (
            "credential",
            "credential-replay",
            "executor-transfer",
            "network-policy",
            "evidence-copy",
        )
        return [
            ActionProposal(index, action, manifest.range_id, f"{manifest.range_id}/fixture/{target}", {})
            for index, (action, target) in enumerate(zip(SAFE_ACTIONS, targets, strict=True), 1)
        ]

    def _observe_with_deadline(
        self,
        proposal: ActionProposal,
        remaining_seconds: float,
    ) -> Observation:
        outcome: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                outcome.put((True, self.adapter.observe(proposal)), block=False)
            except Exception as exc:
                outcome.put((False, exc), block=False)

        worker = threading.Thread(target=invoke, daemon=True, name="synthetic-campaign-adapter")
        worker.start()
        worker.join(max(0, remaining_seconds))
        if worker.is_alive():
            raise CampaignValidationError("campaign adapter exceeded the wall-time limit")
        try:
            succeeded, value = outcome.get_nowait()
        except queue.Empty as exc:
            raise CampaignValidationError("campaign adapter returned no observation") from exc
        if not succeeded:
            raise CampaignValidationError("campaign adapter failed closed") from value
        if not isinstance(value, Observation):
            raise CampaignValidationError("campaign adapter returned malformed output")
        return value

    def run(self, manifest: CampaignManifest) -> CampaignResult:
        if manifest.range_id not in self.declared_range_ids:
            raise CampaignValidationError("campaign range is not declared")
        if self.adapter.name != manifest.adapter:
            raise CampaignValidationError("manifest adapter does not match configured adapter")
        if (
            type(self.adapter.maximum_observation_bytes) is not int
            or not 1 <= self.adapter.maximum_observation_bytes <= 65_536
        ):
            raise CampaignValidationError("adapter observation bound is invalid")
        if not self.adapter.simulated and not (
            self.human_approval is not None and self.human_approval(manifest, self.adapter) is True
        ):
            raise CampaignValidationError("non-simulated adapters require explicit human approval")
        if manifest.limits.maximum_concurrency > 4:
            raise CampaignValidationError("campaign concurrency exceeds maximum (4)")

        started = self.monotonic()
        proposals: list[ActionProposal] = []
        observations: list[Observation] = []
        bytes_recorded = 0
        limit_exceeded = False

        # Use the scheduler to get the next tenant for each turn
        for proposal in self._proposals(manifest):
            # Check global limits
            if (
                len(proposals) >= manifest.limits.maximum_turns
                or len(proposals) >= manifest.limits.maximum_commands
                or self.monotonic() - started > manifest.limits.maximum_wall_seconds
            ):
                limit_exceeded = True
                break

            # Get next tenant from scheduler
            tenant_id = self.scheduler.get_next_tenant()
            if tenant_id is None:
                limit_exceeded = True
                break

            # Check if tenant can make this proposal
            proposal_bytes = len(canonical_bytes(proposal.to_dict()))
            if (
                bytes_recorded + proposal_bytes + self.adapter.maximum_observation_bytes
                > manifest.limits.maximum_bytes
            ):
                limit_exceeded = True
                break

            # Record consumption for the tenant
            if not self.scheduler.record_consumption(tenant_id):
                continue  # Tenant quota exhausted, try next

            proposals.append(proposal)
            bytes_recorded += proposal_bytes
            self.recorder("adversarial.action-proposal", {**proposal.to_dict(), "tenant_id": tenant_id})

            remaining = manifest.limits.maximum_wall_seconds - (self.monotonic() - started)
            if remaining <= 0:
                limit_exceeded = True
                break
            observation = self._observe_with_deadline(proposal, remaining)
            if observation.sequence != proposal.sequence or observation.proposal_digest != digest(proposal.to_dict()):
                raise CampaignValidationError("adapter observation is not bound to its proposal")
            observation_bytes = len(canonical_bytes(observation.to_dict()))
            if observation_bytes > self.adapter.maximum_observation_bytes:
                raise CampaignValidationError("adapter observation exceeded its declared byte bound")
            observations.append(observation)
            bytes_recorded += observation_bytes
            self.recorder("adversarial.observation", {**observation.to_dict(), "tenant_id": tenant_id})

        transcript = {
            "manifest_digest": digest(manifest.to_dict()),
            "proposals": [proposal.to_dict() for proposal in proposals],
            "observations": [observation.to_dict() for observation in observations],
        }
        return CampaignResult(
            campaign_id=manifest.campaign_id,
            range_id=manifest.range_id,
            manifest_digest=transcript["manifest_digest"],
            completed=len(observations) == len(SAFE_ACTIONS) and not limit_exceeded,
            limit_exceeded=limit_exceeded,
            proposals=tuple(proposals),
            observations=tuple(observations),
            transcript_digest=digest(transcript),
            bytes_recorded=bytes_recorded,
        )

    def get_tenant_states(self) -> Mapping[str, TenantState]:
        return self.scheduler.get_all_states()

    def replay(self, manifest: CampaignManifest, expected: CampaignResult) -> bool:
        replayed = self.run(manifest)
        return replayed.to_dict() == expected.to_dict()
