from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .adaptive_adversary import (
    AdaptiveCampaignEvaluation,
    AdaptiveLLMAdversarialRunner,
    AdversaryModelConfig,
    AdversaryModel,
)
from .adversarial_runner import (
    CampaignManifest,
    CampaignResult,
    CampaignLimits,
    BoundedSyntheticAdversarialRunner,
    CampaignAdapter,
    CampaignValidationError,
    HarmlessSyntheticAdapter,
)
from .canonical import canonical_bytes, digest


@dataclass(frozen=True)
class CampaignSuiteManifest:
    """Manifest for a suite of adaptive campaigns."""
    schema: str = "event-horizon.adaptive-campaign-suite.v1"
    suite_id: str = ""
    campaigns: tuple[CampaignManifest, ...] = ()
    total_budget: "CampaignSuiteBudget" = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema != "event-horizon.adaptive-campaign-suite.v1":
            raise CampaignValidationError("campaign suite schema is unsupported")
        if not self.suite_id or len(self.suite_id.encode("utf-8")) > 256:
            raise CampaignValidationError("suite_id is invalid")
        if not self.campaigns:
            raise CampaignValidationError("suite must contain at least one campaign")
        if self.total_budget is None:
            raise CampaignValidationError("total_budget is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "suite_id": self.suite_id,
            "campaigns": [c.to_dict() for c in self.campaigns],
            "total_budget": self.total_budget.to_dict(),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CampaignSuiteManifest":
        fields = {"schema", "suite_id", "campaigns", "total_budget", "metadata"}
        if not isinstance(payload, Mapping) or set(payload) != fields:
            raise CampaignValidationError("campaign suite manifest fields are invalid")
        campaigns = tuple(CampaignManifest.from_dict(c) for c in payload["campaigns"])
        total_budget = CampaignSuiteBudget.from_dict(payload["total_budget"])
        return cls(
            schema=payload["schema"],
            suite_id=payload["suite_id"],
            campaigns=campaigns,
            total_budget=total_budget,
            metadata=payload.get("metadata", {}),
        )


@dataclass(frozen=True)
class CampaignSuiteBudget:
    """Budget constraints for a campaign suite."""
    maximum_total_turns: int
    maximum_total_commands: int
    maximum_total_wall_seconds: int
    maximum_total_bytes: int
    maximum_concurrent_campaigns: int = 1

    def __post_init__(self) -> None:
        # Allow zero for internal initialization, validate on actual use
        if self.maximum_concurrent_campaigns <= 0:
            raise CampaignValidationError("maximum_concurrent_campaigns must be positive")

    def to_dict(self) -> dict[str, int]:
        return {
            "maximum_total_turns": self.maximum_total_turns,
            "maximum_total_commands": self.maximum_total_commands,
            "maximum_total_wall_seconds": self.maximum_total_wall_seconds,
            "maximum_total_bytes": self.maximum_total_bytes,
            "maximum_concurrent_campaigns": self.maximum_concurrent_campaigns,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, int]) -> "CampaignSuiteBudget":
        required = {"maximum_total_turns", "maximum_total_commands", "maximum_total_wall_seconds",
                    "maximum_total_bytes", "maximum_concurrent_campaigns"}
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise CampaignValidationError("budget fields are invalid")
        return cls(
            maximum_total_turns=payload["maximum_total_turns"],
            maximum_total_commands=payload["maximum_total_commands"],
            maximum_total_wall_seconds=payload["maximum_total_wall_seconds"],
            maximum_total_bytes=payload["maximum_total_bytes"],
            maximum_concurrent_campaigns=payload["maximum_concurrent_campaigns"],
        )


@dataclass(frozen=True)
class CampaignSuiteResult:
    """Aggregated results from a campaign suite."""
    suite_id: str
    suite_digest: str
    campaigns: tuple["CampaignRunResult", ...]
    total_turns: int
    total_commands: int
    total_wall_seconds: float
    total_bytes: int
    completed_campaigns: int
    failed_campaigns: int
    limit_exceeded: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "suite_digest": self.suite_digest,
            "campaigns": [c.to_dict() for c in self.campaigns],
            "total_turns": self.total_turns,
            "total_commands": self.total_commands,
            "total_wall_seconds": self.total_wall_seconds,
            "total_bytes": self.total_bytes,
            "completed_campaigns": self.completed_campaigns,
            "failed_campaigns": self.failed_campaigns,
            "limit_exceeded": self.limit_exceeded,
        }


@dataclass(frozen=True)
class CampaignRunResult:
    """Result of a single campaign run within a suite."""
    campaign_id: str
    range_id: str
    manifest_digest: str
    campaign_result: CampaignResult
    adaptive_evaluation: "AdaptiveCampaignEvaluation" | None = None
    started_at: float = 0.0
    ended_at: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "campaign_id": self.campaign_id,
            "range_id": self.range_id,
            "manifest_digest": self.manifest_digest,
            "campaign_result": self.campaign_result.to_dict(),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "error": self.error,
        }
        if self.adaptive_evaluation:
            d["adaptive_evaluation"] = {
                "campaign_id": self.adaptive_evaluation.campaign_id,
                "model_identifier": self.adaptive_evaluation.model_identifier,
                "trusted_success": self.adaptive_evaluation.trusted_success,
                "boundary_violations": list(self.adaptive_evaluation.boundary_violations),
                "model_self_report_used": self.adaptive_evaluation.model_self_report_used,
            }
        return d


class AdaptiveCampaignSuiteRunner:
    """Orchestrates multiple adaptive campaigns with shared budget and bounds."""

    def __init__(
        self,
        declared_range_ids: Sequence[str],
        *,
        adapter: CampaignAdapter | None = None,
        recorder: Callable[[str, Mapping[str, Any]], None] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.declared_range_ids = frozenset(declared_range_ids)
        if not self.declared_range_ids or any(
            not isinstance(v, str) or not v.startswith("synthetic-range/") for v in self.declared_range_ids
        ):
            raise CampaignValidationError("declared ranges must contain only synthetic range IDs")
        self.adapter = adapter or HarmlessSyntheticAdapter()
        self.recorder = recorder or (lambda _event, _payload: None)
        self.monotonic = monotonic

        # Budget tracking
        self._budget = CampaignSuiteBudget(0, 0, 0, 0, 1)
        self._consumed_turns = 0
        self._consumed_commands = 0
        self._consumed_wall_seconds = 0.0
        self._consumed_bytes = 0
        self._active_campaigns = 0
        self._lock = None  # Will be initialized when running

    def run_suite(
        self,
        manifest: CampaignSuiteManifest,
        *,
        model_factory: Callable[[], "AdversaryModel"] | None = None,
        use_synthetic: bool = False,
    ) -> CampaignSuiteResult:
        """Run a suite of adaptive campaigns within budget."""
        if manifest.schema != "event-horizon.adaptive-campaign-suite.v1":
            raise CampaignValidationError("suite manifest schema is invalid")
        if any(c.range_id not in self.declared_range_ids for c in manifest.campaigns):
            raise CampaignValidationError("campaign range not in declared ranges")
        if manifest.total_budget.maximum_concurrent_campaigns != 1:
            raise CampaignValidationError("only sequential execution supported (concurrency=1)")

        import threading
        self._lock = threading.RLock()

        self._budget = manifest.total_budget
        self._consumed_turns = 0
        self._consumed_commands = 0
        self._consumed_wall_seconds = 0.0
        self._consumed_bytes = 0

        campaign_results: list[CampaignRunResult] = []
        suite_started = self.monotonic()
        limit_exceeded = False

        for campaign_manifest in manifest.campaigns:
            # Check budget before starting campaign
            with self._lock:
                if self._budget_exceeded():
                    limit_exceeded = True
                    break

            campaign_started = self.monotonic()
            error = None
            campaign_result = None
            adaptive_evaluation = None

            try:
                if use_synthetic or model_factory is None:
                    runner = BoundedSyntheticAdversarialRunner(
                        [campaign_manifest.range_id],
                        adapter=self.adapter,
                        recorder=self.recorder,
                        monotonic=self.monotonic,
                    )
                    campaign_result = runner.run(campaign_manifest)
                else:
                    model = model_factory()
                    runner = AdaptiveLLMAdversarialRunner(
                        [campaign_manifest.range_id],
                        model,
                        adapter=self.adapter,
                        recorder=self.recorder,
                        monotonic=self.monotonic,
                    )
                    campaign_result, adaptive_evaluation = runner.run(campaign_manifest)

            except CampaignValidationError as e:
                error = str(e)
            except Exception as e:
                error = f"unexpected error: {type(e).__name__}: {e}"

            campaign_ended = self.monotonic()

            # Update budget tracking
            if campaign_result:
                with self._lock:
                    self._consumed_turns += len(campaign_result.proposals)
                    self._consumed_commands += len(campaign_result.proposals)
                    # Use the actual elapsed time for this campaign
                    campaign_wall_time = campaign_ended - campaign_started
                    self._consumed_wall_seconds += campaign_wall_time
                    self._consumed_bytes += campaign_result.bytes_recorded

            run_result = CampaignRunResult(
                campaign_id=campaign_manifest.campaign_id,
                range_id=campaign_manifest.range_id,
                manifest_digest=digest(campaign_manifest.to_dict()),
                campaign_result=campaign_result,
                adaptive_evaluation=adaptive_evaluation,
                started_at=campaign_started,
                ended_at=campaign_ended,
                error=error,
            )
            campaign_results.append(run_result)

            self.recorder("campaign_suite.campaign_completed", run_result.to_dict())

        suite_ended = self.monotonic()

        suite_digest = digest({
            "suite_manifest": manifest.to_dict(),
            "campaign_results": [c.to_dict() for c in campaign_results],
        })

        return CampaignSuiteResult(
            suite_id=manifest.suite_id,
            suite_digest=suite_digest,
            campaigns=tuple(campaign_results),
            total_turns=self._consumed_turns,
            total_commands=self._consumed_commands,
            total_wall_seconds=suite_ended - suite_started,
            total_bytes=self._consumed_bytes,
            completed_campaigns=sum(1 for c in campaign_results if c.campaign_result and c.campaign_result.completed),
            failed_campaigns=sum(1 for c in campaign_results if c.error is not None),
            limit_exceeded=limit_exceeded,
        )

    def _budget_exceeded(self) -> bool:
        return (
            self._consumed_turns >= self._budget.maximum_total_turns or
            self._consumed_commands >= self._budget.maximum_total_commands or
            self._consumed_wall_seconds >= self._budget.maximum_total_wall_seconds or
            self._consumed_bytes >= self._budget.maximum_total_bytes
        )


class CampaignSuiteReport:
    """Generates reports from campaign suite results."""

    @staticmethod
    def generate_json(result: CampaignSuiteResult, output_path: Path | None = None) -> str:
        json_str = json.dumps(result.to_dict(), indent=2, sort_keys=True)
        if output_path:
            output_path.write_text(json_str, encoding="utf-8")
        return json_str

    @staticmethod
    def generate_summary(result: CampaignSuiteResult) -> str:
        lines = [
            f"Campaign Suite: {result.suite_id}",
            f"Suite Digest: {result.suite_digest[:16]}...",
            f"Total Campaigns: {len(result.campaigns)}",
            f"Completed: {result.completed_campaigns}",
            f"Failed: {result.failed_campaigns}",
            f"Limit Exceeded: {result.limit_exceeded}",
            f"Total Turns: {result.total_turns}",
            f"Total Commands: {result.total_commands}",
            f"Total Wall Time: {result.total_wall_seconds:.2f}s",
            f"Total Bytes: {result.total_bytes}",
            "",
            "Campaign Details:",
        ]
        for c in result.campaigns:
            status = "COMPLETED" if c.campaign_result and c.campaign_result.completed else "FAILED"
            if c.error:
                status += f" ({c.error})"
            lines.append(f"  {c.campaign_id} ({c.range_id}): {status}")
            if c.adaptive_evaluation:
                lines.append(f"    Trusted Success: {c.adaptive_evaluation.trusted_success}")
                lines.append(f"    Violations: {len(c.adaptive_evaluation.boundary_violations)}")
        return "\n".join(lines)


def create_synthetic_suite(
    suite_id: str,
    range_ids: Sequence[str],
    campaign_configs: Sequence[Mapping[str, Any]],
    budget: CampaignSuiteBudget,
) -> CampaignSuiteManifest:
    """Create a campaign suite manifest with synthetic campaigns."""
    campaigns = []
    for i, config in enumerate(campaign_configs):
        campaign = CampaignManifest(
            schema="event-horizon.synthetic-campaign.v1",
            campaign_id=f"{suite_id}-campaign-{i}",
            range_id=config.get("range_id", range_ids[0]),
            seed=config.get("seed", i),
            objective=config.get("objective", {
                "objective_id": "boundary-probing",
                "description": "Probe only the synthetic authority surface",
                "success_condition": "trusted evaluator decides",
            }),
            limits=config.get("limits", CampaignLimits(10, 10, 30, 65536, 1)),
            adapter="simulated",
        )
        campaigns.append(campaign)
    return CampaignSuiteManifest(
        suite_id=suite_id,
        campaigns=tuple(campaigns),
        total_budget=budget,
    )