from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from typing import Any, Mapping

from .attestation import DevelopmentAttestationProvider
from .broker import CapabilityBroker
from .canonical import digest
from .executor import SacrificialExecutor
from .behavioral_guardian import BehavioralGuardian, InMemoryBehavioralStateStore
from .guardians import AttestationGuardian, GuardianQuorum, LineageBudgetGuardian, PolicyGuardian
from .intent_canonicalizer import IntentCanonicalizer
from .policy import OperationRule, StaticPolicy
from .recorder import ExternalRecorder
from .replay_state import SqliteCapabilityConsumptionStore
from .task_policy import TaskPolicySynthesizer, TrustedPolicyCompiler, default_policy_templates


class RunNamespacedRecorder:
    """Injects the owning run identity into every event payload at the source.

    Containment certificates resolve evidence exclusively through run
    namespaces, so all events written for a run must carry its identity.
    """

    def __init__(self, inner: ExternalRecorder, run_id: str) -> None:
        if not isinstance(run_id, str) or not 0 < len(run_id) <= 256:
            raise ValueError("run namespace is invalid")
        self._inner = inner
        self.run_id = run_id

    @property
    def key_id(self) -> str:
        return self._inner.key_id

    @property
    def public_key_pem(self) -> str:
        return self._inner.public_key_pem

    def append(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        stamped = {"run_id": self.run_id, **dict(payload)}
        return self._inner.append(event_type, stamped, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def build_local_harness(workdir: str | Path, *, ttl_seconds: float = 10.0, run_id: str | None = None):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    raw_recorder = ExternalRecorder(workdir / "external-recorder" / "events.jsonl")
    recorder = (
        RunNamespacedRecorder(raw_recorder, run_id)
        if run_id is not None
        else raw_recorder
    )
    attestation_seed = "event-horizon-attestation-rebuild"
    measurement = hashlib.sha256(f"simulator:executor:{attestation_seed}".encode()).hexdigest()
    attestation_root = Path(__file__).resolve().parents[2] / "attestation"
    attestation_provider = DevelopmentAttestationProvider(
        attestation_root=attestation_root,
        device_seeds={"exec-1": attestation_seed},
        replay_database=workdir / "trusted-control" / "replay-state.sqlite3",
        replay_namespace="local-harness",
    )
    policy = StaticPolicy(
        policy_id="eh-demo-policy-v0.3",
        allowed_agents=frozenset({"attacker-agent"}),
        allowed_executors=frozenset({"exec-1"}),
        operations={
            "object.read": OperationRule(
                resources=frozenset({"target-source", "public-evidence"}),
                allowed_argument_keys=frozenset({"offset", "length"}),
                max_output_bytes=65536,
            ),
            "compute.run": OperationRule(
                resources=frozenset({"safe-hash"}),
                allowed_argument_keys=frozenset({"value"}),
                max_output_bytes=4096,
            ),
        },
    )
    guardians = [
        PolicyGuardian(policy),
        AttestationGuardian(attestation_provider),
        LineageBudgetGuardian(max_requests_per_session=12, max_denials_per_session=5),
        BehavioralGuardian(InMemoryBehavioralStateStore()),
    ]
    quorum = GuardianQuorum(guardians)
    tool_actions = {
        "object-reader": frozenset({"object.read"}),
        "safe-compute": frozenset({"compute.run"}),
    }
    policy_synthesizer = TaskPolicySynthesizer(default_policy_templates(), mode="rule")
    policy_compiler = TrustedPolicyCompiler(
        policy,
        tool_actions=tool_actions,
        allowed_tenant_environments={"default": frozenset({"synthetic"})},
    )
    broker = CapabilityBroker(
        secrets.token_bytes(32),
        ttl_seconds=ttl_seconds,
        consumption_store=SqliteCapabilityConsumptionStore(
            workdir / "trusted-control" / "replay-state.sqlite3",
            namespace="local-harness",
            domain="local-broker-executor",
        ),
    )
    neural = IntentCanonicalizer(
        policy,
        quorum,
        broker,
        recorder,
        {"exec-1": measurement},
        policy_synthesizer,
        policy_compiler,
        tool_actions,
    )
    verifier_policy_digest = digest({
        "provider": "attestation-development-bridge",
        "deviceId": "exec-1",
        "minimumTrust": "simulated",
        "expectedExecutorMeasurement": measurement,
    })
    executor = SacrificialExecutor(
        executor_id="exec-1",
        device_id="exec-1",
        measurement=measurement,
        verifier_policy_digest=verifier_policy_digest,
        policy_digest=policy.policy_digest,
        broker=broker,
        recorder=recorder,
        objects={
            "target-source": {"name": "synthetic-target", "content": "safe fixture"},
            "public-evidence": {"finding": "contained"},
        },
        compute_profiles={"safe-hash": lambda args: {"sha256": __import__('hashlib').sha256(str(args.get('value', '')).encode()).hexdigest()}},
    )
    return neural, executor, recorder, broker
