from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from event_horizon.canonical import digest
from event_horizon.models import ActionRequest
from event_horizon.policy import OperationRule, StaticPolicy
from event_horizon.task_policy import (
    PolicyTemplate,
    ProviderTrustState,
    TaskPolicySynthesizer,
    TrustedPolicyCompiler,
    task_description_for_request,
)


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def authority_context(
    request: ActionRequest,
    now: float,
    *,
    trust_level: str = "simulated",
    method: str = "simulator",
    required_trust: str = "simulated",
    measurement: str = "1" * 64,
) -> dict[str, Any]:
    verifier_policy_digest = digest({"fixture-verifier": request.executor_id})
    attestation: dict[str, Any] = {
        "valid": True,
        "deviceId": request.executor_id,
        "method": method,
        "trustLevel": trust_level,
        "assuranceLevel": "test-fixture",
        "keyId": "fixture-attestation-key",
        "measurements": {"executor": measurement},
        "bundleDigest": digest({"fixture-bundle": request.request_id}),
        "verifiedAt": _iso(now - 1),
        "verifierPolicyDigest": verifier_policy_digest,
        "nonceContext": {
            "deviceId": request.executor_id,
            "executorId": request.executor_id,
            "sessionId": request.session_id,
            "purpose": request.purpose,
        },
        "nonceIssuedAt": _iso(now - 1),
        "nonceExpiresAt": _iso(now + 300),
    }
    attestation["resultDigest"] = digest(attestation)
    trust = ProviderTrustState.from_attestation(attestation)
    policy = StaticPolicy(
        policy_id="fixture-policy-v1",
        operations={
            request.operation: OperationRule(
                resources=frozenset({request.resource_id}),
                allowed_argument_keys=frozenset(request.arguments),
                max_output_bytes=4_096,
            )
        },
        allowed_agents=frozenset({request.agent_id}),
        allowed_executors=frozenset({request.executor_id}),
    )
    tool_actions = {"fixture-tool": frozenset({request.operation})}
    template = PolicyTemplate(
        task_type="fixture-task",
        tools=("fixture-tool",),
        actions=(request.operation,),
        action_resources={request.operation: (request.resource_id,)},
        argument_constraints={request.operation: tuple(request.arguments)},
        data_classes=("internal",),
        maximum_read_bytes=4_096,
        maximum_write_bytes=0,
        maximum_calls=1,
        maximum_parallelism=1,
        maximum_duration_seconds=60,
        required_trust_tier=required_trust,
    )
    task = task_description_for_request(
        request,
        policy,
        trust,
        tool_actions,
        task_type="fixture-task",
    )
    candidate = TaskPolicySynthesizer({"fixture-task": template}).synthesize(task)
    compiled = TrustedPolicyCompiler(
        policy,
        tool_actions=tool_actions,
        allowed_tenant_environments={"default": frozenset({"synthetic"})},
    ).compile(task, candidate, now_ms=int(now * 1000))
    return {
        "attestation": attestation,
        "trust_state": trust,
        "compiled_ceiling": compiled,
        "device_id": request.executor_id,
        "executor_measurement": measurement,
        "verifier_policy_digest": verifier_policy_digest,
        "policy_digest": policy.policy_digest,
        "guardian_state_digest": digest({"fixture-guardians": "approved"}),
    }


def issue_options(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": context["device_id"],
        "executor_measurement": context["executor_measurement"],
        "trust_state": context["trust_state"],
        "compiled_ceiling": context["compiled_ceiling"],
        "policy_digest": context["policy_digest"],
        "guardian_state_digest": context["guardian_state_digest"],
    }


def verify_options(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": context["device_id"],
        "executor_measurement": context["executor_measurement"],
        "attestation": context["attestation"],
        "verifier_policy_digest": context["verifier_policy_digest"],
        "policy_digest": context["policy_digest"],
        "tenant": "default",
        "environment": "synthetic",
    }
