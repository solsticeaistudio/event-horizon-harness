"""Trusted configuration adapter for the existing signed guardian contract.

Only the supervisor installs this session configuration. RPC clients can submit
requests and signatures, never a policy, ceiling, verifier pin or measurement.
Synthetic attestation remains explicitly simulated and binds the actual build.
"""
from __future__ import annotations

from .canonical import digest
from .component_ids import (STATIC_POLICY_GUARDIAN, EXECUTOR_ATTESTATION_GUARDIAN,
                            LINEAGE_BUDGET_GUARDIAN, BEHAVIORAL_TRANSITION_GUARDIAN)
from .guardians import LineageBudgetGuardian, SequenceGuardian, AttestationGuardian
from .attestation import AttestationError
from .models import ActionRequest, GuardianDecision
from .policy import OperationRule, StaticPolicy
from scripts.capability_fixture_support import authority_context


class SessionAuthority:
    def __init__(self, config):
        if set(config) != {"request", "reference_time", "build_artifacts", "source_commit"}:
            raise ValueError("trusted session configuration fields invalid")
        self.request = ActionRequest.from_dict(config["request"])
        if (self.request.operation != "object.read"
                or set(self.request.arguments) != {"offset", "length"}
                or self.request.arguments["offset"] != 0
                or type(self.request.arguments["length"]) is not int
                or not 0 < self.request.arguments["length"] <= 512):
            raise ValueError("session exceeds fixed retrieval contract")
        self.config = config
        self.policy = StaticPolicy("fixture-policy-v1", {
            "object.read": OperationRule(frozenset({self.request.resource_id}),
                                        frozenset({"offset", "length"}), 512)},
            frozenset({self.request.agent_id}), frozenset({self.request.executor_id}))
        self.context = authority_context(self.request, config["reference_time"],
                                        measurement=digest(config["build_artifacts"]),
                                        max_output_bytes=512)
        if self.context["policy_digest"] != self.policy.policy_digest:
            raise ValueError("independent policy compilation mismatch")
        self.lineage = LineageBudgetGuardian(max_requests_per_session=64)
        self.behavior = SequenceGuardian()
        self.attestor = AttestationGuardian(self)

    def verify_executor(self, executor_id, session_id, purpose):
        expected = self.request
        if (executor_id, session_id, purpose) != (expected.executor_id, expected.session_id, expected.purpose):
            raise AttestationError("executor/session does not match trusted synthetic measurement")
        return self.context["attestation"]

    def evaluate(self, identity, request):
        if identity == STATIC_POLICY_GUARDIAN:
            return self.policy.evaluate(request)
        if identity == EXECUTOR_ATTESTATION_GUARDIAN:
            return self.attestor.evaluate(request)
        if identity == BEHAVIORAL_TRANSITION_GUARDIAN:
            decision = self.behavior.evaluate(request)
            if not decision.allowed:
                return decision
        if request.canonical_payload() != self.request.canonical_payload():
            return GuardianDecision(identity, False, "request outside pinned session lineage",
                                    request_digest=request.request_digest)
        if identity == LINEAGE_BUDGET_GUARDIAN:
            return self.lineage.evaluate(request)
        if identity == BEHAVIORAL_TRANSITION_GUARDIAN:
            return decision
        raise ValueError("unknown guardian")
