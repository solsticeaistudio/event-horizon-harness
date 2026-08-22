from __future__ import annotations

from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from event_horizon.broker import CapabilityBroker, CapabilityError
from event_horizon.models import ActionRequest
from event_horizon.replay_state import InMemoryCapabilityConsumptionStore
from scripts.capability_fixture_support import authority_context, issue_options, verify_options


FIXED_NOW = 1_700_000_000.0


class CapabilityLifecycleMachine(RuleBasedStateMachine):
    """Stateful exercise of issue, redeem, consume, replay, deny, expire, and mutation."""

    def __init__(self) -> None:
        super().__init__()
        self.broker = CapabilityBroker(
            b"stateful-capability-key-no-authority",
            ttl_seconds=10,
            consumption_store=InMemoryCapabilityConsumptionStore(),
        )
        self.sequence = 0
        self.committed: set[str] = set()
        self.consumed: set[str] = set()
        self.denials = 0

    def issue(self):
        self.sequence += 1
        request = ActionRequest(
            request_id=f"stateful-{self.sequence}", session_id="session-1",
            agent_id="attacker-agent", operation="object.read",
            resource_id="target-source", executor_id="exec-1",
            arguments={"length": 1, "offset": 0}, purpose="stateful test",
        )
        authority = authority_context(request, FIXED_NOW)
        capability = self.broker.issue(
            request, **issue_options(authority), max_output_bytes=1_024, now=FIXED_NOW
        )
        return request, capability, verify_options(authority)

    @rule()
    def issue_redeem_consume_then_replay(self) -> None:
        request, capability, context = self.issue()
        claims = self.broker.verify_and_consume(
            capability, request, **context, now=FIXED_NOW
        )
        self.consumed.add(claims.capability_id)
        self.committed.add(claims.capability_id)
        try:
            self.broker.verify_and_consume(capability, request, **context, now=FIXED_NOW)
        except CapabilityError:
            self.denials += 1
        else:  # pragma: no cover - invariant violation path
            raise AssertionError("consumed capability redeemed twice")

    @rule()
    def request_mutation_is_denied(self) -> None:
        request, capability, context = self.issue()
        changed = ActionRequest.from_dict({
            **request.canonical_payload(), "arguments": {"length": 2, "offset": 0}
        })
        try:
            self.broker.verify_and_consume(capability, changed, **context, now=FIXED_NOW)
        except CapabilityError:
            self.denials += 1
        else:  # pragma: no cover
            raise AssertionError("mutated request was authorized")

    @rule()
    def expired_capability_is_denied(self) -> None:
        request, capability, context = self.issue()
        try:
            self.broker.verify_and_consume(
                capability, request, **context, now=capability.claims.expires_at / 1_000
            )
        except CapabilityError:
            self.denials += 1
        else:  # pragma: no cover
            raise AssertionError("expired capability was authorized")

    @rule()
    def trust_or_workload_change_is_denied(self) -> None:
        request, capability, context = self.issue()
        changed = ActionRequest.from_dict({**request.canonical_payload(), "executor_id": "exec-2"})
        try:
            self.broker.verify_and_consume(capability, changed, **context, now=FIXED_NOW)
        except CapabilityError:
            self.denials += 1
        else:  # pragma: no cover
            raise AssertionError("cross-workload capability was authorized")

    @invariant()
    def at_most_one_commit_per_capability(self) -> None:
        assert self.committed.issubset(self.consumed)
        assert len(self.committed) == len(set(self.committed))


CapabilityLifecycleTest = CapabilityLifecycleMachine.TestCase
CapabilityLifecycleTest.settings = settings(
    max_examples=20,
    stateful_step_count=20,
    deadline=None,
    derandomize=True,
)
