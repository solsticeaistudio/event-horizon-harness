from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from event_horizon.factory import build_local_harness
from event_horizon.models import ActionRequest, ValidationError
from event_horizon.intent_canonicalizer import AuthorizationDenied


def payload(**overrides):
    value = {
        "request_id": "req-1",
        "session_id": "session-1",
        "agent_id": "attacker-agent",
        "operation": "object.read",
        "resource_id": "target-source",
        "executor_id": "exec-1",
        "arguments": {"offset": 0, "length": 100},
        "purpose": "test",
    }
    value.update(overrides)
    return value


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.neural, self.executor, self.recorder, self.broker = build_local_harness(self.tmp.name, ttl_seconds=0.05)

    def tearDown(self):
        self.tmp.cleanup()

    def issue(self, **overrides):
        return self.neural.request_capability(payload(**overrides))

    def test_exact_capability_succeeds_once(self):
        request, capability, attestation = self.issue()
        result = self.executor.execute(request, capability, attestation)
        self.assertTrue(result.success)

    def test_replay_is_denied(self):
        request, capability, attestation = self.issue()
        self.assertTrue(self.executor.execute(request, capability, attestation).success)
        result = self.executor.execute(request, capability, attestation)
        self.assertFalse(result.success)
        # The lifecycle tracker rejects the duplicate attempt before any
        # provider interaction; either wording denotes a one-use violation.
        self.assertTrue(
            "replay" in result.error or "duplicate execution" in result.error,
            result.error,
        )

    def test_argument_widening_is_denied_by_policy(self):
        with self.assertRaises(AuthorizationDenied):
            self.issue(arguments={"offset": 0, "length": 10, "url": "https://example.invalid"})

    def test_capability_cannot_be_widened_after_issue(self):
        request, capability, attestation = self.issue()
        changed = ActionRequest.from_dict(payload(arguments={"offset": 0, "length": 101}))
        result = self.executor.execute(changed, capability, attestation)
        self.assertFalse(result.success)
        self.assertIn("binding mismatch", result.error)

    def test_cross_session_use_is_denied(self):
        request, capability, attestation = self.issue()
        changed = ActionRequest.from_dict(payload(session_id="session-2"))
        result = self.executor.execute(changed, capability, attestation)
        self.assertFalse(result.success)
        self.assertIn("session_id", result.error)

    def test_cross_executor_use_is_denied(self):
        request, capability, attestation = self.issue()
        changed = ActionRequest.from_dict(payload(executor_id="exec-2"))
        result = self.executor.execute(changed, capability, attestation)
        self.assertFalse(result.success)
        self.assertIn("executor_id", result.error)

    def test_expired_capability_is_denied(self):
        request, capability, attestation = self.issue()
        time.sleep(0.07)
        result = self.executor.execute(request, capability, attestation)
        self.assertFalse(result.success)
        self.assertIn("expired", result.error)

    def test_unknown_request_field_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.neural.request_capability(payload(secret_override=True))

    def test_prohibited_operation_is_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.issue(operation="http.request", resource_id="internet")

    def test_one_permissive_guardian_cannot_widen_policy(self):
        class CompromisedGuardian:
            name = "compromised"
            def evaluate(self, request):
                from event_horizon.models import GuardianDecision
                return GuardianDecision(self.name, True, "approve everything")
        self.neural.quorum.guardians = list(self.neural.quorum.guardians) + [CompromisedGuardian()]
        with self.assertRaises(AuthorizationDenied):
            self.issue(operation="shell.execute", resource_id="host")

    def test_recorder_tampering_is_detected(self):
        request, capability, attestation = self.issue()
        self.executor.execute(request, capability, attestation)
        path = Path(self.tmp.name) / "external-recorder" / "events.jsonl"
        lines = path.read_text().splitlines()
        event = json.loads(lines[0])
        event["payload"]["agent_id"] = "tampered"
        lines[0] = json.dumps(event, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")
        valid, reason = self.recorder.verify()
        self.assertFalse(valid)
        self.assertIn("digest", reason)


if __name__ == "__main__":
    unittest.main()
