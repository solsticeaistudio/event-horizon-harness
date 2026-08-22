from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from event_horizon.certificate import ContainmentCertificateBuilder
from event_horizon.component_ids import EXECUTOR_ATTESTATION_GUARDIAN
from event_horizon.attestation import DevelopmentAttestationProvider
from event_horizon.factory import build_local_harness


class ExecutorAttestationIntegrationTests(unittest.TestCase):
    def test_development_provider_never_caches_by_executor_id(self):
        provider = DevelopmentAttestationProvider(
            attestation_root=Path(__file__).resolve().parents[1] / "attestation",
            device_seeds={"exec-1": "event-horizon-attestation-rebuild"},
        )
        first = provider.verify_executor("exec-1", "session-a", "capability-issuance")
        second = provider.verify_executor("exec-1", "session-a", "capability-issuance")
        third = provider.verify_executor("exec-1", "session-b", "capability-issuance")
        self.assertNotEqual(first["bundleDigest"], second["bundleDigest"])
        self.assertNotEqual(first["resultDigest"], second["resultDigest"])
        self.assertEqual(third["nonceContext"]["sessionId"], "session-b")
        self.assertNotEqual(second["resultDigest"], third["resultDigest"])

    def test_guardian_records_verified_attestation_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            neural, _executor, recorder, _broker = build_local_harness(tmp)
            neural.request_capability({
                "request_id": "att-1",
                "session_id": "att-session",
                "agent_id": "attacker-agent",
                "operation": "object.read",
                "resource_id": "target-source",
                "executor_id": "exec-1",
                "arguments": {"offset": 0, "length": 10},
                "purpose": "attestation test",
            })
            decisions = [
                event for event in recorder.events()
                if event["event_type"] == "guardian.decision"
                and event["payload"].get("guardian") == EXECUTOR_ATTESTATION_GUARDIAN
            ]
            self.assertEqual(len(decisions), 1)
            evidence = decisions[0]["payload"]["evidence"]
            self.assertEqual(evidence["method"], "simulator")
            self.assertEqual(evidence["trust_level"], "simulated")
            self.assertTrue(evidence["bundle_digest"])
            self.assertTrue(evidence["measurement"])

    def test_certificate_is_ed25519_signed_and_binds_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            neural, executor, recorder, _broker = build_local_harness(
                tmp, run_id="cert-run"
            )
            request, capability, attestation = neural.request_capability({
                "request_id": "cert-1",
                "session_id": "cert-session",
                "agent_id": "attacker-agent",
                "operation": "object.read",
                "resource_id": "target-source",
                "executor_id": "exec-1",
                "arguments": {"offset": 0, "length": 10},
                "purpose": "certificate test",
            })
            result = executor.execute(request, capability, attestation)
            self.assertTrue(result.success)
            certificate_builder = ContainmentCertificateBuilder(recorder, b"C" * 32)
            certificate = certificate_builder.build(
                run_id="cert-run", deployment_id="dep-test", trust_root_manifest_digest=None
            )
            self.assertEqual(certificate["algorithm"], "Ed25519")
            payload = certificate["certificate"]
            # This minimal in-process topology has no verifier statements or
            # watchdog teardown events, so completeness must fail closed even
            # though every recorded claim derives from genuine run evidence.
            self.assertEqual(payload["status"], "incomplete")
            self.assertIn(
                "missing required evidence classes", "".join(payload["blocking_reasons"])
            )
            self.assertEqual(payload["session_id"], request.session_id)
            self.assertIn(
                attestation["resultDigest"],
                payload["evidence"]["attestation"]["result_digests"],
            )
            self.assertEqual(payload["claims"]["capability_issued"], "satisfied")
            self.assertTrue(ContainmentCertificateBuilder.verify(
                certificate,
                public_key_pem=certificate_builder.public_key_pem,
                expected_key_id=certificate_builder.key_id,
            ))
            payload["completed_actions"] = 999
            self.assertFalse(ContainmentCertificateBuilder.verify(
                certificate,
                public_key_pem=certificate_builder.public_key_pem,
                expected_key_id=certificate_builder.key_id,
            ))


if __name__ == "__main__":
    unittest.main()
