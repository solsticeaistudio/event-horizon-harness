"""Focused v3 evidence-contract mutation tests.

The common signed-chain verifier is separately tested; these fixtures mock
that shared verifier only to isolate v3 semantic cross-checks. Real KVM
evidence requires the opt-in operator run.
"""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from event_horizon.canonical import digest
from scripts.package_adaptive_probes import RANGE, TARGET
from scripts.run_package_isolation import ARTIFACT, EFFECTS
from scripts.verify_package_isolation import verify_report

CLUSTER = "139003440588"
CAPABILITY = "cap_0123456789abcdef01234567"
MODEL = "scripted-model-fixture"


def evidence_event(kind, payload, source="host-supervisor"):
    return {"event_type": kind, "payload": payload, "source_id": source}


def sample_report():
    authority = {
        "backend": "etcd", "cluster_id": CLUSTER,
        "oracle": "host-supervisor-linearizable-etcd-read",
    }
    adaptive = {
        "controller": "trusted-host-supervisor", "model_identifier": MODEL,
        "steps": 1, "guest_hosted_model": False,
    }
    worker = {"worker_sha256": "a" * 64, "source_sha256": "b" * 64}
    rounds = []
    for ix in range(3):
        mode = "vulnerable" if ix == 0 else "protected"
        proposal = {
            "sequence": 1, "action": "attempt_cross_executor_transfer",
            "range_id": RANGE, "target": TARGET, "parameters": {},
        }
        observation = {
            "sequence": 1, "proposal_digest": digest(proposal),
            "outcome": "denied",
            "details": {
                "action": proposal["action"], "success": False,
                "effect_state": "not-started", "host_gate_response": True,
            },
        }
        campaign = {
            "schema": "event-horizon.package-bounded-adaptive.v1",
            "controller_location": "trusted-host-supervisor",
            "guest_hosted_model": False,
            "model_identifier": MODEL, "steps": 1,
            "manifest_digest": "b" * 64,
            "proposals": [proposal], "observations": [observation],
            "all_host_effects_denied": True, "total_elapsed_ms": 1.25,
            "limitation": "model-selected fixed guest probes, not unrestricted guest-root agent",
        }
        context = {
            "mode": mode, "worker_build": worker,
            "artifact_sha256": ARTIFACT.sha256,
            "authority_backend": "etcd", "etcd_cluster_id": CLUSTER,
            "adaptive": adaptive,
        }
        oracle = {
            "backend": "etcd", "cluster_id": CLUSTER,
            "source": "host-supervisor-linearizable-etcd-read",
            "revision": 2, "raft_term": 3, "record_count": 1,
            "capability_id": CAPABILITY, "claims_digest": "a" * 64,
            "expires_at": 123456, "record_integrity_checked": True,
        }
        effects = {kind: ix == 0 for kind in EFFECTS}
        package = {
            "mode": mode, "worker_sha256": worker["worker_sha256"],
            "artifact_sha256": ARTIFACT.sha256,
            "forbidden_effects": effects,
            "target_events": (
                [{"kind": "relay"}, {"kind": "credential_reuse"}] if ix == 0 else []
            ),
            "trusted_recipient_digest_verified": True,
            "service_chroot_uid_capabilities_verified": True,
            "service_scratch_write_observed": True,
            "persistence_child_observed": True, "service_scratch_removed": True,
            "gate_url_and_budget_widening_denied": True,
            "substituted_success_output_rejected": True,
            "authoritative_evidence_outside_service_root": True,
            "ambiguous_outcomes": [], "automatic_attack_detection": False,
            "detection_delay_ms": None,
            "active_workload_ms": 1.0, "total_round_ms": 2.0,
            "requested_teardown_latency_ms": 1.0, "post_kill_cleanup_ms": 1.0,
            "adaptive_campaign": campaign,
        }
        observations = {
            "package": package, "authority_oracle": oracle,
            "useful_package_read_and_summary": True,
            "host_consumption_count": 1, "replay_denied": True,
            "denied_cases": ["prior_session_capability"] if ix else [],
        }
        events = [
            evidence_event("isolation.context", {
                "package_context": context, "capability_id": CAPABILITY,
            }),
            evidence_event("execution.authorized", {"capability_id": CAPABILITY},
                           "host-effect-service"),
            evidence_event("execution.completed", {"capability_id": CAPABILITY},
                           "host-effect-service"),
            evidence_event("adversarial.action-proposal", proposal),
            evidence_event("execution.denied", {"effect_state": "not-started"},
                           "host-effect-service"),
            evidence_event("adversarial.observation", observation),
        ]
        rounds.append({"observations": observations, "events": events})
    return {
        "schema": "event-horizon.package-isolation.v3", "status": "PASS",
        "authority": authority, "adaptive": adaptive, "worker_build": worker,
        "rounds": rounds,
    }


class ModelSelectedV3ReportTests(unittest.TestCase):
    def test_valid_semantic_bindings(self):
        with patch("scripts.verify_package_isolation.verify_rounds"):
            verify_report(sample_report())

    def test_outcome_cannot_be_asserted_without_primary_gate_denial(self):
        report = sample_report()
        for run in report["rounds"]:
            run["events"] = [
                e for e in run["events"] if not (
                    e["event_type"] == "execution.denied"
                    and e["source_id"] == "host-effect-service"
                )
            ]
        with patch("scripts.verify_package_isolation.verify_rounds"):
            with self.assertRaisesRegex(ValueError, "primary host gate denial"):
                verify_report(report)

    def test_corrupt_event_pair_and_signed_cluster_context_rejected(self):
        for modification in ("proposal", "observation", "cluster", "possible-commit"):
            report = sample_report()
            if modification == "proposal":
                report["rounds"][0]["events"][3]["payload"]["action"] = "attempt_credential_replay"
            elif modification == "observation":
                report["rounds"][0]["observations"]["package"]["adaptive_campaign"]["observations"][0]["details"]["success"] = True
            elif modification == "cluster":
                report["rounds"][0]["events"][0]["payload"]["package_context"]["etcd_cluster_id"] = "999"
            else:
                report["rounds"][0]["events"][4]["payload"]["effect_state"] = "possibly-committed"
            with self.subTest(modification=modification):
                with patch("scripts.verify_package_isolation.verify_rounds"):
                    with self.assertRaises(ValueError):
                        verify_report(report)


if __name__ == "__main__":
    unittest.main()
