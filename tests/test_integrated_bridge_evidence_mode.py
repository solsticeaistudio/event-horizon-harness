"""Tamper tests for the stricter bridged-KVM experiment mode contract.

This only tests structural mode acceptance; the enclosing v4 verifier continues
to validate signed receipts, guardian approvals, real etcd and guest checks.
"""
import copy
import unittest

from scripts.verify_integrated_authority import (
    BASE_MODE, BRIDGED_MODE, verify_gateway_process_mode,
)


def fixture(bridged=True):
    rounds = []
    for index in range(3):
        roles = {f"role{i}": {"pid": 1100 + index * 20 + i}
                 for i in range(5)}
        observation = {}
        if bridged:
            observation["gateway_process_bridge"] = {
                "gateway_pid": 5000 + index,
                "supervisor_pid": 4000,
                "independent_process": True,
                "guest_vsock_request_path": True,
                "recorder_resides_in_supervisor": True,
            }
        rounds.append({
            "observations": observation,
            "isolated_authority": {
                "roles": roles,
                "coordinators": [{"pid": 2000 + index}],
            },
        })
    return {"experiment_mode": BRIDGED_MODE if bridged else BASE_MODE,
            "rounds": rounds}


class BridgedEvidenceModeTests(unittest.TestCase):
    def test_all_three_distinct_gateway_observations_required(self):
        verify_gateway_process_mode(fixture())

    def test_historical_v4_mode_remains_valid(self):
        verify_gateway_process_mode(fixture(bridged=False))

    def test_unrecognized_mode_refused(self):
        doc = fixture()
        doc["experiment_mode"] = "host-process-sigkill"
        with self.assertRaisesRegex(ValueError, "wrong experiment mode"):
            verify_gateway_process_mode(doc)

    def test_missing_bridge_in_any_round_is_denied(self):
        for index in range(3):
            doc = fixture()
            doc["rounds"][index]["observations"].pop("gateway_process_bridge")
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify_gateway_process_mode(doc)

    def test_baseline_cannot_claim_bridge(self):
        doc = fixture(bridged=False)
        doc["rounds"][0]["observations"]["gateway_process_bridge"] = fixture()["rounds"][0]["observations"]["gateway_process_bridge"]
        with self.assertRaises(ValueError):
            verify_gateway_process_mode(doc)

    def test_tampered_gateway_identity_and_mode_flags_are_rejected(self):
        mutations = (
            ("gateway_pid", 4000),
            ("gateway_pid", True),
            ("gateway_pid", 1120),
            ("gateway_pid", 2001),
            ("supervisor_pid", 2001),
            ("independent_process", False),
            ("guest_vsock_request_path", False),
            ("recorder_resides_in_supervisor", False),
            ("unexpected", True),
        )
        for name, value in mutations:
            doc = fixture()
            doc["rounds"][1]["observations"]["gateway_process_bridge"][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                verify_gateway_process_mode(doc)

    def test_fewer_than_three_rounds_cannot_pass(self):
        doc = fixture()
        doc["rounds"].pop()
        with self.assertRaises(ValueError):
            verify_gateway_process_mode(doc)


    def test_new_process_identity_binding_is_in_signed_dispatch(self):
        document = fixture()
        document["source_commit"] = "f" * 40
        for index, round_record in enumerate(document["rounds"]):
            marker = round_record["observations"]["gateway_process_bridge"]
            marker["identity_binding"] = "pidfd-dispatch-v1"
            round_record["events"] = [{
                "event_type": "execution.dispatch",
                "source_id": "host-effect-service",
                "payload": {
                    "request_digest": "a" * 64,
                    "dispatch_count": 1,
                    "gateway_pid": marker["gateway_pid"],
                },
            }]
        verify_gateway_process_mode(document)
        document["rounds"][1]["events"][0]["payload"]["gateway_pid"] += 1
        with self.assertRaises(ValueError):
            verify_gateway_process_mode(document)

    def test_new_commit_cannot_claim_legacy_pid_marker(self):
        document = fixture()
        document["source_commit"] = "f" * 40
        with self.assertRaises(ValueError):
            verify_gateway_process_mode(document)



if __name__ == "__main__":
    unittest.main()
