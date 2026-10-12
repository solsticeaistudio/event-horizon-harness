"""Strict observation checks for the opt-in KVM recipient mode."""
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from scripts.verify_integrated_authority import RECIPIENT_MODE, verify_gateway_process_mode

DIGEST = "a" * 64


def example():
    rounds = []
    for i in range(3):
        rounds.append({
            "observations": {
                "gateway_process_bridge": {
                    "gateway_pid": 5000+i, "supervisor_pid": 4000,
                    "independent_process": True, "guest_vsock_request_path": True,
                    "recorder_resides_in_supervisor": True,
                },
                "external_recipient": {
                    "count": 1, "rows_digest": DIGEST,
                    "recipient_pid": 6000+i, "journal_state": "possibly-committed",
                    "request_digest": DIGEST,
                },
            },
            "isolated_authority": {
                "configuration": {},
                "roles": {str(j): {"pid": 1000 + 20*i + j} for j in range(5)},
                "coordinators": [{"pid": 2000+i}],
            },
        })
    return {"experiment_mode": RECIPIENT_MODE, "rounds": rounds}


class RecipientModeTests(unittest.TestCase):
    def verify(self, value):
        session = SimpleNamespace(request=SimpleNamespace(request_digest=DIGEST))
        with patch("scripts.verify_integrated_authority.SessionAuthority",
                   return_value=session):
            verify_gateway_process_mode(value)

    def test_three_round_recipient_contract(self):
        self.verify(example())

    def test_missing_and_duplicate_commit_claims_fail(self):
        for count in (0, 2, True):
            value = example()
            value["rounds"][1]["observations"]["external_recipient"]["count"] = count
            with self.assertRaises(ValueError):
                self.verify(value)

    def test_not_a_separate_recipient(self):
        value = example()
        value["rounds"][1]["observations"]["external_recipient"]["recipient_pid"] = 5001
        with self.assertRaises(ValueError):
            self.verify(value)

    def test_missing_recipient_fails(self):
        value = example()
        value["rounds"][2]["observations"].pop("external_recipient")
        with self.assertRaises(ValueError):
            self.verify(value)


    def test_confirmed_recipient_report_requires_signed_pid_and_receipt(self):
        doc = example()
        doc["source_commit"] = "f" * 40
        for round_record in doc["rounds"]:
            marker = round_record["observations"]["gateway_process_bridge"]
            marker["identity_binding"] = "pidfd-dispatch-v1"
            round_record["events"] = [{
                "event_type": "execution.dispatch",
                "source_id": "host-effect-service",
                "payload": {"gateway_pid": marker["gateway_pid"],
                            "dispatch_count": 1, "request_digest": DIGEST},
            }]
            recipient = round_record["observations"]["external_recipient"]
            recipient["journal_state"] = "recipient-confirmed"
            recipient["receipt_digest"] = recipient["rows_digest"]
        self.verify(doc)
        doc["rounds"][1]["observations"]["external_recipient"]["receipt_digest"] = "f" * 64
        with self.assertRaises(ValueError):
            self.verify(doc)

    def test_new_commit_cannot_use_old_possibly_committed_recipient_state(self):
        doc = example()
        doc["source_commit"] = "f" * 40
        with self.assertRaises(ValueError):
            self.verify(doc)


if __name__ == "__main__":
    unittest.main()
