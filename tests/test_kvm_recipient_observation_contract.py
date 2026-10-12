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


if __name__ == "__main__":
    unittest.main()
