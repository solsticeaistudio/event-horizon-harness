from __future__ import annotations

import copy
import tempfile
import unittest

from event_horizon.adversarial_boundary import run
from event_horizon.adversarial_evidence import EvidenceVerificationError, verify_report


class SameHostAdversarialBoundaryTests(unittest.TestCase):
    def test_synthetic_replay_forgery_policy_outage_and_restart(self):
        with tempfile.TemporaryDirectory() as root:
            report = run(root)
        self.assertTrue(report["pass"], report)
        verified = verify_report(report)
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["signed_event_count"], report["signed_evidence"]["event_count"])
        self.assertFalse(verified["authenticated_issuer"])
        self.assertTrue(verify_report(
            report, pinned_public_key_pem=report["signed_evidence"]["public_key_pem"]
        )["authenticated_issuer"])
        for attack in ("observation", "receipt", "truncate", "fake_pass", "wrong_key"):
            tampered = copy.deepcopy(report)
            if attack == "observation":
                tampered["observable"]["valid_once"]["success"] = False
            elif attack == "receipt":
                tampered["signed_evidence"]["events"][0]["receipt"]["signature"] = "invalid"
            elif attack == "truncate":
                tampered["signed_evidence"]["events"].pop()
                tampered["signed_evidence"]["event_count"] -= 1
            elif attack == "fake_pass":
                tampered["pass"] = False
            elif attack == "wrong_key":
                tampered["signed_evidence"]["public_key_pem"] = "forged"
            with self.subTest(attack=attack), self.assertRaises(EvidenceVerificationError):
                verify_report(tampered)
        self.assertFalse(report["hardware_isolation_tested"])
        self.assertFalse(report["etcd_backend_tested"])
        self.assertTrue(report["observable"]["replay"]["denied"])
        self.assertTrue(report["observable"]["unsigned_authority"]["denied"])
        self.assertTrue(report["observable"]["out_of_policy"]["denied"])
        self.assertTrue(report["observable"]["signer_outage"]["denied"])
        self.assertTrue(report["observable"]["replay_after_restart"]["denied"])


if __name__ == "__main__":
    unittest.main()
