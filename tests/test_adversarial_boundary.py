from __future__ import annotations

import tempfile
import unittest

from event_horizon.adversarial_boundary import run


class SameHostAdversarialBoundaryTests(unittest.TestCase):
    def test_synthetic_replay_forgery_policy_outage_and_restart(self):
        with tempfile.TemporaryDirectory() as root:
            report = run(root)
        self.assertTrue(report["pass"], report)
        self.assertFalse(report["hardware_isolation_tested"])
        self.assertFalse(report["etcd_backend_tested"])
        self.assertTrue(report["observable"]["replay"]["denied"])
        self.assertTrue(report["observable"]["unsigned_authority"]["denied"])
        self.assertTrue(report["observable"]["out_of_policy"]["denied"])
        self.assertTrue(report["observable"]["signer_outage"]["denied"])
        self.assertTrue(report["observable"]["replay_after_restart"]["denied"])


if __name__ == "__main__":
    unittest.main()
