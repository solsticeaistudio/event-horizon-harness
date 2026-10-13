"""Negative controls: portable/downgraded/fabricated KVM transport evidence."""

from __future__ import annotations
import unittest

from scripts.verify_integrated_kvm_ack_loss import verify_report as verify_ack
from scripts.verify_integrated_kvm_racing_recovery import verify_report as verify_race


class FencedKvmTransportEvidenceTests(unittest.TestCase):
    def test_unproven_hardware_claims_never_verify(self):
        for verifier, schema, mode in (
            (verify_ack,
             "event-horizon.firecracker-fenced-recipient-ack-loss-recovery.v1",
             "real-kvm-guardian-etcd-fenced-ack-loss"),
            (verify_race,
             "event-horizon.firecracker-fenced-competing-recovery.v1",
             "real-kvm-guardian-etcd-competing-fenced-recovery"),
        ):
            for candidate in (
                {},
                {"schema": schema, "experiment_mode": mode,
                 "status": "INCOMPLETE", "rounds": [{}]},
                {"schema": schema, "experiment_mode": "portable-linux-only",
                 "status": "PASS", "rounds": [{}]},
                {"schema": schema, "experiment_mode": mode,
                 "status": "PASS", "rounds": [{}],
                 "source_commit": "0" * 40, "attestation": "synthetic-fixture",
                 "build_manifest": {"tpm2_enabled": False}},
                {"schema": schema, "experiment_mode": mode,
                 "status": "PASS", "rounds": [],
                 "source_commit": "0" * 40, "attestation": "synthetic-fixture"},
            ):
                with self.subTest(schema=schema, report=candidate), self.assertRaises(
                    (ValueError, TypeError, KeyError, IndexError)
                ):
                    verifier(candidate)


if __name__ == "__main__":
    unittest.main()
