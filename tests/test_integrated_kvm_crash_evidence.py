"""New KVM crash evidence MUST reject all portable/incomplete substitutes."""
import copy
import unittest

from scripts.real_gateway_crash_checkpoints import PHASES
from scripts.verify_integrated_kvm_crash import SCHEMA, MODE, verify_report


def candidate():
    return {
        "schema": SCHEMA,
        "experiment_mode": MODE,
        "source_commit": "a" * 40,
        "status": "PASS",
        "attestation": "synthetic-fixture",
        "build_manifest": {"tpm2_enabled": False},
        "authority": {
            "backend": "etcd",
            "cluster_id": "139003440588",
            "oracle": "host-supervisor-linearizable-etcd-read",
        },
        "rounds": [{} for _ in PHASES],
    }


class FirecrackerCrashEvidenceGateTests(unittest.TestCase):
    def test_host_process_campaign_cannot_pass_as_kvm(self):
        document = candidate()
        document["schema"] = "event-horizon.effect-process-crash.v1"
        with self.assertRaises(ValueError):
            verify_report(document)

    def test_incomplete_or_four_windows_are_never_a_pass(self):
        for modification in (
            lambda d: d.update(status="INCOMPLETE"),
            lambda d: d["rounds"].pop(),
            lambda d: d.update(experiment_mode="linux-host-process-sigkill"),
            lambda d: d.update(attestation="hardware-trusted"),
            lambda d: d["build_manifest"].update(tpm2_enabled=True),
            lambda d: d["authority"].update(backend="sqlite"),
            lambda d: d["authority"].update(cluster_id="not-our-etcd"),
        ):
            value = candidate()
            modification(value)
            with self.assertRaises((ValueError, KeyError, TypeError)):
                verify_report(value)

    def test_fake_pass_with_no_guest_or_signer_receipts_is_rejected(self):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            verify_report(candidate())


if __name__ == "__main__":
    unittest.main()
