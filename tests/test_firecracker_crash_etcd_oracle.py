"""Opt-in fault+fresh-token etcd oracle: no KVM claim from unit fixtures."""
import unittest

from scripts.package_authority_oracle import inspect_committed_consumption
from tests.test_package_authority_oracle import (
    CLUSTER, PREFIX, CAP, BINDING, EXPIRY, b64, reply, signed_record,
)

FAULT = "cap_aaaaaaaaaaaaaaaaaaaaaaaa"
SPARE = "cap_bbbbbbbbbbbbbbbbbbbbbbbb"


class CrashRecoveryEtcdOracleTests(unittest.TestCase):
    def options(self, *, enabled):
        return {
            "cluster_id": CLUSTER, "session_id": "ehk-abc123",
            "capability_id": CAP, "claims_digest": BINDING,
            "expires_at": EXPIRY,
            "extra_bindings": {
                FAULT: ("b" * 64, EXPIRY),
                SPARE: ("c" * 64, EXPIRY),
            },
            "allow_crash_recovery_spare": enabled,
        }

    def rows(self, *, forged=False):
        value = reply()
        data = value["responses"][0]["response_range"]
        data["count"] = "3"
        data["kvs"].extend([
            {"key": b64((PREFIX + FAULT).encode()),
             "value": b64(signed_record(binding="b" * 64))},
            {"key": b64((PREFIX + SPARE).encode()),
             "value": b64(signed_record(binding=("f" if forged else "c") * 64))},
        ])
        return value

    def test_opt_in_only_accepts_exact_three_known_consumptions(self):
        fixture = self.rows()
        received = []
        result = inspect_committed_consumption(
            lambda txn: received.append(txn) or fixture,
            **self.options(enabled=True),
        )
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["primary_record_count"], 1)
        self.assertEqual(set(result["additional_consumed_ids"]), {FAULT, SPARE})
        self.assertEqual(received[0]["success"][0]["requestRange"]["limit"], "4")

    def test_original_integrated_oracle_still_rejects_two_extras(self):
        with self.assertRaises(ValueError):
            inspect_committed_consumption(lambda txn: self.rows(),
                                          **self.options(enabled=False))

    def test_wrong_spare_binding_is_rejected_even_with_opt_in(self):
        with self.assertRaises(ValueError):
            inspect_committed_consumption(lambda txn: self.rows(forged=True),
                                          **self.options(enabled=True))


if __name__ == "__main__":
    unittest.main()
