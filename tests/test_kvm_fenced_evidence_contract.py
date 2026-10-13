"""Portable contract tests for new KVM fenced mode (NOT hardware proof)."""
from __future__ import annotations

import unittest

from scripts.gateway_evidence_contract import (
    GatewayEventContract, GatewayEvidenceContractError,
)
from scripts.verify_integrated_kvm_fenced_baseline import verify_report


HASH = "a" * 64
RECEIPT = "b" * 64


def event(kind, payload):
    return {"source_id": "host-effect-service", "event_type": kind,
            "payload": payload}


def contract():
    gate = GatewayEventContract(
        gateway_pid=7701, request_digest=HASH, request_id="dataset-read",
        capability_id="original", fenced_recipient_id="ehh-owned-kvm-fenced-v1",
    )
    gate.begin_request({"capability": {"claims": {"capability_id": "original"}}})
    return gate


def authorized(cap="original"):
    return event("fenced.authorized", {
        "request_id": "dataset-read", "request_digest": HASH,
        "capability_id": cap,
    })


def confirmed(*, cap="original", original="original",
              recovered=False, committed=True, receipt=RECEIPT):
    return event("fenced.recipient-confirmed", {
        "request_id": "dataset-read", "request_digest": HASH,
        "capability_id": cap, "original_capability_id": original,
        "receipt_digest": receipt, "recipient_id": "ehh-owned-kvm-fenced-v1",
        "commit_sequence": 1, "recovery": recovered,
        "new_effect_commit": committed,
    })


class KvmFencedEvidenceContractTests(unittest.TestCase):
    def test_positive_atomic_commit_is_accepted(self):
        c = contract()
        c.check(authorized())
        c.check(confirmed())
        self.assertTrue(c.finished)
        self.assertEqual(c.original_capability_id, "original")

    def test_fresh_recovery_preserves_original_id_and_no_new_commit(self):
        c = contract()
        c.check(authorized())
        c.check(confirmed())
        c.end_request()
        c.begin_request({"capability": {"claims": {"capability_id": "fresh"}}})
        c.check(authorized("fresh"))
        c.check(confirmed(cap="fresh", recovered=True, committed=False))
        self.assertEqual(c.original_capability_id, "original")

    def test_forged_receipts_and_origins_fail_closed(self):
        for forged in (
            confirmed(original="attacker"),
            confirmed(committed=False),
            confirmed(recovered=True),
            confirmed(receipt="not-digest"),
            confirmed() | {"source_id": "host-supervisor"},
            confirmed() | {"payload": {**confirmed()["payload"], "recipient_id": "other"}},
            confirmed() | {"payload": {**confirmed()["payload"], "commit_sequence": True}},
        ):
            with self.subTest(forged=forged):
                c = contract()
                c.check(authorized())
                with self.assertRaises(GatewayEvidenceContractError):
                    c.check(forged)

    def test_cannot_complete_before_signed_authorization(self):
        with self.assertRaises(GatewayEvidenceContractError):
            contract().check(confirmed())

    def test_old_evidence_contract_rejects_fenced_namespace(self):
        c = GatewayEventContract(
            gateway_pid=7701, request_digest=HASH,
            request_id="dataset-read", capability_id="original",
        )
        c.begin_request({"capability": {"claims": {"capability_id": "original"}}})
        with self.assertRaises(GatewayEvidenceContractError):
            c.check(authorized())

    def test_unsupported_synthetic_hardware_report_rejected(self):
        for falsified in (
            {}, {"schema": "event-horizon.firecracker-inflight-recipient-sigkill.v1"},
            {"schema": "event-horizon.firecracker-fenced-recipient-baseline.v1",
             "experiment_mode": "portable-linux-only", "status": "PASS", "rounds": [{}]},
            {"schema": "event-horizon.firecracker-fenced-recipient-baseline.v1",
             "experiment_mode": "real-kvm-guardian-etcd-atomic-fenced-recipient-baseline",
             "status": "INCOMPLETE", "rounds": [{}]},
        ):
            with self.subTest(report=falsified), self.assertRaises(ValueError):
                verify_report(falsified)


if __name__ == "__main__":
    unittest.main()
