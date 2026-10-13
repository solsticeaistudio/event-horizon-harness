"""Negative controls for host-signed recipient downtime and new KVM schema."""
from __future__ import annotations
import unittest

from scripts.gateway_evidence_contract import (
    GatewayEventContract, GatewayEvidenceContractError,
)
from scripts.verify_integrated_kvm_recipient_crash import verify_report


HASH = "a" * 64
CAP = "original-cap"


def frame(kind, payload):
    return {
        "event_type": kind, "source_id": "host-effect-service",
        "payload": payload,
    }


class RecipientFaultEvidenceTests(unittest.TestCase):

    def make_contract(self):
        contract = GatewayEventContract(
            gateway_pid=7001, request_digest=HASH,
            request_id="dataset-read", capability_id=CAP,
            fenced_recipient_id="ehh-owned-kvm-fenced-v1",
            fenced_original_capability_id=CAP,
        )
        contract.begin_request({
            "capability": {"claims": {"capability_id": CAP}},
        })
        return contract

    def auth(self, capability=CAP):
        return frame("fenced.authorized", {
            "request_id": "dataset-read",
            "request_digest": HASH,
            "capability_id": capability,
        })

    def indeterminate(self, **overrides):
        return frame("fenced.indeterminate", {
            "request_id": "dataset-read",
            "request_digest": HASH,
            "capability_id": CAP,
            "effect_state": "possibly-committed",
            **overrides,
        })

    def test_original_downtime_then_new_signed_capability(self):
        contract = self.make_contract()
        contract.check(self.auth())
        contract.check(self.indeterminate())
        contract.end_request()
        contract.begin_request({
            "capability": {"claims": {"capability_id": "fresh-cap"}},
        })
        contract.check(self.auth("fresh-cap"))
        self.assertFalse(contract.finished)

    def test_indeterminate_cannot_be_substituted_before_authorization(self):
        with self.assertRaises(GatewayEvidenceContractError):
            self.make_contract().check(self.indeterminate())

    def test_guest_cannot_forge_a_clearance_to_reuse_original(self):
        for event in (
            self.indeterminate(effect_state="not-started"),
            self.indeterminate(capability_id="other-cap"),
            self.indeterminate(request_digest="0" * 64),
            self.indeterminate(extra=True),
            self.indeterminate() | {"source_id": "host-supervisor"},
        ):
            with self.subTest(event=event):
                contract = self.make_contract()
                contract.check(self.auth())
                with self.assertRaises(GatewayEvidenceContractError):
                    contract.check(event)

    def test_unverified_or_portable_hardware_evidence_rejected(self):
        for report in (
            {},
            {"schema": "event-horizon.firecracker-fenced-gateway-crash-recovery.v1"},
            {"schema": "event-horizon.firecracker-fenced-recipient-crash-recovery.v1",
             "experiment_mode": "portable-linux-only", "status": "PASS",
             "rounds": [{}, {}]},
            {"schema": "event-horizon.firecracker-fenced-recipient-crash-recovery.v1",
             "experiment_mode": "real-kvm-guardian-etcd-fenced-recipient-restart",
             "status": "INCOMPLETE", "rounds": [{}, {}]},
        ):
            with self.subTest(report=report), self.assertRaises(ValueError):
                verify_report(report)


if __name__ == "__main__":
    unittest.main()
