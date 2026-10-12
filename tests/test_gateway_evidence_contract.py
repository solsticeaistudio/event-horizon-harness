"""Untrusted child evidence cannot request arbitrary supervisor signatures."""
import unittest

from scripts.gateway_evidence_contract import (
    GatewayEventContract, GatewayEvidenceContractError,
)

HASH = "a" * 64
PID = 4201
CAP = "cap_original"


def contract():
    c = GatewayEventContract(
        gateway_pid=PID, request_digest=HASH,
        request_id="dataset-read", capability_id=CAP,
    )
    c.begin_request({"capability": {"claims": {"capability_id": CAP}}})
    return c


def evidence(kind, payload):
    return {"source_id": "host-effect-service", "event_type": kind,
            "payload": payload}


def auth(cap=CAP):
    return evidence("execution.authorized", {
        "request_id": "dataset-read", "request_digest": HASH,
        "capability_id": cap,
    })


def dispatch(pid=PID):
    return evidence("execution.dispatch", {
        "request_digest": HASH, "dispatch_count": 1, "gateway_pid": pid,
    })


def complete():
    return evidence("execution.completed", {
        "request_id": "dataset-read", "capability_id": CAP,
        "success": True, "output_bytes": 74, "effect_state": "completed",
    })


class EvidenceContractTests(unittest.TestCase):
    def test_valid_lifecycle_and_second_capability_without_dispatch(self):
        c = contract()
        c.check(auth())
        c.check(dispatch())
        c.check(complete())
        c.end_request()
        c.begin_request({"capability": {"claims": {"capability_id": "fresh"}}})
        c.check(auth("fresh"))
        with self.assertRaises(GatewayEvidenceContractError):
            c.check(dispatch())
        with self.assertRaises(GatewayEvidenceContractError):
            c.check(complete())

    def test_untrusted_child_cannot_forge_completed_or_pid(self):
        for event in (
            complete(),
            dispatch(),
            evidence("execution.completed", {
                "request_id": "dataset-read", "capability_id": CAP,
                "success": True, "output_bytes": 0, "effect_state": "completed",
            }),
            evidence("isolation.observed", {"all": True}),
            evidence("teardown.verified", {"all": True}),
            evidence("execution.authorized", {"request_id": "dataset-read",
                  "capability_id": "attacker", "request_digest": HASH}),
        ):
            with self.subTest(event=event):
                with self.assertRaises(GatewayEvidenceContractError):
                    contract().check(event)

    def test_pid_substitution_rejected_even_after_authorization(self):
        c = contract()
        c.check(auth())
        for pid in (PID + 1, True, "4201"):
            with self.subTest(pid=pid), self.assertRaises(GatewayEvidenceContractError):
                c.check(dispatch(pid))

    def test_completed_requires_dispatch_and_bounded_shape(self):
        c = contract()
        c.check(auth())
        with self.assertRaises(GatewayEvidenceContractError):
            c.check(complete())
        c.check(dispatch())
        for bad in (
            complete() | {"source_id": "host-supervisor"},
            evidence("execution.completed", complete()["payload"] | {"extra": 7}),
            evidence("execution.completed", complete()["payload"] | {"output_bytes": True}),
            evidence("execution.completed", complete()["payload"] | {"output_bytes": 10**9}),
            evidence("execution.completed", complete()["payload"] | {"success": "true"}),
        ):
            with self.assertRaises(GatewayEvidenceContractError):
                c.check(bad)

    def test_denial_shapes_restricted(self):
        c = contract()
        c.check(evidence("execution.denied", {
            "source": "effect-boundary", "effect_state": "not-started",
        }))
        c.check(evidence("execution.denied", {
            "request_id": "dataset-read", "error_class": "authority-denied",
            "effect_state": "not-started",
        }))
        for payload in (
            {"source": "effect-boundary", "effect_state": "completed"},
            {"request_id": "dataset-read", "error_class": "completed",
             "effect_state": "not-started"},
        ):
            with self.assertRaises(GatewayEvidenceContractError):
                c.check(evidence("execution.denied", payload))


if __name__ == "__main__":
    unittest.main()
