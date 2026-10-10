"""Independent signed-event integrity and observation checks.

This verifier runs without access to the process harness, any signing key,
SQLite state or mutable process memory. Embedded public keys only establish
self-consistency: to authenticate the issuer, pin its public key out-of-band.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping

from .canonical import digest
from .recorder import ExternalRecorder

EXPECTED_CASES = frozenset({
    "valid_once", "replay", "unsigned_authority", "out_of_policy",
    "executor_private_key_probe", "signer_outage", "replay_after_restart",
})


class EvidenceVerificationError(ValueError):
    pass


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise EvidenceVerificationError(reason)


def verify_report(
    report: Mapping[str, Any],
    *,
    pinned_public_key_pem: str | None = None,
) -> dict[str, Any]:
    """Reject tampering, omission, invented observations, or false PASS.

    An internally valid record does NOT prove the host observation is true.
    It proves that the specified recorder signed the asserted event stream.
    """
    _require(isinstance(report, Mapping), "report is not an object")
    _require(
        report.get("schema") == "event-horizon.adversarial-boundary-observations.v1",
        "unknown report schema",
    )
    _require(
        report.get("topology") == "same-host-seven-process-development",
        "unverified topology",
    )
    _require(
        report.get("hardware_isolation_tested") is False
        and report.get("etcd_backend_tested") is False,
        "report overstates hardware or etcd evidence",
    )
    evidence = report.get("signed_evidence")
    _require(isinstance(evidence, Mapping), "signed evidence is missing")
    key = evidence.get("public_key_pem")
    _require(isinstance(key, str) and key, "recorder public key is missing")
    if pinned_public_key_pem is not None:
        _require(key == pinned_public_key_pem, "recorder key differs from pinned key")
    events = evidence.get("events")
    _require(isinstance(events, list) and len(events) > 0, "events missing")
    _require(
        type(evidence.get("event_count")) is int
        and evidence["event_count"] == len(events),
        "signed event count mismatch",
    )
    previous = "0" * 64
    sources: dict[str, int] = defaultdict(int)
    observations: dict[str, Any] = {}
    completed = 0
    for number, record in enumerate(events, 1):
        _require(isinstance(record, dict), "event entry malformed")
        receipt = record.get("receipt")
        fields = {k: v for k, v in record.items() if k != "receipt"}
        _require(
            set(fields) == {
                "sequence", "timestamp", "event_type", "payload", "source_id",
                "source_sequence", "previous_hash", "event_hash",
            },
            "event fields mismatch",
        )
        _require(type(fields["sequence"]) is int and fields["sequence"] == number,
                 "event sequence missing or reordered")
        _require(fields["previous_hash"] == previous, "event chain broken")
        _require(
            isinstance(fields["source_id"], str)
            and fields["source_sequence"] == sources[fields["source_id"]] + 1,
            "source sequence mismatch",
        )
        actual_hash = digest({k: v for k, v in fields.items() if k != "event_hash"})
        _require(fields["event_hash"] == actual_hash, "event hash mismatch")
        _require(
            isinstance(receipt, dict)
            and ExternalRecorder.verify_receipt(receipt, key),
            "event receipt signature invalid",
        )
        receipt_payload = receipt["payload"]
        for name in ("sequence", "event_hash", "source_id", "source_sequence"):
            _require(receipt_payload[name] == fields[name],
                     "receipt does not bind the event")
        sources[fields["source_id"]] = fields["source_sequence"]
        previous = actual_hash
        if fields["event_type"] == "adversarial.observation":
            _require(fields["source_id"] == "coordinator", "observation source mismatch")
            payload = fields["payload"]
            _require(isinstance(payload, dict) and set(payload) == {"case", "result"},
                     "observation payload malformed")
            case = payload["case"]
            _require(case in EXPECTED_CASES and case not in observations,
                     "duplicate or unknown observation")
            observations[case] = payload["result"]
        if fields["event_type"] == "execution.completed":
            completed += 1
    _require(evidence.get("chain_tip") == previous, "signed chain tip mismatch")
    _require(set(observations) == EXPECTED_CASES, "missing adversarial cases")
    _require(report.get("observable") == observations, "unsigned observation differs")
    _require(completed == 1, "expected exactly one signed successful effect")

    # These checks verify what the recorder asserted. They are not independent
    # host/kernel observations of unauthorized effects.
    success = (
        observations["valid_once"].get("success") is True
        and observations["valid_once"].get("effect_state") == "completed"
        and observations["replay"].get("denied") is True
        and observations["replay"].get("effect_state") == "not-started"
        and observations["unsigned_authority"].get("denied") is True
        and observations["out_of_policy"].get("denied") is True
        and observations["executor_private_key_probe"].get("no_authority_key_in_executor") is True
        and observations["executor_private_key_probe"].get("no_ambient_authority_environment") is True
        and observations["signer_outage"].get("denied") is True
        and observations["signer_outage"].get("effect_state") == "not-started"
        and observations["replay_after_restart"].get("denied") is True
    )
    _require(report.get("pass") is success, "PASS field contradicts signed observations")
    return {
        "verified": True,
        "passed": success,
        "authenticated_issuer": pinned_public_key_pem is not None,
        "signed_event_count": len(events),
        "chain_tip": previous,
        "hardware_isolation_tested": False,
        "etcd_backend_tested": False,
    }
