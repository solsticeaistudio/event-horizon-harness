"""Independently verify EHH's signed software-only distributed experiment.

The embedded recorder public key proves internal cryptographic consistency,
NOT trusted issuer identity. Supply a separately pinned key to authenticate
the source. No result here establishes KVM/host isolation.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping

from .canonical import digest
from .recorder import ExternalRecorder

SCHEMA = "event-horizon.distributed-adversarial-evidence.v1"
REQUIRED_CASES = frozenset({
    "valid_effect", "capability_replay", "executor_credential_probe",
    "authority_outage", "recovery_once", "recovery_replay",
    "signer_restart_replay", "signed_certificate",
})


class DistributedEvidenceError(ValueError):
    pass


def _require(value: bool, message: str) -> None:
    if not value:
        raise DistributedEvidenceError(message)


def verify_distributed_report(
    report: Mapping[str, Any],
    *,
    pinned_recorder_public_key: str | None = None,
) -> dict[str, Any]:
    _require(isinstance(report, Mapping), "report must be a mapping")
    _require(report.get("schema") == SCHEMA, "unknown report schema")
    _require(report.get("topology") == "same-host-seven-process-live-etcd",
             "unsupported proof topology")
    _require(report.get("hardware_isolation_tested") is False,
             "hardware isolation cannot be claimed by this report")
    _require(report.get("etcd_backend_tested") is True,
             "signed report lacks etcd backend provenance")
    envelope = report.get("signed_evidence")
    _require(isinstance(envelope, Mapping), "signed evidence envelope missing")
    public_key = envelope.get("recorder_public_key_pem")
    _require(isinstance(public_key, str) and public_key, "recorder key missing")
    if pinned_recorder_public_key is not None:
        _require(public_key == pinned_recorder_public_key,
                 "recorder identity differs from out-of-band pinned key")
    events = envelope.get("events")
    _require(isinstance(events, list) and bool(events), "signed events missing")
    _require(type(envelope.get("event_count")) is int
             and envelope["event_count"] == len(events), "evidence count mismatch")
    expected_fields = {
        "sequence", "timestamp", "event_type", "payload", "source_id",
        "source_sequence", "previous_hash", "event_hash",
    }
    previous = "0" * 64
    seq_by_source: dict[str, int] = defaultdict(int)
    checks: dict[str, bool] = {}
    completions = 0
    issuance = 0
    for n, item in enumerate(events, 1):
        _require(isinstance(item, dict) and set(item) == expected_fields | {"receipt"},
                 "signed event fields malformed")
        event = {k: v for k, v in item.items() if k != "receipt"}
        _require(type(event["sequence"]) is int and event["sequence"] == n,
                 "global event sequence altered")
        _require(event["previous_hash"] == previous, "signed event chain broken")
        source = event["source_id"]
        _require(isinstance(source, str) and source
                 and type(event["source_sequence"]) is int
                 and event["source_sequence"] == seq_by_source[source] + 1,
                 "source-specific evidence sequence altered")
        calculated = digest({k: v for k, v in event.items() if k != "event_hash"})
        _require(event["event_hash"] == calculated, "signed event hash mismatch")
        receipt = item["receipt"]
        _require(
            isinstance(receipt, dict)
            and ExternalRecorder.verify_receipt(receipt, public_key),
            "recorder event receipt signature invalid",
        )
        for bound in ("sequence", "event_hash", "source_id", "source_sequence"):
            _require(receipt["payload"][bound] == event[bound],
                     "recorder receipt does not bind event")
        previous = calculated
        seq_by_source[source] = event["source_sequence"]
        if event["event_type"] == "execution.completed":
            completions += 1
        if event["event_type"] == "capability.issued":
            issuance += 1
        if event["event_type"] == "adversarial.observation":
            payload = event["payload"]
            _require(
                source == "coordinator"
                and isinstance(payload, dict)
                and set(payload) == {"case", "passed"}
                and payload["case"] in REQUIRED_CASES
                and type(payload["passed"]) is bool
                and payload["case"] not in checks,
                "signed adversarial observation is invalid",
            )
            checks[payload["case"]] = payload["passed"]
    _require(previous == envelope.get("chain_tip"), "chain tip mismatch")
    _require(set(checks) == REQUIRED_CASES, "signed adversarial checks incomplete")
    _require(report.get("observations") == checks, "unsigned observations substituted")
    _require(completions == 2, "expected exactly two signed completed effects")
    _require(issuance == 2, "expected exactly two issued capabilities")
    _require(report.get("passed") is all(checks.values()),
             "overall PASS contradicts signed case results")
    return {
        "verified": True,
        "passed": all(checks.values()),
        "authenticated_recorder_identity": pinned_recorder_public_key is not None,
        "evidence_records": len(events),
        "chain_tip": previous,
        "hardware_isolation_tested": False,
        "etcd_backend_tested": True,
    }
