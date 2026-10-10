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
STRICT_SCHEMA = "event-horizon.distributed-adversarial-evidence.v2"
REQUIRED_CASES = frozenset({
    "valid_effect", "capability_replay", "executor_credential_probe",
    "authority_outage", "recovery_once", "recovery_replay",
    "signer_restart_replay", "signed_certificate",
    "tampered_arguments", "unsigned_signer_mutation", "guardian_veto",
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
    if report.get("schema") == STRICT_SCHEMA:
        return _verify_strict_report(report, pinned_recorder_public_key=pinned_recorder_public_key)
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

# New reports use v2. Version 1 remains verifiable for historical experiments,
# but v1 "PASS" means signed *coordinator assertions*, not event-derived proof.
def _verify_strict_report(
    report: Mapping[str, Any], *,
    pinned_recorder_public_key: str | None,
) -> dict[str, Any]:
    # Reuse the full signature, hash-chain, source-sequence, and envelope checks.
    legacy = verify_distributed_report(
        {**report, "schema": SCHEMA},
        pinned_recorder_public_key=pinned_recorder_public_key,
    )
    events = report["signed_evidence"]["events"]
    first = "distributed-7-process"
    second = "during-authority-outage"
    # Other harness / service tests may emit additional execution evidence.
    # Match this experiment's seven named coordinator attempts exactly, rather
    # than assuming it is the only producer of execution events in the chain.
    execution_events = [
        event for event in events
        if event["event_type"] in {
            "execution.completed", "execution.denied", "execution.indeterminate",
        }
        and event["source_id"] == "coordinator"
        and isinstance(event["payload"], Mapping)
        and event["payload"].get("request_id") in {first, second}
    ]
    # Six attempts have distinct signed execution events. During the
    # induced authority outage, even denial-evidence append can fail closed;
    # that seventh attempt therefore needs a separately labeled,
    # post-recovery coordinator probe rather than fictitious primary evidence.
    expected = [
        ("valid_effect", first, True, "completed"),
        ("capability_replay", first, False, "not-started"),
        ("tampered_arguments", first, False, "not-started"),
        ("recovery_once", second, True, "completed"),
        ("recovery_replay", second, False, "not-started"),
        ("signer_restart_replay", first, False, "not-started"),
    ]
    _require(
        len(execution_events) == len(expected),
        "signed primary execution-event count differs from test attempts: "
        + repr([(item["event_type"], item["payload"].get("request_id"))
                for item in execution_events]),
    )
    derived: dict[str, bool] = {}
    for event, (case, request_id, successful, state) in zip(
        execution_events, expected, strict=True,
    ):
        payload = event["payload"]
        _require(event["source_id"] == "coordinator"
                 and isinstance(payload, Mapping)
                 and payload.get("request_id") == request_id
                 and type(payload.get("success")) is bool
                 and payload["success"] is successful
                 and payload.get("effect_state") == state
                 and event["event_type"] == (
                     "execution.completed" if successful else "execution.denied"
                 ), f"{case}: missing or contradictory signed execution record")
        derived[case] = True
    issued = [
        event["payload"].get("request_id")
        for event in events if event["event_type"] == "capability.issued"
    ]
    _require(issued == [first, second],
             "signed capability issues do not match the two authorized requests")
    # These five cases have no complete independent source-side oracle in this topology.
    # Require signed *raw observations*, not bare case/pass booleans, and
    # disclose the remaining coordinator trust assumption to evaluators.
    probes = {}
    for event in events:
        if event["event_type"] != "adversarial.probe":
            continue
        payload = event["payload"]
        _require(event["source_id"] == "coordinator"
                 and isinstance(payload, Mapping)
                 and set(payload) == {"case", "observation"}
                 and payload["case"] not in probes
                 and isinstance(payload["observation"], Mapping),
                 "malformed or repeated signed probe")
        probes[payload["case"]] = payload["observation"]
    _require(set(probes) == {
        "executor_credential_probe", "unsigned_signer_mutation",
        "guardian_veto", "signed_certificate", "authority_outage",
    }, "missing signed raw coordinator probe")
    root = probes["executor_credential_probe"]
    derived["executor_credential_probe"] = (
        root.get("private_key_material_present") is False
        and root.get("ambient_authority_environment_hits") == []
        and root.get("executor_config_has_remote_replay") is False
    )
    # The outage probe is signed after authority recovery; this is a
    # coordinator observation, NOT an independently authenticated denial.
    derived["authority_outage"] = (
        probes["authority_outage"] == {
            "success": False, "effect_state": "not-started",
            "evidence_gap": "authority-unavailable",
        }
    )
    derived["unsigned_signer_mutation"] = (
        probes["unsigned_signer_mutation"] == {"denied": True}
    )
    derived["guardian_veto"] = (
        probes["guardian_veto"] == {
            "denied": True, "request_id": "forbidden-distributed-op",
        }
    )
    derived["signed_certificate"] = (
        probes["signed_certificate"] == {
            "certificate_schema": "event-horizon.containment-certificate.v0.5",
        }
    )
    _require(all(derived.values()), "signed raw coordinator probe does not support PASS")
    _require(derived == report["observations"],
             "claimed outcomes disagree with signed primary events/probes")
    contexts = [
        event for event in events
        if event["event_type"] == "distributed.authority.context"
    ]
    _require(len(contexts) == 1 and contexts[0]["source_id"] == "coordinator",
             "signed distributed authority context missing")
    authority = contexts[0]["payload"]
    import re
    _require(isinstance(authority, Mapping)
             and set(authority) == {
                 "cluster_id", "service_id", "epoch",
                 "checkpoint", "checkpoint_digest",
             }
             and isinstance(authority["cluster_id"], str)
             and authority["cluster_id"].isdecimal()
             and int(authority["cluster_id"]) > 0
             and isinstance(authority["service_id"], str)
             and authority["service_id"]
             and type(authority["epoch"]) is int
             and authority["epoch"] > 0
             and type(authority["checkpoint"]) is int
             and authority["checkpoint"] >= 10
             and isinstance(authority["checkpoint_digest"], str)
             and re.fullmatch(r"[a-f0-9]{64}", authority["checkpoint_digest"]) is not None,
             "signed etcd identity/checkpoint context malformed")
    return {
        **legacy,
        "event_derived_execution_cases": len(expected),
        "signed_coordinator_probe_cases": len(probes),
        "signed_authority_context": True,
        "independent_cluster_attestation": False,
    }
