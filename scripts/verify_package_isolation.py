"""Verify signed paired package-lab observations; embedded keys give integrity only."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from event_horizon.protocol import _object_without_duplicates, _reject_constant  # noqa: E402
from scripts.run_package_isolation import ARTIFACT, EFFECTS  # noqa: E402
from scripts.verify_linux_isolation import verify_rounds  # noqa: E402


def verify_report(report: dict) -> None:
    schema = report["schema"]
    if schema not in {"event-horizon.package-isolation.v1", "event-horizon.package-isolation.v2"}:
        raise ValueError("unknown package experiment evidence schema")
    distributed = schema.endswith(".v2")
    authority = report.get("authority", {"backend": "sqlite"} if not distributed else None)
    if not isinstance(authority, dict):
        raise ValueError("missing report authority identity")
    if distributed:
        if (set(authority) != {"backend", "cluster_id", "oracle"}
                or authority["backend"] != "etcd"
                or authority["oracle"] != "host-supervisor-linearizable-etcd-read"
                or not isinstance(authority["cluster_id"], str)
                or not authority["cluster_id"].isdecimal()
                or int(authority["cluster_id"]) <= 0):
            raise ValueError("invalid pinned distributed authority context")
    elif authority != {"backend": "sqlite"}:
        raise ValueError("local package evidence cannot advertise distributed authority")
    verify_rounds(report, schema=schema, triggers=["requested-stop"] * 3)
    for index, run in enumerate(report["rounds"]):
        observed = run["observations"]
        package = observed["package"]
        mode = "vulnerable" if index == 0 else "protected"
        if package["mode"] != mode or package["artifact_sha256"] != ARTIFACT.sha256:
            raise ValueError("different workload or missing paired control")
        context = next(event["payload"]["package_context"] for event in run["events"]
                       if event["event_type"] == "isolation.context")
        if (context["worker_build"] != report["worker_build"] or context["mode"] != mode
                or context["artifact_sha256"] != ARTIFACT.sha256
                or package["worker_sha256"] != report["worker_build"]["worker_sha256"]):
            raise ValueError("package build/configuration differs from signed context")
        if distributed:
            if (context.get("authority_backend") != "etcd"
                    or context.get("etcd_cluster_id") != authority["cluster_id"]):
                raise ValueError("round's signed context does not bind the pinned etcd authority")
            oracle = observed.get("authority_oracle")
            if not isinstance(oracle, dict) or set(oracle) != {
                "backend", "cluster_id", "revision", "raft_term", "record_count",
                "capability_id", "claims_digest", "expires_at",
                "record_integrity_checked", "source",
            }:
                raise ValueError("distributed replay oracle is absent or malformed")
            if (oracle["backend"] != "etcd"
                    or oracle["cluster_id"] != authority["cluster_id"]
                    or oracle["source"] != authority["oracle"]
                    or oracle["record_integrity_checked"] is not True
                    or type(oracle["record_count"]) is not int
                    or oracle["record_count"] != 1
                    or any(type(oracle[name]) is not int or oracle[name] <= 0
                           for name in ("revision", "raft_term", "expires_at"))
                    or not isinstance(oracle["claims_digest"], str)
                    or len(oracle["claims_digest"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in oracle["claims_digest"])):
                raise ValueError("signed etcd consumption oracle failed checks")
            context_events = [
                e for e in run["events"]
                if e["event_type"] == "isolation.context"
                and e["source_id"] == "host-supervisor"
            ]
            if len(context_events) != 1 or oracle["capability_id"] != context_events[0]["payload"]["capability_id"]:
                raise ValueError("consumption oracle does not bind the session capability")
            authorized = [e for e in run["events"] if e["event_type"] == "execution.authorized"]
            completed = [e for e in run["events"] if e["event_type"] == "execution.completed"]
            if (len(authorized) != 1 or len(completed) != 1
                    or any(e["payload"].get("capability_id") != oracle["capability_id"]
                           for e in authorized + completed)):
                raise ValueError("etcd replay oracle and host execution records disagree")
        else:
            if context.get("authority_backend", "sqlite") != "sqlite" or "authority_oracle" in observed:
                raise ValueError("local replay lab claims unsupported distributed evidence")
        effects = package["forbidden_effects"]
        if set(effects) != set(EFFECTS) or any(value is not (index == 0) for value in effects.values()):
            raise ValueError("paired effect oracle failed")
        if [event["kind"] for event in package["target_events"]] != (["relay", "credential_reuse"] if index == 0 else []):
            raise ValueError("target oracle disagrees with effects")
        for field in ("trusted_recipient_digest_verified", "service_chroot_uid_capabilities_verified",
                      "service_scratch_write_observed", "persistence_child_observed", "service_scratch_removed",
                      "gate_url_and_budget_widening_denied", "substituted_success_output_rejected",
                      "authoritative_evidence_outside_service_root"):
            if package[field] is not True:
                raise ValueError(f"missing package boundary observation: {field}")
        if (observed["useful_package_read_and_summary"] is not True or observed["host_consumption_count"] != 1
                or observed["replay_denied"] is not True or package["ambiguous_outcomes"] != []):
            raise ValueError("useful work, budget, or outcome check failed")
        if index and "prior_session_capability" not in observed["denied_cases"]:
            raise ValueError("cross-session authority was not checked")
        for field in ("active_workload_ms", "total_round_ms", "requested_teardown_latency_ms", "post_kill_cleanup_ms"):
            value = package[field]
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError("invalid measured duration")
        if package["automatic_attack_detection"] is not False or package["detection_delay_ms"] is not None:
            raise ValueError("this lab does not measure automatic detection")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"),
                            object_pairs_hook=_object_without_duplicates, parse_constant=_reject_constant)
        # Aggregate evidence is deeper than an individual bounded RPC frame.
        # Reject non-finite numbers without applying the transport nesting ceiling.
        json.dumps(report, allow_nan=False)
        verify_report(report)
    except (ValueError, KeyError, TypeError, OSError, StopIteration) as exc:
        print(f"Package isolation evidence: INVALID ({exc})")
        return 1
    print("Package isolation evidence: VERIFIED (paired oracle and 3 signed chains; embedded keys, integrity only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
