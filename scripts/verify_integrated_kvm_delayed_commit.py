"""Strict verifier for the SIXTH real Firecracker KVM delayed recipient window.

Requires actual KVM run report, signed guest and guardian, three-node etcd,
supervisor-observed SIGKILL, 0 -> 1 late recipient commits, replay denial,
and complete cgroup teardown. Embedded public keys prove internal integrity,
not an independent witness or hardware attestation.
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from event_horizon.canonical import digest
from scripts.integrated_authority_session import evidence_digest
from scripts.verify_integrated_authority import verify_authority
from scripts.verify_integrated_kvm_crash import parse_report_json
from scripts.verify_kvm_delayed_recipient_bridge import verify_delayed_bridge

SCHEMA = "event-horizon.firecracker-inflight-recipient-sigkill.v1"
MODE = "real-kvm-guardian-etcd-inflight-recipient-gateway-sigkill"


def require(test, message):
    if not test:
        raise ValueError(message)


def verify_report(report):
    require(isinstance(report, dict)
            and report.get("schema") == SCHEMA
            and report.get("experiment_mode") == MODE
            and report.get("status") == "PASS"
            and isinstance(report.get("rounds"), list)
            and len(report["rounds"]) == 1,
            "not a complete sixth KVM window")
    require(isinstance(report.get("source_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", report["source_commit"])
            and report.get("attestation") == "synthetic-fixture"
            and report.get("build_manifest", {}).get("tpm2_enabled") is False,
            "source or synthetic attestation disclosure not pinned")
    a = report.get("authority")
    require(isinstance(a, dict)
            and a.get("backend") == "etcd"
            and a.get("oracle") == "host-supervisor-linearizable-etcd-read"
            and isinstance(a.get("cluster_id"), str)
            and a["cluster_id"].isdecimal()
            and int(a["cluster_id"]) > 0,
            "independent owned three-node etcd not established")
    r = report["rounds"][0]
    events, obs, receipts = r["events"], r["observations"], r["receipts"]
    isolation = r["isolated_authority"]
    session, (primary, spare, fault) = verify_authority(isolation)
    request = session.request
    require(isolation["configuration"]["source_commit"] == report["source_commit"]
            and isolation["configuration"]["build_artifacts"]
            == report["build_manifest"]["artifacts"]
            and obs.get("isolated_authority_digest") == evidence_digest(isolation),
            "guardian/signer transcripts not source and artifact bound")
    pinned = [e for e in events if e["event_type"] == "isolation.context"
              and e["source_id"] == "host-supervisor"]
    require(len(pinned) == 1, "trusted guest context missing or duplicated")
    c = pinned[0]["payload"]
    require(c.get("build_manifest_digest") == digest(report["build_manifest"])
            and c.get("host_kernel") == report["host_kernel"]
            and c.get("session_id") == request.session_id
            and c.get("capability_id") == primary.claims.capability_id
            and c.get("package_context", {}).get("mode") == "protected"
            and c.get("package_context", {}).get("authority_backend") == "etcd",
            "guest, guardian and package context not linked")
    require(obs.get("vm_chroot_verified") is True
            and obs.get("vm_seccomp_verified") is True
            and obs.get("separate_network_namespaces") is True
            and obs.get("host_principal_file_denials") is True
            and obs.get("guest_root_diagnostic", {}).get("uid") == 0
            and obs.get("retired_effect_endpoint_unreachable") is True,
            "real guest/firecracker isolation observation missing")
    teardown = r["teardown"]
    require(teardown.get("trigger") == "requested-stop"
            and all(v is True for k, v in teardown.items() if k != "trigger"),
            "real host cleanup not verified")
    for event_type, payload in (("isolation.observed", obs),
                                ("teardown.verified", teardown)):
        matching = [e for e in events if e["event_type"] == event_type
                    and e["source_id"] == "host-supervisor"]
        require(len(matching) == 1 and matching[0]["payload"] == payload,
                "reported summary not independently signed")
    late = obs["kvm_delayed_commit"]
    effect_key = digest({
        "session_id": request.session_id, "request_id": request.request_id,
    })
    verify_delayed_bridge(
        report=late, events=events, receipts=receipts,
        tip=r["evidence_chain_tip"],
        public_key_pem=r["recorder_public_key_pem"],
        request_digest=request.request_digest, effect_key=effect_key,
    )
    require(obs.get("kvm_recipient_pid") == late["recipient_pid"]
            and obs.get("kvm_recipient_final") == late["after_release"]
            and obs.get("kvm_crash_expected_commits") == 1
            and obs.get("replay_denied") is True,
            "late recipient observation does not match guest and ledger")
    replies = obs["kvm_crash_guest_replies"]
    require(replies["interrupted"] == {
                "success": False, "effect_state": "possibly-committed",
                "error": "gateway-killed",
            } and replies["original_replay"] == late["original_replay"]
            and replies["replacement_replay"] == late["replacement_replay"],
            "guest/vsock did not actually receive fenced failures")
    require(obs.get("recovery_capability_id") == spare.claims.capability_id
            and obs.get("recovery_capability_redeemed") is True
            and "unredeemed_capability_at_teardown" not in obs,
            "fresh signed recovery token consumption hidden")
    pids = {late["recipient_pid"], late["killed_gateway_pid"],
            late["recovery_gateway_pid"]}
    guardians = {r["pid"] for r in isolation["roles"].values()}
    coordinators = {r["pid"] for r in isolation.get("coordinators", [])}
    require(not pids & (guardians | coordinators), "recipient/gateway is guardian")
    oracle = obs["authority_oracle"]
    extras = set(oracle["additional_consumed_ids"])
    require(oracle["source"] == a["oracle"]
            and oracle["backend"] == "etcd"
            and oracle["cluster_id"] == a["cluster_id"]
            and oracle["capability_id"] == primary.claims.capability_id
            and oracle["claims_digest"] == digest(primary.claims.to_dict())
            and oracle["primary_record_count"] == 1
            and oracle["record_integrity_checked"] is True
            and spare.claims.capability_id in extras
            and extras <= {spare.claims.capability_id, fault.claims.capability_id}
            and oracle["record_count"] == 1 + len(extras)
            and obs["host_consumption_count"] == oracle["record_count"],
            "linearizable etcd consumption/guardian binding invalid")
    package = obs["package"]
    require(package["mode"] == "protected"
            and package["worker_sha256"] == report["worker_build"]["worker_sha256"]
            and package["service_scratch_removed"] is True
            and package["authoritative_evidence_outside_service_root"] is True
            and all(v is False for v in package["forbidden_effects"].values()),
            "forbidden package effects escaped isolation")
    negatives = [e["payload"] for e in events if
                 e["event_type"] == "integrated.result"
                 and e["source_id"] == "host-supervisor"]
    require(len(negatives) == 5
            and all(x.get("outcome") == "denied"
                    and x.get("guest_invoked") is True
                    and x.get("effect_state") == "not-started"
                    and x.get("dispatch_before") == x.get("dispatch_after") == 0
                    for x in negatives),
            "negative controls not completed before sixth-window fault")
    return True


def verify_file(path):
    raw = Path(path).read_bytes()
    sidecar = Path(str(path) + ".sha256")
    if sidecar.exists():
        require(sidecar.read_text() ==
                hashlib.sha256(raw).hexdigest() + "  " + Path(path).name + "\n",
                "original sixth-window report SHA-256 mismatch")
    return verify_report(parse_report_json(raw))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    verify_file(args.report)
    print("VERIFIED: sixth real KVM guest/vsock gateway SIGKILL with in-flight "
          "recipient committing only AFTER restart and replay denials; "
          "four guardians, etcd, embedded keys only")
