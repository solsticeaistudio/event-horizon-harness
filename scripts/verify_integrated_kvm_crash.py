"""Strict new-schema verifier for real Firecracker gateway SIGKILL evidence.

A PASS from the portable Linux-process harness can NEVER satisfy this schema.
Embedded Ed25519 receipts establish internal integrity, not external witness.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

# Support direct invocation from any working directory without relying on
# PYTHONPATH or an editable installation. The installed verifier is commonly
# run as `python scripts/verify_integrated_kvm_crash.py original.json`.
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from event_horizon.canonical import digest, strict_json_loads
from scripts.real_gateway_crash_checkpoints import PHASES
from scripts.verify_integrated_authority import verify_authority
from scripts.verify_kvm_gateway_crash_bridge import verify_crash_bridge

SCHEMA = "event-horizon.firecracker-gateway-sigkill.v1"
MODE = "real-kvm-guardian-etcd-recipient-gateway-sigkill"


def require(value, explanation):
    if not value:
        raise ValueError(explanation)


def verify_report(report):
    require(isinstance(report, dict) and report.get("schema") == SCHEMA
            and report.get("experiment_mode") == MODE
            and report.get("status") == "PASS"
            and isinstance(report.get("rounds"), list)
            and len(report["rounds"]) == 5,
            "not a complete five-window KVM gateway SIGKILL experiment")
    require(isinstance(report.get("source_commit"), str)
            and re.fullmatch("[0-9a-f]{40}", report["source_commit"])
            and report.get("attestation") == "synthetic-fixture"
            and report.get("build_manifest", {}).get("tpm2_enabled") is False,
            "missing source provenance or simulated attestation disclosure")
    authority = report.get("authority")
    require(isinstance(authority, dict)
            and authority.get("backend") == "etcd"
            and authority.get("oracle") == "host-supervisor-linearizable-etcd-read"
            and isinstance(authority.get("cluster_id"), str)
            and authority["cluster_id"].isdecimal()
            and int(authority["cluster_id"]) > 0,
            "independent three-node etcd authority not pinned")
    sessions = set()
    for idx, (phase, round_record) in enumerate(zip(PHASES, report["rounds"], strict=True)):
        events, obs, receipts = (
            round_record["events"], round_record["observations"],
            round_record["receipts"],
        )
        isolation = round_record["isolated_authority"]
        session, capabilities = verify_authority(isolation)
        request = session.request
        require(isolation["configuration"]["source_commit"] == report["source_commit"]
                and isolation["configuration"]["build_artifacts"] == report["build_manifest"]["artifacts"],
                "wrong source or measured binaries")
        require(request.session_id not in sessions, "KVM rounds reuse guest session")
        sessions.add(request.session_id)
        primary, spare, fault = capabilities
        # Authority attachments have their own stable canonical evidence hash.
        from scripts.integrated_authority_session import evidence_digest
        require(obs.get("isolated_authority_digest") == evidence_digest(isolation),
                "isolated four-guardian transcript not bound to signed observation")
        contexts = [e for e in events
                    if e["event_type"] == "isolation.context"
                    and e["source_id"] == "host-supervisor"]
        require(len(contexts) == 1, "missing exactly one trusted execution context")
        ctx = contexts[0]["payload"]
        require(ctx.get("build_manifest_digest") == digest(report["build_manifest"])
                and ctx.get("host_kernel") == report["host_kernel"]
                and ctx.get("session_id") == request.session_id
                and ctx.get("capability_id") == primary.claims.capability_id
                and ctx.get("package_context", {}).get("mode") == "protected",
                "guest/manifest/guardian context was not pinned")
        require(obs.get("vm_chroot_verified") is True
                and obs.get("vm_seccomp_verified") is True
                and obs.get("separate_network_namespaces") is True
                and obs.get("host_principal_file_denials") is True
                and obs.get("guest_root_diagnostic", {}).get("uid") == 0
                and obs.get("retired_effect_endpoint_unreachable") is True,
                "missing real jailed Firecracker/guest boundary checks")
        teardown = round_record["teardown"]
        expected_trigger = "supervisor-channel-closed" if idx == 4 else "requested-stop"
        require(teardown.get("trigger") == expected_trigger
                and all(v is True for key, v in teardown.items() if key != "trigger"),
                "incomplete real host cgroup teardown")
        for name, value in (("isolation.observed", obs), ("teardown.verified", teardown)):
            matches = [e for e in events
                       if e["event_type"] == name and e["source_id"] == "host-supervisor"]
            require(len(matches) == 1 and matches[0]["payload"] == value,
                    "report summary was not independently signed by supervisor")
        k, recovered = obs["kvm_crash"], obs["kvm_recovery"]
        verify_crash_bridge(
            phase=phase, crashed=k, recovery=recovered,
            events=events, receipts=receipts,
            tip=round_record["evidence_chain_tip"],
            public_key_pem=round_record["recorder_public_key_pem"],
            request_digest=request.request_digest,
            effect_key=digest({
                "session_id": request.session_id, "request_id": request.request_id,
            }),
        )
        recipients = obs["kvm_recipient_final"]
        require(recipients == recovered["recipient_after_recovery"]
                and obs["kvm_crash_expected_commits"] == (0 if idx < 2 else 1),
                "recipient ledger disagrees with kill phase")
        guest = obs["kvm_crash_guest_replies"]
        require(guest["interrupted"] == {
            "success": False, "effect_state": "possibly-committed",
            "error": "gateway-killed",
        } and guest["original_replay"] == recovered["original_replay"]
                and guest["replacement_replay"] == recovered["replacement_replay"]
                and obs["replay_denied"] is True,
                "actual KVM guest replies do not prove fail-closed restart")
        require(obs.get("recovery_capability_id") == spare.claims.capability_id
                and obs.get("recovery_capability_redeemed") is (idx != 0)
                and "unredeemed_capability_at_teardown" not in obs,
                "signed recovery capability state contradicts replay experiment")
        recipient_pid = obs["kvm_recipient_pid"]
        role_pids = {role["pid"] for role in isolation["roles"].values()}
        coordinator_pids = {role["pid"] for role in isolation.get("coordinators", [])}
        pids = {recipient_pid, k["gateway_pid"], recovered["recovery_pid"]}
        require(type(recipient_pid) is int and recipient_pid > 1
                and len(pids) == 3 and not pids & (role_pids | coordinator_pids),
                "recipient or gateway reused an authorization process")
        # PIDs can legitimately be recycled after a prior guest round has
        # terminated. Require separation among concurrent principals within
        # each round, not historical uniqueness across kernel lifetimes.
        oracle = obs["authority_oracle"]
        extras = set(oracle["additional_consumed_ids"])
        require(oracle["source"] == authority["oracle"]
                and oracle["backend"] == "etcd"
                and oracle["cluster_id"] == authority["cluster_id"]
                and oracle["capability_id"] == primary.claims.capability_id
                and oracle["claims_digest"] == digest(primary.claims.to_dict())
                and oracle["primary_record_count"] == 1
                and oracle["record_integrity_checked"] is True
                and extras <= {spare.claims.capability_id, fault.claims.capability_id}
                and (spare.claims.capability_id in extras) == (idx != 0)
                and oracle["record_count"] == 1 + len(extras)
                and obs["host_consumption_count"] == oracle["record_count"],
                "linearizable etcd oracle disagrees with primary/fresh capability")
        package = obs["package"]
        require(package["mode"] == "protected"
                and package["worker_sha256"] == report["worker_build"]["worker_sha256"]
                and package["service_scratch_removed"] is True
                and package["authoritative_evidence_outside_service_root"] is True
                and all(value is False for value in package["forbidden_effects"].values()),
                "forbidden package effects escaped protected fixture")
        attacks = [e["payload"] for e in events
                   if e["event_type"] == "integrated.result"
                   and e["source_id"] == "host-supervisor"]
        require(len(attacks) == 5
                and all(x.get("outcome") == "denied"
                        and x.get("guest_invoked") is True
                        and x.get("effect_state") == "not-started"
                        and x.get("dispatch_before") == x.get("dispatch_after") == 0
                        for x in attacks),
                "missing pre-crash guest negative controls")
    return True


def verify_file(path):
    raw = Path(path).read_bytes()
    sidecar = Path(str(path) + ".sha256")
    if sidecar.exists():
        require(sidecar.read_text() == (
            hashlib.sha256(raw).hexdigest() + "  " + path.name + "\n"),
            "original report checksum mismatch")
    return verify_report(strict_json_loads(raw))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    verify_file(args.report)
    print("VERIFIED: 5 guest/vsock KVM SIGKILL phases, four guardian approvals, "
          "three-node etcd and independent recipients; embedded keys only")
