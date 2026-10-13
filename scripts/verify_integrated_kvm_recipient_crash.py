"""Strict NEW-schema verifier: two genuine KVM fenced recipient SIGKILL/restart windows.

Embedded Ed25519 signer/recorder receipts are internal trust evidence, not
independent external witnesses or hardware attestation. A portable process
test CANNOT satisfy the KVM session, source, isolation and etcd conditions.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import signal
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from event_horizon.canonical import digest
from scripts.integrated_authority_session import evidence_digest
from scripts.fenced_recipient_service import PHASES as RECIPIENT_PHASES
from scripts.run_package_isolation import CONTENT
from scripts.verify_integrated_authority import verify_authority
from scripts.verify_integrated_kvm_crash import parse_report_json
from scripts.verify_integrated_kvm_fenced_baseline import require, verify_chain


SCHEMA = "event-horizon.firecracker-fenced-recipient-crash-recovery.v1"
MODE = "real-kvm-guardian-etcd-fenced-recipient-restart"
HEX = re.compile(r"[0-9a-f]{64}")


def signed(events, name, source="host-supervisor"):
    found = [(i, e["payload"]) for i, e in enumerate(events)
             if e["event_type"] == name and e["source_id"] == source]
    require(len(found) == 1, "missing/duplicated signed " + name)
    return found[0]


def verify_round(round_report, *, phase, source, manifest, worker_build, host_kernel,
                 cluster_id):
    r = round_report
    events, receipts, obs = r["events"], r["receipts"], r["observations"]
    verify_chain(events, receipts, r["evidence_chain_tip"],
                 r["recorder_public_key_pem"])
    iso = r["isolated_authority"]
    session, (primary, spare, fault) = verify_authority(iso)
    request = session.request
    require(iso["configuration"]["source_commit"] == source
            and iso["configuration"]["build_artifacts"] == manifest["artifacts"]
            and obs.get("isolated_authority_digest") == evidence_digest(iso),
            "four-guardian isolated signer provenance invalid")
    _, ctx = signed(events, "isolation.context")
    require(ctx.get("build_manifest_digest") == digest(manifest)
            and ctx.get("host_kernel") == host_kernel
            and ctx.get("session_id") == request.session_id
            and ctx.get("capability_id") == primary.claims.capability_id
            and ctx.get("package_context", {}).get("mode") == "protected",
            "real KVM signed original request/manifest context missing")
    require(obs.get("vm_chroot_verified") is True
            and obs.get("vm_seccomp_verified") is True
            and obs.get("separate_network_namespaces") is True
            and obs.get("host_principal_file_denials") is True
            and obs.get("retired_effect_endpoint_unreachable") is True
            and obs.get("guest_root_diagnostic", {}).get("uid") == 0
            and obs.get("replay_denied") is True,
            "not an independently observed KVM guest boundary")
    teardown = r["teardown"]
    require(teardown.get("trigger") == "requested-stop"
            and all(v is True for k, v in teardown.items() if k != "trigger"),
            "fault round host cgroup teardown incomplete")
    require(signed(events, "isolation.observed")[1] == obs
            and signed(events, "teardown.verified")[1] == teardown,
            "not an unmodified signed host observation")
    crash = obs.get("kvm_recipient_crash")
    recovered = obs.get("kvm_recipient_recovery")
    fenced = obs.get("fenced_recipient_kvm")
    require(type(crash) is dict and type(recovered) is dict and type(fenced) is dict
            and crash.get("phase") == recovered.get("phase") == phase,
            "fenced SIGKILL phases did not match supervisor")
    require(signed(events, "fenced.recipient-sigkill-observed")[1] == crash
            and signed(events, "fenced.recipient-recovery-observed")[1] == recovered,
            "crash/recovery summary not signed from independent observation")
    n1 = signed(events, "fenced.recipient-sigkill-observed")[0]
    n2 = signed(events, "fenced.recipient-recovery-observed")[0]
    require(n1 < n2, "crash/recovery evidence reordered")
    effect_key = digest({
        "session_id": request.session_id, "request_id": request.request_id,
    })
    expected_before = phase == RECIPIENT_PHASES[0]
    old_count = 0 if expected_before else 1
    gateway_pid = crash.get("gateway_pid")
    original_pid = crash.get("killed_recipient_pid")
    replacement_pid = recovered.get("restarted_recipient_pid")
    authority_pids = {v["pid"] for v in iso["roles"].values()}
    authority_pids.update(v["pid"] for v in iso.get("coordinators", []))
    require(all(type(pid) is int and pid > 1
                for pid in (gateway_pid, original_pid, replacement_pid))
            and len({gateway_pid, original_pid, replacement_pid}) == 3
            and not {gateway_pid, original_pid, replacement_pid} & authority_pids,
            "restarted recipient/gateway reused an active authority identity")
    require(crash == {
        "phase": phase,
        "gateway_pid": gateway_pid,
        "killed_recipient_pid": original_pid,
        "signal": signal.SIGKILL, "exit_code": -signal.SIGKILL,
        "request_digest": request.request_digest,
        "effect_key": effect_key,
        "original_capability_id": primary.claims.capability_id,
        "journal_state": "possibly-committed",
        "recipient_count_after_kill": old_count,
    }, "recipient SIGKILL, durable fence or phase not independently corroborated")
    nrestart, restart = signed(events, "fenced.recipient-restarted-observed")
    require(n1 < nrestart < n2 and restart.get("phase") == phase
            and restart.get("gateway_pid") == gateway_pid
            and restart.get("killed_recipient_pid") == original_pid
            and restart.get("restarted_recipient_pid") == replacement_pid
            and restart.get("recipient_id") == "ehh-owned-kvm-fenced-v1"
            and restart.get("stale_socket_removed") is True
            and type(restart.get("prior_socket_inode")) is int
            and restart["prior_socket_inode"] > 0
            and restart.get("recipient_count_before_recovery") == old_count,
            "recipient did not prove exact stale socket identity and independent restart")
    expected_receipt = digest({
        "schema": "event-horizon.fenced-recipient-receipt.v1",
        "recipient_id": "ehh-owned-kvm-fenced-v1",
        "effect_key": effect_key,
        "request_digest": request.request_digest,
        "output_digest": digest(CONTENT), "sequence": 1,
    })
    require(recovered == {
        "phase": phase,
        "gateway_pid": gateway_pid,
        "killed_recipient_pid": original_pid,
        "restarted_recipient_pid": replacement_pid,
        "original_capability_id": primary.claims.capability_id,
        "recovery_capability_id": spare.claims.capability_id,
        "receipt_digest": expected_receipt,
        "output_digest": digest(CONTENT),
        "commit_sequence": 1,
        "row_count": 1,
        "new_commit_on_recovery": expected_before,
        "journal_state": "recipient-confirmed",
        "original_replay": {
            "success": False, "error": "authority-denied",
        },
        "fresh_recovery": {
            "success": True, "effect_state": "completed",
        },
    }, "recipient recovery receipt or original journal provenance mismatch")
    require(fenced.get("recipient_pid") == replacement_pid
            and fenced.get("gateway_pid") == gateway_pid
            and fenced.get("effect_key") == effect_key
            and fenced.get("request_digest") == request.request_digest
            and fenced.get("recipient_id") == "ehh-owned-kvm-fenced-v1"
            and fenced.get("output_digest") == digest(CONTENT)
            and fenced.get("receipt_digest") == expected_receipt
            and fenced.get("commit_sequence") == 1
            and fenced.get("row_count") == 1
            and fenced.get("journal_state") == "recipient-confirmed"
            and fenced.get("original_capability_id") == primary.claims.capability_id
            and fenced.get("attestation_mode") == "synthetic-fixture",
            "post-restart recipient ledger differs from positive confirmed receipt")
    guest = obs["kvm_recipient_guest_replies"]
    require(guest == {
        "interrupted": {
            "success": False, "error": "recipient-indeterminate",
            "effect_state": "possibly-committed",
        },
        "original_replay": {
            "success": False, "error": "authority-denied",
        },
        "fresh_recovery": {
            "success": True, "effect_state": "completed",
            "output_digest": digest(CONTENT),
        },
    }, "actual jailed guest did not observe ambiguous recipient failure and recovery")
    bridged = obs.get("gateway_process_bridge")
    require(type(bridged) is dict
            and bridged.get("gateway_pid") == gateway_pid
            and bridged.get("identity_binding") == "pidfd-fenced-recipient-v1"
            and bridged.get("independent_process") is True
            and bridged.get("guest_vsock_request_path") is True
            and bridged.get("recorder_resides_in_supervisor") is True,
            "recipient restart did not retain authenticated gateway identity")
    auths = [(i, e["payload"]) for i, e in enumerate(events)
             if e["event_type"] == "fenced.authorized"
             and e["source_id"] == "host-effect-service"]
    indeterminate = [(i, e["payload"]) for i, e in enumerate(events)
                     if e["event_type"] == "fenced.indeterminate"
                     and e["source_id"] == "host-effect-service"]
    commits = [(i, e["payload"]) for i, e in enumerate(events)
               if e["event_type"] == "fenced.recipient-confirmed"
               and e["source_id"] == "host-effect-service"]
    require(len(auths) == 2 and len(indeterminate) == 1 and len(commits) == 1
            and auths[0][0] < indeterminate[0][0] < n1 < nrestart
            < auths[1][0] < commits[0][0] < n2,
            "recipient death lacked properly ordered signed ambiguity, restart and commit")
    require(indeterminate[0][1] == {
        "request_id": request.request_id,
        "request_digest": request.request_digest,
        "capability_id": primary.claims.capability_id,
        "effect_state": "possibly-committed",
    }, "gateway falsely asserted the original recipient could not have committed")
    for (_, payload), cap in zip(auths, (primary, spare), strict=True):
        require(payload == {
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "capability_id": cap.claims.capability_id,
        }, "wrong original or fresh signed authority in recipient campaign")
    require(commits[0][1] == {
        "request_id": request.request_id,
        "request_digest": request.request_digest,
        "capability_id": spare.claims.capability_id,
        "original_capability_id": primary.claims.capability_id,
        "receipt_digest": expected_receipt,
        "recipient_id": "ehh-owned-kvm-fenced-v1",
        "commit_sequence": 1,
        "recovery": True,
        "new_effect_commit": expected_before,
    }, "positive receipt incorrectly attributed new commit/provenance")
    require(not any(e["event_type"] in ("execution.dispatch", "execution.completed")
                    for e in events),
            "legacy callback evidence may not prove atomic recovery")
    oracle = obs["authority_oracle"]
    extras = set(oracle["additional_consumed_ids"])
    require(oracle.get("source") == "host-supervisor-linearizable-etcd-read"
            and oracle.get("backend") == "etcd"
            and oracle.get("cluster_id") == cluster_id
            and oracle.get("capability_id") == primary.claims.capability_id
            and oracle.get("claims_digest") == digest(primary.claims.to_dict())
            and oracle.get("primary_record_count") == 1
            and oracle.get("record_integrity_checked") is True
            and spare.claims.capability_id in extras
            and extras <= {fault.claims.capability_id, spare.claims.capability_id}
            and oracle.get("record_count") == 1 + len(extras)
            and obs.get("host_consumption_count") == oracle["record_count"]
            and obs.get("recovery_capability_redeemed") is True
            and obs.get("recovery_capability_id") == spare.claims.capability_id,
            "linearizable signed authority did not consume original and fresh recovery")
    package = obs.get("package")
    require(type(package) is dict
            and package.get("mode") == "protected"
            and package.get("worker_sha256") == worker_build["worker_sha256"]
            and package.get("service_scratch_removed") is True
            and package.get("authoritative_evidence_outside_service_root") is True
            and all(v is False for v in package["forbidden_effects"].values()),
            "compromised package not isolated from recipient or authority")
    results = [e["payload"] for e in events
               if e["event_type"] == "integrated.result"
               and e["source_id"] == "host-supervisor"]
    require(len(results) == 6
            and all(v["outcome"] == "denied"
                    and v["guest_invoked"] is True
                    and v["effect_state"] == "not-started"
                    and v["dispatch_before"] == v["dispatch_after"] == 0
                    for v in results[:5])
            and results[-1]["name"] == "replay_after_quorum_recovery"
            and results[-1]["dispatch_before"] == results[-1]["dispatch_after"] == 1,
            "pre/post crash adversarial negative controls incomplete")
    require(obs["integrated_gateway"]["dispatches"] == 1,
            "recipient was applied zero/multiple times")
    return request.session_id


def verify_report(report):
    require(type(report) is dict
            and report.get("schema") == SCHEMA
            and report.get("experiment_mode") == MODE
            and report.get("status") == "PASS"
            and type(report.get("rounds")) is list
            and len(report["rounds"]) == len(RECIPIENT_PHASES),
            "not a complete two-phase KVM fenced recovery experiment")
    source = report.get("source_commit")
    require(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
            and report.get("attestation") == "synthetic-fixture"
            and report.get("build_manifest", {}).get("tpm2_enabled") is False,
            "missing source or honest synthetic guest attestation disclosure")
    authority = report.get("authority")
    require(type(authority) is dict
            and authority.get("backend") == "etcd"
            and authority.get("oracle") == "host-supervisor-linearizable-etcd-read"
            and type(authority.get("cluster_id")) is str
            and authority["cluster_id"].isdecimal()
            and int(authority["cluster_id"]) > 0,
            "owned three-member etcd authority not established")
    sessions = []
    for phase, record in zip(RECIPIENT_PHASES, report["rounds"], strict=True):
        sessions.append(verify_round(
            record, phase=phase, source=source,
            manifest=report["build_manifest"],
            worker_build=report["worker_build"],
            host_kernel=report["host_kernel"],
            cluster_id=authority["cluster_id"],
        ))
    require(len(set(sessions)) == len(sessions),
            "multiple crash windows reused a prior signed guest session")
    return True


def verify_file(path: Path):
    path = Path(path)
    raw = path.read_bytes()
    checksum_path = Path(str(path) + ".sha256")
    require(checksum_path.is_file(), "original fenced crash report checksum missing")
    require(checksum_path.read_text() == (
        hashlib.sha256(raw).hexdigest() + "  " + path.name + "\n"
    ), "fenced crash report SHA256 mismatch")
    return verify_report(parse_report_json(raw))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    verify_file(args.report)
    print("PASS: two actual KVM recipient SIGKILL/restart recovery windows independently verified")
