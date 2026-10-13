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
ACK_PHASES = ("drop_ack_after_commit",)
from scripts.run_package_isolation import CONTENT
from scripts.verify_integrated_authority import verify_authority
from scripts.verify_integrated_kvm_crash import parse_report_json
from scripts.verify_integrated_kvm_fenced_baseline import require, verify_chain


SCHEMA = "event-horizon.firecracker-fenced-competing-recovery.v1"
MODE = "real-kvm-guardian-etcd-competing-fenced-recovery"
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
    lost = obs.get("kvm_ack_loss")
    recovered = obs.get("kvm_ack_recovery")
    fenced = obs.get("fenced_recipient_kvm")
    require(type(lost) is dict and type(recovered) is dict and type(fenced) is dict
            and lost.get("phase") == recovered.get("phase") == phase,
            "missing actual KVM host-pinned ACK-loss observations")
    n1, signed_loss = signed(events, "fenced.recipient-ack-lost-observed")
    n2, signed_recovery = signed(events, "fenced.ack-recovered-observed")
    require(signed_loss == lost and signed_recovery == recovered and n1 < n2,
            "lost ACK/recovery summaries not signed or reordered")
    effect_key = digest({
        "session_id": request.session_id, "request_id": request.request_id,
    })
    original_pid = lost.get("gateway_pid")
    recipient_pid = lost.get("recipient_pid")
    authorities = {r["pid"] for r in iso["roles"].values()}
    authorities.update(row["pid"] for row in iso.get("coordinators", []))
    require(all(type(v) is int and v > 1 for v in (original_pid, recipient_pid))
            and original_pid != recipient_pid
            and not {original_pid, recipient_pid} & authorities,
            "ACK loss reused a guardian/recipient/gateway process identity")
    expected_receipt = digest({
        "schema": "event-horizon.fenced-recipient-receipt.v1",
        "recipient_id": "ehh-owned-kvm-fenced-v1",
        "effect_key": effect_key,
        "request_digest": request.request_digest,
        "output_digest": digest(CONTENT), "sequence": 1,
    })
    require(lost == {
        "phase": phase,
        "gateway_pid": original_pid,
        "recipient_pid": recipient_pid,
        "recipient_alive_after_drop": True,
        "gateway_alive_after_drop": True,
        "recipient_count_at_drop": 1,
        "journal_state": "possibly-committed",
        "original_capability_id": primary.claims.capability_id,
        "request_digest": request.request_digest,
        "effect_key": effect_key,
        "receipt_digest_before_ack": expected_receipt,
    }, "ACK suppression was not after the original atomic durable commit")
    require(recovered == {
        "phase": phase,
        "gateway_pid": original_pid,
        "recipient_pid": recipient_pid,
        "recipient_alive_after_recovery": True,
        "gateway_alive_after_recovery": True,
        "row_count": 1,
        "commit_sequence": 1,
        "receipt_digest": expected_receipt,
        "output_digest": digest(CONTENT),
        "original_capability_id": primary.claims.capability_id,
        "recovery_capability_id": spare.claims.capability_id,
        "new_commit_on_recovery": False,
        "journal_state": "recipient-confirmed",
        "original_replay": {"success": False, "error": "authority-denied"},
        "fresh_recovery": {"success": True, "effect_state": "completed"},
    }, "fresh recovery did not positively confirm same original receipt without re-commit")
    require(fenced.get("recipient_pid") == recipient_pid
            and fenced.get("gateway_pid") == original_pid
            and fenced.get("effect_key") == effect_key
            and fenced.get("recipient_id") == "ehh-owned-kvm-fenced-v1"
            and fenced.get("request_digest") == request.request_digest
            and fenced.get("receipt_digest") == expected_receipt
            and fenced.get("commit_sequence") == 1
            and fenced.get("row_count") == 1
            and fenced.get("journal_state") == "recipient-confirmed"
            and fenced.get("original_capability_id") == primary.claims.capability_id
            and fenced.get("attestation_mode") == "synthetic-fixture",
            "independent recipient ledger not consistent with signed ACK-loss recovery")
    require(obs.get("kvm_ack_loss_guest_replies") == {
        "interrupted": {
            "success": False, "error": "recipient-indeterminate",
            "effect_state": "possibly-committed",
        },
        "original_replay": {"success": False, "error": "authority-denied"},
        "fresh_recovery": {
            "success": True, "effect_state": "completed",
            "output_digest": digest(CONTENT),
        },
    }, "actual KVM guest did not observe missing ACK and new signed confirmation")
    bridged = obs.get("gateway_process_bridge")
    require(type(bridged) is dict
            and bridged.get("gateway_pid") == original_pid
            and bridged.get("identity_binding") == "pidfd-fenced-recipient-v1"
            and bridged.get("independent_process") is True
            and bridged.get("guest_vsock_request_path") is True
            and bridged.get("recorder_resides_in_supervisor") is True,
            "ACK loss substituted a host-only gateway or unrelated guest")
    race = obs.get("kvm_competing_recovery")
    n_race, signed_race = signed(events, "fenced.competing-recovery-observed")
    require(type(race) is dict and signed_race == race and n1 < n_race < n2,
            "two-gateway recovery outcome lacks independently signed host observation")
    contenders = race.get("recovery_gateway_pids")
    require(type(contenders) is list and len(contenders) == 2
            and all(type(v) is int and v > 1 for v in contenders)
            and len(set(contenders + [original_pid, recipient_pid])) == 4
            and not set(contenders) & authorities,
            "recovery gateway process identities are not independent")
    require(bridged.get("racing_gateway_pids") == contenders
            and race.get("original_gateway_pid") == original_pid
            and race.get("recovery_capability_ids") == [
                spare.claims.capability_id, fault.claims.capability_id
            ]
            and race.get("both_gateways_succeeded") is True
            and race.get("independent_gateway_processes") is True
            and race.get("host_dispatched_competitor") is True
            and race.get("original_guest_recovery_gateway_index") == 0
            and race.get("gateway_requests_submitted") == 2
            and race.get("durable_effect_count") == 1
            and race.get("same_recipient_receipt") == expected_receipt
            and race.get("original_capability_id") == primary.claims.capability_id
            and race.get("original_effect_key") == effect_key
            and race.get("recovery_results") == [
                {"success": True, "effect_state": "completed", "output_digest": digest(CONTENT)},
                {"success": True, "effect_state": "completed", "output_digest": digest(CONTENT)},
            ],
            "signed competitor outcomes did not converge on the identical original effect")
    auths = [(i, e["payload"]) for i, e in enumerate(events)
             if e["event_type"] == "fenced.authorized"
             and e["source_id"] == "host-effect-service"]
    indeterminate = [(i, e["payload"]) for i, e in enumerate(events)
                     if e["event_type"] == "fenced.indeterminate"
                     and e["source_id"] == "host-effect-service"]
    commits = [(i, e["payload"]) for i, e in enumerate(events)
               if e["event_type"] == "fenced.recipient-confirmed"
               and e["source_id"] == "host-effect-service"]
    require(len(auths) == 3 and len(indeterminate) == 1 and len(commits) == 2
            and auths[0][0] < indeterminate[0][0] < n1,
            "two signed recovery gateway streams incomplete or reordered")
    require(indeterminate[0][1] == {
        "request_id": request.request_id,
        "request_digest": request.request_digest,
        "capability_id": primary.claims.capability_id,
        "effect_state": "possibly-committed",
    }, "original uncertain outcome reclassified without positive receipt")
    expected_auths = {
        primary.claims.capability_id, spare.claims.capability_id,
        fault.claims.capability_id,
    }
    require({payload["capability_id"] for _, payload in auths} == expected_auths,
            "competing gateway capabilities not distinct signed tokens")
    for _, payload in auths:
        require(payload == {
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "capability_id": payload["capability_id"],
        }, "racing capability changed original request bindings")
    require({payload["capability_id"] for _, payload in commits} == {
        spare.claims.capability_id, fault.claims.capability_id,
    }, "both competing gateways did not independently confirm recipient")
    for commit_idx, payload in commits:
        cap = payload["capability_id"]
        require(payload == {
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "capability_id": cap,
            "original_capability_id": primary.claims.capability_id,
            "receipt_digest": expected_receipt,
            "recipient_id": "ehh-owned-kvm-fenced-v1",
            "commit_sequence": 1, "recovery": True,
            "new_effect_commit": False,
        } and n1 < next(i for i, a in auths if a["capability_id"] == cap) < commit_idx < n_race,
        "unproven or duplicate competing gateway confirmation")
    require(not any(e["event_type"] in {"execution.dispatch", "execution.completed"}
                    for e in events),
            "legacy unbounded side-effect callback substituted for transactional receipt")
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
    require(len(results) == 5
            and all(v["outcome"] == "denied"
                    and v["guest_invoked"] is True
                    and v["effect_state"] == "not-started"
                    and v["dispatch_before"] == v["dispatch_after"] == 0
                    for v in results[:4])
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
            and len(report["rounds"]) == len(ACK_PHASES),
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
    for phase, record in zip(ACK_PHASES, report["rounds"], strict=True):
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
    require(checksum_path.is_file(), "original fenced ACK-loss report checksum missing")
    require(checksum_path.read_text() == (
        hashlib.sha256(raw).hexdigest() + "  " + path.name + "\n"
    ), "fenced ACK-loss report SHA256 mismatch")
    return verify_report(parse_report_json(raw))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    verify_file(args.report)
    print("PASS: actual KVM lost ACK and two independently authorized recovery gateways independently verified")
