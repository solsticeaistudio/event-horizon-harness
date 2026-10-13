"""Strict evidence verifier for the NEW Firecracker fenced recipient baseline.

This verifier does not accept portable Linux evidence or historical KVM
reports. Embedded Ed25519 signatures prove internal lineage only, not
independently witnessed attestation. No crash-recovery claim is made.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from event_horizon.canonical import digest
from event_horizon.recorder import ExternalRecorder
from scripts.integrated_authority_session import evidence_digest
from scripts.run_package_isolation import CONTENT
from scripts.verify_integrated_authority import verify_authority
from scripts.verify_integrated_kvm_crash import parse_report_json


SCHEMA = "event-horizon.firecracker-fenced-recipient-baseline.v1"
MODE = "real-kvm-guardian-etcd-atomic-fenced-recipient-baseline"
HEX = re.compile(r"[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_chain(events, receipts, tip, public_key):
    require(isinstance(events, list) and len(events) > 10
            and isinstance(receipts, list) and len(events) == len(receipts),
            "missing recipient evidence or incomplete receipt set")
    previous = "0" * 64
    sequences = {}
    for seq, (event, receipt) in enumerate(zip(events, receipts, strict=True), 1):
        unsigned = {k: v for k, v in event.items() if k != "event_hash"}
        require(event.get("sequence") == seq
                and event.get("previous_hash") == previous
                and event.get("event_hash") == digest(unsigned),
                "fenced KVM event hash chain corrupted")
        sid = event.get("source_id")
        require(isinstance(sid, str)
                and event.get("source_sequence") == sequences.get(sid, 0) + 1,
                "fenced KVM source-event ordering corrupted")
        require(ExternalRecorder.verify_receipt(receipt, public_key)
                and all(receipt["payload"].get(k) == event[k] for k in (
                    "sequence", "event_hash", "source_id", "source_sequence",
                )), "fenced KVM receipt not signed by embedded recorder key")
        sequences[sid] = event["source_sequence"]
        previous = event["event_hash"]
    require(previous == tip, "KVM evidence truncated or chain tip differs")


def verify_report(report):
    require(type(report) is dict and report.get("schema") == SCHEMA
            and report.get("experiment_mode") == MODE
            and report.get("status") == "PASS"
            and type(report.get("rounds")) is list
            and len(report["rounds"]) == 1,
            "not a complete real KVM fenced baseline report")
    source = report.get("source_commit")
    require(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
            and report.get("attestation") == "synthetic-fixture"
            and report.get("build_manifest", {}).get("tpm2_enabled") is False,
            "source and honest synthetic guest attestation not pinned")
    a = report.get("authority")
    require(type(a) is dict and a.get("backend") == "etcd"
            and a.get("oracle") == "host-supervisor-linearizable-etcd-read"
            and type(a.get("cluster_id")) is str and a["cluster_id"].isdecimal()
            and int(a["cluster_id"]) > 0,
            "no pinned independent three-member consensus authority")
    r = report["rounds"][0]
    events, receipts, obs = r["events"], r["receipts"], r["observations"]
    verify_chain(events, receipts, r["evidence_chain_tip"],
                 r["recorder_public_key_pem"])
    isolation = r["isolated_authority"]
    session, (primary, spare, fault) = verify_authority(isolation)
    request = session.request
    require(isolation["configuration"]["source_commit"] == source
            and isolation["configuration"]["build_artifacts"]
            == report["build_manifest"]["artifacts"]
            and obs.get("isolated_authority_digest") == evidence_digest(isolation),
            "signer/guardians not bound to source and measured binaries")
    contexts = [e for e in events if e["event_type"] == "isolation.context"
                and e["source_id"] == "host-supervisor"]
    require(len(contexts) == 1, "trusted pinned KVM context absent or repeated")
    ctx = contexts[0]["payload"]
    require(ctx.get("build_manifest_digest") == digest(report["build_manifest"])
            and ctx.get("host_kernel") == report["host_kernel"]
            and ctx.get("session_id") == request.session_id
            and ctx.get("capability_id") == primary.claims.capability_id
            and ctx.get("package_context", {}).get("mode") == "protected",
            "KVM context/guest manifest not source-bound")
    require(obs.get("vm_chroot_verified") is True
            and obs.get("vm_seccomp_verified") is True
            and obs.get("separate_network_namespaces") is True
            and obs.get("host_principal_file_denials") is True
            and obs.get("guest_root_diagnostic", {}).get("uid") == 0
            and obs.get("retired_effect_endpoint_unreachable") is True
            and obs.get("replay_denied") is True,
            "missing real jailed Firecracker guest isolation controls")
    teardown = r["teardown"]
    require(teardown.get("trigger") == "requested-stop"
            and all(v is True for k, v in teardown.items() if k != "trigger"),
            "KVM host cleanup not complete")
    for kind, payload in (("isolation.observed", obs),
                          ("teardown.verified", teardown)):
        signed = [e for e in events if e["event_type"] == kind
                  and e["source_id"] == "host-supervisor"]
        require(len(signed) == 1 and signed[0]["payload"] == payload,
                "unsigned or replaced KVM observation summary")
    effect_key = digest({
        "session_id": request.session_id, "request_id": request.request_id,
    })
    f = obs.get("fenced_recipient_kvm")
    require(type(f) is dict and set(f) == {
        "recipient_pid", "gateway_pid", "effect_key", "request_digest",
        "recipient_id", "output_digest", "receipt_digest", "commit_sequence",
        "row_count", "journal_state", "original_capability_id",
        "attestation_mode",
    }, "no independently observed atomic fenced recipient report")
    require(f["effect_key"] == effect_key
            and f["request_digest"] == request.request_digest
            and f["output_digest"] == digest(CONTENT)
            and f["row_count"] == 1
            and f["journal_state"] == "recipient-confirmed"
            and f["original_capability_id"] == primary.claims.capability_id
            and f["attestation_mode"] == "synthetic-fixture"
            and type(f["recipient_id"]) is str
            and f["recipient_id"] == "ehh-owned-kvm-fenced-v1"
            and type(f["commit_sequence"]) is int and f["commit_sequence"] == 1
            and type(f["receipt_digest"]) is str
            and HEX.fullmatch(f["receipt_digest"]),
            "KVM fenced recipient count, effect binding or receipt mismatch")
    expected_receipt = digest({
        "schema": "event-horizon.fenced-recipient-receipt.v1",
        "recipient_id": f["recipient_id"], "effect_key": effect_key,
        "request_digest": request.request_digest,
        "output_digest": digest(CONTENT), "sequence": 1,
    })
    require(f["receipt_digest"] == expected_receipt,
            "KVM receipt does not describe the unique original transaction")
    bridge = obs.get("gateway_process_bridge")
    require(type(bridge) is dict
            and bridge.get("identity_binding") == "pidfd-fenced-recipient-v1"
            and bridge.get("independent_process") is True
            and bridge.get("guest_vsock_request_path") is True
            and bridge.get("recorder_resides_in_supervisor") is True
            and bridge.get("gateway_pid") == f["gateway_pid"],
            "independent KVM gateway bridge is not proven")
    pids = (f["recipient_pid"], f["gateway_pid"], bridge["supervisor_pid"])
    authority_pids = {v["pid"] for v in isolation["roles"].values()}
    authority_pids.update(v["pid"] for v in isolation.get("coordinators", []))
    require(all(type(p) is int and p > 1 for p in pids)
            and len(set(pids)) == 3
            and not set(pids) & authority_pids,
            "recipient, gateway and authority share a process identity")
    authors = [e for e in events
               if e["event_type"] == "fenced.authorized"
               and e["source_id"] == "host-effect-service"]
    completed = [e for e in events
                 if e["event_type"] == "fenced.recipient-confirmed"
                 and e["source_id"] == "host-effect-service"]
    require(len(authors) == len(completed) == 1
            and authors[0]["sequence"] < completed[0]["sequence"],
            "fenced authorization and positive commit evidence missing")
    auth, done = authors[0]["payload"], completed[0]["payload"]
    require(auth == {
        "request_id": request.request_id,
        "request_digest": request.request_digest,
        "capability_id": primary.claims.capability_id,
    } and done == {
        "request_id": request.request_id,
        "request_digest": request.request_digest,
        "capability_id": primary.claims.capability_id,
        "original_capability_id": primary.claims.capability_id,
        "receipt_digest": expected_receipt,
        "recipient_id": f["recipient_id"],
        "commit_sequence": 1,
        "recovery": False,
        "new_effect_commit": True,
    }, "gateway completion was not bound to independently observed atomic receipt")
    require(not any(e["event_type"] in (
                "execution.dispatch", "execution.completed"
            ) for e in events),
            "legacy dispatch/completion incorrectly substituted as atomic proof")
    oracle = obs["authority_oracle"]
    extras = set(oracle["additional_consumed_ids"])
    require(oracle.get("source") == a["oracle"]
            and oracle.get("backend") == "etcd"
            and oracle.get("cluster_id") == a["cluster_id"]
            and oracle.get("capability_id") == primary.claims.capability_id
            and oracle.get("claims_digest") == digest(primary.claims.to_dict())
            and oracle.get("primary_record_count") == 1
            and oracle.get("record_integrity_checked") is True
            and extras <= {fault.claims.capability_id}
            and oracle.get("record_count") == 1 + len(extras)
            and obs["host_consumption_count"] == oracle["record_count"]
            and obs["unredeemed_capability_at_teardown"] == spare.claims.capability_id,
            "independent etcd consumption does not match one authorized effect")
    package = obs["package"]
    require(package.get("mode") == "protected"
            and package.get("worker_sha256") == report["worker_build"]["worker_sha256"]
            and package.get("service_scratch_removed") is True
            and package.get("authoritative_evidence_outside_service_root") is True
            and all(v is False for v in package["forbidden_effects"].values()),
            "compromised worker escaped protected process boundary")
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
            "forbidden guest attempts were not denied before/after fenced commit")
    require(obs["integrated_gateway"]["dispatches"] == 1,
            "fenced commit counted as zero or multiple dispatches")
    return True


def verify_file(path: Path):
    path = Path(path)
    data = path.read_bytes()
    checksum_path = Path(str(path) + ".sha256")
    require(checksum_path.is_file(), "original KVM fenced report checksum missing")
    require(checksum_path.read_text() == (
        hashlib.sha256(data).hexdigest() + "  " + path.name + "\n"
    ), "original fenced KVM report checksum mismatch")
    return verify_report(parse_report_json(data))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    verify_file(args.report)
    print("PASS: independently verified REAL KVM fenced initial commit; no crash claim")
