"""Strict internal evidence verifier for genuine in-flight recipient commit race.

This verifies signed host/gateway observations and durable recipient counts.
KVM/guardian/etcd bindings must ALSO be established by the outer sixth
Firecracker report verifier; a portable process-only run cannot satisfy it.
"""
from __future__ import annotations

import re
import signal

from event_horizon.canonical import digest
from event_horizon.recorder import ExternalRecorder

HEX64 = re.compile(r"[0-9a-f]{64}")


def require(test, message):
    if not test:
        raise ValueError(message)


def verify_delayed_bridge(*, report, events, receipts, tip, public_key_pem,
                          request_digest, effect_key):
    require(isinstance(report, dict) and report.get("phase") == "inflight_before_commit",
            "not an in-flight recipient report")
    require(all(isinstance(x, str) and HEX64.fullmatch(x)
                for x in (request_digest, effect_key)), "unbound logical effect")
    require(isinstance(events, list) and bool(events)
            and isinstance(receipts, list) and len(events) == len(receipts),
            "signed event chain incomplete")
    previous, sources = "0" * 64, {}
    for i, (event, receipt) in enumerate(zip(events, receipts, strict=True), 1):
        unsigned = {k: v for k, v in event.items() if k != "event_hash"}
        require(event["sequence"] == i and event["previous_hash"] == previous
                and event["event_hash"] == digest(unsigned),
                "broken sixth-window event hash chain")
        source = event["source_id"]
        require(event["source_sequence"] == sources.get(source, 0) + 1,
                "source event sequence gap")
        require(ExternalRecorder.verify_receipt(receipt, public_key_pem)
                and all(receipt["payload"][k] == event[k] for k in (
                    "sequence", "event_hash", "source_id", "source_sequence"
                )), "invalid sixth-window embedded-key receipt")
        sources[source] = event["source_sequence"]
        previous = event["event_hash"]
    require(previous == tip, "truncated sixth-window chain tip")

    signed_names = ("recipient.inflight-observed",
                    "gateway.delayed-sigkill-observed",
                    "recipient.delayed-commit-observed")
    signed = {}
    order = []
    for name in signed_names:
        found = [(i, e["payload"]) for i, e in enumerate(events)
                 if e["event_type"] == name and e["source_id"] == "host-supervisor"]
        require(len(found) == 1, "missing trusted phase evidence " + name)
        order.append(found[0][0])
        signed[name] = found[0][1]
    require(order == sorted(order) and len(set(order)) == 3,
            "recipient pause, death, and late commit order invalid")
    pause = signed[signed_names[0]]
    death = signed[signed_names[1]]
    require(signed[signed_names[2]] == report,
            "late-commit summary not identical to signed observation")
    before = {"count": 0, "rows_digest": digest([])}
    final = {"count": 1, "rows_digest": digest([[effect_key, request_digest]])}
    require(set(report) == {
        "phase", "killed_gateway_pid", "recovery_gateway_pid",
        "recipient_pid", "signal", "exit_code", "before",
        "at_pause", "after_kill", "before_release", "after_release",
        "journal_state", "request_digest", "effect_key",
        "original_replay", "replacement_replay", "recipient_release_confirmed",
    }, "incomplete delayed-recipient report schema")
    require(report["request_digest"] == request_digest
            and report["effect_key"] == effect_key
            and report["before"] == report["at_pause"] == report["after_kill"]
            == report["before_release"] == before
            and report["after_release"] == final
            and report["journal_state"] == "possibly-committed"
            and report["recipient_release_confirmed"] is True,
            "recipient commit/fence observations invalid")
    killed, recovered, recipient = (report["killed_gateway_pid"],
                                    report["recovery_gateway_pid"],
                                    report["recipient_pid"])
    require(all(type(v) is int and v > 1 for v in (killed, recovered, recipient))
            and len({killed, recovered, recipient}) == 3
            and report["signal"] == signal.SIGKILL
            and report["exit_code"] == -signal.SIGKILL,
            "unproved SIGKILL or process separation")
    require(pause == {
        "phase": "inflight_before_commit",
        "gateway_pid": killed, "recipient_pid": recipient,
        "recipient_before": before, "recipient_at_pause": before,
        "journal_state": "possibly-committed",
        "effect_key": effect_key, "request_digest": request_digest,
    }, "in-flight phase not observed on original gateway")
    require(death == {
        "phase": "inflight_before_commit",
        "gateway_pid": killed, "signal": signal.SIGKILL,
        "exit_code": -signal.SIGKILL, "recipient_at_kill": before,
        "journal_state": "possibly-committed",
    }, "gateway death not bound to original paused recipient")
    require(report["original_replay"] == {
        "success": False, "error": "authority-denied",
    } and report["replacement_replay"] == {
        "success": False, "effect_state": "possibly-committed",
        "error": "prior-effect-unknown",
    }, "guest replays were not fenced before late commit")
    dispatches = [e for e in events if e["event_type"] == "execution.dispatch"]
    completed = [e for e in events if e["event_type"] == "execution.completed"]
    require(len(dispatches) == 1 and not completed
            and dispatches[0]["source_id"] == "host-effect-service"
            and dispatches[0]["payload"]["gateway_pid"] == killed
            and dispatches[0]["payload"]["request_digest"] == request_digest,
            "gateway dispatched twice or invented completion evidence")
    # Event sequence numbers are 1-based; enumerate() positions are 0-based.
    require(dispatches[0]["sequence"] - 1 < order[0],
            "recipient reported pause before original dispatch evidence")
    return True
