"""Fail-closed verification of a trusted host's gateway SIGKILL and recovery.

This verifies the process-bridge evidence semantics and locally signed event
chain. It does NOT upgrade portable results into a Firecracker/KVM claim;
the eventual hardware report must bind these records to guest/vsock evidence
and separate signer/quorum transcripts.
"""
from __future__ import annotations

import re
import signal

from event_horizon.canonical import digest
from event_horizon.recorder import ExternalRecorder
from scripts.real_gateway_crash_checkpoints import PHASES

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def require(test, message):
    if not test:
        raise ValueError(message)


def verify_crash_bridge(*, phase, crashed, recovery, events, receipts,
                        tip, public_key_pem, request_digest, effect_key):
    require(phase in PHASES, "invalid crash phase")
    require(all(isinstance(v, str) and HEX64.fullmatch(v)
                for v in (request_digest, effect_key)), "invalid pinned effect identity")
    require(isinstance(events, list) and bool(events)
            and isinstance(receipts, list)
            and len(events) == len(receipts), "missing signed event receipts")
    previous, source_sequences = "0" * 64, {}
    for sequence, (event, receipt) in enumerate(zip(events, receipts, strict=True), 1):
        unsigned = {key: value for key, value in event.items() if key != "event_hash"}
        require(event["sequence"] == sequence
                and event["previous_hash"] == previous
                and event["event_hash"] == digest(unsigned),
                "altered crash evidence chain")
        source = event["source_id"]
        require(event["source_sequence"] == source_sequences.get(source, 0) + 1,
                "missing source event")
        require(ExternalRecorder.verify_receipt(receipt, public_key_pem),
                "forged crash evidence receipt")
        require(all(receipt["payload"][name] == event[name] for name in (
            "sequence", "event_hash", "source_id", "source_sequence",
        )), "receipt does not bind event")
        source_sequences[source] = event["source_sequence"]
        previous = event["event_hash"]
    require(previous == tip, "truncated crash evidence")
    observations = {}
    for event_name, signed in (("gateway.crash-observed", crashed),
                               ("gateway.recovery-observed", recovery)):
        matching = [(idx, e) for idx, e in enumerate(events) if e["event_type"] == event_name]
        require(len(matching) == 1
                and matching[0][1]["source_id"] == "host-supervisor"
                and matching[0][1]["payload"] == signed,
                "missing or forged trusted crash/recovery observation")
        observations[event_name] = matching[0][0]
    require(observations["gateway.crash-observed"]
            < observations["gateway.recovery-observed"],
            "recovery recorded before gateway SIGKILL")
    require(set(crashed) == {
        "phase", "gateway_pid", "signal", "exit_code",
        "recipient_before", "recipient_after_kill", "expected_commits",
    }, "invalid crash observation schema")
    require(set(recovery) == {
        "phase", "killed_pid", "recovery_pid", "recipient_after_recovery",
        "journal_state_after_kill", "original_replay", "replacement_replay",
    }, "invalid recovery observation schema")
    expected = 0 if phase in PHASES[:2] else 1
    require(crashed["phase"] == recovery["phase"] == phase
            and type(crashed["gateway_pid"]) is int and crashed["gateway_pid"] > 1
            and type(recovery["recovery_pid"]) is int and recovery["recovery_pid"] > 1
            and recovery["killed_pid"] == crashed["gateway_pid"]
            and recovery["recovery_pid"] != crashed["gateway_pid"]
            and crashed["signal"] == signal.SIGKILL
            and crashed["exit_code"] == -signal.SIGKILL
            and type(crashed["expected_commits"]) is int
            and crashed["expected_commits"] == expected,
            "SIGKILL process identity or expected effect count invalid")
    expected_digest = digest([]) if expected == 0 else digest([[effect_key, request_digest]])
    for name, row, count in (
        ("before", crashed["recipient_before"], 0),
        ("at kill", crashed["recipient_after_kill"], expected),
        ("after recovery", recovery["recipient_after_recovery"], expected),
    ):
        require(isinstance(row, dict) and set(row) == {"count", "rows_digest"}
                and type(row["count"]) is int and row["count"] == count
                and row["rows_digest"] == (digest([]) if count == 0 else expected_digest),
                f"independent recipient {name} observation invalid")
    state = None if phase == PHASES[0] else "possibly-committed"
    require(recovery["journal_state_after_kill"] == state,
            "journal observation contradicts reservation state")
    require(recovery["original_replay"] == {
        "success": False, "error": "authority-denied",
    }, "consumed authorization was executed again")
    require(recovery["replacement_replay"] == (
        None if state is None else {
            "success": False, "effect_state": "possibly-committed",
            "error": "prior-effect-unknown",
        }
    ), "fresh signed authorization bypassed durable reservation")
    dispatch = [e for e in events if e["event_type"] == "execution.dispatch"]
    require(len(dispatch) == expected
            and all(e["source_id"] == "host-effect-service"
                    and e["payload"]["request_digest"] == request_digest
                    and e["payload"]["gateway_pid"] == crashed["gateway_pid"]
                    for e in dispatch), "gateway dispatch evidence inconsistent with crash")
    completions = [e for e in events if e["event_type"] == "execution.completed"]
    require(len(completions) == (1 if phase == PHASES[4] else 0),
            "completion evidence inconsistent with checkpoint")
    return True
