"""Verify exported experiment evidence; embedded keys establish integrity only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from event_horizon.canonical import canonical_bytes, digest
from event_horizon.protocol import _object_without_duplicates, _reject_constant
from event_horizon.recorder import ExternalRecorder


def verify_report(report: dict) -> None:
    verify_rounds(report, schema="event-horizon.linux-isolation-experiment.v1",
                  triggers=["requested-stop", "deadline", "supervisor-channel-closed"])


def verify_rounds(report: dict, *, schema: str, triggers: list[str]) -> None:
    if report["schema"] != schema or report["status"] != "PASS":
        raise ValueError("not a completed isolation experiment")
    if len(report["rounds"]) != len(triggers):
        raise ValueError("missing teardown experiment")
    for run, trigger in zip(report["rounds"], triggers, strict=True):
        events, receipts = run["events"], run["receipts"]
        if not events or len(events) != len(receipts):
            raise ValueError("missing events or receipts")
        previous = "0" * 64
        sources = {}
        for sequence, (event, receipt) in enumerate(zip(events, receipts, strict=True), 1):
            unsigned = {key: value for key, value in event.items() if key != "event_hash"}
            if digest(unsigned) != event["event_hash"] or event["previous_hash"] != previous:
                raise ValueError("event chain altered")
            if event["sequence"] != sequence or event["source_sequence"] != sources.get(event["source_id"], 0) + 1:
                raise ValueError("evidence reordered or missing")
            if not ExternalRecorder.verify_receipt(receipt, run["recorder_public_key_pem"]):
                raise ValueError("invalid evidence signature")
            for key in ("sequence", "event_hash", "source_id", "source_sequence"):
                if receipt["payload"][key] != event[key]:
                    raise ValueError("receipt does not bind its event")
            sources[event["source_id"]] = event["source_sequence"]
            previous = event["event_hash"]
        if previous != run["evidence_chain_tip"]:
            raise ValueError("evidence truncated")
        for event_type, payload in (("isolation.observed", run["observations"]), ("teardown.verified", run["teardown"])):
            matching = [event for event in events if event["event_type"] == event_type and event["source_id"] == "host-supervisor"]
            if len(matching) != 1 or matching[0]["payload"] != payload:
                raise ValueError("summary differs from signed host observation")
        context = [event for event in events if event["event_type"] == "isolation.context" and event["source_id"] == "host-supervisor"]
        if len(context) != 1 or context[0]["payload"]["build_manifest_digest"] != digest(report["build_manifest"]):
            raise ValueError("build context differs from signed evidence")
        if context[0]["payload"]["host_kernel"] != report["host_kernel"]:
            raise ValueError("host context differs from signed evidence")
        completed = [event for event in events if event["event_type"] == "execution.completed"]
        if len(completed) != 1 or completed[0]["source_id"] != "host-effect-service":
            raise ValueError("expected one independently observed dataset read")
        if any(event["event_type"] == "execution.indeterminate" for event in events):
            raise ValueError("experiment contains unresolved outcomes")
        if run["teardown"]["trigger"] != trigger or any(
            value is not True for key, value in run["teardown"].items() if key != "trigger"
        ):
            raise ValueError("teardown was not verified")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"),
                            object_pairs_hook=_object_without_duplicates, parse_constant=_reject_constant)
        canonical_bytes(report)  # Evidence timestamps legitimately contain finite fractions.
        verify_report(report)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"Linux isolation evidence: INVALID ({exc})")
        return 1
    print("Linux isolation evidence: VERIFIED (3 chains and signed receipts; embedded keys, integrity only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
