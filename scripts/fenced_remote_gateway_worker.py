"""Separate process gateway for fenced-recipient crash and race experiments.

Uses genuinely signed capabilities, durable independent replay/journal files,
and authenticated recipient IPC. Fault points are supervisor-only test options.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal

from event_horizon.broker import CapabilityVerifier
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_effect_recovery import FencedEffectRecoveryGateway
from event_horizon.fenced_recipient_transport import FencedRecipientClient
from event_horizon.models import ActionRequest, IssuedCapability
from event_horizon.recorder import ExternalRecorder
from event_horizon.trusted_effect_gateway import select_consumption_store
from scripts.fenced_recipient_service import load_config


PHASES = ("before_recipient_rpc", "after_recipient_reply")


def run(config: dict, phase: str | None) -> dict:
    if type(config) is not dict or set(config) != {
        "public_key_pem", "key_id", "request", "capability", "verification_context",
        "socket_path", "recipient_id", "auth_key_hex", "journal_path",
        "replay_path", "recorder_path", "output",
    }:
        raise ValueError("invalid trusted gateway config")
    request = ActionRequest.from_dict(config["request"])
    cap = IssuedCapability.from_dict(config["capability"])
    context = config["verification_context"]

    class CrashingClient(FencedRecipientClient):
        def apply(self, **kwargs):
            if phase == "before_recipient_rpc":
                print("PHASE:before_recipient_rpc", flush=True)
                while True:
                    signal.pause()
            receipt = super().apply(**kwargs)
            if phase == "after_recipient_reply":
                print("PHASE:after_recipient_reply", flush=True)
                while True:
                    signal.pause()
            return receipt

    store = select_consumption_store(
        backend="sqlite", namespace=request.session_id,
        domain="external-effect", sqlite_path=config["replay_path"],
    )
    try:
        recipient = CrashingClient(
            config["socket_path"], recipient_id=config["recipient_id"],
            auth_key=bytes.fromhex(config["auth_key_hex"]), timeout=2,
        )
        gateway = FencedEffectRecoveryGateway(
            CapabilityVerifier(config["public_key_pem"], config["key_id"], store),
            ExternalRecorder(config["recorder_path"]),
            DurableEffectJournal(config["journal_path"]),
            recipient, output_factory=lambda _: config["output"],
        )
        result = gateway.execute(
            request, cap, context["attestation"],
            executor_measurement=context["executor_measurement"],
            device_id=context["device_id"],
            verifier_policy_digest=context["verifier_policy_digest"],
            policy_digest=context["policy_digest"],
        )
        return {
            "accepted": result.accepted, "effect_state": result.effect_state,
            "error_class": result.error_class, "output": result.output,
        }
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--lab-fault", choices=PHASES)
    args = parser.parse_args()
    # Same strict config-file ownership contract as the recipient.
    config = load_gateway_config(args.config)
    result = run(config, args.lab_fault)
    print("RESULT:" + json.dumps(result, sort_keys=True), flush=True)


def load_gateway_config(path: Path) -> dict:
    # The recipient and gateway share the same private-file ownership checks.
    import os
    import stat
    from event_horizon.fenced_recipient_transport import _private_parent
    _private_parent(path)
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise ValueError("trusted gateway config not private")
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
