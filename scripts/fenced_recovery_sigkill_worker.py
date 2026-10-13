"""Lab-only real gateway SIGKILL checkpoints for cooperating recipient recovery.

No Firecracker, no external networking, no arbitrary effect callbacks. The
supervisor alone writes a private trusted config and chooses a single
checkpoint. An opt-in recipient wrapper blocks the gateway process either
before or just after its atomic SQLite commit, so the test can SIGKILL it.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal

from event_horizon.broker import CapabilityVerifier
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.fenced_effect_recovery import FencedEffectRecoveryGateway
from event_horizon.fenced_recipient import FencedSqliteRecipient
from event_horizon.models import ActionRequest, IssuedCapability
from event_horizon.recorder import ExternalRecorder
from event_horizon.trusted_effect_gateway import select_consumption_store

PHASES = ("before_recipient_commit", "after_recipient_commit")


def run(config: dict, *, phase: str):
    required = {
        "public_key_pem", "key_id", "request", "capability", "verification_context",
        "recipient_path", "recipient_id", "journal_path", "replay_path", "recorder_path",
        "output",
    }
    if set(config) != required or phase not in PHASES:
        raise ValueError("invalid trusted fenced recovery laboratory configuration")
    request = ActionRequest.from_dict(config["request"])
    cap = IssuedCapability.from_dict(config["capability"])
    context = config["verification_context"]

    class KillPointRecipient(FencedSqliteRecipient):
        def apply(self, **kwargs):
            if phase == "before_recipient_commit":
                print("PHASE:before_recipient_commit", flush=True)
                while True:
                    signal.pause()
            receipt = super().apply(**kwargs)
            # The old gateway MUST die after an independent durable recipient
            # commit, but before journal confirmation or client ack.
            print("PHASE:after_recipient_commit", flush=True)
            while True:
                signal.pause()

    store = select_consumption_store(
        backend="sqlite", namespace=request.session_id,
        domain="external-effect", sqlite_path=config["replay_path"],
    )
    try:
        gateway = FencedEffectRecoveryGateway(
            CapabilityVerifier(config["public_key_pem"], config["key_id"], store),
            ExternalRecorder(config["recorder_path"]),
            DurableEffectJournal(config["journal_path"]),
            KillPointRecipient(
                config["recipient_path"], recipient_id=config["recipient_id"],
            ),
            output_factory=lambda _: config["output"],
        )
        result = gateway.execute(
            request, cap, context["attestation"],
            executor_measurement=context["executor_measurement"],
            device_id=context["device_id"],
            verifier_policy_digest=context["verifier_policy_digest"],
            policy_digest=context["policy_digest"],
        )
        raise RuntimeError("kill checkpoint not reached; result=" + repr(result))
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=PHASES)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    run(config, phase=args.phase)


if __name__ == "__main__":
    main()
