"""Trusted standalone recipient entrypoint for the owned KVM bridge experiment.

Accepts only a root-owned config path; never listens on a network interface.
Runs separately from the gateway so its FULL-sync SQLite commits survive kill.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.effect_crash_recipient import recipient_main, RECIPIENT_CRASH_PHASES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--crash-phase", choices=RECIPIENT_CRASH_PHASES,
                        help="lab-only SIGKILL checkpoint; no normal recipient uses this")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if not isinstance(config, dict) or set(config) != {
        "recipient_socket", "recipient_database", "effect_key", "request_digest",
    }:
        raise ValueError("untrusted or malformed recipient configuration")
    return recipient_main(config, crash_phase=args.crash_phase)


if __name__ == "__main__":
    raise SystemExit(main())
