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
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--crash-phase", choices=RECIPIENT_CRASH_PHASES,
                       help="lab-only SIGKILL checkpoint; normal recipient unaffected")
    modes.add_argument("--pause-before-commit-fd", type=int,
                       help="lab-only supervisor-owned pipe to resume inflight commit")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if not isinstance(config, dict) or set(config) != {
        "recipient_socket", "recipient_database", "effect_key", "request_digest",
    }:
        raise ValueError("untrusted or malformed recipient configuration")
    return recipient_main(config, crash_phase=args.crash_phase,
                          pause_before_commit_fd=args.pause_before_commit_fd)


if __name__ == "__main__":
    raise SystemExit(main())
