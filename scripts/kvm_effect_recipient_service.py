"""Trusted standalone recipient entrypoint for the owned KVM bridge experiment.

Accepts only a root-owned config path; never listens on a network interface.
Runs separately from the gateway so its FULL-sync SQLite commits survive kill.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.effect_crash_recipient import recipient_main


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if not isinstance(config, dict) or set(config) != {
        "recipient_socket", "recipient_database", "effect_key", "request_digest",
    }:
        raise ValueError("untrusted or malformed recipient configuration")
    return recipient_main(config)


if __name__ == "__main__":
    raise SystemExit(main())
