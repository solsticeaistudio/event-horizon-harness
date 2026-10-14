"""Operator CLI: EXTERNAL power-controller witness + boot-separated SQLite proof.

NO shutdown, reboot, power-control command or remote SSH is implemented.
Use only a disposable dedicated VM/host with independently controlled power.
Never copy the witness private key onto the target under test.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from event_horizon.powercut_proof import (
    _boot_id, prepare, create_external_statement, verify,
)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("boot-id", help="Show this Linux machine's current boot identifier")
    a = sub.add_parser("prepare", help="Target: fsync FIRST synthetic effect + baseline")
    a.add_argument("--database", required=True, type=Path)
    a.add_argument("--preflight", required=True, type=Path)
    a.add_argument("--recipient-id", required=True)
    b = sub.add_parser("attest", help="Independent controller: sign OBSERVED event")
    b.add_argument("--preflight", required=True, type=Path)
    b.add_argument("--event-log", required=True, type=Path)
    b.add_argument("--controller-id", required=True)
    b.add_argument("--boot-id-after", required=True)
    b.add_argument("--private-key", required=True, type=Path)
    b.add_argument("--statement", required=True, type=Path)
    c = sub.add_parser("verify", help="Recovered target: verify signed controller+row")
    c.add_argument("--preflight", required=True, type=Path)
    c.add_argument("--statement", required=True, type=Path)
    c.add_argument("--event-log", required=True, type=Path)
    c.add_argument("--controller-public-key", required=True, type=Path)
    c.add_argument("--database", required=True, type=Path)
    c.add_argument("--report", required=True, type=Path)
    args = p.parse_args()
    if args.action == "boot-id":
        print(_boot_id())
    elif args.action == "prepare":
        print(json.dumps(prepare(
            database=args.database, preflight_path=args.preflight,
            recipient_id=args.recipient_id,
        ), sort_keys=True))
        print("STOP: export the ORIGINAL preflight to your SEPARATE controller "
              "and validate persistence; do not disconnect power yet.")
    elif args.action == "attest":
        print(json.dumps(create_external_statement(
            preflight_path=args.preflight, event_log_path=args.event_log,
            controller_id=args.controller_id, boot_id_after=args.boot_id_after,
            private_key_path=args.private_key, statement_path=args.statement,
        ), sort_keys=True))
    elif args.action == "verify":
        print(json.dumps(verify(
            preflight_path=args.preflight, statement_path=args.statement,
            event_log_path=args.event_log,
            controller_public_key=args.controller_public_key,
            database=args.database, report_path=args.report,
        ), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"INCOMPLETE/FAIL-CLOSED: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        raise SystemExit(1) from exc
