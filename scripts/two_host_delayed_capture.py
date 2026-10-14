"""Schedule a READ-ONLY HP recipient checkpoint while SSH is unreachable.

The HP laptop may have no usable screen: arm this on HP via SSH BEFORE
manually disconnecting its only network. The detached worker waits a bounded
interval, then signs ONLY the local SQLite receipt and writes immutable
original JSON + SHA256. It does not change networking or power.

A timer is NOT an independent network fault witness; the actual MSI TLS
probe must still show an indeterminate connection at that same phase.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from scripts.two_host_campaign import (
    _private_parent, _revision, _safe_key, capture, recipient_snapshot,
)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--worker", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--delay-seconds", type=int, required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--effect-key", required=True)
    p.add_argument("--request-digest", required=True)
    p.add_argument("--recipient-id", required=True)
    p.add_argument("--database", type=Path, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--log", type=Path,
                   help="Host-only 0600 diagnostic log, never published")
    args = p.parse_args()
    if not 1 <= args.delay_seconds <= 3600:
        raise ValueError("scheduled checkpoint delay must be 1-3600 seconds")
    if args.worker:
        time.sleep(args.delay_seconds)
        args.role, args.phase = "recipient", "disconnected"
        args.journal_db = args.consensus_config = args.tls_config = None
        capture(args)
        return
    if args.log is None:
        raise ValueError("detached witness needs an explicit private log path")
    if args.output.exists() or Path(str(args.output) + ".sha256").exists():
        raise FileExistsError("scheduled recipient observation already exists")
    # Confirm meaningful baseline before a laptop becomes unreachable:
    # no scheduled capture of a missing/malformed original ledger.
    _revision()
    _safe_key(args.private_key)
    recipient_snapshot(
        database=args.database, effect_key=args.effect_key,
        request_digest=args.request_digest, recipient_id=args.recipient_id,
    )
    _private_parent(args.log)
    fd = os.open(args.log, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    cmd = [
        sys.executable, str(Path(__file__).resolve()), "--worker",
        "--delay-seconds", str(args.delay_seconds),
        "--run-id", args.run_id,
        "--effect-key", args.effect_key,
        "--request-digest", args.request_digest,
        "--recipient-id", args.recipient_id,
        "--database", str(args.database),
        "--private-key", str(args.private_key),
        "--output", str(args.output),
    ]
    try:
        with os.fdopen(fd, "wb") as log:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, cwd=ROOT,
                start_new_session=True, close_fds=True,
            )
    except BaseException:
        raise
    print(
        f"ARMED: local HP capture PID={proc.pid}, delay={args.delay_seconds}s. "
        "Now isolate only the intended lab network. "
        f"After reconnection, confirm {args.output} AND .sha256 exist; "
        f"diagnostics at {args.log}. No proof is claimed until verified.",
        flush=True,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"INCOMPLETE: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
