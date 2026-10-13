"""Trusted standalone fenced recipient process (synthetic SQLite effect only).

The independent supervisor chooses a 0600 config in a trusted directory.
It must never pass this IPC key, database path or socket to the guest.
SIGKILL leaves a socket inode; supervisor must identify/reap the prior PID,
verify the stale inode's ownership/type, then unlink before restart.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat

from event_horizon.fenced_recipient_transport import serve_fenced_recipient


PHASES = ("before_commit", "after_commit_before_reply")
TRANSPORT_FAULTS = ("drop_before_commit", "drop_ack_after_commit")


def load_config(path: Path) -> dict:
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise ValueError("recipient config must be private and operator-owned")
    from event_horizon.fenced_recipient_transport import _private_parent
    _private_parent(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if type(raw) is not dict or set(raw) != {
        "socket_path", "recipient_database", "recipient_id", "auth_key_hex",
    }:
        raise ValueError("invalid trusted recipient configuration")
    if type(raw["auth_key_hex"]) is not str or len(raw["auth_key_hex"]) != 64:
        raise ValueError("invalid IPC key encoding")
    return raw


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--lab-fault", choices=PHASES + TRANSPORT_FAULTS, default=None)
    args = parser.parse_args()
    config = load_config(args.config)
    key = bytes.fromhex(config["auth_key_hex"])
    used = False

    def checkpoint(phase: str) -> bool:
        nonlocal used
        # These modes are selected only by the trusted host supervisor.
        # Never infer non-commit from an unreadable/missing reply.
        drop_phase = {
            "drop_before_commit": "before_commit",
            "drop_ack_after_commit": "after_commit_before_reply",
        }.get(args.lab_fault)
        if phase == drop_phase and not used:
            used = True
            print("DROPPED:" + str(args.lab_fault), flush=True)
            return True
        if phase == args.lab_fault and not used:
            used = True
            print("PHASE:" + phase, flush=True)
            while True:
                signal.pause()
        return False

    serve_fenced_recipient(
        config["socket_path"], config["recipient_database"],
        recipient_id=config["recipient_id"], auth_key=key,
        ready=lambda: print("READY", flush=True),
        checkpoint=checkpoint if args.lab_fault else None,
    )


if __name__ == "__main__":
    main()
