"""Host-owned durable recipient and independently observed commit ledger.

This is a process/socket component, NOT hardware isolation or external attestation.
The recipient survives gateway SIGKILL; supervisor reads its own SQLite records.
"""
from __future__ import annotations

import json
import os
import signal
from pathlib import Path
import socket
import sqlite3
import stat

from event_horizon.canonical import digest


# Explicit, supervisor-only fault-injection checkpoints. Never enabled in the
# normal recipient; marker is emitted BEFORE committing or acknowledging.
RECIPIENT_CRASH_PHASES = (
    "before_commit",
    "after_commit_before_ack",
)


class RecipientCrashProbe:
    def __init__(self, phase: str):
        if phase not in RECIPIENT_CRASH_PHASES:
            raise ValueError("unknown recipient fault checkpoint")
        self.phase = phase
        self.used = False

    def mark(self, phase: str):
        if phase != self.phase:
            return
        if self.used:
            raise RuntimeError("recipient fault checkpoint repeated")
        self.used = True
        print("PHASE:" + phase, flush=True)
        while True:
            signal.pause()


def _recipient_db(path: Path) -> sqlite3.Connection:
    # The external recipient owns its SQLite journal. Create it privately,
    # without following symlinks; never silently accept attacker-owned files.
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077 or metadata.st_nlink != 1):
            raise RuntimeError("recipient ledger is not a private owned file")
    finally:
        os.close(fd)
    db = sqlite3.connect(path, timeout=5, isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS commits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        effect_key TEXT NOT NULL,
        request_digest TEXT NOT NULL
    )""")
    return db


def observed_recipient(path: Path) -> dict:
    """Independent supervisor read, not the gateway's return value."""
    with _recipient_db(path) as db:
        rows = db.execute(
            "SELECT effect_key, request_digest FROM commits ORDER BY id"
        ).fetchall()
    return {"count": len(rows), "rows_digest": digest([list(row) for row in rows])}


def recipient_main(config: dict, *, crash_phase: str | None = None,
                   pause_before_commit_fd: int | None = None) -> int:
    """Separate durable recipient, with opt-in supervisor-owned fault controls."""
    if crash_phase is not None and pause_before_commit_fd is not None:
        raise ValueError("recipient kill and delayed-commit controls are exclusive")
    if pause_before_commit_fd is not None and (
            type(pause_before_commit_fd) is not int or pause_before_commit_fd < 3):
        raise ValueError("recipient delayed commit requires a private control fd")
    probe = RecipientCrashProbe(crash_phase) if crash_phase is not None else None
    delayed_once = False
    socket_path = config["recipient_socket"]
    db_path = Path(config["recipient_database"])
    if os.path.lexists(socket_path):
        raise RuntimeError("recipient endpoint already exists")
    with _recipient_db(db_path):
        pass
    service = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    service.bind(socket_path)
    os.chmod(socket_path, 0o600)
    service.listen(4)
    service.settimeout(1)
    print("READY", flush=True)
    try:
        while True:
            try:
                client, _ = service.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(3)
                data = client.recv(4096)
                payload = json.loads(data)
                if (set(payload) != {"effect_key", "request_digest"}
                        or payload["effect_key"] != config["effect_key"]
                        or payload["request_digest"] != config["request_digest"]):
                    client.sendall(b'{"error":"invalid-binding"}\n')
                    continue
                if probe is not None:
                    probe.mark("before_commit")
                # Fault injection only: the recipient has validated the exact
                # logical effect but has NOT entered its SQLite transaction.
                # A private supervisor-held pipe may release it AFTER the
                # gateway dies. EOF must abort instead of permitting commit.
                if pause_before_commit_fd is not None and not delayed_once:
                    delayed_once = True
                    print("PHASE:inflight_before_commit", flush=True)
                    release = os.read(pause_before_commit_fd, 1)
                    os.close(pause_before_commit_fd)
                    pause_before_commit_fd = None
                    if release != b"R":
                        raise RuntimeError("trusted recipient release not confirmed")
                with _recipient_db(db_path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        "INSERT INTO commits(effect_key, request_digest) VALUES (?, ?)",
                        (payload["effect_key"], payload["request_digest"]),
                    )
                    db.execute("COMMIT")
                if probe is not None:
                    probe.mark("after_commit_before_ack")
                try:
                    client.sendall(b'{"committed":true}\n')
                except (BrokenPipeError, ConnectionResetError):
                    # Commit is already durable. The gateway may have been
                    # SIGKILLed during delivery; NEVER roll back or retry it.
                    # Continue serving independent requests.
                    pass
    finally:
        service.close()

