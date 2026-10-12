"""Host-owned durable recipient and independently observed commit ledger.

This is a process/socket component, NOT hardware isolation or external attestation.
The recipient survives gateway SIGKILL; supervisor reads its own SQLite records.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sqlite3
import stat

from event_horizon.canonical import digest


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


def recipient_main(config: dict) -> int:
    """Separate recipient service; its journal remains alive across gateway kills."""
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
                with _recipient_db(db_path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        "INSERT INTO commits(effect_key, request_digest) VALUES (?, ?)",
                        (payload["effect_key"], payload["request_digest"]),
                    )
                    db.execute("COMMIT")
                client.sendall(b'{"committed":true}\n')
    finally:
        service.close()

