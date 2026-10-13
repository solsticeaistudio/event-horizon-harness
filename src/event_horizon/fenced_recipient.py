"""Opt-in cooperating recipient with atomic, durable effect deduplication.

Only supports effects represented by the SAME SQLite transaction as their
idempotency row. It does NOT make arbitrary third-party HTTP/API calls exactly
once. Caller and DB directory are trusted host components, never guest input.
A negative observation NEVER frees an earlier gateway reservation.
"""
from __future__ import annotations

import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .canonical import canonical_bytes, digest

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class FencedRecipientError(RuntimeError):
    """Recipient refused an ambiguous, incorrect, or unavailable operation."""


class FencedRecipientBindingError(FencedRecipientError):
    """Same logical key was rebound to a different request or result."""


@dataclass(frozen=True)
class FencedReceipt:
    effect_key: str
    request_digest: str
    recipient_id: str
    output: object
    output_digest: str
    receipt_digest: str
    sequence: int
    newly_committed: bool


class FencedSqliteRecipient:
    """Trusted synthetic recipient: business effect and dedupe row commit together.

    An existing key always returns the ORIGINAL durable result. Competing
    writers serialize under SQLite BEGIN IMMEDIATE, including across processes.
    No source of independent side effects is permitted in this implementation.
    """

    def __init__(self, path: str | Path, *, recipient_id: str):
        self.path = Path(path)
        if (not self.path.is_absolute() or str(path) == ":memory:"
                or not isinstance(recipient_id, str)
                or not (1 <= len(recipient_id) <= 128)
                or not all(c.isascii() and (c.isalnum() or c in "-_.:")
                            for c in recipient_id)):
            raise ValueError("fenced recipient needs a pinned ID and absolute disk path")
        self.recipient_id = recipient_id
        owner = os.geteuid()
        parent = self.path.parent
        current = parent
        while True:
            info = os.lstat(current)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner):
                raise FencedRecipientError("recipient has untrusted ancestor")
            if current == parent and info.st_uid != owner:
                raise FencedRecipientError("recipient directory ownership mismatch")
            if info.st_mode & 0o022 and not (
                current != parent and info.st_uid == 0
                and info.st_mode & stat.S_ISVTX
            ):
                raise FencedRecipientError("recipient has writable ancestor")
            if current == current.parent:
                break
            current = current.parent
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise FencedRecipientError("recipient file must be private, unlinked only once")
        finally:
            os.close(fd)
        try:
            with self._db() as db:
                db.execute("""CREATE TABLE IF NOT EXISTS recipient_identity (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    recipient_id TEXT NOT NULL)""")
                db.execute("""CREATE TABLE IF NOT EXISTS effects (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    effect_key TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL,
                    output_json BLOB NOT NULL,
                    output_digest TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL)""")
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT recipient_id FROM recipient_identity WHERE singleton=1"
                ).fetchone()
                if row is None:
                    db.execute(
                        "INSERT INTO recipient_identity(singleton,recipient_id) VALUES(1,?)",
                        (recipient_id,),
                    )
                elif row[0] != recipient_id:
                    raise FencedRecipientBindingError("durable recipient identity changed")
                db.execute("COMMIT")
        except sqlite3.Error as exc:
            raise FencedRecipientError("fenced recipient startup unavailable") from exc

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=5000")
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    @staticmethod
    def _key(effect_key: str, request_digest: str):
        if (not isinstance(effect_key, str) or not _HEX64.fullmatch(effect_key)
                or not isinstance(request_digest, str)
                or not _HEX64.fullmatch(request_digest)):
            raise ValueError("fenced recipient requires canonical effect/request digests")

    def _receipt_digest(self, key, request_digest, output_digest, sequence):
        return digest({
            "schema": "event-horizon.fenced-recipient-receipt.v1",
            "recipient_id": self.recipient_id,
            "effect_key": key,
            "request_digest": request_digest,
            "output_digest": output_digest,
            "sequence": sequence,
        })

    def apply(self, *, effect_key: str, request_digest: str, output: object) -> FencedReceipt:
        """Commit once; atomic row represents the entire synthetic business effect.

        Reapplication requires identical key, request AND output. A late original
        writer and a recovered writer can race: only one INSERT ever commits.
        """
        self._key(effect_key, request_digest)
        raw = canonical_bytes(output)
        output_digest = digest(output)
        if len(raw) > 16_384:
            raise ValueError("effect exceeds synthetic recipient storage ceiling")
        try:
            with self._db() as db:
                try:
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute(
                        "SELECT sequence,request_digest,output_json,output_digest,receipt_digest "
                        "FROM effects WHERE effect_key=?",
                        (effect_key,),
                    ).fetchone()
                    created = row is None
                    if created:
                        cursor = db.execute(
                            "INSERT INTO effects(effect_key,request_digest,output_json,"
                            "output_digest,receipt_digest) VALUES(?,?,?,?,?)",
                            (effect_key, request_digest, raw, output_digest, ""),
                        )
                        sequence = cursor.lastrowid
                        receipt_digest = self._receipt_digest(
                            effect_key, request_digest, output_digest, sequence
                        )
                        db.execute(
                            "UPDATE effects SET receipt_digest=? WHERE effect_key=?",
                            (receipt_digest, effect_key),
                        )
                    else:
                        sequence, prior_digest, prior_raw, prior_hash, receipt_digest = row
                        if (prior_digest != request_digest or prior_raw != raw
                                or prior_hash != output_digest
                                or receipt_digest != self._receipt_digest(
                                    effect_key, request_digest, prior_hash, sequence
                                )):
                            raise FencedRecipientBindingError(
                                "effect key already committed with incompatible binding"
                            )
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
        except sqlite3.Error as exc:
            raise FencedRecipientError("atomic recipient outcome unavailable") from exc
        return FencedReceipt(
            effect_key, request_digest, self.recipient_id, output,
            output_digest, receipt_digest, sequence, created,
        )

    def observe(self, *, effect_key: str, request_digest: str) -> FencedReceipt | None:
        """Positive observation only. NONE is never a license to release a fence."""
        self._key(effect_key, request_digest)
        try:
            with self._db() as db:
                row = db.execute(
                    "SELECT sequence,request_digest,output_json,output_digest,receipt_digest "
                    "FROM effects WHERE effect_key=?", (effect_key,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise FencedRecipientError("recipient observation unavailable") from exc
        if row is None:
            return None
        seq, binding, raw, output_digest, receipt_digest = row
        from .canonical import strict_json_loads
        output = strict_json_loads(raw, require_canonical=True)
        if (binding != request_digest or digest(output) != output_digest
                or receipt_digest != self._receipt_digest(
                    effect_key, binding, output_digest, seq
                )):
            raise FencedRecipientBindingError("untrusted persisted effect row")
        return FencedReceipt(
            effect_key, request_digest, self.recipient_id, output,
            output_digest, receipt_digest, seq, False,
        )

    def commit_count(self) -> int:
        with self._db() as db:
            return db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
