"""Conservative SQLite dispatch journal for externally visible effects.

A reserved capability is NEVER automatically executed again after a crash.
A durable reservation proves neither that a recipient committed nor that
dispatch began. Only an out-of-band trusted recipient observation may resolve
its outcome. This module does not provide exactly-once external effects.
"""
from __future__ import annotations

import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EffectJournalError(RuntimeError):
    """The trusted journal was unavailable or its state was contradictory."""


class EffectAlreadyReserved(EffectJournalError):
    """A previously reserved action has incompatible claimed authority."""


class DurableEffectJournal:
    """Host-owned, fail-closed SQLite journal; do not expose its path to guests."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if str(path) == ":memory:" or not self.path.is_absolute():
            raise ValueError("durable effect journal requires an absolute disk path")
        if not self.path.parent.is_dir():
            raise ValueError("trusted journal directory must already exist")
        # Local executor code must not control the trusted journal directory.
        if self.path.parent.stat().st_mode & 0o022:
            raise ValueError("trusted journal directory is writable by another principal")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                    raise EffectJournalError("trusted journal must be a private regular file")
            finally:
                os.close(fd)
            with self._db() as db:
                db.execute("""CREATE TABLE IF NOT EXISTS effects (
                    tenant TEXT NOT NULL, environment TEXT NOT NULL,
                    effect_key TEXT NOT NULL, capability_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    claims_digest TEXT NOT NULL, state TEXT NOT NULL
                      CHECK(state IN ('possibly-committed', 'recipient-confirmed')),
                    receipt_digest TEXT,
                    PRIMARY KEY (tenant, environment, capability_id),
                    UNIQUE (tenant, environment, effect_key)
                )""")
        except sqlite3.Error as exc:
            raise EffectJournalError("effect journal startup failed") from exc

    @contextmanager
    def _db(self):
        db = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=5000")
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    @staticmethod
    def _validate(tenant, environment, effect_key, capability_id, request_digest, claims_digest):
        if any(not isinstance(x, str) or not x or len(x) > 256
               for x in (tenant, environment, capability_id)):
            raise ValueError("effect journal identity invalid")
        if any(not isinstance(x, str) or not HEX64.fullmatch(x)
               for x in (effect_key, request_digest, claims_digest)):
            raise ValueError("effect journal digest invalid")

    def reserve(self, *, tenant: str, environment: str, effect_key: str,
                capability_id: str, request_digest: str, claims_digest: str) -> bool:
        """Atomically reserve BEFORE dispatch. False means no repeat dispatch.

        On an ambiguous failure the caller must deny; never retry a potentially
        committed effect using a new capability without reconciliation.
        """
        self._validate(tenant, environment, effect_key, capability_id, request_digest, claims_digest)
        try:
            with self._db() as db:
                try:
                    db.execute("BEGIN IMMEDIATE")
                    existing = db.execute(
                        "SELECT effect_key, capability_id, request_digest, claims_digest "
                        "FROM effects WHERE tenant=? AND environment=? "
                        "AND (effect_key=? OR capability_id=?)",
                        (tenant, environment, effect_key, capability_id),
                    ).fetchone()
                    if existing is not None:
                        if existing != (effect_key, capability_id, request_digest, claims_digest):
                            raise EffectAlreadyReserved("logical effect already reserved or capability rebound")
                        db.execute("COMMIT")
                        return False
                    db.execute(
                        "INSERT INTO effects "
                        "(tenant, environment, effect_key, capability_id, "
                        "request_digest, claims_digest, state) "
                        "VALUES (?, ?, ?, ?, ?, ?, 'possibly-committed')",
                        (tenant, environment, effect_key, capability_id, request_digest, claims_digest),
                    )
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
        except sqlite3.Error as exc:
            raise EffectJournalError("effect journal reservation unavailable") from exc

    def observe(self, *, tenant: str, environment: str, capability_id: str):
        try:
            with self._db() as db:
                row = db.execute(
                    "SELECT request_digest, claims_digest, state, receipt_digest "
                    "FROM effects WHERE tenant=? AND environment=? AND capability_id=?",
                    (tenant, environment, capability_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise EffectJournalError("effect journal observation unavailable") from exc
        if row is None:
            return None
        return {"request_digest": row[0], "claims_digest": row[1],
                "state": row[2], "receipt_digest": row[3]}

    def confirm_from_trusted_recipient(self, *, tenant: str, environment: str,
                                       effect_key: str, capability_id: str,
                                       request_digest: str, claims_digest: str,
                                       receipt_digest: str) -> None:
        """Trusted caller MUST independently validate the recipient receipt.

        Never call this solely on a handler return value or a timeout.
        """
        self._validate(tenant, environment, effect_key, capability_id, request_digest, claims_digest)
        if not isinstance(receipt_digest, str) or not HEX64.fullmatch(receipt_digest):
            raise ValueError("trusted recipient receipt digest invalid")
        try:
            with self._db() as db:
                try:
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute(
                        "SELECT effect_key, request_digest, claims_digest, state, receipt_digest "
                        "FROM effects WHERE tenant=? AND environment=? AND capability_id=?",
                        (tenant, environment, capability_id),
                    ).fetchone()
                    if row is None or row[:3] != (effect_key, request_digest, claims_digest):
                        raise EffectJournalError("recipient receipt is not bound to a reservation")
                    if row[3] == "recipient-confirmed" and row[4] != receipt_digest:
                        raise EffectJournalError("conflicting recipient confirmation")
                    db.execute(
                        "UPDATE effects SET state='recipient-confirmed', receipt_digest=? "
                        "WHERE tenant=? AND environment=? AND capability_id=?",
                        (receipt_digest, tenant, environment, capability_id),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
        except sqlite3.Error as exc:
            raise EffectJournalError("recipient confirmation unavailable") from exc
