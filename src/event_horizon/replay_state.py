from __future__ import annotations

import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Protocol


_CAPABILITY_ID = re.compile(r"^cap_[0-9a-f]{24}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCOPE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class CapabilityConsumptionError(RuntimeError):
    pass


class CapabilityConsumptionStore(Protocol):
    def consume(
        self,
        capability_id: str,
        claims_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool: ...


def _validate_transition(
    capability_id: str,
    claims_digest: str,
    expires_at: int,
    consumed_at: int,
) -> None:
    if not isinstance(capability_id, str) or _CAPABILITY_ID.fullmatch(capability_id) is None:
        raise CapabilityConsumptionError("capability consumption ID is malformed")
    if not isinstance(claims_digest, str) or _DIGEST.fullmatch(claims_digest) is None:
        raise CapabilityConsumptionError("capability claims digest is malformed")
    if type(expires_at) is not int or type(consumed_at) is not int:
        raise CapabilityConsumptionError("capability consumption times must be integers")
    if expires_at <= 0 or consumed_at < 0:
        raise CapabilityConsumptionError("capability consumption times are invalid")


class InMemoryCapabilityConsumptionStore:
    """Volatile, thread-safe consumption state for tests and simulations only.

    This store is never a valid production default: all state is lost when the
    process dies, which silently converts one-use capabilities into reusable
    ones after a restart. Production call sites must inject
    :class:`SqliteCapabilityConsumptionStore` (or a remote replay store).
    """

    def __init__(self) -> None:
        self._consumed: dict[str, tuple[str, int]] = {}
        self._lock = threading.RLock()

    def consume(
        self,
        capability_id: str,
        claims_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool:
        _validate_transition(capability_id, claims_digest, expires_at, consumed_at)
        with self._lock:
            previous = self._consumed.get(capability_id)
            if previous is not None:
                if previous != (claims_digest, expires_at):
                    raise CapabilityConsumptionError("capability ID collided with different signed claims")
                return False
            self._consumed[capability_id] = (claims_digest, expires_at)
            return True


# Explicit alias so test call sites read as development-only at the use site.
DevelopmentInMemoryConsumptionStore = InMemoryCapabilityConsumptionStore


class SqliteCapabilityConsumptionStore:
    """Durable single-host consumption shared by broker or executor replicas."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        namespace: str = "default",
        domain: str,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        path = Path(database_path)
        if not str(path) or str(path) == ":memory:":
            raise ValueError("durable capability database path is invalid")
        if _SCOPE.fullmatch(namespace) is None or _SCOPE.fullmatch(domain) is None:
            raise ValueError("capability database namespace or domain is invalid")
        if type(busy_timeout_ms) is not int or not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("capability database busy timeout is invalid")
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.namespace = namespace
        self.domain = domain
        self.busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        self._closed = False
        try:
            database = self._connect()
            try:
                database.execute("PRAGMA journal_mode = WAL")
                database.execute(
                    """
                    CREATE TABLE IF NOT EXISTS event_horizon_replay_schema (
                        component TEXT PRIMARY KEY,
                        version INTEGER NOT NULL
                    ) WITHOUT ROWID
                    """
                )
                database.execute(
                    """
                    INSERT OR IGNORE INTO event_horizon_replay_schema (component, version)
                    VALUES ('capability-consumption', 1)
                    """
                )
                schema = database.execute(
                    """
                    SELECT version FROM event_horizon_replay_schema
                    WHERE component = 'capability-consumption'
                    """
                ).fetchone()
                if schema != (1,):
                    raise CapabilityConsumptionError(
                        "capability replay database schema version is unsupported"
                    )
                database.execute(
                    """
                    CREATE TABLE IF NOT EXISTS capability_consumptions (
                        namespace TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        capability_id TEXT NOT NULL,
                        claims_digest TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER NOT NULL,
                        PRIMARY KEY (namespace, domain, capability_id)
                    ) WITHOUT ROWID
                    """
                )
            finally:
                database.close()
        except sqlite3.Error as exc:
            raise CapabilityConsumptionError("capability replay database initialization failed") from exc
        if os.name != "nt":
            path.chmod(0o600)

    def consume(
        self,
        capability_id: str,
        claims_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool:
        _validate_transition(capability_id, claims_digest, expires_at, consumed_at)
        with self._lock:
            self._assert_open()
            database: sqlite3.Connection | None = None
            try:
                database = self._connect()
                database.execute("BEGIN IMMEDIATE")
                cursor = database.execute(
                    """
                    INSERT INTO capability_consumptions (
                        namespace, domain, capability_id, claims_digest, expires_at, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(namespace, domain, capability_id) DO NOTHING
                    """,
                    (
                        self.namespace,
                        self.domain,
                        capability_id,
                        claims_digest,
                        expires_at,
                        consumed_at,
                    ),
                )
                if cursor.rowcount == 1:
                    database.execute("COMMIT")
                    return True
                row = database.execute(
                    """
                    SELECT claims_digest, expires_at FROM capability_consumptions
                    WHERE namespace = ? AND domain = ? AND capability_id = ?
                    """,
                    (self.namespace, self.domain, capability_id),
                ).fetchone()
                database.execute("COMMIT")
            except sqlite3.Error as exc:
                if database is not None:
                    self._rollback(database)
                raise CapabilityConsumptionError("capability replay transaction failed closed") from exc
            finally:
                if database is not None:
                    database.close()
            if row is None or len(row) != 2:
                raise CapabilityConsumptionError("capability replay record disappeared")
            if row[0] != claims_digest or row[1] != expires_at:
                raise CapabilityConsumptionError("capability ID collided with different signed claims")
            return False

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def _connect(self) -> sqlite3.Connection:
        database = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1_000,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            database.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            database.execute("PRAGMA synchronous = FULL")
            database.execute("PRAGMA foreign_keys = ON")
            database.execute("PRAGMA trusted_schema = OFF")
        except sqlite3.Error:
            database.close()
            raise
        return database

    @staticmethod
    def _rollback(database: sqlite3.Connection) -> None:
        try:
            database.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _assert_open(self) -> None:
        if self._closed:
            raise CapabilityConsumptionError("capability replay database is closed")
