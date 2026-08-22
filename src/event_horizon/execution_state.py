from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol


_CAPABILITY_ID = re.compile(r"^(?:cap|canary)_[0-9a-f]{24}$")
_SCOPE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_DETAIL_BYTES = 8_192


class ExecutionStateError(RuntimeError):
    """The capability/execution lifecycle reached an illegal or unsafe state."""


class ExecutionState(str, Enum):
    ISSUED = "issued"
    AUTHORIZED = "authorized"
    CONSUMED = "consumed"
    INTENT_RECORDED = "intent_recorded"
    DISPATCHED = "dispatched"
    EFFECT_UNKNOWN = "effect_unknown"
    EFFECT_CONFIRMED = "effect_confirmed"
    INDETERMINATE = "indeterminate"
    RECONCILED = "reconciled"
    CLOSED = "closed"
    DENIED = "denied"


# States from which a provider effect may already have occurred.
EFFECT_RISK_STATES = frozenset({
    ExecutionState.DISPATCHED,
    ExecutionState.EFFECT_UNKNOWN,
    ExecutionState.EFFECT_CONFIRMED,
    ExecutionState.INDETERMINATE,
})

TERMINAL_STATES = frozenset({ExecutionState.CLOSED, ExecutionState.DENIED})

UNRESOLVED_STATES = frozenset(ExecutionState) - TERMINAL_STATES

RECONCILIATION_RESOLUTIONS = frozenset({
    "confirmed_not_committed",
    "committed",
    "indeterminate",
})

_TRANSITIONS: dict[ExecutionState, frozenset[ExecutionState]] = {
    ExecutionState.ISSUED: frozenset({ExecutionState.AUTHORIZED, ExecutionState.DENIED}),
    # A capability can never return to a reusable state.
    ExecutionState.AUTHORIZED: frozenset({ExecutionState.CONSUMED}),
    ExecutionState.CONSUMED: frozenset({ExecutionState.INTENT_RECORDED}),
    ExecutionState.INTENT_RECORDED: frozenset({ExecutionState.DISPATCHED}),
    # Crossing the dispatch boundary means the effect outcome is no longer
    # provable as absent. Only EFFECT_CONFIRMED, EFFECT_UNKNOWN, or explicit
    # INDETERMINATE classification are legal.
    ExecutionState.DISPATCHED: frozenset({
        ExecutionState.EFFECT_UNKNOWN,
        ExecutionState.EFFECT_CONFIRMED,
        ExecutionState.INDETERMINATE,
    }),
    # Uncertainty must remain uncertainty until reconciliation proves otherwise.
    ExecutionState.EFFECT_UNKNOWN: frozenset({ExecutionState.INDETERMINATE, ExecutionState.RECONCILED}),
    ExecutionState.EFFECT_CONFIRMED: frozenset({ExecutionState.INDETERMINATE, ExecutionState.RECONCILED}),
    ExecutionState.INDETERMINATE: frozenset({ExecutionState.RECONCILED}),
    ExecutionState.RECONCILED: frozenset({ExecutionState.CLOSED}),
    ExecutionState.CLOSED: frozenset(),
    ExecutionState.DENIED: frozenset(),
}


def is_legal_transition(current: ExecutionState, target: ExecutionState) -> bool:
    return target in _TRANSITIONS.get(current, frozenset())


def _validate_capability_id(capability_id: str) -> None:
    if not isinstance(capability_id, str) or _CAPABILITY_ID.fullmatch(capability_id) is None:
        raise ExecutionStateError("capability ID is malformed")


def _validate_details(details: Mapping[str, Any] | None) -> str:
    if details is None:
        return "{}"
    if not isinstance(details, Mapping):
        raise ExecutionStateError("transition details must be an object")
    encoded = json.dumps(dict(details), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > _MAX_DETAIL_BYTES:
        raise ExecutionStateError("transition details exceed the bounded size")
    return encoded


class ExecutionStateStore(Protocol):
    def record_transition(
        self,
        namespace: str,
        capability_id: str,
        expected_current: ExecutionState | None,
        target: ExecutionState,
        details_json: str,
    ) -> int:
        """Atomically move state; return the new sequence number."""
        ...

    def current_state(
        self,
        namespace: str,
        capability_id: str,
    ) -> tuple[ExecutionState, int] | None: ...

    def unresolved(self, namespace: str) -> list[tuple[str, str]]: ...


class InMemoryExecutionStateStore:
    """Thread-safe development store; state is lost with this object."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state: dict[tuple[str, str], tuple[ExecutionState, int]] = {}
        self._history: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def record_transition(
        self,
        namespace: str,
        capability_id: str,
        expected_current: ExecutionState | None,
        target: ExecutionState,
        details_json: str,
    ) -> int:
        key = (namespace, capability_id)
        with self._lock:
            current = self._state.get(key)
            if (current[0] if current else None) != expected_current:
                raise ExecutionStateError("execution state changed concurrently")
            sequence = (current[1] + 1) if current else 1
            self._state[key] = (target, sequence)
            self._history.setdefault(key, []).append({
                "sequence": sequence,
                "from": expected_current.value if expected_current else None,
                "to": target.value,
                "details": json.loads(details_json),
                "recorded_at": time.time(),
            })
            return sequence

    def current_state(
        self,
        namespace: str,
        capability_id: str,
    ) -> tuple[ExecutionState, int] | None:
        with self._lock:
            return self._state.get((namespace, capability_id))

    def unresolved(self, namespace: str) -> list[tuple[str, str]]:
        with self._lock:
            return [
                (capability_id, state.value)
                for (ns, capability_id), (state, _sequence) in self._state.items()
                if ns == namespace and state not in TERMINAL_STATES
            ]


class SqliteExecutionStateStore:
    """Durable single-host lifecycle state shared by cooperating processes."""

    SCHEMA_VERSION = 1

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        path = Path(database_path)
        if not str(path) or str(path) == ":memory:":
            raise ValueError("durable execution-state database path is invalid")
        if type(busy_timeout_ms) is not int or not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("execution-state database busy timeout is invalid")
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
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
                    VALUES ('capability-execution', ?)
                    """,
                    (self.SCHEMA_VERSION,),
                )
                schema = database.execute(
                    """
                    SELECT version FROM event_horizon_replay_schema
                    WHERE component = 'capability-execution'
                    """
                ).fetchone()
                if schema != (self.SCHEMA_VERSION,):
                    raise ExecutionStateError("execution-state schema version is unsupported")
                database.execute(
                    """
                    CREATE TABLE IF NOT EXISTS capability_execution_transitions (
                        namespace TEXT NOT NULL,
                        capability_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        from_state TEXT,
                        to_state TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        recorded_at REAL NOT NULL,
                        PRIMARY KEY (namespace, capability_id, sequence)
                    ) WITHOUT ROWID
                    """
                )
            finally:
                database.close()
        except sqlite3.Error as exc:
            raise ExecutionStateError("execution-state database initialization failed") from exc
        if os.name != "nt":
            path.chmod(0o600)

    def record_transition(
        self,
        namespace: str,
        capability_id: str,
        expected_current: ExecutionState | None,
        target: ExecutionState,
        details_json: str,
    ) -> int:
        _validate_capability_id(capability_id)
        if _SCOPE.fullmatch(namespace) is None:
            raise ExecutionStateError("execution-state namespace is invalid")
        with self._lock:
            self._assert_open()
            database: sqlite3.Connection | None = None
            try:
                database = self._connect()
                database.execute("BEGIN IMMEDIATE")
                row = database.execute(
                    """
                    SELECT to_state, MAX(sequence) FROM capability_execution_transitions
                    WHERE namespace = ? AND capability_id = ?
                    """,
                    (namespace, capability_id),
                ).fetchone()
                actual = row[0] if row and row[0] is not None else None
                if actual is not None and isinstance(actual, str):
                    actual = ExecutionState(actual)
                if actual != expected_current:
                    raise ExecutionStateError("execution state changed concurrently")
                sequence = (row[1] + 1) if row and row[1] is not None else 1
                database.execute(
                    """
                    INSERT INTO capability_execution_transitions (
                        namespace, capability_id, sequence, from_state, to_state,
                        details_json, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        namespace,
                        capability_id,
                        sequence,
                        expected_current.value if expected_current else None,
                        target.value,
                        details_json,
                        time.time(),
                    ),
                )
                database.execute("COMMIT")
                return sequence
            except sqlite3.Error as exc:
                if database is not None:
                    self._rollback(database)
                raise ExecutionStateError("execution-state transaction failed closed") from exc
            finally:
                if database is not None:
                    database.close()

    def current_state(
        self,
        namespace: str,
        capability_id: str,
    ) -> tuple[ExecutionState, int] | None:
        _validate_capability_id(capability_id)
        with self._lock:
            self._assert_open()
            database: sqlite3.Connection | None = None
            try:
                database = self._connect()
                row = database.execute(
                    """
                    SELECT to_state, sequence FROM capability_execution_transitions
                    WHERE namespace = ? AND capability_id = ?
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (namespace, capability_id),
                ).fetchone()
            except sqlite3.Error as exc:
                raise ExecutionStateError("execution-state read failed closed") from exc
            finally:
                if database is not None:
                    database.close()
        if row is None:
            return None
        return ExecutionState(row[0]), int(row[1])

    def unresolved(self, namespace: str) -> list[tuple[str, str]]:
        if _SCOPE.fullmatch(namespace) is None:
            raise ExecutionStateError("execution-state namespace is invalid")
        terminal_values = [state.value for state in TERMINAL_STATES]
        placeholders = ",".join("?" for _ in terminal_values)
        with self._lock:
            self._assert_open()
            database: sqlite3.Connection | None = None
            try:
                database = self._connect()
                rows = database.execute(
                    f"""
                    SELECT capability_id, to_state FROM capability_execution_transitions t
                    WHERE namespace = ? AND sequence = (
                        SELECT MAX(sequence) FROM capability_execution_transitions x
                        WHERE x.namespace = t.namespace AND x.capability_id = t.capability_id
                    ) AND to_state NOT IN ({placeholders})
                    """,
                    (namespace, *terminal_values),
                ).fetchall()
            except sqlite3.Error as exc:
                raise ExecutionStateError("execution-state scan failed closed") from exc
            finally:
                if database is not None:
                    database.close()
            return [(str(row[0]), str(row[1])) for row in rows]

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
            raise ExecutionStateError("execution-state database is closed")


class CapabilityExecutionTracker:
    """Validated lifecycle for one-use capability executions.

    Every transition is checked against the explicit legal-edge table before it
    is durably recorded. Illegal transitions are rejected and surfaced to the
    caller; they never silently mutate stored state.
    """

    def __init__(
        self,
        store: ExecutionStateStore,
        *,
        namespace: str = "default",
    ) -> None:
        if not hasattr(store, "record_transition"):
            raise TypeError("execution state store is required")
        if _SCOPE.fullmatch(namespace) is None:
            raise ValueError("execution tracker namespace is invalid")
        self.store = store
        self.namespace = namespace

    def begin(self, capability_id: str, *, details: Mapping[str, Any] | None = None) -> ExecutionState:
        _validate_capability_id(capability_id)
        existing = self.store.current_state(self.namespace, capability_id)
        if existing is not None:
            raise ExecutionStateError(
                f"capability {capability_id} already entered the execution lifecycle"
            )
        self.store.record_transition(
            self.namespace,
            capability_id,
            None,
            ExecutionState.ISSUED,
            _validate_details(details),
        )
        return ExecutionState.ISSUED

    def load(self, capability_id: str) -> ExecutionState | None:
        _validate_capability_id(capability_id)
        found = self.store.current_state(self.namespace, capability_id)
        return found[0] if found else None

    def transition(
        self,
        capability_id: str,
        target: ExecutionState,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> ExecutionState:
        if not isinstance(target, ExecutionState):
            raise ExecutionStateError("transition target must be an ExecutionState")
        found = self.store.current_state(self.namespace, capability_id)
        if found is None:
            raise ExecutionStateError(f"unknown execution for capability {capability_id}")
        current, _sequence = found
        if not is_legal_transition(current, target):
            raise ExecutionStateError(
                f"illegal lifecycle transition {current.value} -> {target.value} "
                f"for capability {capability_id}"
            )
        self.store.record_transition(
            self.namespace,
            capability_id,
            current,
            target,
            _validate_details(details),
        )
        return target

    def reconcile(
        self,
        capability_id: str,
        *,
        resolution: str,
        evidence_digest: str,
        declared_pure: bool = False,
    ) -> ExecutionState:
        """Resolve uncertainty using positive evidence only.

        For executions past the effect boundary on potentially effectful
        operations, ``confirmed_not_committed`` is illegal: absence of an
        external effect cannot be inferred from local failure signals. A
        handler architecturally declared pure (``declared_pure``) carries that
        provider-side proof by construction, so ``confirmed_not_committed``
        remains available for it even after confirmation.
        """
        if resolution not in RECONCILIATION_RESOLUTIONS:
            raise ExecutionStateError("reconciliation resolution is invalid")
        if not isinstance(evidence_digest, str) or _DIGEST.fullmatch(evidence_digest) is None:
            raise ExecutionStateError("reconciliation evidence digest is invalid")
        found = self.store.current_state(self.namespace, capability_id)
        if found is None:
            raise ExecutionStateError(f"unknown execution for capability {capability_id}")
        current = found[0]
        if resolution == "confirmed_not_committed":
            if current in TERMINAL_STATES or current is ExecutionState.RECONCILED:
                raise ExecutionStateError(
                    f"resolution confirmed_not_committed is illegal from {current.value}"
                )
            if declared_pure:
                if current not in {
                    ExecutionState.CONSUMED,
                    ExecutionState.INTENT_RECORDED,
                    ExecutionState.DISPATCHED,
                    ExecutionState.EFFECT_UNKNOWN,
                    ExecutionState.EFFECT_CONFIRMED,
                }:
                    raise ExecutionStateError(
                        f"resolution confirmed_not_committed is illegal from {current.value}"
                    )
            elif current not in {ExecutionState.CONSUMED, ExecutionState.INTENT_RECORDED, ExecutionState.EFFECT_UNKNOWN}:
                raise ExecutionStateError(
                    f"an execution past the effect boundary can never be "
                    f"confirmed not committed without provider-side proof"
                )
        elif resolution == "committed" and (
            current not in EFFECT_RISK_STATES and not declared_pure
        ):
            raise ExecutionStateError(
                f"resolution committed requires effect risk, found {current.value}"
            )
        if current is ExecutionState.DISPATCHED:
            # Crash-window recovery routes through explicit uncertainty.
            self.transition(
                capability_id,
                ExecutionState.INDETERMINATE,
                details={"routed": "reconciliation-from-dispatch"},
            )
        return self.transition(
            capability_id,
            ExecutionState.RECONCILED,
            details={
                "resolution": resolution,
                "evidence_digest": evidence_digest,
                "declared_pure": bool(declared_pure),
            },
        )

    def close(self, capability_id: str, *, evidence_digest: str) -> ExecutionState:
        if not isinstance(evidence_digest, str) or _DIGEST.fullmatch(evidence_digest) is None:
            raise ExecutionStateError("closing evidence digest is invalid")
        return self.transition(
            capability_id,
            ExecutionState.CLOSED,
            details={"evidence_digest": evidence_digest},
        )

    def assert_resolved_for_certification(self) -> None:
        unresolved = self.store.unresolved(self.namespace)
        if unresolved:
            listing = ", ".join(sorted(f"{capability}:{state}" for capability, state in unresolved))
            raise ExecutionStateError(
                f"unresolved capability executions block certification: {listing}"
            )

    def transitions_for_testing(self) -> dict[str, list[str]]:
        return {
            state.value: sorted(target.value for target in targets)
            for state, targets in _TRANSITIONS.items()
        }
