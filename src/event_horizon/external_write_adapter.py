"""External write adapter with transaction semantics for effect boundary."""
from __future__ import annotations

import abc
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from event_horizon.recorder import ExternalRecorder


class ExternalWriteError(RuntimeError):
    """External write operation error."""
    pass


class TransactionError(RuntimeError):
    """Transaction coordination error."""
    pass


class ExternalWriteAdapter(abc.ABC):
    """Abstract base class for external write adapters.
    
    Provides atomic, durable external write operations with:
    - Two-phase commit (prepare/commit/abort)
    - Idempotency via operation IDs
    - Durable transaction log
    - Reconciliation support
    """
    
    @abc.abstractmethod
    def prepare(self, operation_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """Prepare phase: validate and reserve resources.
        
        Returns prepared result or raises ExternalWriteError.
        """
        ...
    
    @abc.abstractmethod
    def commit(self, operation_id: str) -> Mapping[str, Any]:
        """Commit phase: make the write permanent.
        
        Returns committed result or raises TransactionError.
        """
        ...
    
    @abc.abstractmethod
    def abort(self, operation_id: str) -> Mapping[str, Any]:
        """Abort phase: rollback any prepared changes.
        
        Returns abort confirmation or raises TransactionError.
        """
        ...
    
    @abc.abstractmethod
    def get_status(self, operation_id: str) -> Mapping[str, Any]:
        """Get transaction status for reconciliation."""
        ...


@dataclass(frozen=True)
class TransactionRecord:
    """Durable transaction record for recovery."""
    operation_id: str
    state: str  # "prepared", "committed", "aborted", "pending"
    payload: Mapping[str, Any]
    prepared_at: Optional[str] = None
    committed_at: Optional[str] = None
    aborted_at: Optional[str] = None
    result: Optional[Mapping[str, Any]] = None


class SQLiteTransactionLog:
    """Durable transaction log using SQLite."""
    
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()
    
    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    operation_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK (state IN ('pending', 'prepared', 'committed', 'aborted')),
                    payload_json TEXT NOT NULL,
                    prepared_at TEXT,
                    committed_at TEXT,
                    aborted_at TEXT,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_transactions_state ON transactions(state)
            """)
    
    def create_pending(self, operation_id: str, payload: Mapping[str, Any]) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                conn.execute("""
                    INSERT INTO transactions (operation_id, state, payload_json, created_at, updated_at)
                    VALUES (?, 'pending', ?, ?, ?)
                """, (operation_id, json.dumps(payload), now, now))
    
    def mark_prepared(self, operation_id: str, result: Mapping[str, Any]) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                conn.execute("""
                    UPDATE transactions 
                    SET state = 'prepared', result_json = ?, prepared_at = ?, updated_at = ?
                    WHERE operation_id = ? AND state = 'pending'
                """, (json.dumps(result), now, now, operation_id))
    
    def mark_committed(self, operation_id: str, result: Mapping[str, Any]) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                conn.execute("""
                    UPDATE transactions 
                    SET state = 'committed', result_json = ?, committed_at = ?, updated_at = ?
                    WHERE operation_id = ? AND state = 'prepared'
                """, (json.dumps(result), now, now, operation_id))
    
    def mark_aborted(self, operation_id: str, reason: str) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                conn.execute("""
                    UPDATE transactions 
                    SET state = 'aborted', result_json = ?, aborted_at = ?, updated_at = ?
                    WHERE operation_id = ? AND state IN ('pending', 'prepared')
                """, (json.dumps({"reason": reason}), now, now, operation_id))
    
    def get_status(self, operation_id: str) -> Optional[TransactionRecord]:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute("""
                    SELECT operation_id, state, payload_json, prepared_at, committed_at, aborted_at, result_json
                    FROM transactions WHERE operation_id = ?
                """, (operation_id,)).fetchone()
                if not row:
                    return None
                return TransactionRecord(
                    operation_id=row[0],
                    state=row[1],
                    payload=json.loads(row[2]),
                    prepared_at=row[3],
                    committed_at=row[4],
                    aborted_at=row[5],
                    result=json.loads(row[6]) if row[6] else None,
                )
    
    def get_pending_transactions(self) -> Sequence[TransactionRecord]:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("""
                    SELECT operation_id, state, payload_json, prepared_at, committed_at, aborted_at, result_json
                    FROM transactions WHERE state IN ('pending', 'prepared')
                """).fetchall()
                return [
                    TransactionRecord(
                        operation_id=r[0],
                        state=r[1],
                        payload=json.loads(r[2]),
                        prepared_at=r[3],
                        committed_at=r[4],
                        aborted_at=r[5],
                        result=json.loads(r[6]) if r[6] else None,
                    )
                    for r in rows
                ]


class FilesystemWriteAdapter(ExternalWriteAdapter):
    """Filesystem write adapter with atomic writes and transaction support.
    
    Provides atomic file writes with:
    - Write to temporary file + atomic rename
    - Two-phase commit via transaction log
    - Idempotency via operation IDs
    - Recovery of incomplete transactions
    """
    
    def __init__(
        self,
        base_path: Path,
        recorder: ExternalRecorder,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB default
    ) -> None:
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.recorder = recorder
        self.max_file_size = max_file_size
        self.transaction_log = SQLiteTransactionLog(self.base_path / "transactions.sqlite3")
        self._lock = threading.RLock()
    
    def prepare(self, operation_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """Validate and prepare the write operation."""
        with self._lock:
            # Check for duplicate operation
            existing = self.transaction_log.get_status(operation_id)
            if existing:
                if existing.state == "committed":
                    return {"status": "already_committed", "result": existing.result}
                if existing.state == "prepared":
                    return {"status": "already_prepared", "result": existing.result}
                if existing.state == "aborted":
                    # Allow retry after abort
                    pass
            
            # Validate payload
            if "path" not in payload:
                raise ExternalWriteError("missing path in payload")
            if "content" not in payload:
                raise ExternalWriteError("missing content in payload")
            
            path = payload["path"]
            content = payload["content"]
            
            # Security checks
            if not isinstance(path, str) or not path:
                raise ExternalWriteError("invalid path")
            if ".." in path or path.startswith("/"):
                raise ExternalWriteError("path traversal not allowed")
            if not isinstance(content, (str, bytes)):
                raise ExternalWriteError("content must be string or bytes")
            
            content_bytes = content.encode("utf-8") if isinstance(content, str) else content
            if len(content_bytes) > self.max_file_size:
                raise ExternalWriteError(f"content exceeds max size: {self.max_file_size}")
            
            # Write to temporary file
            temp_path = self.base_path / f".tmp.{operation_id}"
            try:
                with open(temp_path, "wb") as f:
                    f.write(content_bytes)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                raise ExternalWriteError(f"failed to write temp file: {e}")
            
            # Record in transaction log
            self.transaction_log.create_pending(operation_id, payload)
            self.transaction_log.mark_prepared(operation_id, {"temp_path": str(temp_path), "size": len(content_bytes)})
            
            return {"status": "prepared", "operation_id": operation_id}
    
    def commit(self, operation_id: str) -> Mapping[str, Any]:
        """Commit the prepared write."""
        with self._lock:
            status = self.transaction_log.get_status(operation_id)
            if not status:
                raise TransactionError(f"transaction not found: {operation_id}")
            if status.state != "prepared":
                raise TransactionError(f"transaction not in prepared state: {status.state}")
            
            temp_path_str = status.result.get("temp_path") if status.result else None
            if not temp_path_str:
                raise TransactionError("missing temp path in prepared transaction")
            
            temp_path = Path(temp_path_str)
            payload = status.payload
            final_path = self.base_path / payload["path"]
            
            # Ensure parent directory exists
            final_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Atomic rename
            try:
                temp_path.rename(final_path)
            except OSError as e:
                raise TransactionError(f"atomic rename failed: {e}")
            
            # Verify
            if not final_path.exists():
                raise TransactionError("file not found after commit")
            
            # Record commit
            result = {"path": str(final_path), "size": final_path.stat().st_size}
            self.transaction_log.mark_committed(operation_id, result)
            
            # Record in evidence
            self.recorder.append("external.write.committed", {
                "operation_id": operation_id,
                "path": payload["path"],
                "size": result["size"],
            }, source_id="external-write-adapter")
            
            return {"status": "committed", "result": result}
    
    def abort(self, operation_id: str) -> Mapping[str, Any]:
        """Abort a prepared or pending transaction."""
        with self._lock:
            status = self.transaction_log.get_status(operation_id)
            if not status:
                return {"status": "not_found", "operation_id": operation_id}
            
            if status.state == "committed":
                return {"status": "already_committed", "result": status.result}
            
            # Clean up temp file if exists
            if status.result and "temp_path" in status.result:
                try:
                    Path(status.result["temp_path"]).unlink(missing_ok=True)
                except OSError:
                    pass
            
            self.transaction_log.mark_aborted(operation_id, "aborted by request")
            
            self.recorder.append("external.write.aborted", {
                "operation_id": operation_id,
                "reason": "aborted by request",
            }, source_id="external-write-adapter")
            
            return {"status": "aborted", "operation_id": operation_id}
    
    def get_status(self, operation_id: str) -> Mapping[str, Any]:
        """Get transaction status for reconciliation."""
        status = self.transaction_log.get_status(operation_id)
        if not status:
            return {"status": "not_found", "operation_id": operation_id}
        return {
            "status": status.state,
            "operation_id": operation_id,
            "result": status.result,
            "prepared_at": status.prepared_at,
            "committed_at": status.committed_at,
            "aborted_at": status.aborted_at,
        }
    
    def reconcile(self) -> Mapping[str, Any]:
        """Recover incomplete transactions after crash/restart."""
        pending = self.transaction_log.get_pending_transactions()
        results = {"recovered": 0, "aborted": 0, "errors": []}
        
        for txn in pending:
            try:
                if txn.state == "prepared":
                    # Try to commit
                    self.commit(txn.operation_id)
                    results["recovered"] += 1
                elif txn.state == "pending":
                    # Abort pending transactions
                    self.abort(txn.operation_id)
                    results["aborted"] += 1
            except Exception as e:
                results["errors"].append({"operation_id": txn.operation_id, "error": str(e)})
        
        return results