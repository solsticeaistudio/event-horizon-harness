"""PostgreSQL external write adapter with two-phase commit."""
from __future__ import annotations

import json
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

from event_horizon.adapters.base import (
    ExternalWriteAdapter,
    PrepareResult,
    CommitResult,
    AbortResult,
    TransactionState,
)
from event_horizon.canonical import canonical_bytes, digest


@dataclass(frozen=True)
class PostgreSQLConfig:
    """PostgreSQL adapter configuration."""
    host: str = "localhost"
    port: int = 5432
    database: str = "event_horizon"
    user: str = "postgres"
    password: str = ""
    min_connections: int = 2
    max_connections: int = 10
    schema: str = "public"
    advisory_lock_prefix: int = 0x4548  # "EH" in hex


class PostgreSQLAdapter(ExternalWriteAdapter):
    """PostgreSQL adapter with two-phase commit using advisory locks.

    Uses a transaction log table and PostgreSQL advisory locks for 2PC coordination.
    Each transaction gets a unique advisory lock to prevent concurrent modifications.
    """

    adapter_type = "postgresql"

    def __init__(self, config: PostgreSQLConfig) -> None:
        self.config = config
        self._pool = pool.ThreadedConnectionPool(
            config.min_connections,
            config.max_connections,
            host=config.host,
            port=config.port,
            database=config.database,
            user=config.user,
            password=config.password,
            cursor_factory=RealDictCursor,
        )
        self._lock = threading.Lock()
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        """Create the transaction log table if it doesn't exist."""
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self.config.schema}.eh_transaction_log (
                        transaction_id VARCHAR(64) PRIMARY KEY,
                        state VARCHAR(20) NOT NULL DEFAULT 'pending',
                        operation_type VARCHAR(64) NOT NULL,
                        operation_data JSONB NOT NULL,
                        prepare_metadata JSONB,
                        external_id TEXT,
                        error TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS
                        idx_eh_transaction_log_state
                        ON {self.config.schema}.eh_transaction_log (state);
                """)
                conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get a connection from the pool."""
        conn = self._pool.getconn()
        try:
            yield conn
        finally:
            self._pool.putconn(conn)

    @contextmanager
    def _advisory_lock(self, transaction_id: str):
        """Acquire a PostgreSQL advisory lock for the transaction."""
        lock_key = self._transaction_to_lock_key(transaction_id)
        with self._get_connection() as conn:
            with conn.cursor() as cur:
                # Try to acquire lock (non-blocking)
                cur.execute("SELECT pg_try_advisory_xact_lock(%s)", (lock_key,))
                acquired = cur.fetchone()["pg_try_advisory_xact_lock"]
                if not acquired:
                    raise RuntimeError(f"Could not acquire advisory lock for {transaction_id}")
                try:
                    yield
                finally:
                    # Lock is released at transaction end automatically
                    pass

    def _transaction_to_lock_key(self, transaction_id: str) -> int:
        """Convert transaction ID to a 64-bit integer for advisory lock."""
        # Use first 16 hex chars as integer
        hash_bytes = transaction_id.encode()
        # Simple hash to 64-bit
        h = 0
        for b in hash_bytes:
            h = (h * 31 + b) & 0xFFFFFFFFFFFFFFFF
        return (self.config.advisory_lock_prefix << 48) | (h & 0xFFFFFFFFFFFF)

    def _generate_prepare_metadata(self, transaction_id: str, operation: Mapping[str, Any]) -> Mapping[str, Any]:
        """Generate metadata needed for commit/abort from prepare phase."""
        return {
            "transaction_id": transaction_id,
            "operation_type": operation.get("type", "unknown"),
            "operation_data_hash": digest(operation.get("data", {})),
        }

    def prepare(
        self,
        transaction_id: str,
        operation: Mapping[str, Any],
    ) -> PrepareResult:
        """Prepare phase: validate operation and reserve resources."""
        try:
            with self._advisory_lock(transaction_id):
                with self._get_connection() as conn:
                    with conn.cursor() as cur:
                        # Check if transaction already exists
                        cur.execute(
                            f"SELECT state FROM {self.config.schema}.eh_transaction_log WHERE transaction_id = %s",
                            (transaction_id,),
                        )
                        existing = cur.fetchone()
                        if existing:
                            state = existing["state"]
                            if state == "committed":
                                return PrepareResult(
                                    transaction_id=transaction_id,
                                    success=True,
                                    error="Already committed",
                                    metadata={"state": state},
                                )
                            elif state == "prepared":
                                return PrepareResult(
                                    transaction_id=transaction_id,
                                    success=True,
                                    error="Already prepared",
                                    metadata={"state": state},
                                )

                        # Validate operation structure
                        op_type = operation.get("type")
                        op_data = operation.get("data", {})
                        if not op_type:
                            return PrepareResult(
                                transaction_id=transaction_id,
                                success=False,
                                error="Missing operation type",
                            )

                        # Insert pending transaction
                        prepare_metadata = self._generate_prepare_metadata(transaction_id, operation)
                        cur.execute(
                            f"""
                            INSERT INTO {self.config.schema}.eh_transaction_log
                            (transaction_id, state, operation_type, operation_data, prepare_metadata)
                            VALUES (%s, 'pending', %s, %s, %s)
                            ON CONFLICT (transaction_id) DO UPDATE SET
                                state = EXCLUDED.state,
                                operation_type = EXCLUDED.operation_type,
                                operation_data = EXCLUDED.operation_data,
                                prepare_metadata = EXCLUDED.prepare_metadata,
                                updated_at = NOW()
                            """,
                            (
                                transaction_id,
                                operation.get("type", "unknown"),
                                json.dumps(operation.get("data", {})),
                                json.dumps(prepare_metadata),
                            ),
                        )
                        conn.commit()

            return PrepareResult(
                transaction_id=transaction_id,
                success=True,
                metadata=prepare_metadata,
            )

        except Exception as e:
            return PrepareResult(
                transaction_id=transaction_id,
                success=False,
                error=str(e),
            )

    def commit(
        self,
        transaction_id: str,
        prepare_metadata: Mapping[str, Any],
    ) -> CommitResult:
        """Commit phase: execute the actual write operation."""
        try:
            with self._advisory_lock(transaction_id):
                with self._get_connection() as conn:
                    with conn.cursor() as cur:
                        # Get transaction state
                        cur.execute(
                            f"SELECT state, operation_type, operation_data FROM {self.config.schema}.eh_transaction_log WHERE transaction_id = %s",
                            (transaction_id,),
                        )
                        row = cur.fetchone()
                        if not row:
                            return CommitResult(
                                transaction_id=transaction_id,
                                success=False,
                                error="Transaction not found",
                            )

                        state = row["state"]
                        if state == "committed":
                            return CommitResult(
                                transaction_id=transaction_id,
                                success=True,
                                external_id=row.get("external_id"),
                            )
                        if state == "aborted":
                            return CommitResult(
                                transaction_id=transaction_id,
                                success=False,
                                error="Transaction was aborted",
                            )
                        if state != "pending" and state != "prepared":
                            return CommitResult(
                                transaction_id=transaction_id,
                                success=False,
                                error=f"Invalid state for commit: {state}",
                            )

                        # Execute the actual operation
                        op_type = row["operation_type"]
                        op_data = row["operation_data"]
                        external_id = self._execute_operation(cur, op_type, op_data)

                        # Mark as committed
                        cur.execute(
                            f"""
                            UPDATE {self.config.schema}.eh_transaction_log
                            SET state = 'committed', external_id = %s, updated_at = NOW()
                            WHERE transaction_id = %s
                            """,
                            (external_id, transaction_id),
                        )
                        conn.commit()

            return CommitResult(
                transaction_id=transaction_id,
                success=True,
                external_id=external_id,
            )

        except Exception as e:
            # Try to mark as failed
            try:
                with self._get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            f"UPDATE {self.config.schema}.eh_transaction_log SET state = 'failed', error = %s WHERE transaction_id = %s",
                            (str(e), transaction_id),
                        )
                        conn.commit()
            except Exception:
                pass
            return CommitResult(
                transaction_id=transaction_id,
                success=False,
                error=str(e),
            )

    def _execute_operation(self, cursor, op_type: str, op_data: Mapping[str, Any]) -> str:
        """Execute the actual database operation. Returns external reference ID."""
        if op_type == "insert":
            table = op_data.get("table")
            columns = op_data.get("columns", [])
            values = op_data.get("values", [])
            placeholders = ", ".join(["%s"] * len(columns))
            cols = ", ".join(columns)
            cursor.execute(
                f"INSERT INTO {self.config.schema}.{table} ({cols}) VALUES ({placeholders}) RETURNING id",
                values,
            )
            result = cursor.fetchone()
            return str(result["id"]) if result else "unknown"

        elif op_type == "update":
            table = op_data.get("table")
            set_clause = ", ".join([f"{k} = %s" for k in op_data.get("set", {}).keys()])
            where_clause = op_data.get("where", "1=1")
            where_params = op_data.get("where_params", [])
            set_params = list(op_data.get("set", {}).values())
            cursor.execute(
                f"UPDATE {self.config.schema}.{table} SET {set_clause} WHERE {where_clause}",
                set_params + where_params,
            )
            return str(cursor.rowcount)

        elif op_type == "delete":
            table = op_data.get("table")
            where_clause = op_data.get("where", "1=1")
            where_params = op_data.get("where_params", [])
            cursor.execute(
                f"DELETE FROM {self.config.schema}.{table} WHERE {where_clause}",
                where_params,
            )
            return str(cursor.rowcount)

        elif op_type == "exec":
            # Raw SQL execution (for migrations, etc.)
            sql = op_data.get("sql")
            params = op_data.get("params", [])
            cursor.execute(sql, params)
            return "executed"

        else:
            raise ValueError(f"Unknown operation type: {op_type}")

    def abort(
        self,
        transaction_id: str,
        prepare_metadata: Mapping[str, Any],
    ) -> AbortResult:
        """Abort phase: rollback any prepared resources."""
        try:
            with self._advisory_lock(transaction_id):
                with self._get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            f"SELECT state FROM {self.config.schema}.eh_transaction_log WHERE transaction_id = %s",
                            (transaction_id,),
                        )
                        row = cur.fetchone()
                        if not row:
                            return AbortResult(
                                transaction_id=transaction_id,
                                success=False,
                                error="Transaction not found",
                            )

                        state = row["state"]
                        if state in ("aborted", "committed"):
                            return AbortResult(
                                transaction_id=transaction_id,
                                success=True,
                                error=f"Already {state}",
                            )

                        cur.execute(
                            f"UPDATE {self.config.schema}.eh_transaction_log SET state = 'aborted', updated_at = NOW() WHERE transaction_id = %s",
                            (transaction_id,),
                        )
                        conn.commit()

            return AbortResult(
                transaction_id=transaction_id,
                success=True,
            )

        except Exception as e:
            return AbortResult(
                transaction_id=transaction_id,
                success=False,
                error=str(e),
            )

    def get_status(self, transaction_id: str) -> TransactionState:
        """Get the current state of a transaction."""
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"SELECT state FROM {self.config.schema}.eh_transaction_log WHERE transaction_id = %s",
                        (transaction_id,),
                    )
                    row = cur.fetchone()
                    if not row:
                        return TransactionState.FAILED
                    return TransactionState(row["state"])
        except Exception:
            return TransactionState.FAILED

    def close(self) -> None:
        """Close all connections in the pool."""
        if self._pool:
            self._pool.closeall()
            self._pool = None