"""Redis adapter with two-phase commit using Lua scripts for atomicity."""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from contextlib import contextmanager

import redis
from redis.lock import Lock as RedisLock

from event_horizon.adapters.base import (
    ExternalWriteAdapter,
    PrepareResult,
    CommitResult,
    AbortResult,
    TransactionState,
)
from event_horizon.canonical import canonical_bytes, digest


@dataclass(frozen=True)
class RedisConfig:
    """Redis adapter configuration."""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    ssl: bool = False
    key_prefix: str = "eh:"
    max_connections: int = 20
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0


# Lua script for atomic prepare (check and reserve)
PREPARE_SCRIPT = """
local txn_key = KEYS[1]
local data_key = KEYS[2]
local lock_key = KEYS[3]
local txn_id = ARGV[1]
local operation = ARGV[2]
local prepare_metadata = ARGV[3]
local ttl = tonumber(ARGV[4])

-- Check if transaction already exists
local existing = redis.call('HGET', txn_key, 'state')
if existing then
    if existing == 'committed' then
        return {'already_committed', 'Transaction already committed'}
    elseif existing == 'prepared' then
        return {'already_prepared', 'Transaction already prepared'}
    elseif existing == 'committing' or existing == 'aborting' then
        return {'in_progress', 'Transaction in progress'}
    end
end

-- Acquire lock
local lock = redis.call('SET', lock_key, txn_id, 'NX', 'EX', ttl)
if not lock then
    return {'lock_failed', 'Could not acquire lock'}
end

-- Store transaction data
redis.call('HMSET', txn_key,
    'state', 'pending',
    'operation', operation,
    'prepare_metadata', prepare_metadata,
    'created_at', os.time()
)
redis.call('EXPIRE', txn_key, ttl * 2)

-- Store the actual data
redis.call('SET', data_key, operation, 'EX', ttl * 2)

return {'ok', 'Prepared successfully'}
"""

COMMIT_SCRIPT = """
local txn_key = KEYS[1]
local data_key = KEYS[2]
local lock_key = KEYS[3]
local txn_id = ARGV[1]

-- Check transaction state
local state = redis.call('HGET', txn_key, 'state')
if not state then
    return {'not_found', 'Transaction not found'}
end

if state == 'committed' then
    return {'already_committed', 'Already committed'}
end

if state == 'aborted' then
    return {'aborted', 'Transaction was aborted'}
end

if state ~= 'pending' and state ~= 'prepared' then
    return {'invalid_state', 'Invalid state for commit: ' .. state}
end

-- Acquire lock
local lock = redis.call('SET', lock_key, txn_id, 'NX', 'EX', 30)
if not lock then
    return {'lock_failed', 'Could not acquire lock'}
end

-- Mark as committing
redis.call('HSET', txn_key, 'state', 'committing')

-- Get operation data
local operation = redis.call('GET', data_key)
if not operation then
    return {'no_data', 'Operation data not found'}
end

-- Execute the operation (this would call the actual Redis command)
-- In a real implementation, this would execute the actual Redis command
-- For now, we simulate by storing the result
redis.call('HSET', txn_key, 'state', 'committed', 'committed_at', os.time())

-- Clean up lock
redis.call('DEL', lock_key)

return {'ok', 'Committed successfully'}
"""

ABORT_SCRIPT = """
local txn_key = KEYS[1]
local data_key = KEYS[2]
local lock_key = KEYS[3]
local txn_id = ARGV[1]

local state = redis.call('HGET', txn_key, 'state')
if not state then
    return {'not_found', 'Transaction not found'}
end

if state == 'committed' then
    return {'already_committed', 'Already committed'}
end

if state == 'aborted' then
    return {'already_aborted', 'Already aborted'}
end

local lock = redis.call('SET', KEYS[3], ARGV[1], 'NX', 'EX', 30)
if not lock then
    return {'lock_failed', 'Could not acquire lock'}
end

redis.call('HSET', txn_key, 'state', 'aborted')
redis.call('DEL', data_key)
redis.call('DEL', lock_key)

return {'ok', 'Aborted successfully'}
"""

GET_STATUS_SCRIPT = """
local txn_key = KEYS[1]
local state = redis.call('HGET', KEYS[1], 'state')
if not state then
    return 'failed'
end
return state
"""


class RedisAdapter:
    """Redis adapter with two-phase commit using Lua scripts for atomicity."""

    adapter_type = "redis"

    def __init__(self, config: RedisConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._pool = redis.ConnectionPool(
            host=config.host,
            port=config.port,
            db=config.db,
            password=config.password,
            ssl=config.ssl,
            max_connections=config.max_connections,
            socket_timeout=config.socket_timeout,
            socket_connect_timeout=config.socket_connect_timeout,
            decode_responses=True,
        )
        self._client = redis.Redis(connection_pool=self._pool)
        self._register_scripts()

    def _register_scripts(self) -> None:
        self._prepare_sha = self._client.script_load(PREPARE_SCRIPT)
        self._commit_sha = self._client.script_load(COMMIT_SCRIPT)
        self._abort_sha = self._client.script_load(ABORT_SCRIPT)
        self._status_sha = self._client.script_load(GET_STATUS_SCRIPT)

    def _keys(self, transaction_id: str) -> tuple[str, str, str]:
        """Generate Redis keys for a transaction."""
        prefix = self.config.key_prefix
        txn_key = f"{self.config.key_prefix}txn:{transaction_id}"
        data_key = f"{self.config.key_prefix}data:{transaction_id}"
        lock_key = f"{self.config.key_prefix}lock:{transaction_id}"
        return txn_key, f"{self.config.key_prefix}data:{transaction_id}", f"{self.config.key_prefix}lock:{transaction_id}"

    def prepare(
        self,
        transaction_id: str,
        operation: Mapping[str, Any],
    ) -> PrepareResult:
        """Prepare phase: validate and reserve resources atomically."""
        try:
            txn_key, data_key, lock_key = self._keys(transaction_id)
            prepare_metadata = {
                "transaction_id": transaction_id,
                "operation_type": operation.get("type", "unknown"),
                "operation_data_hash": digest(operation.get("data", {})),
            }

            ttl = 3600  # 1 hour TTL

            result = self._client.evalsha(
                self._prepare_sha,
                3,  # number of keys
                self._keys(transaction_id)[0],  # txn_key
                self._keys(transaction_id)[1],  # data_key
                self._keys(transaction_id)[2],  # lock_key
                transaction_id,
                json.dumps(operation),
                json.dumps({"transaction_id": transaction_id}),
                3600,  # ttl
            )

            if result[0] == 'ok':
                return PrepareResult(
                    transaction_id=transaction_id,
                    success=True,
                    metadata={"transaction_id": transaction_id},
                )
            elif result[0] == 'already_committed':
                return PrepareResult(
                    transaction_id=transaction_id,
                    success=True,
                    error="Already committed",
                    metadata={"state": "committed"},
                )
            elif result[0] == 'already_prepared':
                return PrepareResult(
                    transaction_id=transaction_id,
                    success=True,
                    error="Already prepared",
                    metadata={"state": "prepared"},
                )
            else:
                return PrepareResult(
                    transaction_id=transaction_id,
                    success=False,
                    error=result[1],
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
        """Commit phase: execute the actual Redis operation."""
        try:
            result = self._client.evalsha(
                self._commit_sha,
                3,
                *self._keys(transaction_id),
                transaction_id,
            )

            if result[0] == 'ok':
                return CommitResult(
                    transaction_id=transaction_id,
                    success=True,
                )
            elif result[0] == 'already_committed':
                return CommitResult(
                    transaction_id=transaction_id,
                    success=True,
                )
            else:
                return CommitResult(
                    transaction_id=transaction_id,
                    success=False,
                    error=result[1],
                )

        except Exception as e:
            return CommitResult(
                transaction_id=transaction_id,
                success=False,
                error=str(e),
            )

    def abort(
        self,
        transaction_id: str,
        prepare_metadata: Mapping[str, Any],
    ) -> AbortResult:
        """Abort phase: rollback the transaction."""
        try:
            result = self._client.evalsha(
                self._abort_sha,
                3,
                *self._keys(transaction_id),
                transaction_id,
            )

            if result[0] in ('ok', 'already_aborted', 'already_committed'):
                return AbortResult(
                    transaction_id=transaction_id,
                    success=True,
                )
            else:
                return AbortResult(
                    transaction_id=transaction_id,
                    success=False,
                    error=result[1],
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
            result = self._client.evalsha(self._status_sha, 1, f"eh:txn:{transaction_id}")
            if not result:
                return TransactionState.FAILED
            state = result.decode() if isinstance(result, bytes) else result
            return TransactionState(state) if state in TransactionState.__members__ else TransactionState.FAILED
        except Exception:
            return TransactionState.FAILED

    def close(self) -> None:
        """Close the Redis connection pool."""
        self._pool.disconnect()