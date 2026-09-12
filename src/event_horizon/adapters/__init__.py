"""External effect adapters with two-phase commit support."""
from __future__ import annotations

from .base import (
    ExternalWriteAdapter,
    TransactionState,
    PrepareResult,
    CommitResult,
    AbortResult,
)
from .postgresql import PostgreSQLAdapter
from .s3 import S3Adapter
from .redis import RedisAdapter
from .http import HTTPAdapter

__all__ = [
    "ExternalWriteAdapter",
    "TransactionState",
    "PrepareResult",
    "CommitResult",
    "AbortResult",
    "PostgreSQLAdapter",
    "S3Adapter",
    "RedisAdapter",
    "HTTPAdapter",
]