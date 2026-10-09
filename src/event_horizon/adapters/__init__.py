"""External effect adapters. Optional third-party clients load on demand."""
from __future__ import annotations

from importlib import import_module

from .base import (
    ExternalWriteAdapter,
    TransactionState,
    PrepareResult,
    CommitResult,
    AbortResult,
)

_OPTIONAL_ADAPTERS = {
    "PostgreSQLAdapter": ".postgresql",
    "S3Adapter": ".s3",
    "RedisAdapter": ".redis",
    "HTTPAdapter": ".http",
}

def __getattr__(name: str):
    module_name = _OPTIONAL_ADAPTERS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(module_name, __name__), name)

__all__ = [
    "ExternalWriteAdapter",
    "TransactionState",
    "PrepareResult",
    "CommitResult",
    "AbortResult",
    *_OPTIONAL_ADAPTERS.keys(),
]
