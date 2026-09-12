"""Base interface for external write adapters with two-phase commit."""
from __future__ import annotations

import abc
import enum
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Optional


class TransactionState(str, enum.Enum):
    """States in the two-phase commit protocol."""
    PENDING = "pending"
    PREPARED = "prepared"
    COMMITTED = "committed"
    ABORTED = "aborted"
    FAILED = "failed"


@dataclass(frozen=True)
class PrepareResult:
    """Result of the prepare phase."""
    transaction_id: str
    success: bool
    error: Optional[str] = None
    metadata: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class CommitResult:
    """Result of the commit phase."""
    transaction_id: str
    success: bool
    error: Optional[str] = None
    external_id: Optional[str] = None  # External system's transaction ID


@dataclass(frozen=True)
class AbortResult:
    """Result of the abort phase."""
    transaction_id: str
    success: bool
    error: Optional[str] = None


class ExternalWriteAdapter(abc.ABC):
    """Abstract base class for external write adapters with 2PC support.

    Implementations must provide atomic, durable external writes with
    two-phase commit semantics for integration with the capability system.
    """

    @property
    @abc.abstractmethod
    def adapter_type(self) -> str:
        """Unique identifier for this adapter type (e.g., 'postgresql', 's3')."""
        ...

    @abc.abstractmethod
    def prepare(
        self,
        transaction_id: str,
        operation: Mapping[str, Any],
    ) -> PrepareResult:
        """Prepare phase: validate and reserve resources for the operation.

        Args:
            transaction_id: Unique identifier for this transaction (from capability system)
            operation: The operation to prepare, including all necessary data

        Returns:
            PrepareResult indicating success/failure and any metadata needed for commit/abort

        The adapter should:
        - Validate the operation can be executed
        - Reserve any necessary resources (locks, space, etc.)
        - Persist enough state to complete or rollback later
        - Return success=True if prepared, False if cannot proceed
        """
        ...

    @abc.abstractmethod
    def commit(
        self,
        transaction_id: str,
        prepare_metadata: Mapping[str, Any],
    ) -> CommitResult:
        """Commit phase: make the prepared operation permanent.

        Args:
            transaction_id: Unique identifier for this transaction
            prepare_metadata: Metadata returned from prepare phase

        Returns:
            CommitResult with success status and external system's transaction ID

        The adapter should:
        - Execute the actual write operation
        - Return external system's transaction/reference ID
        - Be idempotent (safe to retry with same transaction_id)
        """
        ...

    @abc.abstractmethod
    def abort(
        self,
        transaction_id: str,
        prepare_metadata: Mapping[str, Any],
    ) -> AbortResult:
        """Abort phase: rollback any prepared resources.

        Args:
            transaction_id: Unique identifier for this transaction
            prepare_metadata: Metadata returned from prepare phase

        Returns:
            AbortResult indicating success/failure

        The adapter should:
        - Release any reserved resources
        - Rollback any partial state
        - Be idempotent (safe to retry)
        """
        ...

    @abc.abstractmethod
    def get_status(
        self,
        transaction_id: str,
    ) -> TransactionState:
        """Get the current state of a transaction.

        Used for reconciliation and recovery after crashes.
        """
        ...

    @abc.abstractmethod
    def close(self) -> None:
        """Clean up resources (connections, pools, etc.)."""
        ...


def generate_transaction_id(prefix: str = "txn") -> str:
    """Generate a unique transaction ID."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"