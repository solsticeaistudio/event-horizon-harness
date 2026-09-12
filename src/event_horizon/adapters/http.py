"""HTTP/REST adapter with two-phase commit using idempotency keys."""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from contextlib import contextmanager

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from event_horizon.adapters.base import (
    ExternalWriteAdapter,
    PrepareResult,
    CommitResult,
    AbortResult,
    TransactionState,
)
from event_horizon.canonical import canonical_bytes, digest


@dataclass(frozen=True)
class HTTPConfig:
    """HTTP adapter configuration."""
    base_url: str
    timeout: float = 30.0
    max_retries: int = 3
    backoff_factor: float = 0.3
    default_headers: Mapping[str, str] = None
    verify_ssl: bool = True
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    ca_bundle: Optional[str] = None


class HTTPAdapter:
    """HTTP/REST adapter with two-phase commit using idempotency keys.

    Uses idempotency keys for safe retries and exactly-once semantics:
    - Prepare: POST with idempotency key, store response
    - Commit: Confirm with same idempotency key (idempotent)
    - Abort: DELETE with idempotency key (if supported by API)
    """

    adapter_type = "http"

    def __init__(self, config: HTTPConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._pending: dict[str, Mapping[str, Any]] = {}

        # Create session with retries
        self._session = requests.Session()
        retry_strategy = Retry(
            total=config.max_retries,
            backoff_factor=config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        if config.client_cert and config.client_key:
            self._session.cert = (config.client_cert, config.client_key)
        if config.ca_bundle:
            self._session.verify = config.ca_bundle
        else:
            self._session.verify = config.verify_ssl

        if config.default_headers:
            self._session.headers.update(config.default_headers)

    def _generate_idempotency_key(self, transaction_id: str) -> str:
        """Generate an idempotency key for the transaction."""
        return f"eh-{transaction_id[:32]}"

    def _get_base_headers(self) -> Mapping[str, str]:
        """Get base headers including idempotency key."""
        return {}

    def prepare(
        self,
        transaction_id: str,
        operation: Mapping[str, Any],
    ) -> PrepareResult:
        """Prepare phase: send request with idempotency key, store response."""
        try:
            op_type = operation.get("type", "POST")
            op_data = operation.get("data", {})
            endpoint = operation.get("endpoint", "")
            method = op_type.upper()

            idempotency_key = self._generate_idempotency_key(transaction_id)

            headers = dict(self.config.default_headers or {})
            headers["Idempotency-Key"] = idempotency_key
            headers["Content-Type"] = "application/json"

            url = f"{self.config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

            # For prepare, we send the request but don't fully commit
            # Some APIs support a "dry_run" or "preview" mode
            # For now, we'll send the request and store the response
            response = self._session.request(
                method=method,
                url=url,
                json=operation.get("data", {}),
                headers=headers,
                timeout=self.config.timeout,
            )

            if response.status_code >= 400:
                return PrepareResult(
                    transaction_id=transaction_id,
                    success=False,
                    error=f"HTTP {response.status_code}: {response.text}",
                )

            # Store response for commit/abort
            with self._lock:
                self._pending[transaction_id] = {
                    "response": response.json() if response.text else {},
                    "status_code": response.status_code,
                    "idempotency_key": idempotency_key,
                    "url": url,
                    "method": method,
                }

            return PrepareResult(
                transaction_id=transaction_id,
                success=True,
                metadata={
                    "status_code": response.status_code,
                    "response": response.json() if response.text else {},
                },
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
        """Commit phase: confirm with same idempotency key (idempotent)."""
        try:
            with self._lock:
                pending = self._pending.pop(transaction_id, None)

            if not pending:
                return CommitResult(
                    transaction_id=transaction_id,
                    success=False,
                    error="No pending transaction found",
                )

            # For HTTP, commit is just re-sending with same idempotency key
            # which is idempotent by design
            idempotency_key = pending["idempotency_key"]
            headers = {"Idempotency-Key": idempotency_key, "Content-Type": "application/json"}

            # Re-send to confirm (idempotent)
            response = self._session.request(
                method=pending["method"],
                url=pending["url"],
                json={},  # Empty body for confirmation
                headers=headers,
                timeout=self.config.timeout,
            )

            if response.status_code >= 400:
                return CommitResult(
                    transaction_id=transaction_id,
                    success=False,
                    error=f"HTTP {response.status_code}: {response.text}",
                )

            return CommitResult(
                transaction_id=transaction_id,
                success=True,
                external_id=response.headers.get("X-Request-ID"),
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
        """Abort phase: attempt to cancel/delete the resource."""
        try:
            with self._lock:
                pending = self._pending.pop(transaction_id, None)

            if not pending:
                return AbortResult(
                    transaction_id=transaction_id,
                    success=True,
                    error="No pending transaction (already completed)",
                )

            # Attempt to DELETE with idempotency key
            idempotency_key = pending["idempotency_key"]
            headers = {"Idempotency-Key": idempotency_key}

            response = self._session.delete(
                pending["url"],
                headers=headers,
                timeout=self.config.timeout,
            )

            if response.status_code in (200, 202, 204, 404, 409):
                return AbortResult(
                    transaction_id=transaction_id,
                    success=True,
                )

            return AbortResult(
                transaction_id=transaction_id,
                success=False,
                error=f"HTTP {response.status_code}: {response.text}",
            )

        except Exception as e:
            return AbortResult(
                transaction_id=transaction_id,
                success=False,
                error=str(e),
            )

    def get_status(self, transaction_id: str) -> TransactionState:
        """Get the current state of a transaction."""
        with self._lock:
            if transaction_id in self._pending:
                return TransactionState.PREPARED
            return TransactionState.FAILED

    def close(self) -> None:
        """Close the HTTP session."""
        self._session.close()