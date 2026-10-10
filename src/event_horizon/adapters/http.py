"""HTTP/REST adapter with two-phase commit using idempotency keys."""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import requests
from requests.adapters import HTTPAdapter as RequestsHTTPAdapter
from urllib3.util.retry import Retry

from event_horizon.adapters.base import (
    PrepareResult,
    CommitResult,
    AbortResult,
    TransactionState,
)


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
    # Dry-run parameter for prepare phase validation (e.g., "dry_run=true", "preview=true")
    # If None, uses HEAD request for validation
    dry_run_param: Optional[str] = None
    # HTTP method for prepare validation (if dry_run_param not set)
    # "HEAD" validates without body, "OPTIONS" checks allowed methods
    prepare_method: str = "HEAD"


class HTTPAdapter:
    """Preflight/commit HTTP adapter for trusted, explicitly idempotent APIs.

    This is not distributed two-phase commit and cannot guarantee exactly-once
    effects. The remote service must independently enforce idempotency keys.
    Ambiguous commits are never retried automatically.
    """

    adapter_type = "http"

    def __init__(self, config: HTTPConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._pending: dict[str, Mapping[str, Any]] = {}
        self._states: dict[str, TransactionState] = {}

        # Create session with retries
        self._session = requests.Session()
        retry_strategy = Retry(
            total=config.max_retries,
            backoff_factor=config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = RequestsHTTPAdapter(max_retries=retry_strategy)
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
        return "eh-" + hashlib.sha256(transaction_id.encode("utf-8")).hexdigest()

    def _get_base_headers(self) -> Mapping[str, str]:
        """Get base headers including idempotency key."""
        return {}

    def prepare(
        self,
        transaction_id: str,
        operation: Mapping[str, Any],
    ) -> PrepareResult:
        """Prepare phase: validate the request WITHOUT causing external effects.

        Uses dry-run parameter or HEAD/OPTIONS request for validation.
        The actual write occurs only in commit().
        """
        try:
            if not isinstance(transaction_id, str) or not transaction_id:
                raise ValueError("transaction ID is required")
            with self._lock:
                if transaction_id in self._states:
                    raise ValueError("transaction ID has already been used")
            op_type = operation.get("type", "POST")
            op_data = operation.get("data", {})
            endpoint = operation.get("endpoint", "")
            if not isinstance(op_type, str):
                raise ValueError("HTTP method must be text")
            method = op_type.upper()
            if method not in ("POST", "PUT", "PATCH"):
                raise ValueError("only POST, PUT, and PATCH commits are supported")
            if not isinstance(endpoint, str) or endpoint.startswith("/") or ".." in endpoint.split("/"):
                raise ValueError("endpoint must be a relative path without traversal")

            idempotency_key = self._generate_idempotency_key(transaction_id)

            headers = dict(self.config.default_headers or {})
            headers["Idempotency-Key"] = idempotency_key
            headers["Content-Type"] = "application/json"

            url = f"{self.config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

            # Prepare phase: validate WITHOUT causing external effect
            # Option 1: Use dry_run parameter if configured
            # Option 2: Use HEAD/OPTIONS request for validation
            prepare_url = url
            prepare_method = self.config.prepare_method
            prepare_headers = dict(headers)
            prepare_json = None

            if self.config.dry_run_param:
                # Add dry-run parameter to URL or body
                separator = "&" if "?" in url else "?"
                prepare_url = f"{url}{separator}{self.config.dry_run_param}"
                prepare_method = method
                prepare_json = op_data
            else:
                # Use HEAD or OPTIONS for validation (no body)
                prepare_json = None

            response = self._session.request(
                method=prepare_method,
                url=prepare_url,
                json=prepare_json,
                headers=prepare_headers,
                timeout=self.config.timeout,
                allow_redirects=False,
            )

            if response.status_code >= 400 or response.status_code in (301, 302, 303, 307, 308):
                return PrepareResult(
                    transaction_id=transaction_id,
                    success=False,
                    error=f"HTTP {response.status_code}: {response.text}",
                )

            # Store pending transaction for commit/abort
            with self._lock:
                if transaction_id in self._states:
                    raise ValueError("transaction ID has already been used")
                self._states[transaction_id] = TransactionState.PREPARED
                self._pending[transaction_id] = {
                    "url": url,
                    "method": method,
                    "data": op_data,
                    "idempotency_key": idempotency_key,
                    "headers": headers,
                    "prepare_status": response.status_code,
                }

            return PrepareResult(
                transaction_id=transaction_id,
                success=True,
                metadata={
                    "prepare_status": response.status_code,
                    "validated": True,
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
        """Commit phase: execute the ACTUAL write with idempotency key.

        This is where the external effect occurs. The prepare phase only validated.
        """
        try:
            with self._lock:
                pending = self._pending.pop(transaction_id, None)
                if pending is not None:
                    # An effect may occur after this point; never auto-retry it.
                    self._states[transaction_id] = TransactionState.INDETERMINATE

            if not pending:
                return CommitResult(
                    transaction_id=transaction_id,
                    success=False,
                    error="No pending transaction found",
                )

            # Commit phase: execute the actual write with idempotency key
            idempotency_key = pending["idempotency_key"]
            headers = dict(pending["headers"])
            headers["Idempotency-Key"] = idempotency_key

            # Send the ACTUAL request with the operation data
            response = self._session.request(
                method=pending["method"],
                url=pending["url"],
                json=pending["data"],
                headers=headers,
                timeout=self.config.timeout,
                allow_redirects=False,
            )

            if response.status_code >= 400 or response.status_code in (301, 302, 303, 307, 308):
                return CommitResult(
                    transaction_id=transaction_id,
                    success=False,
                    error=f"HTTP {response.status_code}: {response.text}",
                )

            with self._lock:
                self._states[transaction_id] = TransactionState.COMMITTED
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
        """Cancel a prepared local operation without sending DELETE.

        Once commit dispatch begins, the result may be indeterminate and abort
        cannot claim that a remote effect was reversed.
        """
        with self._lock:
            pending = self._pending.pop(transaction_id, None)
            if pending is None:
                return AbortResult(
                    transaction_id=transaction_id,
                    success=False,
                    error="not prepared; a remote effect may have occurred",
                )
            self._states[transaction_id] = TransactionState.ABORTED
        return AbortResult(transaction_id=transaction_id, success=True)

    def get_status(self, transaction_id: str) -> TransactionState:
        """Return local status; indeterminate requires remote reconciliation."""
        with self._lock:
            return self._states.get(transaction_id, TransactionState.FAILED)

    def close(self) -> None:
        """Close the HTTP session."""
        self._session.close()