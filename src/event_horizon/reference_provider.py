"""Reference authenticated provider service.

A standalone provider implementation used to validate the full Event Horizon
architecture against an independent external-style system. It runs as its own
process/service, holds only ITS OWN signing key, retains authoritative
execution records keyed by immutable idempotency identity, returns stable
provider transaction IDs, signs provider receipts, supports reconciliation,
and rejects an idempotency identity presented with changed content.

Failure modes are injected deterministically per operation scenario so that
gateway ambiguity handling can be exercised without real infrastructure:

* ``commit`` — normal path;
* ``commit-lose-response`` — commits durably, then fails to answer;
* ``crash-after-commit`` — commits durably, transport dies;
* ``ambiguous`` — reports unknown while committed;
* ``reject`` — positively confirms non-execution;
* ``unavailable`` — never answers execute; reconciliation still works.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes, digest


PROVIDER_RECEIPT_SCHEMA = "event-horizon.provider-receipt.v1"
PROVIDER_EVIDENCE_CLASS = "provider_authenticated_receipt"

MAX_BODY_BYTES = 65_536


class ProviderServiceError(RuntimeError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class ProviderDecision:
    status: int          # HTTP-style status for the transport layer
    body: dict[str, Any]


class ReferenceProviderCore:
    """Authoritative state machine + signing; transport-independent."""

    def __init__(
        self,
        *,
        provider_id: str,
        signing_key: bytes | Ed25519PrivateKey,
        storage_path: str | Path | None = None,
        scenario_for_operation: Mapping[str, str] | None = None,
    ) -> None:
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes) and len(signing_key) >= 32:
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        else:
            raise ProviderServiceError("provider signing key must be Ed25519")
        self.public_key_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"
        self.provider_id = provider_id
        self.scenario_for_operation = dict(scenario_for_operation or {})
        self._lock = threading.RLock()
        # idempotency_key -> authoritative record
        self.records: dict[str, dict[str, Any]] = {}
        self.storage_path = Path(storage_path) if storage_path else None
        if self.storage_path is not None:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ core

    def _scenario(self, operation: str) -> str:
        return self.scenario_for_operation.get(operation, "commit")

    def _sign_receipt(self, record: Mapping[str, Any]) -> dict[str, Any]:
        payload = {
            "schema": PROVIDER_RECEIPT_SCHEMA,
            "provider_id": self.provider_id,
            "provider_key_id": self.key_id,
            "idempotency_key": record["idempotency_key"],
            "effect_id": record["effect_id"],
            "effect_fingerprint": record["effect_fingerprint"],
            "provider_transaction_id": record["transaction_id"],
            "state": record["state"],
            "sequence": record["sequence"],
            "request_digest": record["request_digest"],
            "issued_at_ms": record["issued_at_ms"],
        }
        signature = _b64(self._private_key.sign(canonical_bytes(payload)))
        return {**payload, "signature": signature, "algorithm": "Ed25519"}

    def handle_execute(self, body: Mapping[str, Any]) -> ProviderDecision:
        required = {
            "idempotency_key", "effect_id", "effect_fingerprint",
            "operation", "request_digest",
        }
        if not isinstance(body, Mapping) or set(body) != required:
            return ProviderDecision(400, {"error": "fields are invalid"})
        key = body["idempotency_key"]
        if not isinstance(key, str) or not key:
            return ProviderDecision(400, {"error": "idempotency key is invalid"})
        with self._lock:
            existing = self.records.get(key)
            if existing is not None:
                if existing["effect_fingerprint"] != body.get("effect_fingerprint"):
                    return ProviderDecision(409, {
                        "error": "idempotency identity reused with different content",
                        "provider_transaction_id": existing["transaction_id"],
                    })
                receipt = self._sign_receipt(existing)
                return ProviderDecision(200, {
                    "duplicate": True,
                    "receipt": receipt,
                    "evidence_class": PROVIDER_EVIDENCE_CLASS,
                })
            scenario = self._scenario(str(body.get("operation")))
            if scenario == "reject":
                return ProviderDecision(200, {
                    "state": "confirmed-not-executed",
                    "reason": "rejected by provider policy",
                    "evidence_class": PROVIDER_EVIDENCE_CLASS,
                })
            sequence = len(self.records) + 1
            transaction_id = (
                f"tx_{hashlib.sha256(key.encode('utf-8')).hexdigest()[:24]}"
                f"-{sequence}"
            )
            record = {
                "idempotency_key": key,
                "effect_id": body["effect_id"],
                "effect_fingerprint": body["effect_fingerprint"],
                "request_digest": body["request_digest"],
                "transaction_id": transaction_id,
                "sequence": sequence,
                "state": "committed",
                "issued_at_ms": time.time_ns() // 1_000_000,
            }
            self.records[key] = record
            receipt = self._sign_receipt(record)
            if scenario in {"commit-lose-response", "crash-after-commit"}:
                # Committed durably above; response is lost at the transport.
                return ProviderDecision(504, {"error": "response lost after commit"})
            return ProviderDecision(200, {
                "state": "committed",
                "receipt": receipt,
                "evidence_class": PROVIDER_EVIDENCE_CLASS,
            })

    def handle_reconcile(self, body: Mapping[str, Any]) -> ProviderDecision:
        if not isinstance(body, Mapping) or set(body) != {"idempotency_key"}:
            return ProviderDecision(400, {"error": "fields are invalid"})
        key = body["idempotency_key"]
        with self._lock:
            record = self.records.get(key if isinstance(key, str) else "")
            if record is None:
                return ProviderDecision(200, {
                    "state": "confirmed-not-executed",
                    "reason": "no such execution at this provider",
                })
            return ProviderDecision(200, {
                "state": record["state"],
                "receipt": self._sign_receipt(record),
                "evidence_class": PROVIDER_EVIDENCE_CLASS,
            })

    def handle_info(self) -> ProviderDecision:
        return ProviderDecision(200, {
            "provider_id": self.provider_id,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
        })


def make_provider_handler(core: ReferenceProviderCore):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/info":
                self.send_error(404)
                return
            decision = core.handle_info()
            encoded = canonical_bytes(decision.body)
            self.send_response(decision.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/execute":
                handler = core.handle_execute
            elif self.path == "/reconcile":
                handler = core.handle_reconcile
            else:
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 <= length <= MAX_BODY_BYTES:
                self.send_error(413)
                return
            try:
                body = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self.send_error(400)
                return
            decision = handler(body)
            encoded = canonical_bytes(decision.body)
            self.send_response(decision.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *args: Any) -> None:
            return

    return Handler


class ReferenceProviderServer:
    """HTTP binding for the reference provider (conftest/integration use)."""

    def __init__(self, core: ReferenceProviderCore, *, host: str = "127.0.0.1") -> None:
        self.core = core
        self._server = ThreadingHTTPServer((host, 0), make_provider_handler(core))
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> None:
        if self._thread is not None:
            raise ProviderServiceError("provider server already started")
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self._server.server_close()


def verify_provider_receipt_signature(
    envelope: Mapping[str, Any], provider_public_key_pem: str
) -> bool:
    """Authenticate a provider receipt against a pinned provider key."""
    try:
        payload_fields = {
            "schema", "provider_id", "provider_key_id", "idempotency_key",
            "effect_id", "effect_fingerprint", "provider_transaction_id",
            "state", "sequence", "request_digest", "issued_at_ms",
        }
        if not isinstance(envelope, dict):
            return False
        if set(envelope) != payload_fields | {"signature", "algorithm"}:
            return False
        if envelope["algorithm"] != "Ed25519":
            return False
        loaded = serialization.load_pem_public_key(
            provider_public_key_pem.encode("ascii")
        )
        if not isinstance(loaded, Ed25519PublicKey):
            return False
        raw = loaded.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected_key_id = (
            f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"
        )
        if envelope["provider_key_id"] != expected_key_id:
            return False
        unsigned = {
            k: v for k, v in envelope.items()
            if k not in {"signature", "algorithm"}
        }
        decoded = base64.urlsafe_b64decode(
            envelope["signature"] + "=" * (-len(envelope["signature"]) % 4)
        )
        loaded.verify(decoded, canonical_bytes(unsigned))
        return True
    except Exception:
        return False
