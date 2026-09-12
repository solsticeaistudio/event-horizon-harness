from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .canonical import digest


class RecorderIntegrityError(RuntimeError):
    pass


class ExternalRecorder:
    """Append-only hash-chained recorder for an external evidence process."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        signing_key: bytes | Ed25519PrivateKey | None = None,
        *,
        max_event_bytes: int = 16_384,
        metrics_callback: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
        prometheus_registry: Optional[object] = None,
        otel_meter: Optional[object] = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not 512 <= max_event_bytes <= 65_536:
            raise ValueError("invalid recorder event limit")
        self.max_event_bytes = max_event_bytes
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes):
            if len(signing_key) < 32:
                raise ValueError("recorder signing seed must be at least 32 bytes")
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        elif signing_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise TypeError("unsupported recorder signing key")
        self._public_key = self._private_key.public_key()
        raw_public = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"
        self._lock = threading.RLock()
        self._tip = "0" * 64
        self._count = 0
        self._source_sequences: dict[str, int] = {}
        self._recover()

        # Metrics/observability hooks
        self._metrics_callback = metrics_callback
        self._prometheus_registry = prometheus_registry
        self._otel_meter = otel_meter
        self._prometheus_metrics: dict[str, object] = {}
        self._otel_instruments: dict[str, object] = {}
        self._init_prometheus_metrics()
        self._init_otel_instruments()

    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics if registry provided."""
        if self._prometheus_registry is None:
            return
        try:
            from prometheus_client import Counter, Histogram, Gauge, REGISTRY
            registry = self._prometheus_registry if self._prometheus_registry is not REGISTRY else REGISTRY
            
            self._prometheus_metrics["events_appended"] = Counter(
                "event_horizon_events_appended_total",
                "Total number of events appended to the recorder",
                ["event_type", "source_id"],
                registry=registry,
            )
            self._prometheus_metrics["append_duration"] = Histogram(
                "event_horizon_append_duration_seconds",
                "Time spent appending events",
                ["event_type"],
                registry=registry,
            )
            self._prometheus_metrics["event_size"] = Histogram(
                "event_horizon_event_size_bytes",
                "Size of appended events in bytes",
                ["event_type"],
                registry=registry,
            )
            self._prometheus_metrics["integrity_errors"] = Counter(
                "event_horizon_integrity_errors_total",
                "Total number of integrity errors",
                ["error_type"],
                registry=registry,
            )
            self._prometheus_metrics["event_count"] = Gauge(
                "event_horizon_event_count",
                "Current number of events in the recorder",
                registry=registry,
            )
        except ImportError:
            self._prometheus_metrics = {}
            self._prometheus_registry = None

    def _init_otel_instruments(self) -> None:
        """Initialize OpenTelemetry instruments if meter provided."""
        if self._otel_meter is None:
            return
        try:
            from opentelemetry.metrics import Meter
            meter = self._otel_meter if isinstance(self._otel_meter, Meter) else None
            if meter is None:
                return
            
            self._otel_instruments["events_appended"] = meter.create_counter(
                "event_horizon.events_appended",
                description="Total number of events appended",
                unit="1",
            )
            self._otel_instruments["append_duration"] = meter.create_histogram(
                "event_horizon.append_duration",
                description="Time spent appending events",
                unit="s",
            )
            self._otel_instruments["event_size"] = meter.create_histogram(
                "event_horizon.event_size",
                description="Size of appended events",
                unit="By",
            )
            self._otel_instruments["integrity_errors"] = meter.create_counter(
                "event_horizon.integrity_errors",
                description="Total number of integrity errors",
                unit="1",
            )
        except ImportError:
            self._otel_instruments = {}
            self._otel_meter = None

    def _emit_metrics(self, event_type: str, source_id: str, duration: float, size: int) -> None:
        """Emit metrics for an append operation."""
        # Prometheus
        if "events_appended" in self._prometheus_metrics:
            self._prometheus_metrics["events_appended"].labels(
                event_type=event_type, source_id=source_id
            ).inc()
            self._prometheus_metrics["append_duration"].labels(
                event_type=event_type
            ).observe(duration)
            self._prometheus_metrics["event_size"].labels(
                event_type=event_type
            ).observe(size)
            self._prometheus_metrics["event_count"].set(self._count)

        # OpenTelemetry
        if "events_appended" in self._otel_instruments:
            attrs = {"event_type": event_type, "source_id": source_id}
            self._otel_instruments["events_appended"].add(1, attributes=attrs)
            self._otel_instruments["append_duration"].record(duration, attributes=attrs)
            self._otel_instruments["event_size"].record(len, attributes=attrs)

    def _emit_integrity_error(self, error_type: str) -> None:
        """Emit metrics for an integrity error."""
        if "integrity_errors" in self._prometheus_metrics:
            self._prometheus_metrics["integrity_errors"].labels(error_type=error_type).inc()
        if "integrity_errors" in self._otel_instruments:
            self._otel_instruments["integrity_errors"].add(1, attributes={"error_type": error_type})

        if self._metrics_callback:
            self._metrics_callback("integrity_error", {"error_type": error_type})

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def _scan(self) -> tuple[bool, str, str, int, dict[str, int]]:
        previous = "0" * 64
        count = 0
        source_sequences: dict[str, int] = {}
        if not self.path.exists():
            return True, "ok", previous, count, source_sequences
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if len(line.encode("utf-8")) != self.max_event_bytes:
                    return False, f"event digest or envelope size failure at line {line_number}", previous, count, source_sequences
                if not line.strip():
                    return False, f"blank record at line {line_number}", previous, count, source_sequences
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"invalid JSON at line {line_number}", previous, count, source_sequences
                expected_fields = {
                    "sequence", "timestamp", "event_type", "payload", "source_id",
                    "source_sequence", "previous_hash", "event_hash",
                }
                if not isinstance(event, dict) or set(event) != expected_fields:
                    return False, f"invalid event fields at line {line_number}", previous, count, source_sequences
                if event["sequence"] != count + 1:
                    return False, f"sequence gap at line {line_number}", previous, count, source_sequences
                source_id = event["source_id"]
                source_sequence = event["source_sequence"]
                if not isinstance(source_id, str) or not source_id or not isinstance(source_sequence, int):
                    return False, f"invalid source sequence at line {line_number}", previous, count, source_sequences
                if source_sequence != source_sequences.get(source_id, 0) + 1:
                    return False, f"source loss or reordering at line {line_number}", previous, count, source_sequences
                claimed = event.pop("event_hash")
                if event.get("previous_hash") != previous:
                    return False, f"chain linkage failure at line {line_number}", previous, count, source_sequences
                if claimed != digest(event):
                    return False, f"event digest failure at line {line_number}", previous, count, source_sequences
                previous = claimed
                count += 1
                source_sequences[source_id] = source_sequence
        return True, "ok", previous, count, source_sequences

    def _recover(self) -> None:
        valid, reason, tip, count, source_sequences = self._scan()
        if not valid:
            raise RecorderIntegrityError(f"recorder recovery failed: {reason}")
        self._tip = tip
        self._count = count
        self._source_sequences = source_sequences

    def append(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        source_id: str = "local",
        source_sequence: int | None = None,
    ) -> dict[str, Any]:
        start_time = time.perf_counter()
        with self._lock:
            valid, reason, tip, count, source_sequences = self._scan()
            if not valid or tip != self._tip or count != self._count:
                raise RecorderIntegrityError(f"recorder changed outside authority: {reason}")
            if not isinstance(event_type, str) or not event_type or len(event_type) > 128:
                raise ValueError("invalid recorder event type")
            if not isinstance(payload, dict) or not isinstance(source_id, str) or not source_id:
                raise ValueError("invalid recorder event envelope")
            expected_source_sequence = source_sequences.get(source_id, 0) + 1
            if source_sequence is None:
                source_sequence = expected_source_sequence
            if source_sequence != expected_source_sequence:
                raise RecorderIntegrityError("source event loss or reordering detected")
            event = {
                "sequence": self._count + 1,
                "timestamp": time.time(),
                "event_type": event_type,
                "payload": payload,
                "source_id": source_id,
                "source_sequence": source_sequence,
                "previous_hash": self._tip,
            }
            event["event_hash"] = digest(event)
            encoded_event = canonical_bytes(event)
            if len(encoded_event) + 1 > self.max_event_bytes:
                raise ValueError("recorder event exceeds fixed envelope")
            encoded = encoded_event + (b" " * (self.max_event_bytes - len(encoded_event) - 1)) + b"\n"
            with self.path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            self._tip = event["event_hash"]
            self._count += 1
            self._source_sequences[source_id] = source_sequence
            receipt_payload = {
                "sequence": event["sequence"],
                "event_hash": event["event_hash"],
                "source_id": source_id,
                "source_sequence": source_sequence,
                "issued_at": time.time(),
                "key_id": self.key_id,
            }
            signature = base64.urlsafe_b64encode(
                self._private_key.sign(canonical_bytes(receipt_payload))
            ).rstrip(b"=").decode("ascii")

            # Emit metrics
            duration = time.perf_counter() - start_time
            size = len(encoded_event)
            self._emit_metrics(event_type, source_id, duration, size)
            if self._metrics_callback:
                self._metrics_callback("event_appended", {
                    "event_type": event_type,
                    "source_id": source_id,
                    "duration": duration,
                    "size": size,
                })

            return {
                **event,
                "receipt": {
                    "payload": receipt_payload,
                    "signature": signature,
                    "algorithm": "Ed25519",
                },
            }

    def count(self) -> int:
        return self._count

    def verify(self) -> tuple[bool, str]:
        valid, reason, tip, _count, _source_sequences = self._scan()
        return (True, tip) if valid else (False, reason)

    @staticmethod
    def verify_receipt(receipt: dict[str, Any], public_key_pem: str) -> bool:
        try:
            if set(receipt) != {"payload", "signature", "algorithm"}:
                return False
            if receipt["algorithm"] != "Ed25519":
                return False
            payload = receipt["payload"]
            if not isinstance(payload, dict) or set(payload) != {
                "sequence", "event_hash", "source_id", "source_sequence", "issued_at", "key_id"
            }:
                return False
            if (
                not isinstance(payload["sequence"], int)
                or payload["sequence"] < 1
                or not isinstance(payload["source_sequence"], int)
                or payload["source_sequence"] < 1
                or not isinstance(payload["source_id"], str)
                or not payload["source_id"]
                or not isinstance(payload["event_hash"], str)
                or re.fullmatch(r"[0-9a-f]{64}", payload["event_hash"]) is None
                or not isinstance(payload["issued_at"], (int, float))
                or isinstance(payload["issued_at"], bool)
                or not math.isfinite(payload["issued_at"])
                or not isinstance(payload["key_id"], str)
            ):
                return False
            public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            raw_public = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            expected_key_id = f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"
            if payload["key_id"] != expected_key_id:
                return False
            if not isinstance(receipt["signature"], str):
                return False
            padding = "=" * (-len(receipt["signature"]) % 4)
            signature = base64.urlsafe_b64decode(receipt["signature"] + padding)
            if base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != receipt["signature"]:
                return False
            public_key.verify(signature, canonical_bytes(payload))
            return True
        except (KeyError, TypeError, ValueError, InvalidSignature):
            return False

    def events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
