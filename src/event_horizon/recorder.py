from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .canonical import digest


RECORDER_CHECKPOINT_SCHEMA = "event-horizon.recorder-checkpoint.v2"
LEGACY_RECORDER_CHECKPOINT_SCHEMA = "event-horizon.recorder-checkpoint.v1"
GENESIS_CHAIN_TIP = "0" * 64
_CHECKPOINT_FIELDS = {
    "schema",
    "deployment_id",
    "manifest_digest",
    "recorder_id",
    "sequence",
    "chain_tip",
    "previous_checkpoint_digest",
    "issued_at_ms",
}
_LEGACY_CHECKPOINT_FIELDS = {
    "schema",
    "recorder_key_id",
    "sequence",
    "chain_tip",
    "previous_checkpoint_digest",
    "issued_at",
}
_CHECKPOINT_ENVELOPE_FIELDS = {"checkpoint", "signature", "algorithm", "key_id"}


class RecorderIntegrityError(RuntimeError):
    pass


def _checkpoint_digest(checkpoint_payload: Mapping[str, Any]) -> str:
    return digest(dict(checkpoint_payload))


@dataclass(frozen=True)
class VerifiedRecorderSnapshot:
    """One immutable verified view of the entire recorded history.

    ``events``, ``chain_tip``, and ``chain_valid`` always describe exactly the
    same byte sequence because they are produced by a single scan.
    """

    events: tuple[dict[str, Any], ...]
    event_count: int
    chain_tip: str
    chain_valid: bool
    reason: str
    source_sequences: Mapping[str, int] = field(default_factory=dict)

    def event_hashes(self) -> tuple[str, ...]:
        return tuple(event["event_hash"] for event in self.events)


class CheckpointAnchor(Protocol):
    """Durable storage outside the authority of the recorder file itself."""

    def persist(self, envelope: dict[str, Any]) -> None: ...

    def load_latest(self) -> dict[str, Any] | None: ...


class FileCheckpointAnchor:
    """Append-only local checkpoint journal kept separate from the events file."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def persist(self, envelope: dict[str, Any]) -> None:
        encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

    def load_latest(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        latest: dict[str, Any] | None = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    latest = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise RecorderIntegrityError("checkpoint anchor contains malformed JSON") from exc
                if not isinstance(latest, dict):
                    raise RecorderIntegrityError("checkpoint anchor entry is not an object")
        return latest


class ExternalRecorder:
    """Append-only hash-chained recorder for an external evidence process."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        signing_key: bytes | Ed25519PrivateKey | None = None,
        *,
        max_event_bytes: int = 16_384,
        checkpoint_verification_key_pem: str | None = None,
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
        # Read-only views (for example the certificate service) never hold the
        # recorder signing key; they pin the recorder's public key out of band
        # and use it to authenticate exported checkpoints.
        if checkpoint_verification_key_pem is not None:
            loaded = serialization.load_pem_public_key(
                checkpoint_verification_key_pem.encode("ascii")
            )
            if not isinstance(loaded, Ed25519PublicKey):
                raise ValueError("checkpoint verification key must be Ed25519")
            self._checkpoint_key: Ed25519PublicKey = loaded
        else:
            self._checkpoint_key = self._public_key
        self._lock = threading.RLock()
        self._tip = GENESIS_CHAIN_TIP
        self._count = 0
        self._source_sequences: dict[str, int] = {}
        self._recover()

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

    def _scan_events(self) -> tuple[bool, str, str, int, dict[str, int], tuple[dict[str, Any], ...]]:
        previous = GENESIS_CHAIN_TIP
        count = 0
        source_sequences: dict[str, int] = {}
        events: list[dict[str, Any]] = []
        if not self.path.exists():
            return True, "ok", previous, count, source_sequences, ()
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if len(line.encode("utf-8")) != self.max_event_bytes:
                    return False, f"event digest or envelope size failure at line {line_number}", previous, count, source_sequences, tuple(events)
                if not line.strip():
                    return False, f"blank record at line {line_number}", previous, count, source_sequences, tuple(events)
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"invalid JSON at line {line_number}", previous, count, source_sequences, tuple(events)
                expected_fields = {
                    "sequence", "timestamp", "event_type", "payload", "source_id",
                    "source_sequence", "previous_hash", "event_hash",
                }
                if not isinstance(event, dict) or set(event) != expected_fields:
                    return False, f"invalid event fields at line {line_number}", previous, count, source_sequences, tuple(events)
                if event["sequence"] != count + 1:
                    return False, f"sequence gap at line {line_number}", previous, count, source_sequences, tuple(events)
                source_id = event["source_id"]
                source_sequence = event["source_sequence"]
                if not isinstance(source_id, str) or not source_id or not isinstance(source_sequence, int):
                    return False, f"invalid source sequence at line {line_number}", previous, count, source_sequences, tuple(events)
                if source_sequence != source_sequences.get(source_id, 0) + 1:
                    return False, f"source loss or reordering at line {line_number}", previous, count, source_sequences, tuple(events)
                claimed = event.pop("event_hash")
                if event.get("previous_hash") != previous:
                    return False, f"chain linkage failure at line {line_number}", previous, count, source_sequences, tuple(events)
                if claimed != digest(event):
                    return False, f"event digest failure at line {line_number}", previous, count, source_sequences, tuple(events)
                event["event_hash"] = claimed
                events.append(event)
                previous = claimed
                count += 1
                source_sequences[source_id] = source_sequence
        return True, "ok", previous, count, source_sequences, tuple(events)

    def _scan(self) -> tuple[bool, str, str, int, dict[str, int]]:
        valid, reason, tip, count, source_sequences, _events = self._scan_events()
        return valid, reason, tip, count, source_sequences

    def append(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        source_id: str = "local",
        source_sequence: int | None = None,
    ) -> dict[str, Any]:
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
                "timestamp": time.time_ns() // 1_000_000,
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
                "issued_at": time.time_ns() // 1_000_000,
                "key_id": self.key_id,
            }
            signature = base64.urlsafe_b64encode(
                self._private_key.sign(canonical_bytes(receipt_payload))
            ).rstrip(b"=").decode("ascii")
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

    def verified_snapshot(self) -> VerifiedRecorderSnapshot:
        """Return one atomic verified view of the full history.

        Consumers that make security decisions (for example the certificate
        builder) must use this single snapshot instead of combining separate
        ``verify()`` and ``events()`` reads, which can observe different file
        states.
        """
        with self._lock:
            valid, reason, tip, count, source_sequences, events = self._scan_events()
            if not valid:
                raise RecorderIntegrityError(f"recorder verification failed: {reason}")
            return VerifiedRecorderSnapshot(
                events=events,
                event_count=count,
                chain_tip=tip,
                chain_valid=True,
                reason=reason,
                source_sequences=dict(source_sequences),
            )

    def issue_checkpoint(
        self,
        anchor: CheckpointAnchor,
        *,
        deployment_id: str,
        manifest_digest: str,
    ) -> dict[str, Any]:
        """Sign the current chain state and persist it via an external anchor.

        v0.6 checkpoints bind the deployment identity and the applicable
        trust-root manifest digest so witnessed history is deployment-scoped
        and trust-root-versioned. Legacy v1 checkpoints remain verifiable for
        historical purposes but are never treated as witnessed evidence.
        """
        if self._checkpoint_key is not self._public_key:
            raise RecorderIntegrityError(
                "this recorder view does not hold the signing key and cannot issue checkpoints"
            )
        if not isinstance(deployment_id, str) or not deployment_id:
            raise RecorderIntegrityError("checkpoint deployment ID is invalid")
        if (
            not isinstance(manifest_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None
        ):
            raise RecorderIntegrityError("checkpoint manifest digest is invalid")
        snapshot = self.verified_snapshot()
        previous = anchor.load_latest()
        previous_digest = GENESIS_CHAIN_TIP
        if previous is not None:
            envelope = self._require_checkpoint_envelope(previous)
            payload = envelope["checkpoint"]
            if payload["schema"] != RECORDER_CHECKPOINT_SCHEMA:
                raise RecorderIntegrityError(
                    "cannot chain a v0.6 checkpoint onto a legacy checkpoint"
                )
            if (
                payload["recorder_id"] != self.key_id
                or payload["sequence"] > snapshot.event_count
                or (payload["sequence"] == snapshot.event_count and payload["chain_tip"] != snapshot.chain_tip)
                or payload["deployment_id"] != deployment_id
                or payload["manifest_digest"] != manifest_digest
            ):
                raise RecorderIntegrityError(
                    "anchored checkpoint contradicts the current recorder history "
                    "or was issued under a different deployment/manifest"
                )
            previous_digest = _checkpoint_digest(payload)
        checkpoint_payload = {
            "schema": RECORDER_CHECKPOINT_SCHEMA,
            "deployment_id": deployment_id,
            "manifest_digest": manifest_digest,
            "recorder_id": self.key_id,
            "sequence": snapshot.event_count,
            "chain_tip": snapshot.chain_tip,
            "previous_checkpoint_digest": previous_digest,
            "issued_at_ms": time.time_ns() // 1_000_000,
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(checkpoint_payload))
        ).rstrip(b"=").decode("ascii")
        envelope = {
            "checkpoint": checkpoint_payload,
            "signature": signature,
            "algorithm": "Ed25519",
            "key_id": self.key_id,
        }
        anchor.persist(envelope)
        return envelope

    def verify_against_anchor(self, anchor: CheckpointAnchor) -> tuple[bool, str]:
        """Detect rollback or replacement relative to the anchored checkpoint."""
        anchored = anchor.load_latest()
        if anchored is None:
            return False, "no anchored checkpoint is available"
        try:
            envelope = self._require_checkpoint_envelope(anchored)
        except RecorderIntegrityError as exc:
            return False, str(exc)
        payload = envelope["checkpoint"]
        try:
            snapshot = self.verified_snapshot()
        except RecorderIntegrityError as exc:
            return False, str(exc)
        if snapshot.chain_tip == payload["chain_tip"] and snapshot.event_count >= payload["sequence"]:
            return True, "ok"
        if snapshot.event_count < payload["sequence"]:
            return False, "recorder history rolled back behind the anchored checkpoint"
        return False, "recorder history diverged from the anchored checkpoint"

    def _require_checkpoint_envelope(
        self,
        envelope: Any,
        *,
        allow_legacy: bool = False,
    ) -> Mapping[str, Any]:
        if not isinstance(envelope, dict) or set(envelope) != _CHECKPOINT_ENVELOPE_FIELDS:
            raise RecorderIntegrityError("checkpoint envelope fields are invalid")
        if envelope["algorithm"] != "Ed25519":
            raise RecorderIntegrityError("checkpoint algorithm is unsupported")
        payload = envelope["checkpoint"]
        schema = payload.get("schema") if isinstance(payload, dict) else None
        if schema == LEGACY_RECORDER_CHECKPOINT_SCHEMA:
            if not allow_legacy:
                raise RecorderIntegrityError(
                    "legacy v1 checkpoints are not valid witnessed evidence"
                )
            return self._verify_legacy_checkpoint_envelope(envelope)
        if not isinstance(payload, dict) or set(payload) != _CHECKPOINT_FIELDS:
            raise RecorderIntegrityError("checkpoint payload fields are invalid")
        if schema != RECORDER_CHECKPOINT_SCHEMA:
            raise RecorderIntegrityError(f"unsupported checkpoint schema: {schema!r}")
        if (
            not isinstance(payload["chain_tip"], str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["chain_tip"]) is None
        ):
            raise RecorderIntegrityError("checkpoint chain tip is malformed")
        if type(payload["sequence"]) is not int or payload["sequence"] < 0:
            raise RecorderIntegrityError("checkpoint sequence is invalid")
        if not isinstance(payload["deployment_id"], str) or not payload["deployment_id"]:
            raise RecorderIntegrityError("checkpoint deployment ID is invalid")
        if (
            not isinstance(payload["manifest_digest"], str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["manifest_digest"]) is None
        ):
            raise RecorderIntegrityError("checkpoint manifest digest is malformed")
        raw_checkpoint = self._checkpoint_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected_checkpoint_key_id = f"ed25519:{hashlib.sha256(raw_checkpoint).hexdigest()[:32]}"
        if (
            envelope["key_id"] != expected_checkpoint_key_id
            or payload["recorder_id"] != expected_checkpoint_key_id
        ):
            raise RecorderIntegrityError("checkpoint was not issued by the pinned recorder key")
        issued_at_ms = payload["issued_at_ms"]
        if type(issued_at_ms) is not int or issued_at_ms < 0:
            raise RecorderIntegrityError("checkpoint issuance time is invalid")
        signature = envelope["signature"]
        if not isinstance(signature, str):
            raise RecorderIntegrityError("checkpoint signature is malformed")
        try:
            decoded = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
            if len(decoded) != 64:
                raise RecorderIntegrityError("checkpoint signature length is invalid")
            self._checkpoint_key.verify(decoded, canonical_bytes(payload))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise RecorderIntegrityError("checkpoint signature is invalid") from exc
        return envelope

    def _verify_legacy_checkpoint_envelope(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = envelope["checkpoint"]
        raw_checkpoint = self._checkpoint_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = f"ed25519:{hashlib.sha256(raw_checkpoint).hexdigest()[:32]}"
        if envelope["key_id"] != expected or payload["recorder_key_id"] != expected:
            raise RecorderIntegrityError("legacy checkpoint key identity mismatch")
        if type(payload["issued_at"]) is not int or payload["issued_at"] < 0:
            raise RecorderIntegrityError("legacy checkpoint issuance time is invalid")
        try:
            decoded = base64.urlsafe_b64decode(
                envelope["signature"] + "=" * (-len(envelope["signature"]) % 4)
            )
            if len(decoded) != 64:
                raise RecorderIntegrityError("legacy checkpoint signature length is invalid")
            self._checkpoint_key.verify(decoded, canonical_bytes(payload))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise RecorderIntegrityError("legacy checkpoint signature is invalid") from exc
        return envelope

    @staticmethod
    def verify_checkpoint_signature(envelope: Mapping[str, Any], public_key_pem: str) -> bool:
        """Verify an exported checkpoint against a trusted recorder key."""
        try:
            if not isinstance(envelope, dict) or set(envelope) != _CHECKPOINT_ENVELOPE_FIELDS:
                return False
            if envelope["algorithm"] != "Ed25519":
                return False
            payload = envelope["checkpoint"]
            if not isinstance(payload, dict) or set(payload) != _CHECKPOINT_FIELDS:
                return False
            if payload["schema"] != RECORDER_CHECKPOINT_SCHEMA:
                return False
            loaded = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            if not isinstance(loaded, Ed25519PublicKey):
                return False
            raw = loaded.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            expected_key_id = f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"
            if envelope["key_id"] != payload["recorder_id"] or envelope["key_id"] != expected_key_id:
                return False
            signature = base64.urlsafe_b64decode(envelope["signature"] + "=" * (-len(envelope["signature"]) % 4))
            if len(signature) != 64:
                return False
            loaded.verify(signature, canonical_bytes(payload))
            return True
        except (InvalidSignature, ValueError, TypeError, UnicodeError):
            return False

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
                or type(payload["issued_at"]) is not int
                or payload["issued_at"] < 0
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
