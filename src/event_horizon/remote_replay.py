from __future__ import annotations

import base64
import hashlib
import http.server
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest, strict_json_loads
from .protected_boundary import AuthorizationReplayError
from .replay_state import CapabilityConsumptionError


REQUEST_SCHEMA = "event-horizon.replay-request.v2"
RESPONSE_SCHEMA = "event-horizon.replay-response.v2"
GENESIS_SCHEMA = "event-horizon.replay-genesis.v2"
MAX_REQUEST_LIFETIME_MS = 30_000
MAX_CLOCK_SKEW_MS = 2_000
MAX_HTTP_BODY_BYTES = 65_536

_SCOPE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{32}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_CAPABILITY_ID = re.compile(r"^cap_[0-9a-f]{24}$")

_REQUEST_FIELDS = {
    "algorithm",
    "client_key_id",
    "expected_epoch",
    "expires_at",
    "issued_at",
    "minimum_checkpoint",
    "minimum_checkpoint_digest",
    "operation",
    "partition",
    "payload",
    "request_id",
    "schema",
    "service_id",
    "signature",
}
_RESPONSE_FIELDS = {
    "accepted",
    "algorithm",
    "checkpoint",
    "checkpoint_digest",
    "epoch",
    "request_digest",
    "request_id",
    "responded_at",
    "result",
    "schema",
    "server_key_id",
    "service_id",
    "signature",
    "status",
}
_OPERATIONS = {
    "authorization-consume",
    "capability-consume",
    "nonce-consume",
    "nonce-create",
    "nonce-inspect",
}


class ReplayProtocolError(RuntimeError):
    """The peer violated the authenticated replay protocol."""


class ReplayUnavailableError(RuntimeError):
    """The replay authority could not produce a verified response."""


class ReplayStateError(RuntimeError):
    """The reference state machine could not complete a transition safely."""


def _now_ms(now: Callable[[], float] | None = None) -> int:
    value = time.time() if now is None else now()
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ReplayProtocolError("replay clock is invalid")
    return int(value * 1000)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    if not isinstance(value, str):
        raise ReplayProtocolError("base64url value is not a string")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ReplayProtocolError("base64url value is malformed") from exc
    if _b64url(decoded) != value:
        raise ReplayProtocolError("base64url value is not canonical")
    return decoded


def replay_key_id(public_key: Ed25519PublicKey) -> str:
    """Key identity for the remote replay protocol.

    Unified scheme: every Event Horizon ``ed25519:`` key ID is derived from the
    32-byte RAW public key (``ed25519:<sha256(raw)[:32]>``). Earlier versions
    of this module hashed the DER SubjectPublicKeyInfo encoding instead; that
    incompatible derivation is retired so one prefix always means one
    derivation algorithm across Python and TypeScript.
    """
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(encoded).hexdigest()[:32]}"


def genesis_checkpoint_digest(service_id: str, epoch: int) -> str:
    _require_scope(service_id, "service ID")
    _require_positive_integer(epoch, "epoch")
    return digest({"schema": GENESIS_SCHEMA, "service_id": service_id, "epoch": epoch})


def _require_scope(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SCOPE.fullmatch(value) is None:
        raise ReplayProtocolError(f"{label} is invalid")
    return value


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReplayProtocolError(f"{label} is invalid")
    return value


def _require_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ReplayProtocolError(f"{label} is invalid")
    return value


def _require_positive_integer(value: Any, label: str) -> int:
    return _require_integer(value, label, minimum=1)


def _normalize_checkpoint_state(
    service_id: str,
    epoch: int,
    checkpoint: Any,
    checkpoint_digest: Any,
    label: str,
) -> tuple[int, str]:
    normalized_checkpoint = _require_integer(checkpoint, f"{label} checkpoint")
    expected_genesis = genesis_checkpoint_digest(service_id, epoch)
    if normalized_checkpoint == 0:
        if checkpoint_digest is None:
            return 0, expected_genesis
        supplied_digest = _require_digest(checkpoint_digest, f"{label} checkpoint digest")
        if supplied_digest != expected_genesis:
            raise ReplayProtocolError(
                f"{label} checkpoint zero must use the epoch genesis digest"
            )
        return 0, supplied_digest
    if checkpoint_digest is None:
        raise ReplayProtocolError(
            f"{label} restored checkpoint requires an explicit digest"
        )
    return normalized_checkpoint, _require_digest(
        checkpoint_digest,
        f"{label} checkpoint digest",
    )


def _require_exact_fields(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReplayProtocolError(f"{label} fields are invalid")
    return value


def _is_nonce(value: Any) -> bool:
    if not isinstance(value, str) or _NONCE.fullmatch(value) is None:
        return False
    try:
        return len(_decode_b64url(value)) == 32
    except ReplayProtocolError:
        return False


def _load_private_key(value: bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes) and len(value) == 32:
        return Ed25519PrivateKey.from_private_bytes(value)
    raise ValueError("replay signing key must be a 32-byte Ed25519 seed")


def _load_public_key(value: str | Ed25519PublicKey) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    if not isinstance(value, str):
        raise ValueError("replay verification key must be Ed25519")
    try:
        key = serialization.load_pem_public_key(value.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("replay verification key is malformed") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("replay verification key must be Ed25519")
    return key


@dataclass(frozen=True)
class ReplayClientPolicy:
    public_key: Ed25519PublicKey
    operations: frozenset[str]
    partitions: frozenset[str]

    @classmethod
    def create(
        cls,
        public_key: str | Ed25519PublicKey,
        *,
        operations: set[str] | frozenset[str],
        partitions: set[str] | frozenset[str],
    ) -> ReplayClientPolicy:
        if not operations or not operations <= _OPERATIONS:
            raise ValueError("replay client operations are invalid")
        if not partitions or any(_SCOPE.fullmatch(item) is None for item in partitions):
            raise ValueError("replay client partitions are invalid")
        return cls(_load_public_key(public_key), frozenset(operations), frozenset(partitions))

    @property
    def key_id(self) -> str:
        return replay_key_id(self.public_key)


class ReplayTransport(Protocol):
    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


class ReplayRequestSigner:
    def __init__(
        self,
        signing_key: bytes | Ed25519PrivateKey,
        service_id: str,
        *,
        lifetime_ms: int = 5_000,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.private_key = _load_private_key(signing_key)
        self.public_key = self.private_key.public_key()
        self.key_id = replay_key_id(self.public_key)
        self.service_id = _require_scope(service_id, "service ID")
        if type(lifetime_ms) is not int or not 1 <= lifetime_ms <= MAX_REQUEST_LIFETIME_MS:
            raise ValueError("replay request lifetime is invalid")
        self.lifetime_ms = lifetime_ms
        self.now = now

    @property
    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(
        self,
        *,
        operation: str,
        partition: str,
        payload: Mapping[str, Any],
        expected_epoch: int,
        minimum_checkpoint: int,
        minimum_checkpoint_digest: str,
    ) -> dict[str, Any]:
        if operation not in _OPERATIONS:
            raise ReplayProtocolError("replay operation is unsupported")
        _require_scope(partition, "replay partition")
        _require_positive_integer(expected_epoch, "expected epoch")
        _require_integer(minimum_checkpoint, "minimum checkpoint")
        _require_digest(minimum_checkpoint_digest, "minimum checkpoint digest")
        if not isinstance(payload, Mapping):
            raise ReplayProtocolError("replay payload must be an object")
        issued_at = _now_ms(self.now)
        unsigned = {
            "schema": REQUEST_SCHEMA,
            "algorithm": "Ed25519",
            "service_id": self.service_id,
            "client_key_id": self.key_id,
            "request_id": _b64url(secrets.token_bytes(32)),
            "issued_at": issued_at,
            "expires_at": issued_at + self.lifetime_ms,
            "expected_epoch": expected_epoch,
            "minimum_checkpoint": minimum_checkpoint,
            "minimum_checkpoint_digest": minimum_checkpoint_digest,
            "operation": operation,
            "partition": partition,
            "payload": dict(payload),
        }
        return {
            **unsigned,
            "signature": _b64url(self.private_key.sign(canonical_bytes(unsigned))),
        }


class ReferenceReplayService:
    """Signed single-writer reference state machine.

    SQLite serializes transitions. This class demonstrates the protocol contract;
    it is not a consensus system and does not claim Byzantine fault tolerance.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        service_id: str,
        epoch: int,
        signing_key: bytes | Ed25519PrivateKey,
        clients: Mapping[str, ReplayClientPolicy],
        now: Callable[[], float] | None = None,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self.path = Path(database_path).resolve()
        if str(database_path) == ":memory:":
            raise ValueError("reference replay state must be durable")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.service_id = _require_scope(service_id, "service ID")
        self._initial_epoch = _require_positive_integer(epoch, "epoch")
        self.private_key = _load_private_key(signing_key)
        self.public_key = self.private_key.public_key()
        self.server_key_id = replay_key_id(self.public_key)
        self.clients = dict(clients)
        if any(key != policy.key_id or _KEY_ID.fullmatch(key) is None for key, policy in self.clients.items()):
            raise ValueError("replay client policy key IDs are inconsistent")
        if type(busy_timeout_ms) is not int or not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("replay database busy timeout is invalid")
        self.busy_timeout_ms = busy_timeout_ms
        self.now = now
        self._closed = False
        self._lock = threading.RLock()
        self._initialize()

    @property
    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def checkpoint(self) -> tuple[int, int, str]:
        database = self._connect()
        try:
            row = database.execute(
                "SELECT epoch, checkpoint, checkpoint_digest FROM replay_metadata WHERE singleton = 1"
            ).fetchone()
        finally:
            database.close()
        if row is None:
            raise ReplayStateError("replay metadata disappeared")
        return int(row[0]), int(row[1]), str(row[2])

    def promote(
        self,
        new_epoch: int,
        *,
        continuity_checkpoint: int,
        continuity_digest: str,
        signing_key: bytes | Ed25519PrivateKey | None = None,
    ) -> None:
        """Perform an explicit operator-controlled failover epoch promotion."""

        _require_positive_integer(new_epoch, "new epoch")
        _require_integer(continuity_checkpoint, "continuity checkpoint")
        _require_digest(continuity_digest, "continuity digest")
        promoted_private_key = self.private_key if signing_key is None else _load_private_key(signing_key)
        promoted_public_key = promoted_private_key.public_key()
        promoted_key_id = replay_key_id(promoted_public_key)
        with self._lock:
            database = self._connect()
            try:
                database.execute("BEGIN IMMEDIATE")
                row = database.execute(
                    "SELECT epoch, checkpoint, checkpoint_digest FROM replay_metadata WHERE singleton = 1"
                ).fetchone()
                if row is None:
                    raise ReplayStateError("replay metadata disappeared")
                if new_epoch <= row[0]:
                    raise ReplayStateError("failover epoch must increase")
                if (row[1], row[2]) != (continuity_checkpoint, continuity_digest):
                    raise ReplayStateError("failover continuity checkpoint does not match restored state")
                promoted_digest = continuity_digest
                if continuity_checkpoint == 0:
                    promoted_digest = genesis_checkpoint_digest(self.service_id, new_epoch)
                    database.execute(
                        """
                        UPDATE replay_checkpoints
                        SET epoch = ?, checkpoint_digest = ?
                        WHERE checkpoint = 0
                        """,
                        (new_epoch, promoted_digest),
                    )
                database.execute(
                    """
                    UPDATE replay_metadata
                    SET epoch = ?, server_key_id = ?, checkpoint_digest = ?
                    WHERE singleton = 1
                    """,
                    (new_epoch, promoted_key_id, promoted_digest),
                )
                database.execute("COMMIT")
            except (sqlite3.Error, ReplayStateError) as exc:
                self._rollback(database)
                if isinstance(exc, ReplayStateError):
                    raise
                raise ReplayStateError("replay epoch promotion failed closed") from exc
            finally:
                database.close()
            self.private_key = promoted_private_key
            self.public_key = promoted_public_key
            self.server_key_id = promoted_key_id

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        authenticated, policy, request_digest = self._authenticate_request(request)
        operation = str(authenticated["operation"])
        partition = str(authenticated["partition"])
        if operation not in policy.operations or partition not in policy.partitions:
            return self._signed_nontransition_response(
                authenticated,
                request_digest,
                "client-not-authorized",
                {"reason": "client policy does not authorize operation and partition"},
            )

        with self._lock:
            self._assert_open()
            database = self._connect()
            try:
                database.execute("BEGIN IMMEDIATE")
                metadata = database.execute(
                    "SELECT epoch, checkpoint, checkpoint_digest FROM replay_metadata WHERE singleton = 1"
                ).fetchone()
                if metadata is None:
                    raise ReplayStateError("replay metadata disappeared")
                epoch, checkpoint, checkpoint_digest = metadata
                if authenticated["expected_epoch"] != epoch:
                    database.execute("COMMIT")
                    return self._sign_response(
                        authenticated,
                        request_digest,
                        accepted=False,
                        status="epoch-mismatch",
                        result={"reason": "service epoch does not match the pinned client epoch"},
                        epoch=epoch,
                        checkpoint=checkpoint,
                        checkpoint_digest=checkpoint_digest,
                    )
                minimum = authenticated["minimum_checkpoint"]
                continuity = database.execute(
                    "SELECT checkpoint_digest FROM replay_checkpoints WHERE checkpoint = ?",
                    (minimum,),
                ).fetchone()
                if continuity is None or continuity[0] != authenticated["minimum_checkpoint_digest"]:
                    database.execute("COMMIT")
                    return self._sign_response(
                        authenticated,
                        request_digest,
                        accepted=False,
                        status="checkpoint-mismatch",
                        result={"reason": "service cannot prove the client's checkpoint continuity"},
                        epoch=epoch,
                        checkpoint=checkpoint,
                        checkpoint_digest=checkpoint_digest,
                    )

                accepted, status, result = self._apply_transition(
                    database,
                    operation,
                    partition,
                    authenticated["payload"],
                )
                next_checkpoint = checkpoint + 1
                next_digest = digest(
                    {
                        "schema": "event-horizon.replay-checkpoint.v2",
                        "previous_digest": checkpoint_digest,
                        "epoch": epoch,
                        "checkpoint": next_checkpoint,
                        "request_digest": request_digest,
                        "accepted": accepted,
                        "status": status,
                        "result_digest": digest(result),
                    }
                )
                database.execute(
                    "INSERT INTO replay_checkpoints (checkpoint, epoch, checkpoint_digest) VALUES (?, ?, ?)",
                    (next_checkpoint, epoch, next_digest),
                )
                database.execute(
                    "UPDATE replay_metadata SET checkpoint = ?, checkpoint_digest = ? WHERE singleton = 1",
                    (next_checkpoint, next_digest),
                )
                database.execute("COMMIT")
            except ReplayProtocolError:
                self._rollback(database)
                raise
            except (sqlite3.Error, ReplayStateError) as exc:
                self._rollback(database)
                raise ReplayStateError("replay transition failed closed") from exc
            finally:
                database.close()
        return self._sign_response(
            authenticated,
            request_digest,
            accepted=accepted,
            status=status,
            result=result,
            epoch=epoch,
            checkpoint=next_checkpoint,
            checkpoint_digest=next_digest,
        )

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def _authenticate_request(
        self,
        request: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], ReplayClientPolicy, str]:
        value = _require_exact_fields(request, _REQUEST_FIELDS, "replay request")
        if value["schema"] != REQUEST_SCHEMA or value["algorithm"] != "Ed25519":
            raise ReplayProtocolError("replay request schema or algorithm is invalid")
        if value["service_id"] != self.service_id:
            raise ReplayProtocolError("replay request service ID is invalid")
        client_key_id = value["client_key_id"]
        if not isinstance(client_key_id, str) or _KEY_ID.fullmatch(client_key_id) is None:
            raise ReplayProtocolError("replay client key ID is invalid")
        policy = self.clients.get(client_key_id)
        if policy is None:
            raise ReplayProtocolError("replay client key is not registered")
        request_id = value["request_id"]
        if not _is_nonce(request_id):
            raise ReplayProtocolError("replay request ID is invalid")
        issued_at = _require_integer(value["issued_at"], "request issuance time")
        expires_at = _require_positive_integer(value["expires_at"], "request expiration time")
        now = _now_ms(self.now)
        if expires_at <= issued_at or expires_at - issued_at > MAX_REQUEST_LIFETIME_MS:
            raise ReplayProtocolError("replay request lifetime is invalid")
        if issued_at > now + MAX_CLOCK_SKEW_MS or now >= expires_at:
            raise ReplayProtocolError("replay request is outside its freshness window")
        _require_positive_integer(value["expected_epoch"], "expected epoch")
        _require_integer(value["minimum_checkpoint"], "minimum checkpoint")
        _require_digest(value["minimum_checkpoint_digest"], "minimum checkpoint digest")
        if value["operation"] not in _OPERATIONS:
            raise ReplayProtocolError("replay operation is unsupported")
        _require_scope(value["partition"], "replay partition")
        if not isinstance(value["payload"], Mapping):
            raise ReplayProtocolError("replay payload must be an object")
        signature = value["signature"]
        if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
            raise ReplayProtocolError("replay request signature is malformed")
        unsigned = {key: item for key, item in value.items() if key != "signature"}
        try:
            policy.public_key.verify(_decode_b64url(signature), canonical_bytes(unsigned))
        except (InvalidSignature, ValueError) as exc:
            raise ReplayProtocolError("replay request signature is invalid") from exc
        return value, policy, digest(value)

    def _apply_transition(
        self,
        database: sqlite3.Connection,
        operation: str,
        partition: str,
        payload: Any,
    ) -> tuple[bool, str, dict[str, Any]]:
        if operation == "nonce-create":
            return self._nonce_create(database, partition, payload)
        if operation == "nonce-consume":
            return self._nonce_consume(database, partition, payload)
        if operation == "nonce-inspect":
            return self._nonce_inspect(database, partition, payload)
        if operation == "capability-consume":
            return self._token_consume(database, partition, operation, payload)
        if operation == "authorization-consume":
            return self._token_consume(database, partition, operation, payload)
        raise ReplayProtocolError("replay operation is unsupported")

    @staticmethod
    def _nonce_create(
        database: sqlite3.Connection,
        partition: str,
        payload: Any,
    ) -> tuple[bool, str, dict[str, Any]]:
        fields = {"context", "context_digest", "expires_at", "issued_at", "nonce"}
        value = _require_exact_fields(payload, fields, "nonce-create payload")
        nonce = value["nonce"]
        if not _is_nonce(nonce):
            raise ReplayProtocolError("attestation nonce is malformed")
        context = _require_exact_fields(
            value["context"],
            {"deviceId", "executorId", "purpose", "sessionId"},
            "nonce context",
        )
        if any(not isinstance(item, str) or not item or len(item) > 256 for item in context.values()):
            raise ReplayProtocolError("nonce context value is invalid")
        context_digest = _require_digest(value["context_digest"], "nonce context digest")
        if context_digest != digest(context):
            raise ReplayProtocolError("nonce context digest does not match context")
        issued_at = _require_integer(value["issued_at"], "nonce issuance time")
        expires_at = _require_positive_integer(value["expires_at"], "nonce expiration time")
        if expires_at <= issued_at or expires_at - issued_at > 3_600_000:
            raise ReplayProtocolError("nonce lifetime is invalid")
        cursor = database.execute(
            """
            INSERT INTO replay_nonces (
                partition, nonce, context_json, context_digest, issued_at, expires_at, state
            ) VALUES (?, ?, ?, ?, ?, ?, 'issued')
            ON CONFLICT(partition, nonce) DO NOTHING
            """,
            (
                partition,
                nonce,
                canonical_bytes(context).decode("utf-8"),
                context_digest,
                issued_at,
                expires_at,
            ),
        )
        if cursor.rowcount == 1:
            return True, "created", {}
        row = database.execute(
            """
            SELECT context_json, context_digest, issued_at, expires_at
            FROM replay_nonces WHERE partition = ? AND nonce = ?
            """,
            (partition, nonce),
        ).fetchone()
        expected = (
            canonical_bytes(context).decode("utf-8"),
            context_digest,
            issued_at,
            expires_at,
        )
        if row != expected:
            return False, "collision", {}
        return False, "already-exists", {}

    @staticmethod
    def _nonce_consume(
        database: sqlite3.Connection,
        partition: str,
        payload: Any,
    ) -> tuple[bool, str, dict[str, Any]]:
        value = _require_exact_fields(payload, {"context_digest", "nonce", "now"}, "nonce-consume payload")
        nonce = value["nonce"]
        if not _is_nonce(nonce):
            raise ReplayProtocolError("attestation nonce is malformed")
        context_digest = _require_digest(value["context_digest"], "nonce context digest")
        now = _require_integer(value["now"], "nonce consumption time")
        row = database.execute(
            """
            SELECT context_json, context_digest, issued_at, expires_at, state, consumed_at
            FROM replay_nonces WHERE partition = ? AND nonce = ?
            """,
            (partition, nonce),
        ).fetchone()
        if row is None:
            return False, "unknown", {}
        record = ReferenceReplayService._nonce_record(nonce, row)
        if row[4] == "consumed":
            return False, "consumed", {"record": record}
        if row[4] == "expired" or now >= row[3]:
            database.execute(
                "UPDATE replay_nonces SET state = 'expired' WHERE partition = ? AND nonce = ? AND state = 'issued'",
                (partition, nonce),
            )
            record["state"] = "expired"
            return False, "expired", {"record": record}
        if row[1] != context_digest:
            return False, "wrong-context", {"record": record}
        cursor = database.execute(
            """
            UPDATE replay_nonces SET state = 'consumed', consumed_at = ?
            WHERE partition = ? AND nonce = ? AND state = 'issued' AND context_digest = ? AND expires_at > ?
            """,
            (now, partition, nonce, context_digest, now),
        )
        if cursor.rowcount != 1:
            raise ReplayStateError("nonce compare-and-transition lost serialization")
        record["state"] = "consumed"
        record["consumedAt"] = now
        return True, "consumed-now", {"record": record}

    @staticmethod
    def _nonce_inspect(
        database: sqlite3.Connection,
        partition: str,
        payload: Any,
    ) -> tuple[bool, str, dict[str, Any]]:
        value = _require_exact_fields(payload, {"nonce", "now"}, "nonce-inspect payload")
        nonce = value["nonce"]
        if not _is_nonce(nonce):
            raise ReplayProtocolError("attestation nonce is malformed")
        now = _require_integer(value["now"], "nonce inspection time")
        row = database.execute(
            """
            SELECT context_json, context_digest, issued_at, expires_at, state, consumed_at
            FROM replay_nonces WHERE partition = ? AND nonce = ?
            """,
            (partition, nonce),
        ).fetchone()
        if row is None:
            return False, "unknown", {}
        record = ReferenceReplayService._nonce_record(nonce, row)
        if row[4] == "issued" and now >= row[3]:
            database.execute(
                "UPDATE replay_nonces SET state = 'expired' WHERE partition = ? AND nonce = ? AND state = 'issued'",
                (partition, nonce),
            )
            record["state"] = "expired"
        return True, "found", {"record": record}

    @staticmethod
    def _nonce_record(nonce: str, row: tuple[Any, ...]) -> dict[str, Any]:
        context = strict_json_loads(row[0], require_canonical=True)
        record: dict[str, Any] = {
            "nonce": nonce,
            "context": context,
            "contextDigest": row[1],
            "issuedAt": row[2],
            "expiresAt": row[3],
            "state": row[4],
        }
        if row[5] is not None:
            record["consumedAt"] = row[5]
        return record

    @staticmethod
    def _token_consume(
        database: sqlite3.Connection,
        partition: str,
        operation: str,
        payload: Any,
    ) -> tuple[bool, str, dict[str, Any]]:
        value = _require_exact_fields(
            payload,
            {"binding_digest", "consumed_at", "expires_at", "token"},
            f"{operation} payload",
        )
        token = value["token"]
        if operation == "capability-consume":
            if not isinstance(token, str) or _CAPABILITY_ID.fullmatch(token) is None:
                raise ReplayProtocolError("capability ID is malformed")
        elif not _is_nonce(token):
            raise ReplayProtocolError("authorization nonce is malformed")
        binding_digest = _require_digest(value["binding_digest"], "token binding digest")
        expires_at = _require_positive_integer(value["expires_at"], "token expiration time")
        consumed_at = _require_integer(value["consumed_at"], "token consumption time")
        cursor = database.execute(
            """
            INSERT INTO replay_tokens (
                partition, operation, token, binding_digest, expires_at, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(partition, operation, token) DO NOTHING
            """,
            (partition, operation, token, binding_digest, expires_at, consumed_at),
        )
        if cursor.rowcount == 1:
            return True, "consumed-now", {}
        row = database.execute(
            """
            SELECT binding_digest, expires_at FROM replay_tokens
            WHERE partition = ? AND operation = ? AND token = ?
            """,
            (partition, operation, token),
        ).fetchone()
        if row != (binding_digest, expires_at):
            return False, "collision", {}
        return False, "consumed", {}

    def _signed_nontransition_response(
        self,
        request: Mapping[str, Any],
        request_digest: str,
        status: str,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        epoch, checkpoint, checkpoint_digest = self.checkpoint()
        return self._sign_response(
            request,
            request_digest,
            accepted=False,
            status=status,
            result=result,
            epoch=epoch,
            checkpoint=checkpoint,
            checkpoint_digest=checkpoint_digest,
        )

    def _sign_response(
        self,
        request: Mapping[str, Any],
        request_digest: str,
        *,
        accepted: bool,
        status: str,
        result: Mapping[str, Any],
        epoch: int,
        checkpoint: int,
        checkpoint_digest: str,
    ) -> dict[str, Any]:
        unsigned = {
            "schema": RESPONSE_SCHEMA,
            "algorithm": "Ed25519",
            "service_id": self.service_id,
            "server_key_id": self.server_key_id,
            "epoch": epoch,
            "checkpoint": checkpoint,
            "checkpoint_digest": checkpoint_digest,
            "request_id": request["request_id"],
            "request_digest": request_digest,
            "accepted": accepted,
            "status": status,
            "result": dict(result),
            "responded_at": _now_ms(self.now),
        }
        return {
            **unsigned,
            "signature": _b64url(self.private_key.sign(canonical_bytes(unsigned))),
        }

    def _initialize(self) -> None:
        database = self._connect()
        try:
            database.execute("PRAGMA journal_mode = WAL")
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    service_id TEXT NOT NULL,
                    server_key_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    checkpoint INTEGER NOT NULL,
                    checkpoint_digest TEXT NOT NULL
                )
                """
            )
            genesis = genesis_checkpoint_digest(self.service_id, self._initial_epoch)
            database.execute(
                """
                INSERT OR IGNORE INTO replay_metadata (
                    singleton, schema_version, service_id, server_key_id,
                    epoch, checkpoint, checkpoint_digest
                ) VALUES (1, 1, ?, ?, ?, 0, ?)
                """,
                (self.service_id, self.server_key_id, self._initial_epoch, genesis),
            )
            metadata = database.execute(
                """
                SELECT schema_version, service_id, server_key_id
                FROM replay_metadata WHERE singleton = 1
                """
            ).fetchone()
            if metadata != (1, self.service_id, self.server_key_id):
                raise ReplayStateError("replay database identity or schema is incompatible")
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_checkpoints (
                    checkpoint INTEGER PRIMARY KEY,
                    epoch INTEGER NOT NULL,
                    checkpoint_digest TEXT NOT NULL
                )
                """
            )
            database.execute(
                """
                INSERT OR IGNORE INTO replay_checkpoints (checkpoint, epoch, checkpoint_digest)
                VALUES (0, ?, ?)
                """,
                (self._initial_epoch, genesis),
            )
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    partition TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('issued', 'consumed', 'expired')),
                    consumed_at INTEGER,
                    PRIMARY KEY (partition, nonce)
                ) WITHOUT ROWID
                """
            )
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_tokens (
                    partition TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    token TEXT NOT NULL,
                    binding_digest TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER NOT NULL,
                    PRIMARY KEY (partition, operation, token)
                ) WITHOUT ROWID
                """
            )
        except (sqlite3.Error, ReplayStateError) as exc:
            if isinstance(exc, ReplayStateError):
                raise
            raise ReplayStateError("replay database initialization failed") from exc
        finally:
            database.close()

    def _connect(self) -> sqlite3.Connection:
        database = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1_000,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            database.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            database.execute("PRAGMA synchronous = FULL")
            database.execute("PRAGMA foreign_keys = ON")
            database.execute("PRAGMA trusted_schema = OFF")
        except sqlite3.Error:
            database.close()
            raise
        return database

    @staticmethod
    def _rollback(database: sqlite3.Connection) -> None:
        try:
            database.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _assert_open(self) -> None:
        if self._closed:
            raise ReplayUnavailableError("replay service is closed")


CLIENT_CONTINUITY_SCHEMA = "event-horizon.replay-client-continuity.v2"


class ReplayClientContinuityStore(Protocol):
    """Durable storage for the client's pinned replay-service continuity state.

    Rollback protection must not rely solely on process RAM: persisting the
    latest accepted checkpoint lets a restarted client distinguish true first
    contact from recovery, and detect service rollback against remembered
    history.
    """

    def save(self, state: Mapping[str, Any]) -> None: ...

    def load(self) -> Mapping[str, Any] | None: ...


class FileReplayClientContinuityStore:
    """Single-file JSON store for client replay continuity (one host)."""

    _FIELDS = {
        "schema", "service_id", "server_key_id", "epoch",
        "checkpoint", "checkpoint_digest",
    }

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise ValueError("durable replay client continuity path is invalid")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.path.parent.chmod(0o700)

    def save(self, state: Mapping[str, Any]) -> None:
        value = dict(state)
        if set(value) != self._FIELDS or value["schema"] != CLIENT_CONTINUITY_SCHEMA:
            raise ReplayStateError("client continuity state fields are invalid")
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def load(self) -> Mapping[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReplayStateError("client continuity store is malformed") from exc
        if not isinstance(value, dict) or set(value) != self._FIELDS:
            raise ReplayStateError("client continuity store fields are invalid")
        return value


class AuthenticatedReplayClient:
    """Fail-closed client with a pinned epoch, server key, and checkpoint.

    When a continuity store is injected, every accepted checkpoint advance is
    persisted so restarts recover the exact latest accepted root instead of
    silently falling back to genesis.
    """

    def __init__(
        self,
        signer: ReplayRequestSigner,
        transport: ReplayTransport,
        server_public_key: str | Ed25519PublicKey,
        *,
        epoch: int,
        checkpoint: int = 0,
        checkpoint_digest: str | None = None,
        continuity_store: ReplayClientContinuityStore | None = None,
    ) -> None:
        self.signer = signer
        self.transport = transport
        self.server_public_key = _load_public_key(server_public_key)
        self.server_key_id = replay_key_id(self.server_public_key)
        self.epoch = _require_positive_integer(epoch, "client epoch")
        self.checkpoint, self.checkpoint_digest = _normalize_checkpoint_state(
            signer.service_id,
            epoch,
            checkpoint,
            checkpoint_digest,
            "client",
        )
        self.continuity_store = continuity_store
        self._lock = threading.RLock()
        if continuity_store is not None and checkpoint > 0:
            # Recovered from caller-supplied state; make sure the durable copy
            # agrees before any request is sent.
            persisted = continuity_store.load()
            if persisted is not None and (
                int(persisted.get("checkpoint", -1)) > checkpoint
                or (
                    int(persisted.get("checkpoint", -1)) == checkpoint
                    and persisted.get("checkpoint_digest") != checkpoint_digest
                )
            ):
                raise ReplayStateError(
                    "durable client continuity is ahead of or forked from the supplied state"
                )

    def _persist_continuity_locked(self) -> None:
        if self.continuity_store is None:
            return
        self.continuity_store.save({
            "schema": CLIENT_CONTINUITY_SCHEMA,
            "service_id": self.signer.service_id,
            "server_key_id": self.server_key_id,
            "epoch": self.epoch,
            "checkpoint": self.checkpoint,
            "checkpoint_digest": self.checkpoint_digest,
        })

    def call(
        self,
        operation: str,
        partition: str,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        with self._lock:
            request = self.signer.sign(
                operation=operation,
                partition=partition,
                payload=payload,
                expected_epoch=self.epoch,
                minimum_checkpoint=self.checkpoint,
                minimum_checkpoint_digest=self.checkpoint_digest,
            )
            try:
                response = self.transport(request)
            except ReplayProtocolError:
                raise
            except Exception as exc:
                raise ReplayUnavailableError("replay service request failed closed") from exc
            verified = self._verify_response(request, response)
            if verified["status"] == "checkpoint-mismatch":
                raise ReplayProtocolError("replay service cannot prove checkpoint continuity")
            response_checkpoint = int(verified["checkpoint"])
            if response_checkpoint > self.checkpoint:
                self.checkpoint = response_checkpoint
                self.checkpoint_digest = str(verified["checkpoint_digest"])
                self._persist_continuity_locked()
            return verified

    def adopt_epoch(
        self,
        epoch: int,
        *,
        checkpoint: int,
        checkpoint_digest: str | None = None,
        server_public_key: str | Ed25519PublicKey | None = None,
        transport: ReplayTransport | None = None,
    ) -> None:
        """Accept an operator-authorized promotion after continuity is checked."""

        with self._lock:
            promoted_epoch = _require_positive_integer(epoch, "promoted epoch")
            promoted_checkpoint, promoted_digest = _normalize_checkpoint_state(
                self.signer.service_id,
                promoted_epoch,
                checkpoint,
                checkpoint_digest,
                "promoted",
            )
            promoted_public_key = self.server_public_key
            promoted_server_key_id = self.server_key_id
            if server_public_key is not None:
                promoted_public_key = _load_public_key(server_public_key)
                promoted_server_key_id = replay_key_id(promoted_public_key)
            if transport is not None and not callable(transport):
                raise TypeError("promoted replay transport must be callable")
            if promoted_epoch <= self.epoch:
                raise ReplayProtocolError("promoted epoch must increase")
            if promoted_checkpoint < self.checkpoint:
                raise ReplayProtocolError("promoted service checkpoint regresses")
            if (
                promoted_checkpoint > 0
                and promoted_checkpoint == self.checkpoint
                and promoted_digest != self.checkpoint_digest
            ):
                raise ReplayProtocolError("promoted service checkpoint forks known history")
            self.server_public_key = promoted_public_key
            self.server_key_id = promoted_server_key_id
            if transport is not None:
                self.transport = transport
            self.epoch = promoted_epoch
            self.checkpoint = promoted_checkpoint
            self.checkpoint_digest = promoted_digest
            self._persist_continuity_locked()

    def _verify_response(
        self,
        request: Mapping[str, Any],
        response: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        value = _require_exact_fields(response, _RESPONSE_FIELDS, "replay response")
        if value["schema"] != RESPONSE_SCHEMA or value["algorithm"] != "Ed25519":
            raise ReplayProtocolError("replay response schema or algorithm is invalid")
        if value["service_id"] != self.signer.service_id:
            raise ReplayProtocolError("replay response service ID is invalid")
        if value["server_key_id"] != self.server_key_id:
            raise ReplayProtocolError("replay response server key is not pinned")
        if value["request_id"] != request["request_id"] or value["request_digest"] != digest(request):
            raise ReplayProtocolError("replay response is not bound to the exact request")
        if value["epoch"] != self.epoch:
            raise ReplayProtocolError("replay response came from an unpinned or stale epoch")
        checkpoint = _require_integer(value["checkpoint"], "response checkpoint")
        checkpoint_digest = _require_digest(value["checkpoint_digest"], "response checkpoint digest")
        if checkpoint < self.checkpoint:
            raise ReplayProtocolError("replay service checkpoint regressed")
        if checkpoint == self.checkpoint and checkpoint_digest != self.checkpoint_digest:
            raise ReplayProtocolError("replay service checkpoint forked known history")
        if type(value["accepted"]) is not bool or not isinstance(value["status"], str):
            raise ReplayProtocolError("replay response decision is malformed")
        if not isinstance(value["result"], Mapping):
            raise ReplayProtocolError("replay response result is malformed")
        _require_integer(value["responded_at"], "response time")
        signature = value["signature"]
        if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
            raise ReplayProtocolError("replay response signature is malformed")
        unsigned = {key: item for key, item in value.items() if key != "signature"}
        try:
            self.server_public_key.verify(_decode_b64url(signature), canonical_bytes(unsigned))
        except (InvalidSignature, ValueError) as exc:
            raise ReplayProtocolError("replay response signature is invalid") from exc
        return value


class RemoteCapabilityConsumptionStore:
    def __init__(self, client: AuthenticatedReplayClient, *, partition: str) -> None:
        self.client = client
        self.partition = _require_scope(partition, "capability replay partition")

    def consume(
        self,
        capability_id: str,
        claims_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool:
        response = self.client.call(
            "capability-consume",
            self.partition,
            {
                "token": capability_id,
                "binding_digest": claims_digest,
                "expires_at": expires_at,
                "consumed_at": consumed_at,
            },
        )
        if response["status"] == "collision":
            raise CapabilityConsumptionError("remote capability ID collided with different signed claims")
        if response["status"] not in {"consumed-now", "consumed"}:
            raise CapabilityConsumptionError("remote capability replay service failed closed")
        return response["accepted"] is True


class RemoteAuthorizationReplayStore:
    def __init__(self, client: AuthenticatedReplayClient, *, partition: str) -> None:
        self.client = client
        self.partition = _require_scope(partition, "authorization replay partition")

    def consume(
        self,
        nonce: str,
        request_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool:
        response = self.client.call(
            "authorization-consume",
            self.partition,
            {
                "token": nonce,
                "binding_digest": request_digest,
                "expires_at": expires_at,
                "consumed_at": consumed_at,
            },
        )
        if response["status"] == "collision":
            raise AuthorizationReplayError(
                "remote protected-request nonce collided with different authorization"
            )
        if response["status"] not in {"consumed-now", "consumed"}:
            raise AuthorizationReplayError("remote protected-request replay service failed closed")
        return response["accepted"] is True


class HttpReplayTransport:
    def __init__(self, url: str, *, timeout_seconds: float = 2.0) -> None:
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError("replay service URL is invalid")
        if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 30:
            raise ValueError("replay transport timeout is invalid")
        self.url = url
        self.timeout_seconds = float(timeout_seconds)

    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        body = canonical_bytes(request)
        message = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(message, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise ReplayUnavailableError("replay service returned a non-success status")
                content = response.read(MAX_HTTP_BODY_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ReplayUnavailableError("replay service is unavailable") from exc
        if len(content) > MAX_HTTP_BODY_BYTES:
            raise ReplayProtocolError("replay service response is too large")
        value = strict_json_loads(content, require_canonical=True)
        if not isinstance(value, Mapping):
            raise ReplayProtocolError("replay service response is not an object")
        return value


class ReplayHttpServer:
    """Small HTTP binding for protocol conformance and controlled deployments."""

    def __init__(
        self,
        service: ReferenceReplayService,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        if not isinstance(host, str) or not host:
            raise ValueError("replay HTTP host is invalid")
        if type(port) is not int or not 0 <= port <= 65_535:
            raise ValueError("replay HTTP port is invalid")
        handler = self._handler(service)
        self._server = http.server.ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/v1/transition"

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("replay HTTP server is already started")
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self._server.server_close()

    @staticmethod
    def _handler(service: ReferenceReplayService) -> type[http.server.BaseHTTPRequestHandler]:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/v1/transition":
                    self.send_error(404)
                    return
                content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
                if content_type != "application/json":
                    self.send_error(415)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "-1"))
                except ValueError:
                    self.send_error(400)
                    return
                if not 0 <= length <= MAX_HTTP_BODY_BYTES:
                    self.send_error(413)
                    return
                try:
                    parsed = strict_json_loads(self.rfile.read(length), require_canonical=True)
                    if not isinstance(parsed, Mapping):
                        raise ReplayProtocolError("replay request is not an object")
                    response = service.handle(parsed)
                    encoded = canonical_bytes(response)
                except (ReplayProtocolError, ReplayStateError, ValueError):
                    self.send_error(400)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, _format: str, *args: Any) -> None:
                return

        return Handler
