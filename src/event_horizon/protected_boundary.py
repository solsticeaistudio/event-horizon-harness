from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest
from .protocol import ProtocolError


AUTHORIZATION_SCHEMA = "event-horizon.protected-request.v2"
MAX_AUTHORIZATION_LIFETIME_MS = 30_000
MAX_AUTHORIZATION_CLOCK_SKEW_MS = 2_000

_NONCE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{32}$")
_SCOPE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")


class AuthorizationReplayError(RuntimeError):
    pass


class AuthorizationReplayStore(Protocol):
    def consume(
        self,
        nonce: str,
        request_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool: ...


def _is_canonical_nonce(value: str) -> bool:
    if not isinstance(value, str) or _NONCE.fullmatch(value) is None:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        return False
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    return len(decoded) == 32 and canonical == value


def protected_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


def provision_private_seed(path: str | os.PathLike[str], seed: bytes) -> Path:
    """Create a non-overwritable local development key fixture.

    POSIX permissions are enforced. Windows ACL administration is outside this
    portable helper's claim and must be supplied by the deployment boundary.
    """

    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("protected signing seed must be exactly 32 bytes")
    target = Path(path).absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise FileExistsError("protected signing seed path must not be a symlink")
    if os.name != "nt":
        target.parent.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    try:
        handle = os.fdopen(descriptor, "wb", closefd=True)
        descriptor = -1
        with handle:
            handle.write(seed)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            target.chmod(0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return target


def load_private_seed(path: str | os.PathLike[str]) -> bytes:
    target = Path(path)
    try:
        path_metadata = target.lstat()
    except OSError as exc:
        raise RuntimeError("protected signing seed is unavailable") from exc
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        raise RuntimeError("protected signing seed must be a regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(target, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("protected signing seed must be a regular file")
        if (path_metadata.st_dev, path_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RuntimeError("protected signing seed changed during load")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError("protected signing seed permissions are too broad")
        handle = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = -1
        with handle:
            value = handle.read(33)
    except OSError as exc:
        raise RuntimeError("protected signing seed could not be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value) != 32:
        raise RuntimeError("protected signing seed must be exactly 32 bytes")
    return value


def _now_ms(now: Callable[[], float] | None = None) -> int:
    value = time.time() if now is None else now()
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError("protected-boundary clock is invalid")
    return int(value * 1000)


def _validate_replay_values(
    nonce: str,
    request_digest: str,
    expires_at: int,
    consumed_at: int,
) -> None:
    if not _is_canonical_nonce(nonce):
        raise AuthorizationReplayError("protected request nonce is malformed")
    if not isinstance(request_digest, str) or _DIGEST.fullmatch(request_digest) is None:
        raise AuthorizationReplayError("protected request digest is malformed")
    if type(expires_at) is not int or type(consumed_at) is not int:
        raise AuthorizationReplayError("protected request times must be integers")
    if expires_at <= 0 or consumed_at < 0:
        raise AuthorizationReplayError("protected request times are invalid")


class InMemoryAuthorizationReplayStore:
    """Thread-safe development store; state is lost with this object."""

    def __init__(self) -> None:
        self._records: dict[str, tuple[str, int]] = {}
        self._lock = threading.RLock()

    def consume(
        self,
        nonce: str,
        request_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool:
        _validate_replay_values(nonce, request_digest, expires_at, consumed_at)
        with self._lock:
            previous = self._records.get(nonce)
            if previous is not None:
                if previous != (request_digest, expires_at):
                    raise AuthorizationReplayError(
                        "protected request nonce collided with different authorization"
                    )
                return False
            self._records[nonce] = (request_digest, expires_at)
            return True


class SqliteAuthorizationReplayStore:
    """Durable one-host authorization replay state for one protected audience."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        namespace: str,
        audience: str,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        path = Path(database_path)
        if not str(path) or str(path) == ":memory:":
            raise ValueError("protected request replay database path is invalid")
        if _SCOPE.fullmatch(namespace) is None or _SCOPE.fullmatch(audience) is None:
            raise ValueError("protected request namespace or audience is invalid")
        if type(busy_timeout_ms) is not int or not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("protected request database busy timeout is invalid")
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.namespace = namespace
        self.audience = audience
        self.busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        self._closed = False
        try:
            database = self._connect()
            try:
                database.execute("PRAGMA journal_mode = WAL")
                database.execute(
                    """
                    CREATE TABLE IF NOT EXISTS event_horizon_replay_schema (
                        component TEXT PRIMARY KEY,
                        version INTEGER NOT NULL
                    ) WITHOUT ROWID
                    """
                )
                database.execute(
                    """
                    INSERT OR IGNORE INTO event_horizon_replay_schema (component, version)
                    VALUES ('protected-request', 1)
                    """
                )
                schema = database.execute(
                    """
                    SELECT version FROM event_horizon_replay_schema
                    WHERE component = 'protected-request'
                    """
                ).fetchone()
                if schema != (1,):
                    raise AuthorizationReplayError(
                        "protected request replay schema version is unsupported"
                    )
                database.execute(
                    """
                    CREATE TABLE IF NOT EXISTS protected_request_authorizations (
                        namespace TEXT NOT NULL,
                        audience TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        request_digest TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER NOT NULL,
                        PRIMARY KEY (namespace, audience, nonce)
                    ) WITHOUT ROWID
                    """
                )
            finally:
                database.close()
        except sqlite3.Error as exc:
            raise AuthorizationReplayError(
                "protected request replay database initialization failed"
            ) from exc
        if os.name != "nt":
            self.path.chmod(0o600)

    def consume(
        self,
        nonce: str,
        request_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool:
        _validate_replay_values(nonce, request_digest, expires_at, consumed_at)
        with self._lock:
            self._assert_open()
            database: sqlite3.Connection | None = None
            try:
                database = self._connect()
                database.execute("BEGIN IMMEDIATE")
                cursor = database.execute(
                    """
                    INSERT INTO protected_request_authorizations (
                        namespace, audience, nonce, request_digest, expires_at, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(namespace, audience, nonce) DO NOTHING
                    """,
                    (
                        self.namespace,
                        self.audience,
                        nonce,
                        request_digest,
                        expires_at,
                        consumed_at,
                    ),
                )
                if cursor.rowcount == 1:
                    database.execute("COMMIT")
                    return True
                row = database.execute(
                    """
                    SELECT request_digest, expires_at
                    FROM protected_request_authorizations
                    WHERE namespace = ? AND audience = ? AND nonce = ?
                    """,
                    (self.namespace, self.audience, nonce),
                ).fetchone()
                database.execute("COMMIT")
            except sqlite3.Error as exc:
                if database is not None:
                    self._rollback(database)
                raise AuthorizationReplayError(
                    "protected request replay transaction failed closed"
                ) from exc
            finally:
                if database is not None:
                    database.close()
            if row is None or len(row) != 2:
                raise AuthorizationReplayError("protected request replay record disappeared")
            if row != (request_digest, expires_at):
                raise AuthorizationReplayError(
                    "protected request nonce collided with different authorization"
                )
            return False

    def close(self) -> None:
        with self._lock:
            self._closed = True

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
            raise AuthorizationReplayError("protected request replay database is closed")


class ProtectedRequestSigner:
    def __init__(
        self,
        signing_key: bytes | Ed25519PrivateKey,
        audience: str,
        *,
        lifetime_ms: int = 5_000,
        now: Callable[[], float] | None = None,
    ) -> None:
        if isinstance(signing_key, Ed25519PrivateKey):
            private_key = signing_key
        elif isinstance(signing_key, bytes) and len(signing_key) == 32:
            private_key = Ed25519PrivateKey.from_private_bytes(signing_key)
        else:
            raise ValueError("protected client signing key must be Ed25519")
        if _SCOPE.fullmatch(audience) is None:
            raise ValueError("protected request audience is invalid")
        if type(lifetime_ms) is not int or not 1 <= lifetime_ms <= MAX_AUTHORIZATION_LIFETIME_MS:
            raise ValueError("protected authorization lifetime is invalid")
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self.key_id = protected_key_id(self._public_key)
        self.audience = audience
        self.lifetime_ms = lifetime_ms
        self._now = now

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def authorize(
        self,
        request: Mapping[str, Any],
        *,
        purpose: str = "",
    ) -> dict[str, Any]:
        if set(request) != {"type", "request_id", "deadline_ms", "body"}:
            raise ValueError("protected request envelope fields are invalid")
        issued_at = _now_ms(self._now)
        deadline = request["deadline_ms"]
        if type(deadline) is not int or deadline <= issued_at:
            raise ValueError("protected request deadline has expired")
        expires_at = min(issued_at + self.lifetime_ms, deadline)
        signed = {
            "schema": AUTHORIZATION_SCHEMA,
            "algorithm": "Ed25519",
            "audience": self.audience,
            "key_id": self.key_id,
            "purpose": purpose,
            "nonce": base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii"),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "request_digest": digest(request),
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(signed))
        ).rstrip(b"=").decode("ascii")
        return {**signed, "signature": signature}


class ProtectedRequestVerifier:
    def __init__(
        self,
        public_key: str | bytes | Ed25519PublicKey,
        key_id: str,
        audience: str,
        replay_store: AuthorizationReplayStore,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        if isinstance(public_key, Ed25519PublicKey):
            loaded = public_key
        else:
            encoded = public_key.encode("ascii") if isinstance(public_key, str) else public_key
            loaded = serialization.load_pem_public_key(encoded)
        if not isinstance(loaded, Ed25519PublicKey):
            raise TypeError("protected client verification key must be Ed25519")
        actual_key_id = protected_key_id(loaded)
        if key_id != actual_key_id or _KEY_ID.fullmatch(key_id) is None:
            raise ValueError("protected client key identity does not match")
        if _SCOPE.fullmatch(audience) is None:
            raise ValueError("protected request audience is invalid")
        self._public_key = loaded
        self.key_id = key_id
        self.audience = audience
        self.replay_store = replay_store
        self._now = now

    def authorize(
        self,
        request: Mapping[str, Any],
        authorization: Mapping[str, Any],
        *,
        expected_purpose: str | None = None,
    ) -> None:
        fields = {
            "schema", "algorithm", "audience", "key_id", "nonce", "purpose",
            "issued_at", "expires_at", "request_digest", "signature",
        }
        if not isinstance(authorization, Mapping) or set(authorization) != fields:
            raise ProtocolError("authorization_invalid", "authorization fields are invalid")
        signed = {key: authorization[key] for key in fields if key != "signature"}
        if (
            signed["schema"] != AUTHORIZATION_SCHEMA
            or signed["algorithm"] != "Ed25519"
            or signed["audience"] != self.audience
            or signed["key_id"] != self.key_id
            or not _is_canonical_nonce(signed["nonce"])
            or not isinstance(signed["purpose"], str)
            or len(signed["purpose"]) > 128
            or not isinstance(signed["request_digest"], str)
            or _DIGEST.fullmatch(signed["request_digest"]) is None
            or not isinstance(authorization["signature"], str)
            or _SIGNATURE.fullmatch(authorization["signature"]) is None
        ):
            raise ProtocolError("authorization_denied", "authorization identity is invalid")
        # Purpose binding: a signature valid for one RPC purpose must never be
        # accepted for another, even when the key and envelope are otherwise
        # legitimate (cross-service role substitution fails closed).
        if expected_purpose is not None and signed["purpose"] != expected_purpose:
            raise ProtocolError(
                "authorization_purpose",
                f"authorization purpose {signed['purpose']!r} does not match "
                f"required purpose {expected_purpose!r}",
            )
        issued_at = signed["issued_at"]
        expires_at = signed["expires_at"]
        if type(issued_at) is not int or type(expires_at) is not int:
            raise ProtocolError("authorization_invalid", "authorization times are invalid")
        current = _now_ms(self._now)
        if issued_at > current + MAX_AUTHORIZATION_CLOCK_SKEW_MS:
            raise ProtocolError("authorization_denied", "authorization was issued in the future")
        if expires_at <= current:
            raise ProtocolError("authorization_expired", "authorization has expired")
        if expires_at <= issued_at or expires_at - issued_at > MAX_AUTHORIZATION_LIFETIME_MS:
            raise ProtocolError("authorization_invalid", "authorization lifetime is invalid")
        if expires_at > request["deadline_ms"]:
            raise ProtocolError("authorization_invalid", "authorization exceeds request deadline")
        actual_digest = digest(request)
        if signed["request_digest"] != actual_digest:
            raise ProtocolError("authorization_denied", "authorization request digest mismatch")
        try:
            signature = base64.urlsafe_b64decode(authorization["signature"] + "==")
            if (
                len(signature) != 64
                or base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
                != authorization["signature"]
            ):
                raise ValueError("noncanonical protected request signature")
            self._public_key.verify(signature, canonical_bytes(signed))
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise ProtocolError("authorization_denied", "authorization signature is invalid") from exc
        try:
            accepted = self.replay_store.consume(
                signed["nonce"],
                actual_digest,
                expires_at,
                current,
            )
        except Exception as exc:
            raise ProtocolError(
                "authorization_unavailable",
                "authorization replay state failed closed",
            ) from exc
        if not accepted:
            raise ProtocolError("authorization_replay", "authorization was already consumed")
