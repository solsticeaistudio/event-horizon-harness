"""Authenticated local IPC to an independently supervised atomic fenced recipient.

Only trusted host processes receive the private IPC key and socket location.
This transport does not grant effect authority; the gateway verifies and
consumes signed capabilities before dispatch. The service implements only
the synthetic transactional SQLite effect, NEVER arbitrary external calls.
Linux peer credentials + an HMAC per bounded request/response bind the
channel to the configured trust domain. Disconnects remain indeterminate.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
from typing import Any, Callable

from .canonical import canonical_bytes, digest, strict_json_loads
from .fenced_recipient import (
    FencedReceipt, FencedRecipientBindingError, FencedRecipientError,
    FencedSqliteRecipient,
)
from .protocol import encode_frame, read_frame

MAX_RPC_BYTES = 32_768


def _private_parent(path: Path) -> None:
    """Reject mutable ancestors and unsafe socket parents, including symlinks."""
    if not path.is_absolute():
        raise ValueError("trusted recipient socket must use an absolute path")
    owner = os.geteuid()
    current = path.parent
    while True:
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner):
            raise FencedRecipientError("untrusted socket ancestor")
        if current == path.parent and info.st_uid != owner:
            raise FencedRecipientError("socket directory must be owned by operator")
        if info.st_mode & 0o022 and not (
            current != path.parent and info.st_uid == 0
            and info.st_mode & stat.S_ISVTX
        ):
            raise FencedRecipientError("socket under mutable ancestor")
        if current == current.parent:
            break
        current = current.parent


def _key(key: bytes) -> bytes:
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("trusted recipient IPC requires a 256-bit private key")
    return key


def _mac(key: bytes, nonce: str, body: dict) -> str:
    return hmac.new(
        key, canonical_bytes({"nonce": nonce, "body": body}), hashlib.sha256,
    ).hexdigest()


def _pack(key: bytes, nonce: str, body: dict) -> dict:
    return {"nonce": nonce, "body": body, "mac": _mac(key, nonce, body)}


def _unpack(key: bytes, frame: Any, *, nonce: str | None = None) -> tuple[str, dict]:
    if (type(frame) is not dict or set(frame) != {"nonce", "body", "mac"}
            or type(frame["nonce"]) is not str or len(frame["nonce"]) != 32
            or not all(c in "0123456789abcdef" for c in frame["nonce"])
            or type(frame["body"]) is not dict
            or type(frame["mac"]) is not str or len(frame["mac"]) != 64
            or not hmac.compare_digest(
                frame["mac"], _mac(key, frame["nonce"], frame["body"])
            )
            or (nonce is not None and frame["nonce"] != nonce)):
        raise FencedRecipientError("unauthenticated recipient IPC frame")
    return frame["nonce"], frame["body"]


def _peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise FencedRecipientError("Unix peer credentials unavailable; fail closed")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _, uid, _ = struct.unpack("3i", raw)
    return uid


def _receipt(body: Any, recipient_id: str) -> FencedReceipt:
    if (type(body) is not dict or set(body) != {
        "effect_key", "request_digest", "recipient_id", "output",
        "output_digest", "receipt_digest", "sequence", "newly_committed",
    } or type(body["sequence"]) is not int or body["sequence"] < 1
            or type(body["newly_committed"]) is not bool
            or body["recipient_id"] != recipient_id
            or any(type(body[field]) is not str or len(body[field]) != 64
                   or any(c not in "0123456789abcdef" for c in body[field])
                   for field in (
                       "effect_key", "request_digest", "output_digest", "receipt_digest"
                   ))):
        raise FencedRecipientError("malformed or rebinding recipient receipt")
    try:
        raw = canonical_bytes(body["output"])
        strict_json_loads(raw, require_canonical=True)
        if len(raw) > 16_384 or digest(body["output"]) != body["output_digest"]:
            raise ValueError("recipient output digest mismatch")
        expected = digest({
            "schema": "event-horizon.fenced-recipient-receipt.v1",
            "recipient_id": recipient_id, "effect_key": body["effect_key"],
            "request_digest": body["request_digest"],
            "output_digest": body["output_digest"], "sequence": body["sequence"],
        })
        if not hmac.compare_digest(expected, body["receipt_digest"]):
            raise ValueError("recipient receipt digest mismatch")
    except (ValueError, TypeError) as exc:
        raise FencedRecipientError("invalid durable recipient receipt") from exc
    return FencedReceipt(**body)


def _serialize(receipt: FencedReceipt) -> dict:
    return {
        "effect_key": receipt.effect_key,
        "request_digest": receipt.request_digest,
        "recipient_id": receipt.recipient_id,
        "output": receipt.output,
        "output_digest": receipt.output_digest,
        "receipt_digest": receipt.receipt_digest,
        "sequence": receipt.sequence,
        "newly_committed": receipt.newly_committed,
    }


class FencedRecipientClient:
    """Trusted host-owned remote adapter; no database handle in gateway.

    An RPC timeout/EOF never proves an effect did not commit. The gateway must
    keep the original reservation and recover with NEW signed authority.
    """

    def __init__(
        self, socket_path: str | Path, *, recipient_id: str,
        auth_key: bytes, server_uid: int | None = None, timeout: float = 3.0,
    ):
        self.socket_path = Path(socket_path)
        _private_parent(self.socket_path)
        if (type(recipient_id) is not str or not recipient_id
                or len(recipient_id) > 128 or not all(
                    c.isascii() and (c.isalnum() or c in "-_.:")
                    for c in recipient_id
                )):
            raise ValueError("recipient identity must be pinned")
        self.recipient_id = recipient_id
        self._auth_key = _key(auth_key)
        self._server_uid = os.geteuid() if server_uid is None else server_uid
        if type(self._server_uid) is not int or self._server_uid < 0:
            raise ValueError("invalid pinned server UID")
        if not 0 < timeout <= 30:
            raise ValueError("invalid bounded recipient timeout")
        self._timeout = timeout

    def _exchange(self, body: dict) -> dict:
        nonce = secrets.token_hex(16)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(self._timeout)
                channel.connect(str(self.socket_path))
                if _peer_uid(channel) != self._server_uid:
                    raise FencedRecipientError("recipient server UID changed")
                channel.sendall(encode_frame(
                    _pack(self._auth_key, nonce, body), max_bytes=MAX_RPC_BYTES,
                ))
                with channel.makefile("rb") as stream:
                    frame = read_frame(stream, max_bytes=MAX_RPC_BYTES)
            _, reply = _unpack(self._auth_key, frame, nonce=nonce)
            if set(reply) == {"error"} and reply["error"] in (
                "binding-denied", "recipient-unavailable", "invalid-request",
            ):
                raise FencedRecipientError("recipient refused authenticated request")
            if set(reply) != {"receipt"}:
                raise FencedRecipientError("malformed recipient reply")
            return reply
        except (OSError, EOFError, ValueError, TypeError) as exc:
            raise FencedRecipientError("recipient transport outcome indeterminate") from exc

    def apply(self, *, effect_key: str, request_digest: str, output: object) -> FencedReceipt:
        raw = canonical_bytes(output)
        strict_json_loads(raw, require_canonical=True)
        if len(raw) > 16_384:
            raise FencedRecipientError("recipient output exceeds durable ceiling")
        reply = self._exchange({
            "operation": "apply", "recipient_id": self.recipient_id,
            "effect_key": effect_key, "request_digest": request_digest,
            "output": output,
        })
        if reply["receipt"] is None:
            raise FencedRecipientError("apply returned no positive receipt")
        receipt = _receipt(reply["receipt"], self.recipient_id)
        if (receipt.effect_key != effect_key or receipt.request_digest != request_digest
                or receipt.output_digest != digest(output)):
            raise FencedRecipientBindingError("authenticated recipient applied wrong binding")
        return receipt

    def observe(self, *, effect_key: str, request_digest: str) -> FencedReceipt | None:
        reply = self._exchange({
            "operation": "observe", "recipient_id": self.recipient_id,
            "effect_key": effect_key, "request_digest": request_digest,
        })
        if reply["receipt"] is None:
            return None
        receipt = _receipt(reply["receipt"], self.recipient_id)
        if receipt.effect_key != effect_key or receipt.request_digest != request_digest:
            raise FencedRecipientBindingError("recipient observation rebind")
        return receipt


def serve_fenced_recipient(
    socket_path: str | Path, database: str | Path, *, recipient_id: str,
    auth_key: bytes, ready: Callable[[], None] | None = None,
    checkpoint: Callable[[str], None] | None = None,
) -> None:
    """Serve a single pinned recipient in its own OS process.

    Supervisor chooses all paths and private key. Fault callbacks are trusted
    local lab hooks only; they are not exposed through the wire protocol.
    """
    path = Path(socket_path)
    _private_parent(path)
    key = _key(auth_key)
    recipient = FencedSqliteRecipient(database, recipient_id=recipient_id)
    if os.path.lexists(path):
        raise FencedRecipientError("recipient socket already exists; supervisor must reconcile")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chmod(path, 0o600)
        inode = os.lstat(path).st_ino
        listener.listen(32)
        listener.settimeout(1)
        if ready is not None:
            ready()
        try:
            while True:
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    try:
                        connection.settimeout(5)
                        if _peer_uid(connection) != os.geteuid():
                            continue
                        with connection.makefile("rb") as stream:
                            frame = read_frame(stream, max_bytes=MAX_RPC_BYTES)
                        nonce, body = _unpack(key, frame)
                        if (set(body) not in (
                            {"operation", "recipient_id", "effect_key", "request_digest"},
                            {"operation", "recipient_id", "effect_key", "request_digest", "output"},
                        ) or body["recipient_id"] != recipient_id):
                            answer = {"error": "invalid-request"}
                        else:
                            op = body["operation"]
                            if op == "apply" and "output" in body:
                                if checkpoint is not None and checkpoint("before_commit") is True:
                                    # Host-only transport fault: no business commit,
                                    # but gateway must treat EOF as indeterminate.
                                    continue
                                value = recipient.apply(
                                    effect_key=body["effect_key"],
                                    request_digest=body["request_digest"],
                                    output=body["output"],
                                )
                                if checkpoint is not None and checkpoint("after_commit_before_reply") is True:
                                    # The durable transaction completed. Intentionally
                                    # suppress only the ACK; no replay clearance follows.
                                    continue
                                answer = {"receipt": _serialize(value)}
                            elif op == "observe" and "output" not in body:
                                value = recipient.observe(
                                    effect_key=body["effect_key"],
                                    request_digest=body["request_digest"],
                                )
                                answer = {"receipt": None if value is None else _serialize(value)}
                            else:
                                answer = {"error": "invalid-request"}
                        connection.sendall(encode_frame(
                            _pack(key, nonce, answer), max_bytes=MAX_RPC_BYTES,
                        ))
                    except (FencedRecipientError, ValueError, TypeError, KeyError):
                        # A rejected binding must never become a successful ACK.
                        try:
                            if "nonce" in locals():
                                connection.sendall(encode_frame(
                                    _pack(key, nonce, {"error": "binding-denied"}),
                                    max_bytes=MAX_RPC_BYTES,
                                ))
                        except OSError:
                            pass
                    except (OSError, EOFError):
                        # Includes network loss after a durable commit.
                        pass
                    finally:
                        # Never reuse a prior authenticated nonce on another connection.
                        if "nonce" in locals():
                            del nonce
        finally:
            try:
                if os.lstat(path).st_ino == inode:
                    os.unlink(path)
            except FileNotFoundError:
                pass
