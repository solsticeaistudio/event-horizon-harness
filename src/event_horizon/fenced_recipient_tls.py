"""Explicit opt-in mTLS transport for a cooperating remotely hosted recipient.

This is a *transport*, not a source of execution authority. The trusted
gateway still validates a separately signed capability and preserves its
durable original reservation. No negative observation (EOF, timeout,
partition, TLS failure) authorizes releasing or rebinding an effect key.

Server and client require verified mTLS *and* exact leaf-certificate SHA256
pins to prevent an unrelated CA-authorized principal joining the effect
domain. Existing Unix SO_PEERCRED/HMAC protocol remains unchanged.
A remote transport is not by itself multi-host evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import socket
import ssl
import threading
from pathlib import Path
from typing import Callable

from .canonical import canonical_bytes, digest, strict_json_loads
from .fenced_recipient import (
    FencedRecipientBindingError, FencedRecipientError, FencedSqliteRecipient,
)
from .fenced_recipient_transport import (
    MAX_RPC_BYTES, _key, _pack, _receipt, _serialize, _unpack,
)
from .protocol import encode_frame, read_frame


def _cert_pin(pin: str) -> str:
    if (type(pin) is not str or len(pin) != 64
            or any(c not in "0123456789abcdef" for c in pin)):
        raise ValueError("remote peer leaf certificate requires lowercase SHA-256 pin")
    return pin


def _identity(recipient_id: str) -> str:
    if (type(recipient_id) is not str or not 1 <= len(recipient_id) <= 128
            or not all(c.isascii() and (c.isalnum() or c in "-_.:")
                        for c in recipient_id)):
        raise ValueError("invalid pinned recipient identity")
    return recipient_id


def _ssl_context(*, server: bool, ca_file: str | Path,
                 cert_file: str | Path, key_file: str | Path) -> ssl.SSLContext:
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    if not server:
        context.check_hostname = True
    context.load_verify_locations(cafile=str(ca_file))
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return context


def _require_pin(connection: ssl.SSLSocket, sha256: str) -> None:
    leaf = connection.getpeercert(binary_form=True)
    if not leaf or not hmac.compare_digest(
        hashlib.sha256(leaf).hexdigest(), sha256,
    ):
        raise FencedRecipientError("remote TLS leaf identity does not match pin")


class FencedTlsRecipientClient:
    """Gateway-side verified mTLS recipient, same HMAC request/receipt binding."""

    def __init__(self, *, host: str, port: int, server_name: str,
                 ca_file: str | Path, client_cert_file: str | Path,
                 client_key_file: str | Path, server_cert_sha256: str,
                 recipient_id: str, auth_key: bytes, timeout: float = 3.0):
        if (type(host) is not str or not host or any(x in host for x in "/@ \\")
                or type(server_name) is not str or not server_name
                or any(x in server_name for x in "/@ \\")
                or type(port) is not int or not 1 <= port <= 65535
                or not 0 < timeout <= 30):
            raise ValueError("remote gateway recipient address/timeout invalid")
        self.host = host
        self.port = port
        self.server_name = server_name
        self.recipient_id = _identity(recipient_id)
        self._auth_key = _key(auth_key)
        self._timeout = timeout
        self._server_pin = _cert_pin(server_cert_sha256)
        self._context = _ssl_context(
            server=False, ca_file=ca_file,
            cert_file=client_cert_file, key_file=client_key_file,
        )

    def _exchange(self, body: dict) -> dict:
        import secrets
        nonce = secrets.token_hex(16)
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self._timeout,
            ) as raw:
                raw.settimeout(self._timeout)
                with self._context.wrap_socket(
                    raw, server_hostname=self.server_name,
                ) as connection:
                    _require_pin(connection, self._server_pin)
                    connection.sendall(encode_frame(
                        _pack(self._auth_key, nonce, body), max_bytes=MAX_RPC_BYTES,
                    ))
                    with connection.makefile("rb") as stream:
                        answer = read_frame(stream, max_bytes=MAX_RPC_BYTES)
            _, reply = _unpack(self._auth_key, answer, nonce=nonce)
        except (OSError, ssl.SSLError, EOFError, TimeoutError,
                ValueError, TypeError) as exc:
            raise FencedRecipientError(
                "remote recipient outcome indeterminate; original fence remains"
            ) from exc
        if set(reply) == {"error"} and reply["error"] in (
            "binding-denied", "recipient-unavailable", "invalid-request",
        ):
            raise FencedRecipientError("remote recipient refused authenticated request")
        if set(reply) != {"receipt"}:
            raise FencedRecipientError("unverifiable remote recipient reply")
        return reply

    def apply(self, *, effect_key: str, request_digest: str, output: object):
        raw = canonical_bytes(output)
        strict_json_loads(raw, require_canonical=True)
        if len(raw) > 16_384:
            raise FencedRecipientError("remote recipient output exceeds ceiling")
        reply = self._exchange({
            "operation": "apply", "recipient_id": self.recipient_id,
            "effect_key": effect_key, "request_digest": request_digest,
            "output": output,
        })
        if reply["receipt"] is None:
            raise FencedRecipientError("missing positive recipient receipt")
        receipt = _receipt(reply["receipt"], self.recipient_id)
        if (receipt.effect_key != effect_key or receipt.request_digest != request_digest
                or receipt.output_digest != digest(output)):
            raise FencedRecipientBindingError("remote receipt changed effect binding")
        return receipt

    def observe(self, *, effect_key: str, request_digest: str):
        reply = self._exchange({
            "operation": "observe", "recipient_id": self.recipient_id,
            "effect_key": effect_key, "request_digest": request_digest,
        })
        if reply["receipt"] is None:
            return None
        receipt = _receipt(reply["receipt"], self.recipient_id)
        if receipt.effect_key != effect_key or receipt.request_digest != request_digest:
            raise FencedRecipientBindingError("remote observation rebound")
        return receipt


def serve_fenced_tls_recipient(
    *, host: str, port: int, database: str | Path, recipient_id: str,
    auth_key: bytes, ca_file: str | Path, server_cert_file: str | Path,
    server_key_file: str | Path, client_cert_sha256: str,
    ready: Callable[[int], None] | None = None,
    stop: threading.Event | None = None,
    checkpoint: Callable[[str], bool] | None = None,
) -> None:
    """Serve the same atomic SQLite effect on a separate authenticated host.

    Only bind to an explicitly trusted interface (caller owns firewall). No
    auto-retry or clearing after lost ACK. TLS+HMAC are distinct controls.
    A lab may drop the outgoing reply ONLY after the durable recipient commit.
    """
    if (type(host) is not str or not host or any(x in host for x in "/@ \\")
            or type(port) is not int or not 0 <= port <= 65535):
        raise ValueError("invalid explicitly selected recipient listen address")
    rid, key = _identity(recipient_id), _key(auth_key)
    client_pin = _cert_pin(client_cert_sha256)
    context = _ssl_context(
        server=True, ca_file=ca_file,
        cert_file=server_cert_file, key_file=server_key_file,
    )
    recipient = FencedSqliteRecipient(database, recipient_id=rid)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(16)
        listener.settimeout(0.3)
        if ready is not None:
            ready(listener.getsockname()[1])
        while stop is None or not stop.is_set():
            try:
                channel, _ = listener.accept()
            except socket.timeout:
                continue
            with channel:
                channel.settimeout(3)
                try:
                    with context.wrap_socket(channel, server_side=True) as tls:
                        _require_pin(tls, client_pin)
                        with tls.makefile("rb") as stream:
                            frame = read_frame(stream, max_bytes=MAX_RPC_BYTES)
                        nonce, body = _unpack(key, frame)
                        if (set(body) not in (
                            {"operation", "recipient_id", "effect_key", "request_digest"},
                            {"operation", "recipient_id", "effect_key", "request_digest", "output"},
                        ) or body["recipient_id"] != rid):
                            answer = {"error": "invalid-request"}
                        else:
                            try:
                                if body["operation"] == "apply" and "output" in body:
                                    if checkpoint is not None and checkpoint("before_commit"):
                                        continue
                                    value = recipient.apply(
                                        effect_key=body["effect_key"],
                                        request_digest=body["request_digest"],
                                        output=body["output"],
                                    )
                                    if (checkpoint is not None
                                            and checkpoint("after_commit_before_reply")):
                                        continue
                                    answer = {"receipt": _serialize(value)}
                                elif body["operation"] == "observe" and "output" not in body:
                                    value = recipient.observe(
                                        effect_key=body["effect_key"],
                                        request_digest=body["request_digest"],
                                    )
                                    answer = {"receipt": None if value is None
                                              else _serialize(value)}
                                else:
                                    answer = {"error": "invalid-request"}
                            except (FencedRecipientError, ValueError, TypeError):
                                answer = {"error": "binding-denied"}
                        tls.sendall(encode_frame(
                            _pack(key, nonce, answer), max_bytes=MAX_RPC_BYTES,
                        ))
                except (ssl.SSLError, OSError, EOFError, FencedRecipientError,
                        ValueError, TypeError, KeyError):
                    # A failed transport is NOT a negative commit observation.
                    continue
