"""Interchangeable fail-closed capability replay backends.

Option A uses EHH's existing durable, locally atomic SQLite implementation.
Option B uses etcd v3's consensus-backed compare-and-put transaction. Its
authoritative records have no lease, TTL, or automatic expiry, preventing
expired capabilities from being forgotten and replayed after cleanup.

The etcd JSON gateway is only a binding: deploy a correctly configured
3/5-member etcd cluster, secure the gateway, and test partition behavior.
"""
from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .canonical import canonical_bytes, strict_json_loads
from .replay_state import (
    CapabilityConsumptionError,
    CapabilityConsumptionStore,
    SqliteCapabilityConsumptionStore,
    _validate_transition,
)

_MAX_BODY_BYTES = 65_536
_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_CLUSTER = re.compile(r"^[0-9]+$")
_INT = re.compile(r"^[0-9]+$")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise CapabilityConsumptionError("etcd response contains a non-text value")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise CapabilityConsumptionError("etcd response value is not valid base64") from exc
    if _b64(raw) != value:
        raise CapabilityConsumptionError("etcd response value is not canonical")
    return raw


def _number(value: object, what: str, *, allow_zero: bool = False) -> int:
    if not isinstance(value, str) or not _INT.fullmatch(value):
        raise CapabilityConsumptionError(f"etcd {what} is malformed")
    number = int(value)
    if number == 0 and not allow_zero:
        raise CapabilityConsumptionError(f"etcd {what} is invalid")
    return number


class EtcdTransactionTransport(Protocol):
    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class EtcdGatewayConfig:
    """TLS-protected etcd JSON gateway, not an untrusted public API."""
    endpoint: str
    ca_file: str | None = None
    client_cert_file: str | None = None
    client_key_file: str | None = None
    timeout_seconds: float = 2.0
    auth_token: str | None = None
    # Never enable for production: local development only.
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        url = urllib.parse.urlsplit(self.endpoint)
        if url.scheme not in {"http", "https"} or not url.hostname:
            raise ValueError("etcd gateway endpoint must be an http(s) URL")
        if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("etcd endpoint must contain only scheme and authority")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 30:
            raise ValueError("etcd timeout must be in (0, 30] seconds")
        if url.scheme == "http":
            if not self.allow_insecure_loopback or url.hostname not in {"127.0.0.1", "::1", "localhost"}:
                raise ValueError("plaintext etcd gateway permitted only for explicit loopback tests")
        else:
            if not (self.ca_file and self.client_cert_file and self.client_key_file):
                raise ValueError("remote etcd gateway requires CA and client certificate/key")
        if self.auth_token is not None and (not self.auth_token or any(x in self.auth_token for x in "\r\n")):
            raise ValueError("invalid etcd authentication token")


class _RejectEtcdRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward credentials or authority writes across HTTP redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class EtcdV3TransactionTransport:
    def __init__(self, config: EtcdGatewayConfig):
        self.config = config
        self._context: ssl.SSLContext | None = None
        if config.endpoint.startswith("https://"):
            ctx = ssl.create_default_context(cafile=config.ca_file)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(config.client_cert_file, config.client_key_file)
            self._context = ctx
        handlers = [_RejectEtcdRedirects()]
        if self._context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self._context))
        self._opener = urllib.request.build_opener(*handlers)

    def __call__(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = canonical_bytes(body)
        if len(payload) > _MAX_BODY_BYTES:
            raise CapabilityConsumptionError("etcd transaction request too large")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.config.auth_token is not None:
            headers["Authorization"] = self.config.auth_token
        request = urllib.request.Request(
            self.config.endpoint.rstrip("/") + "/v3/kv/txn",
            data=payload, headers=headers, method="POST",
        )
        try:
            # Never automatically retry a request whose commit may be ambiguous.
            with self._opener.open(
                request, timeout=self.config.timeout_seconds
            ) as response:
                if response.status != 200:
                    raise CapabilityConsumptionError("etcd transaction did not succeed")
                content = response.read(_MAX_BODY_BYTES + 1)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise CapabilityConsumptionError("etcd authority unavailable; deny operation") from exc
        if len(content) > _MAX_BODY_BYTES:
            raise CapabilityConsumptionError("etcd response too large")
        try:
            decoded = strict_json_loads(content)
        except (ValueError, TypeError) as exc:
            raise CapabilityConsumptionError("etcd response is malformed") from exc
        if not isinstance(decoded, Mapping):
            raise CapabilityConsumptionError("etcd response must be an object")
        return decoded


class EtcdV3CapabilityConsumptionStore:
    """One-use capability consumption via a single etcd v3 linearizable Txn.

    Server-side compare VERSION==0 and put are one consensus-backed transaction.
    A conflict branch reads the existing record within the same transaction;
    a different claims binding is a collision, not an ordinary replay.
    Every response must carry the pinned cluster ID and a valid Raft term.
    No automatic retry on uncertain network outcome; no automatic key deletion.
    """

    def __init__(
        self,
        transport: EtcdTransactionTransport,
        *,
        expected_cluster_id: str,
        namespace: str = "default",
        domain: str = "broker",
    ) -> None:
        if not callable(transport):
            raise TypeError("etcd transaction transport must be callable")
        if _CLUSTER.fullmatch(expected_cluster_id) is None or int(expected_cluster_id) == 0:
            raise ValueError("expected etcd cluster ID must be pinned")
        if _ID.fullmatch(namespace) is None or _ID.fullmatch(domain) is None:
            raise ValueError("etcd namespace and domain are invalid")
        self.transport = transport
        self.expected_cluster_id = expected_cluster_id
        self.namespace = namespace
        self.domain = domain

    def consume(
        self,
        capability_id: str,
        claims_digest: str,
        expires_at: int,
        consumed_at: int,
    ) -> bool:
        _validate_transition(capability_id, claims_digest, expires_at, consumed_at)
        # Length-prefixed and validated scopes avoid collisions and traversal.
        key = _b64(
            f"/event-horizon/replay/v1/{self.namespace}/{self.domain}/{capability_id}".encode()
        )
        record = {
            "claims_digest": claims_digest,
            "expires_at": expires_at,
            "consumed_at": consumed_at,
            "schema": "eh.capability-consumption.v1",
        }
        transaction = {
            "compare": [{
                "target": "VERSION", "result": "EQUAL",
                "key": key, "version": "0",
            }],
            "success": [{"requestPut": {
                "key": key, "value": _b64(canonical_bytes(record)),
            }}],
            "failure": [{"requestRange": {"key": key, "serializable": False}}],
        }
        try:
            response = self.transport(transaction)
        except CapabilityConsumptionError:
            raise
        except Exception as exc:
            raise CapabilityConsumptionError(
                "etcd transaction failed or timed out; deny uncertain outcome"
            ) from exc
        if not isinstance(response, Mapping):
            raise CapabilityConsumptionError("etcd response is not an object")
        header = response.get("header")
        if not isinstance(header, Mapping):
            raise CapabilityConsumptionError("etcd response header is missing")
        if str(header.get("cluster_id")) != self.expected_cluster_id:
            raise CapabilityConsumptionError("etcd cluster identity mismatch")
        _number(header.get("revision"), "revision")
        _number(header.get("raft_term"), "term")
        # Proto3 JSON omits scalar fields with default values. For an etcd
        # Txn, absent 'succeeded' means false, but only the conflict branch
        # below is accepted: it must contain the actual existing binding.
        succeeded = response.get("succeeded", False)
        if type(succeeded) is not bool:
            raise CapabilityConsumptionError("etcd transaction decision is invalid")
        branches = response.get("responses")
        if not isinstance(branches, list) or len(branches) != 1:
            raise CapabilityConsumptionError("etcd transaction branch is missing")
        if succeeded:
            if not isinstance(branches[0], Mapping) or not isinstance(
                branches[0].get("response_put"), Mapping
            ):
                raise CapabilityConsumptionError("etcd put acknowledgment missing")
            return True
        failure = branches[0]
        if not isinstance(failure, Mapping) or not isinstance(
            failure.get("response_range"), Mapping
        ):
            raise CapabilityConsumptionError("etcd collision read is missing")
        entries = failure["response_range"].get("kvs")
        if not isinstance(entries, list) or len(entries) != 1:
            raise CapabilityConsumptionError("etcd consumed record is missing")
        row = entries[0]
        if not isinstance(row, Mapping) or row.get("key") != key:
            raise CapabilityConsumptionError("etcd collision record key mismatch")
        try:
            previous = strict_json_loads(_decode(row.get("value")))
        except (ValueError, TypeError) as exc:
            raise CapabilityConsumptionError("etcd consumed record is malformed") from exc
        if not isinstance(previous, Mapping) or set(previous) != set(record):
            raise CapabilityConsumptionError("etcd consumed record schema mismatch")
        if (
            previous["schema"] != record["schema"]
            or previous["claims_digest"] != claims_digest
            or previous["expires_at"] != expires_at
            or type(previous["consumed_at"]) is not int
        ):
            raise CapabilityConsumptionError("capability ID collided with different signed claims")
        return False


def local_authority(
    database_path: str | Path, *, namespace: str = "default", domain: str = "broker"
) -> CapabilityConsumptionStore:
    """Option A: durable single-host authority; never silently use in-memory."""
    return SqliteCapabilityConsumptionStore(
        database_path, namespace=namespace, domain=domain
    )


def etcd_authority(
    config: EtcdGatewayConfig, *, expected_cluster_id: str,
    namespace: str = "default", domain: str = "broker"
) -> CapabilityConsumptionStore:
    """Option B: configure an external quorum-backed etcd authority."""
    return EtcdV3CapabilityConsumptionStore(
        EtcdV3TransactionTransport(config),
        expected_cluster_id=expected_cluster_id,
        namespace=namespace, domain=domain,
    )
