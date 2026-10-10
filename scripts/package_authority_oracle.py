"""Host-side independent etcd replay oracle for owned package-containment runs.

This verifies persisted consumption in a pinned etcd cluster *after* the
trusted gateway executes. It is not an independent observer of all effects,
nor a substitute for external witness identity or full signed replay service.
No target endpoint or authority secret is supplied by the compromised worker.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from typing import Any

from event_horizon.authority_backends import (
    EtcdGatewayConfig, EtcdV3TransactionTransport,
)
from event_horizon.canonical import strict_json_loads


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("etcd response lacks an encoded byte field")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("etcd response has malformed base64") from exc
    if _b64(raw) != value:
        raise ValueError("etcd response byte encoding is noncanonical")
    return raw


def _number(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.isdecimal() or int(value) <= 0:
        raise ValueError(f"etcd {label} missing or invalid")
    return int(value)


def owned_etcd_config(endpoint: str, cluster_id: str) -> dict[str, Any]:
    """Explicit opt-in for an owned, loopback-only disposable etcd lab."""
    EtcdGatewayConfig(
        endpoint=endpoint, allow_insecure_loopback=True,
        timeout_seconds=2.0,
    )
    if (not isinstance(cluster_id, str) or not cluster_id.isdecimal()
            or int(cluster_id) <= 0):
        raise ValueError("experiment must pin the real etcd cluster ID")
    # This experiment accepts *only* loopback. No remote or credentialed target.
    from urllib.parse import urlsplit
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {
        "127.0.0.1", "::1", "localhost",
    }:
        raise ValueError("this package experiment permits owned loopback etcd only")
    return {
        "endpoint": endpoint,
        "allow_insecure_loopback": True,
        "timeout_seconds": 2.0,
    }


def inspect_committed_consumption(
    transport: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    *,
    cluster_id: str,
    session_id: str,
    capability_id: str,
    claims_digest: str,
    expires_at: int,
) -> dict[str, Any]:
    """Linearizable range of one session's entire replay partition.

    Check both the *number* of writes and the precise binding. This host-side
    oracle runs independently from the compromised worker and gateway code
    path, but still trusts the configured etcd cluster and transport.
    """
    if (not isinstance(session_id, str) or not session_id.startswith("ehk-")
            or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in session_id)):
        raise ValueError("session must be an owned temporary isolation ID")
    if not isinstance(cluster_id, str) or not cluster_id.isdecimal() or int(cluster_id) <= 0:
        raise ValueError("invalid pinned cluster")
    if not isinstance(capability_id, str) or not capability_id.startswith("cap_"):
        raise ValueError("invalid capability identifier")
    if (not isinstance(claims_digest, str) or len(claims_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in claims_digest)):
        raise ValueError("invalid signed capability binding")
    if type(expires_at) is not int or expires_at <= 0:
        raise ValueError("invalid expected expiration")
    prefix = (
        f"/event-horizon/replay/v1/{session_id}/external-effect/".encode("ascii")
    )
    # Prefix end is next lexicographic byte after the trailing slash.
    end = prefix[:-1] + bytes((prefix[-1] + 1,))
    reply = transport({
        "compare": [],
        "success": [{"requestRange": {
            "key": _b64(prefix), "range_end": _b64(end),
            "serializable": False, "limit": "2",
        }}],
        "failure": [],
    })
    if not isinstance(reply, Mapping):
        raise ValueError("etcd oracle response is not an object")
    head = reply.get("header")
    if not isinstance(head, Mapping) or str(head.get("cluster_id")) != cluster_id:
        raise ValueError("etcd oracle observed an unexpected cluster")
    revision = _number(head.get("revision"), "revision")
    term = _number(head.get("raft_term"), "Raft term")
    if reply.get("succeeded") is not True:
        raise ValueError("etcd oracle did not receive the expected read transaction")
    parts = reply.get("responses")
    if not isinstance(parts, list) or len(parts) != 1:
        raise ValueError("etcd oracle returned an invalid branch")
    part = parts[0]
    if not isinstance(part, Mapping):
        raise ValueError("etcd oracle branch malformed")
    value = part.get("response_range")
    if not isinstance(value, Mapping):
        raise ValueError("etcd oracle has no range response")
    entries = value.get("kvs")
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValueError("expected exactly one committed capability consumption")
    if "count" in value and (not str(value["count"]).isdecimal() or int(value["count"]) != 1):
        raise ValueError("etcd oracle count is not one")
    row = entries[0]
    if not isinstance(row, Mapping):
        raise ValueError("etcd oracle record malformed")
    expected_key = prefix + capability_id.encode("ascii")
    if _decode(row.get("key")) != expected_key:
        raise ValueError("etcd oracle found an unexpected consumed capability")
    record = strict_json_loads(_decode(row.get("value")))
    if not isinstance(record, Mapping) or set(record) != {
        "schema", "claims_digest", "expires_at", "consumed_at",
    }:
        raise ValueError("etcd oracle replay record schema invalid")
    if (record["schema"] != "eh.capability-consumption.v1"
            or record["claims_digest"] != claims_digest
            or type(record["expires_at"]) is not int
            or record["expires_at"] != expires_at
            or type(record["consumed_at"]) is not int):
        raise ValueError("etcd oracle found a mismatched replay binding")
    return {
        "backend": "etcd",
        "cluster_id": cluster_id,
        "revision": revision,
        "raft_term": term,
        "record_count": 1,
        "capability_id": capability_id,
        "claims_digest": claims_digest,
        "expires_at": expires_at,
        "record_integrity_checked": True,
        "source": "host-supervisor-linearizable-etcd-read",
    }


def observe_owned_etcd(
    config: Mapping[str, Any], *, session_id: str,
    capability_id: str, claims_digest: str, expires_at: int,
) -> dict[str, Any]:
    return inspect_committed_consumption(
        EtcdV3TransactionTransport(EtcdGatewayConfig(**config["etcd_gateway"])),
        cluster_id=config["etcd_cluster_id"],
        session_id=session_id, capability_id=capability_id,
        claims_digest=claims_digest, expires_at=expires_at,
    )
