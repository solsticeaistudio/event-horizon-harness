"""Consensus-backed immutable effect reservations for cooperating recipients.

Every first reservation uses ONE etcd v3 Txn that atomically creates the
effect-key row and a separate capability-ID index. No lease/TTL/deletion.
An already-reserved effect never transfers its original capability identity.
A fresh signed capability is required for every recovery attempt; that check
belongs to FencedEffectRecoveryGateway/CapabilityVerifier, not this journal.

Confirmations only transition possibly-committed -> recipient-confirmed after
the caller has independently corroborated a positive durable recipient receipt.
An unavailable quorum, uncertain transport result, damaged/missing index,
malformed response, or concurrent incompatible mutation fails CLOSED.

etcd is an honest crash-fault-tolerant consensus authority, not Byzantine-
resistant storage. This module is portable protocol code, NOT a physical
multi-host, cross-region or power-cut experiment. Do not bootstrap/reset the
namespace during recovery and do not use the same namespace for unrelated
effect domains.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from .authority_backends import (
    EtcdGatewayConfig, EtcdTransactionTransport, EtcdV3TransactionTransport,
    _b64, _decode, _number, _ID,
)
from .canonical import canonical_bytes, strict_json_loads
from .effect_outcome_journal import EffectAlreadyReserved, EffectJournalError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CLUSTER = re.compile(r"^[0-9]+$")
_ROW_SCHEMA = "event-horizon.etcd-fenced-effect.v1"
_INDEX_SCHEMA = "event-horizon.etcd-effect-capability-index.v1"
_FIELDS = frozenset({
    "schema", "tenant", "environment", "effect_key", "capability_id",
    "request_digest", "claims_digest", "state", "receipt_digest",
    "fenced_protocol", "fenced_recipient_id", "fenced_output_digest",
})
_INDEX_FIELDS = frozenset({
    "schema", "tenant", "environment", "capability_id", "effect_key",
})
_MAX_CAS_LOSSES = 8


def _scope(value: str, what: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError(f"invalid trusted {what}")
    return value


def _identity(tenant: str, environment: str, effect_key: str,
              capability_id: str | None = None) -> None:
    for item, what in ((tenant, "tenant"), (environment, "environment")):
        if (type(item) is not str or not item or len(item) > 256
                or any(ord(c) < 32 for c in item)):
            raise ValueError(f"invalid {what} identity")
    if type(effect_key) is not str or not _HEX64.fullmatch(effect_key):
        raise ValueError("invalid effect key digest")
    if capability_id is not None and (type(capability_id) is not str
                                      or not capability_id or len(capability_id) > 256
                                      or any(ord(c) < 32 for c in capability_id)):
        raise ValueError("invalid capability ID")


def _digest_field(value: str, what: str) -> None:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise ValueError(f"invalid {what}")


def _range(key: str) -> dict:
    return {"requestRange": {"key": key, "serializable": False}}


def _put(key: str, value: dict) -> dict:
    return {"requestPut": {"key": key, "value": _b64(canonical_bytes(value))}}


def _version_zero(key: str) -> dict:
    return {"target": "VERSION", "result": "EQUAL", "key": key, "version": "0"}


def _mod_equals(key: str, revision: int) -> dict:
    return {"target": "MOD", "result": "EQUAL", "key": key,
            "mod_revision": str(revision)}


class EtcdFencedEffectJournal:
    """Host-owned etcd effect journal shared by trusted gateway processes.

    Every invocation must pin the SAME cluster ID, namespace and domain.
    Any network error or ambiguous commit must be surfaced, NEVER retried
    as a new first reservation. Genuine replicated gateway capability
    consumption must separately use the consensus-backed replay store.
    """

    def __init__(self, transport: EtcdTransactionTransport, *,
                 expected_cluster_id: str, namespace: str,
                 domain: str = "effect-fence"):
        if not callable(transport):
            raise TypeError("etcd effect journal requires transaction transport")
        if (type(expected_cluster_id) is not str
                or not _CLUSTER.fullmatch(expected_cluster_id)
                or int(expected_cluster_id) <= 0):
            raise ValueError("effect journal must pin a nonzero etcd cluster ID")
        self.namespace = _scope(namespace, "namespace")
        self.domain = _scope(domain, "domain")
        self.expected_cluster_id = expected_cluster_id
        self.transport = transport

    @classmethod
    def connect(cls, config: EtcdGatewayConfig, *,
                expected_cluster_id: str, namespace: str,
                domain: str = "effect-fence") -> "EtcdFencedEffectJournal":
        return cls(EtcdV3TransactionTransport(config),
                   expected_cluster_id=expected_cluster_id,
                   namespace=namespace, domain=domain)

    def _stem(self, tenant: str, environment: str) -> str:
        # Hex-encoded, length-unambiguous UTF-8 scoped identities.
        return (f"/event-horizon/fenced-effects/v1/{self.namespace}/{self.domain}/"
                f"{tenant.encode('utf-8').hex()}/{environment.encode('utf-8').hex()}")

    def _effect_key(self, tenant: str, environment: str, key: str) -> str:
        return _b64(f"{self._stem(tenant, environment)}/effect/{key}".encode())

    def _cap_key(self, tenant: str, environment: str, cap: str) -> str:
        # Avoid path delimiter / control characters in the caller's cap ID.
        return _b64(f"{self._stem(tenant, environment)}/cap/{cap.encode('utf-8').hex()}".encode())

    def _txn(self, *, compare: list[dict], success: list[dict],
             failure: list[dict]) -> tuple[bool, list]:
        try:
            r = self.transport({
                "compare": compare, "success": success, "failure": failure,
            })
        except Exception as exc:
            raise EffectJournalError(
                "effect fence transaction unavailable or indeterminate; NO retry"
            ) from exc
        if type(r) is not dict or type(r.get("header")) is not dict:
            raise EffectJournalError("untrusted etcd effect journal response")
        header = r["header"]
        if str(header.get("cluster_id")) != self.expected_cluster_id:
            raise EffectJournalError("effect fence changed etcd cluster identity")
        try:
            _number(header.get("revision"), "revision")
            _number(header.get("raft_term"), "raft term")
        except Exception as exc:
            raise EffectJournalError("effect journal missing authoritative revision") from exc
        succeeded = r.get("succeeded", False)
        if type(succeeded) is not bool:
            raise EffectJournalError("etcd effect-fence decision invalid")
        replies = r.get("responses")
        count = len(success if succeeded else failure)
        if type(replies) is not list or len(replies) != count:
            raise EffectJournalError("effect journal transaction branch incomplete")
        return succeeded, replies

    def _entry(self, reply: Any, key: str, *, missing: bool = False):
        if type(reply) is not dict or type(reply.get("response_range")) is not dict:
            raise EffectJournalError("missing linearizable etcd record range")
        entries = reply["response_range"].get("kvs", [])
        if type(entries) is not list or len(entries) > 1:
            raise EffectJournalError("malformed etcd record count")
        if not entries:
            if missing:
                return None
            raise EffectJournalError("etcd effect/index record disappeared")
        e = entries[0]
        if type(e) is not dict or e.get("key") != key:
            raise EffectJournalError("unexpected etcd record key")
        try:
            mod = _number(e.get("mod_revision"), "effect record revision")
            raw = _decode(e.get("value"))
            record = strict_json_loads(raw, require_canonical=True)
        except Exception as exc:
            raise EffectJournalError("etcd effect record is malformed") from exc
        if type(record) is not dict:
            raise EffectJournalError("etcd effect record is not a canonical object")
        return record, mod

    def _validated(self, effect: dict, index: dict, tenant: str,
                   environment: str, effect_key: str) -> dict:
        if (set(effect) != _FIELDS or set(index) != _INDEX_FIELDS
                or effect["schema"] != _ROW_SCHEMA
                or index["schema"] != _INDEX_SCHEMA
                or any(effect[k] != v for k, v in (
                    ("tenant", tenant), ("environment", environment),
                    ("effect_key", effect_key),
                    ("fenced_protocol", "atomic-sqlite-v1"),
                ))
                or any(index[k] != effect[k] for k in (
                    "tenant", "environment", "capability_id", "effect_key",
                ))
                or effect["state"] not in ("possibly-committed", "recipient-confirmed")
                or (effect["state"] == "possibly-committed"
                    and effect["receipt_digest"] is not None)
                or (effect["state"] == "recipient-confirmed"
                    and (type(effect["receipt_digest"]) is not str
                         or not _HEX64.fullmatch(effect["receipt_digest"])))):
            raise EffectJournalError("corrupt or rebound consensus effect fence")
        for digest in ("request_digest", "claims_digest", "fenced_output_digest"):
            if type(effect[digest]) is not str or not _HEX64.fullmatch(effect[digest]):
                raise EffectJournalError("damaged durable fence digest")
        cap, recipient = effect["capability_id"], effect["fenced_recipient_id"]
        if (type(cap) is not str or not cap or len(cap) > 256
                or type(recipient) is not str or not recipient or len(recipient) > 128):
            raise EffectJournalError("damaged original authority or recipient identity")
        return effect

    def _read_effect(self, tenant: str, environment: str, effect_key: str):
        ek = self._effect_key(tenant, environment, effect_key)
        ok, rows = self._txn(compare=[], success=[_range(ek)], failure=[])
        if not ok:
            raise EffectJournalError("linearizable effect observation failed")
        effect_entry = self._entry(rows[0], ek, missing=True)
        if effect_entry is None:
            return None
        effect, revision = effect_entry
        cap = effect.get("capability_id")
        if type(cap) is not str or not cap or len(cap) > 256:
            raise EffectJournalError("effect owner capability missing")
        ck = self._cap_key(tenant, environment, cap)
        # Atomic two-key snapshot: verify the index still exists and binds
        # the original capability, even after future updates.
        ok, replies = self._txn(
            compare=[], success=[_range(ek), _range(ck)], failure=[],
        )
        if not ok:
            raise EffectJournalError("consensus snapshot unavailable")
        latest = self._entry(replies[0], ek)
        idx = self._entry(replies[1], ck)
        actual = self._validated(latest[0], idx[0], tenant, environment, effect_key)
        return actual, latest[1]

    def reserve_fenced(self, *, tenant: str, environment: str, effect_key: str,
                       capability_id: str, request_digest: str,
                       claims_digest: str, recipient_id: str,
                       output_digest: str) -> bool:
        _identity(tenant, environment, effect_key, capability_id)
        _digest_field(request_digest, "request digest")
        _digest_field(claims_digest, "claims digest")
        _digest_field(output_digest, "output digest")
        if (type(recipient_id) is not str or not recipient_id
                or len(recipient_id) > 128):
            raise ValueError("invalid pinned recipient")
        ek = self._effect_key(tenant, environment, effect_key)
        ck = self._cap_key(tenant, environment, capability_id)
        row = {
            "schema": _ROW_SCHEMA, "tenant": tenant, "environment": environment,
            "effect_key": effect_key, "capability_id": capability_id,
            "request_digest": request_digest, "claims_digest": claims_digest,
            "state": "possibly-committed", "receipt_digest": None,
            "fenced_protocol": "atomic-sqlite-v1",
            "fenced_recipient_id": recipient_id,
            "fenced_output_digest": output_digest,
        }
        idx = {
            "schema": _INDEX_SCHEMA, "tenant": tenant,
            "environment": environment, "capability_id": capability_id,
            "effect_key": effect_key,
        }
        ok, replies = self._txn(
            compare=[_version_zero(ek), _version_zero(ck)],
            success=[_put(ek, row), _put(ck, idx)],
            failure=[_range(ek), _range(ck)],
        )
        if ok:
            if any(type(r) is not dict or type(r.get("response_put")) is not dict
                   for r in replies):
                raise EffectJournalError("etcd effect reservation ACK missing")
            return True
        effect = self._entry(replies[0], ek, missing=True)
        cap = self._entry(replies[1], ck, missing=True)
        if effect is None:
            raise EffectAlreadyReserved(
                "capability previously bound to another effect or fence deleted"
            )
        found = effect[0]
        if type(found) is not dict:
            raise EffectJournalError("malformed existing effect reservation")
        owner = found.get("capability_id")
        if type(owner) is not str or not owner or len(owner) > 256:
            raise EffectJournalError("existing effect owner unreadable")
        original_ck = self._cap_key(tenant, environment, owner)
        if owner == capability_id:
            if cap is None:
                raise EffectJournalError("original effect has no capability index")
            self._validated(found, cap[0], tenant, environment, effect_key)
            expected = {**row, "state": found["state"],
                        "receipt_digest": found["receipt_digest"]}
            if found != expected:
                raise EffectAlreadyReserved("existing effect reservation has incompatible binding")
            return False
        # Read and validate original binding before treating a different signed
        # recovery capability as an already-reserved logical effect.
        existing = self._read_effect(tenant, environment, effect_key)
        if existing is None:
            raise EffectJournalError("original fence disappeared during recovery")
        current = existing[0]
        if (cap is not None or current["capability_id"] != owner
                or current["request_digest"] != request_digest
                or current["fenced_recipient_id"] != recipient_id
                or current["fenced_output_digest"] != output_digest):
            raise EffectAlreadyReserved("effect or signed capability bound to another operation")
        raise EffectAlreadyReserved("original durable effect already reserved")

    def observe_effect(self, *, tenant: str, environment: str, effect_key: str):
        _identity(tenant, environment, effect_key)
        entry = self._read_effect(tenant, environment, effect_key)
        if entry is None:
            return None
        row = entry[0]
        return {name: row[name] for name in (
            "capability_id", "request_digest", "claims_digest", "state",
            "receipt_digest", "fenced_protocol", "fenced_recipient_id",
            "fenced_output_digest",
        )}

    def observe(self, *, tenant: str, environment: str, capability_id: str):
        _identity(tenant, environment, "a" * 64, capability_id)
        ck = self._cap_key(tenant, environment, capability_id)
        ok, replies = self._txn(compare=[], success=[_range(ck)], failure=[])
        if not ok:
            raise EffectJournalError("capability-index linearizable read failed")
        index = self._entry(replies[0], ck, missing=True)
        if index is None:
            return None
        data = index[0]
        if (set(data) != _INDEX_FIELDS or data["schema"] != _INDEX_SCHEMA
                or data["tenant"] != tenant or data["environment"] != environment
                or data["capability_id"] != capability_id):
            raise EffectJournalError("invalid capability index")
        key = data["effect_key"]
        _identity(tenant, environment, key)
        row = self.observe_effect(
            tenant=tenant, environment=environment, effect_key=key,
        )
        if row is None or row["capability_id"] != capability_id:
            raise EffectJournalError("capability index points to missing effect")
        return {name: row[name] for name in (
            "request_digest", "claims_digest", "state", "receipt_digest",
        )}

    def confirm_from_trusted_recipient(self, *, tenant: str, environment: str,
                                       effect_key: str, capability_id: str,
                                       request_digest: str, claims_digest: str,
                                       receipt_digest: str) -> None:
        _identity(tenant, environment, effect_key, capability_id)
        for value, what in ((request_digest, "request"),
                            (claims_digest, "claims"),
                            (receipt_digest, "receipt")):
            _digest_field(value, what)
        key = self._effect_key(tenant, environment, effect_key)
        for _ in range(_MAX_CAS_LOSSES):
            item = self._read_effect(tenant, environment, effect_key)
            if item is None:
                raise EffectJournalError("cannot confirm unreserved effect")
            row, mod = item
            if (row["capability_id"] != capability_id
                    or row["request_digest"] != request_digest
                    or row["claims_digest"] != claims_digest):
                raise EffectJournalError("confirmation cannot rewrite original provenance")
            if row["state"] == "recipient-confirmed":
                if row["receipt_digest"] != receipt_digest:
                    raise EffectJournalError("conflicting immutable recipient receipt")
                return
            confirmed = {**row, "state": "recipient-confirmed",
                         "receipt_digest": receipt_digest}
            ok, replies = self._txn(
                compare=[_mod_equals(key, mod)],
                success=[_put(key, confirmed)],
                failure=[_range(key)],
            )
            if ok:
                if (type(replies[0]) is not dict
                        or type(replies[0].get("response_put")) is not dict):
                    raise EffectJournalError("effect confirmation ACK missing")
                return
            # A proven CAS loser may re-read; a lost response is an exception
            # above and NEVER triggers blind retry.
            self._entry(replies[0], key)
        raise EffectJournalError("effect confirmation exhausted concurrent CAS retries")
