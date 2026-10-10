"""Signed replay state machine with *atomic* etcd transitions and checkpoints.

Every committed replay decision updates the authoritative head, per-token
state (when changed), and immutable checkpoint index in one etcd v3 Txn.
There is no read-modify-write race: every proposal compares the head's
mod_revision and re-evaluates on a proven CAS loss. Transport errors,
including post-commit timeouts, NEVER cause automatic retry.

The entire service must run in the trusted domain, holding the etcd mTLS
credentials and replay Ed25519 signing seed; neither reaches a guest worker.

Security boundaries: etcd is trusted for persistence/consensus, not
Byzantine fault tolerance. Signed checkpoints protect *pinned clients'
continuity*; a new client with no out-of-band anchor cannot detect operator
rollback or deletion. A lost/mutated authority head fails closed unless an
operator explicitly requests bootstrap.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from collections import deque
import threading
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .authority_backends import (
    EtcdGatewayConfig,
    EtcdTransactionTransport,
    EtcdV3TransactionTransport,
    _b64,
    _decode,
    _number,
)
from .canonical import canonical_bytes, digest, strict_json_loads
from .remote_replay import (
    ReferenceReplayService,
    ReplayClientPolicy,
    ReplayProtocolError,
    ReplayStateError,
    _CAPABILITY_ID,
    _OPERATIONS,
    _is_nonce,
    _load_private_key,
    _require_digest,
    _require_exact_fields,
    _require_integer,
    _require_positive_integer,
    _require_scope,
    genesis_checkpoint_digest,
    replay_key_id,
    _now_ms,
    MAX_CLOCK_SKEW_MS,
)
from .replay_state import CapabilityConsumptionError


class EtcdSignedReplayService:
    """Full single-consensus-domain signed replay authority.

    Supports nonce-create/consume/inspect, capability-consume and
    authorization-consume with the same envelopes as ReferenceReplayService.
    A single etcd cluster head serializes ALL operations and checkpoints.
    This is a correctness-first prototype: the global metadata key is a
    write hotspot; scale/sharding requires an explicitly designed future
    ordering scheme. No automatic key expiration, tombstone compaction,
    epoch promotion or administrative key rotation.
    """

    _MAX_ATTEMPTS = 96
    _DOMAIN = "event-horizon.signed-replay-head.v1"
    _SUPPORTED = frozenset({
        "nonce-create", "nonce-consume", "nonce-inspect",
        "capability-consume", "authorization-consume",
    })

    def __init__(
        self,
        transport: EtcdTransactionTransport,
        *,
        expected_cluster_id: str,
        namespace: str,
        service_id: str,
        epoch: int,
        signing_key: bytes | Ed25519PrivateKey,
        clients: Mapping[str, ReplayClientPolicy],
        now: Callable[[], float] | None = None,
        bootstrap: bool = False,
        transition_clock: Callable[[], float] | None = None,
        max_client_requests_per_minute: int = 240,
    ):
        if not callable(transport):
            raise TypeError("etcd replay transport must be callable")
        if not isinstance(expected_cluster_id, str) or not expected_cluster_id.isdecimal() or int(expected_cluster_id) <= 0:
            raise ValueError("etcd cluster identity must be pinned")
        self.transport = transport
        self.expected_cluster_id = expected_cluster_id
        self.namespace = _require_scope(namespace, "etcd replay namespace")
        self.service_id = _require_scope(service_id, "replay service ID")
        self.epoch = _require_positive_integer(epoch, "replay epoch")
        self.private_key = _load_private_key(signing_key)
        self.public_key = self.private_key.public_key()
        self.server_key_id = replay_key_id(self.public_key)
        self.clients = dict(clients)
        if any(key != policy.key_id for key, policy in self.clients.items()):
            raise ValueError("replay client policy key mismatch")
        self.now = now
        # transition_clock is for deterministic lab tests; production uses
        # the trusted server clock used by signed request freshness.
        self._transition_clock = transition_clock
        if type(max_client_requests_per_minute) is not int or max_client_requests_per_minute < 1:
            raise ValueError("per-client replay request limit must be positive")
        self.max_client_requests_per_minute = max_client_requests_per_minute
        self._admission_lock = threading.Lock()
        self._admission = {}
        self.prefix = f"/event-horizon/signed-replay/v1/{self.namespace}/{self.service_id}"
        self.head_key = _b64(f"{self.prefix}/head".encode("utf-8"))
        if bootstrap:
            self._bootstrap()
        else:
            self.checkpoint()  # prohibit missing/deleted/uninitialized authority

    @classmethod
    def connect(
        cls,
        config: EtcdGatewayConfig,
        *,
        expected_cluster_id: str,
        namespace: str,
        service_id: str,
        epoch: int,
        signing_key: bytes | Ed25519PrivateKey,
        clients: Mapping[str, ReplayClientPolicy],
        bootstrap: bool = False,
    ) -> EtcdSignedReplayService:
        return cls(
            EtcdV3TransactionTransport(config),
            expected_cluster_id=expected_cluster_id,
            namespace=namespace, service_id=service_id, epoch=epoch,
            signing_key=signing_key, clients=clients, bootstrap=bootstrap,
        )

    @property
    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def _ckpt_key(self, number: int) -> str:
        return _b64(f"{self.prefix}/checkpoint/{self.epoch}/{number}".encode("utf-8"))

    def _record_key(self, operation: str, partition: str, token: str) -> str:
        kind = "nonce" if operation.startswith("nonce-") else operation
        return _b64(
            f"{self.prefix}/record/{kind}/{partition}/{token}".encode("utf-8")
        )

    def _call(self, transaction: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            response = self.transport(transaction)
        except CapabilityConsumptionError as exc:
            raise ReplayStateError("etcd replay transaction uncertain; deny authorization") from exc
        except Exception as exc:
            raise ReplayStateError("etcd replay transaction unavailable; deny authorization") from exc
        if not isinstance(response, Mapping) or not isinstance(response.get("header"), Mapping):
            raise ReplayStateError("etcd replay response header is missing")
        header = response["header"]
        if str(header.get("cluster_id")) != self.expected_cluster_id:
            raise ReplayStateError("etcd cluster identity differs from pinned identity")
        try:
            _number(header.get("revision"), "revision")
            _number(header.get("raft_term"), "raft term")
        except CapabilityConsumptionError as exc:
            raise ReplayStateError("etcd response term or revision is invalid") from exc
        return response

    @staticmethod
    def _branch(response: Mapping[str, Any], *, succeeded: bool, length: int) -> list:
        actual = response.get("succeeded", False)
        if type(actual) is not bool or actual is not succeeded:
            if type(actual) is bool and not actual and succeeded:
                raise ReplayStateError("etcd conditional transaction did not succeed")
            raise ReplayStateError("etcd response decision is malformed")
        branches = response.get("responses")
        if not isinstance(branches, list) or len(branches) != length:
            raise ReplayStateError("etcd transaction response branch mismatch")
        return branches

    @staticmethod
    def _range_item(item: Any, key: str) -> tuple[dict[str, Any] | None, int]:
        if not isinstance(item, Mapping) or not isinstance(item.get("response_range"), Mapping):
            raise ReplayStateError("etcd range response malformed")
        kvs = item["response_range"].get("kvs", [])
        if not isinstance(kvs, list) or len(kvs) > 1:
            raise ReplayStateError("etcd range response count invalid")
        if not kvs:
            return None, 0
        kv = kvs[0]
        if not isinstance(kv, Mapping) or kv.get("key") != key:
            raise ReplayStateError("etcd range key differs from requested key")
        try:
            revision = _number(kv.get("mod_revision"), "mod revision")
            raw = _decode(kv.get("value"))
            parsed = strict_json_loads(raw, require_canonical=True)
        except (ValueError, TypeError, CapabilityConsumptionError) as exc:
            raise ReplayStateError("etcd authority record is malformed") from exc
        if not isinstance(parsed, dict):
            raise ReplayStateError("etcd authority record is not an object")
        return parsed, revision

    def _range(self, *keys: str) -> list[tuple[dict[str, Any] | None, int]]:
        request = {
            "compare": [],
            "success": [
                {"requestRange": {"key": key, "serializable": False}}
                for key in keys
            ],
            "failure": [],
        }
        response = self._call(request)
        parts = self._branch(response, succeeded=True, length=len(keys))
        return [self._range_item(item, key) for item, key in zip(parts, keys)]

    def _validate_head(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, dict) or set(state) != {
            "schema", "service_id", "epoch", "server_key_id",
            "checkpoint", "checkpoint_digest",
        }:
            raise ReplayStateError("etcd replay head missing or schema incompatible")
        if (
            state["schema"] != self._DOMAIN
            or state["service_id"] != self.service_id
            or state["epoch"] != self.epoch
            or state["server_key_id"] != self.server_key_id
            or type(state["checkpoint"]) is not int
            or state["checkpoint"] < 0
            or not isinstance(state["checkpoint_digest"], str)
            or len(state["checkpoint_digest"]) != 64
        ):
            raise ReplayStateError("etcd replay epoch, signer or checkpoint mismatch")
        if state["checkpoint"] == 0 and state["checkpoint_digest"] != genesis_checkpoint_digest(
            self.service_id, self.epoch
        ):
            raise ReplayStateError("etcd genesis checkpoint invalid")
        return state

    def _bootstrap(self) -> None:
        genesis = genesis_checkpoint_digest(self.service_id, self.epoch)
        head = {
            "schema": self._DOMAIN,
            "service_id": self.service_id,
            "epoch": self.epoch,
            "server_key_id": self.server_key_id,
            "checkpoint": 0,
            "checkpoint_digest": genesis,
        }
        response = self._call({
            "compare": [{"key": self.head_key, "target": "VERSION", "result": "EQUAL", "version": "0"}],
            "success": [
                {"requestPut": {"key": self.head_key, "value": _b64(canonical_bytes(head))}},
                {"requestPut": {"key": self._ckpt_key(0), "value": _b64(canonical_bytes({"digest": genesis}))}},
            ],
            "failure": [{"requestRange": {"key": self.head_key, "serializable": False}}],
        })
        if response.get("succeeded") is True:
            self._branch(response, succeeded=True, length=2)
        elif response.get("succeeded", False) is False:
            parts = self._branch(response, succeeded=False, length=1)
            existing, _ = self._range_item(parts[0], self.head_key)
            self._validate_head(existing)
        else:
            raise ReplayStateError("etcd replay bootstrap response invalid")
        self.checkpoint()  # read back a quorum-confirmed genesis or current head

    def checkpoint(self) -> tuple[int, int, str]:
        [(head, _revision)] = self._range(self.head_key)
        state = self._validate_head(head)
        return self.epoch, state["checkpoint"], state["checkpoint_digest"]

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        authenticated, policy, request_digest = ReferenceReplayService._authenticate_request(self, request)
        # Bound authenticated-client workload before reaching the global
        # etcd head. Each service instance has its own in-memory limit;
        # deploy an upstream distributed limiter for multi-instance use.
        self._admit_client(authenticated["client_key_id"])
        operation = authenticated["operation"]
        partition = authenticated["partition"]
        if operation not in self._SUPPORTED:
            raise ReplayProtocolError("etcd replay operation is unsupported")
        token = authenticated["payload"].get("nonce" if operation.startswith("nonce-") else "token")
        if operation.startswith("nonce-"):
            if not _is_nonce(token):
                raise ReplayProtocolError("attestation nonce is malformed")
        elif operation == "capability-consume":
            if not isinstance(token, str) or _CAPABILITY_ID.fullmatch(token) is None:
                raise ReplayProtocolError("capability ID is malformed")
        elif not _is_nonce(token):
            raise ReplayProtocolError("authorization nonce is malformed")
        record_key = self._record_key(operation, partition, token)
        min_ckpt_key = self._ckpt_key(authenticated["minimum_checkpoint"])

        for _attempt in range(self._MAX_ATTEMPTS):
            (head, revision), (history, _), (record, _) = self._range(
                self.head_key, min_ckpt_key, record_key,
            )
            state = self._validate_head(head)
            if operation not in policy.operations or partition not in policy.partitions:
                return self._sign_response(
                    authenticated, request_digest, accepted=False,
                    status="client-not-authorized", result={"reason": "client policy rejects operation/partition"},
                    state=state,
                )
            if authenticated["expected_epoch"] != self.epoch:
                return self._sign_response(
                    authenticated, request_digest, accepted=False,
                    status="epoch-mismatch", result={"reason": "client epoch is not pinned"}, state=state,
                )
            if (
                history is None
                or set(history) != {"digest"}
                or history["digest"] != authenticated["minimum_checkpoint_digest"]
            ):
                return self._sign_response(
                    authenticated, request_digest, accepted=False,
                    status="checkpoint-mismatch",
                    result={"reason": "checkpoint continuity cannot be demonstrated"},
                    state=state,
                )
            accepted, status, result, next_record = self._transition(
                operation, authenticated["payload"], token, record,
            )
            # A duplicate denial, wrong-context attempt, or read-only
            # inspection is not a state transition. Return a signed result
            # pinned to the observed head without creating another global
            # checkpoint. This significantly reduces write amplification.
            if next_record == record:
                return self._sign_response(
                    authenticated, request_digest, accepted=accepted,
                    status=status, result=result, state=state,
                )
            next_num = state["checkpoint"] + 1
            next_digest = digest({
                "schema": "event-horizon.replay-checkpoint.v1",
                "previous_digest": state["checkpoint_digest"],
                "epoch": self.epoch,
                "checkpoint": next_num,
                "request_digest": request_digest,
                "accepted": accepted,
                "status": status,
                "result_digest": digest(result),
            })
            next_head = {**state, "checkpoint": next_num, "checkpoint_digest": next_digest}
            success = [
                {"requestPut": {"key": self.head_key, "value": _b64(canonical_bytes(next_head))}},
                {"requestPut": {"key": self._ckpt_key(next_num), "value": _b64(canonical_bytes({"digest": next_digest}))}},
            ]
            if next_record != record:
                success.append({"requestPut": {
                    "key": record_key, "value": _b64(canonical_bytes(next_record)),
                }})
            txn = {
                "compare": [
                    {"key": self.head_key, "target": "MOD", "result": "EQUAL", "mod_revision": str(revision)},
                    {"key": self._ckpt_key(next_num), "target": "VERSION", "result": "EQUAL", "version": "0"},
                ],
                "success": success,
                "failure": [{"requestRange": {"key": self.head_key, "serializable": False}}],
            }
            response = self._call(txn)
            if response.get("succeeded") is True:
                parts = self._branch(response, succeeded=True, length=len(success))
                if any(
                    not isinstance(item, Mapping) or not isinstance(item.get("response_put"), Mapping)
                    for item in parts
                ):
                    raise ReplayStateError("etcd committed replay response missing put acknowledgments")
                return self._sign_response(
                    authenticated, request_digest, accepted=accepted, status=status,
                    result=result, state=next_head,
                )
            parts = self._branch(response, succeeded=False, length=1)
            current, current_revision = self._range_item(parts[0], self.head_key)
            self._validate_head(current)
            if current_revision == revision:
                # Another actor could have preoccupied the next checkpoint key;
                # this implies inconsistent state, not harmless contention.
                raise ReplayStateError("etcd checkpoint key collision; refusing continuation")
            # CAS conflict is proven, unlike timeout; safe to recompute.
        raise ReplayStateError("etcd replay contention budget exhausted; deny operation")

    def _sign_response(
        self, request: Mapping[str, Any], request_digest: str, *,
        accepted: bool, status: str, result: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        return ReferenceReplayService._sign_response(
            self, request, request_digest, accepted=accepted, status=status,
            result=result, epoch=self.epoch,
            checkpoint=state["checkpoint"],
            checkpoint_digest=state["checkpoint_digest"],
        )

    @staticmethod
    def _nonce_export(token: str, row: Mapping[str, Any]) -> dict[str, Any]:
        result = {
            "nonce": token,
            "context": row["context"],
            "contextDigest": row["context_digest"],
            "issuedAt": row["issued_at"],
            "expiresAt": row["expires_at"],
            "state": row["state"],
        }
        if row["consumed_at"] is not None:
            result["consumedAt"] = row["consumed_at"]
        return result

    def _admit_client(self, client_key_id: str) -> None:
        instant = time.monotonic()
        with self._admission_lock:
            hits = self._admission.setdefault(client_key_id, deque())
            while hits and instant - hits[0] >= 60:
                hits.popleft()
            if len(hits) >= self.max_client_requests_per_minute:
                raise ReplayProtocolError("replay client request budget exhausted")
            hits.append(instant)

    def _transition(
        self,
        operation: str, payload: Mapping[str, Any], token: str,
        existing: dict[str, Any] | None,
    ) -> tuple[bool, str, dict[str, Any], dict[str, Any] | None]:
        trusted_now = _now_ms(self._transition_clock or self.now)
        if operation in {"capability-consume", "authorization-consume"}:
            value = _require_exact_fields(
                payload, {"binding_digest", "consumed_at", "expires_at", "token"}, "token payload"
            )
            binding = _require_digest(value["binding_digest"], "token binding")
            expiry = _require_positive_integer(value["expires_at"], "token expiry")
            claimed_time = _require_integer(value["consumed_at"], "token consumption")
            if abs(claimed_time - trusted_now) > MAX_CLOCK_SKEW_MS:
                raise ReplayProtocolError("token timestamp differs from trusted service clock")
            if trusted_now >= expiry:
                return False, "expired", {}, existing
            if existing is None:
                return True, "consumed-now", {}, {
                    "schema": "eh.signed-replay-token.v1",
                    "binding_digest": binding, "expires_at": expiry, "consumed_at": trusted_now,
                }
            if (
                set(existing) != {"schema", "binding_digest", "expires_at", "consumed_at"}
                or existing["schema"] != "eh.signed-replay-token.v1"
                or not isinstance(existing["consumed_at"], int)
            ):
                raise ReplayStateError("etcd token record corrupted")
            if (existing["binding_digest"], existing["expires_at"]) != (binding, expiry):
                return False, "collision", {}, existing
            return False, "consumed", {}, existing

        if operation == "nonce-create":
            value = _require_exact_fields(
                payload, {"context", "context_digest", "expires_at", "issued_at", "nonce"}, "nonce-create"
            )
            context = _require_exact_fields(
                value["context"], {"deviceId", "executorId", "purpose", "sessionId"}, "nonce context"
            )
            if any(
                not isinstance(item, str) or not item or len(item) > 256
                for item in context.values()
            ):
                raise ReplayProtocolError("nonce context invalid")
            cdigest = _require_digest(value["context_digest"], "nonce context digest")
            if cdigest != digest(context):
                raise ReplayProtocolError("nonce context binding invalid")
            issued = _require_integer(value["issued_at"], "nonce issued")
            expires = _require_positive_integer(value["expires_at"], "nonce expires")
            if expires <= issued or expires - issued > 3_600_000:
                raise ReplayProtocolError("nonce lifetime invalid")
            if abs(issued - trusted_now) > MAX_CLOCK_SKEW_MS or trusted_now >= expires:
                raise ReplayProtocolError("nonce issuance is outside trusted time window")
            candidate = {
                "schema": "eh.signed-replay-nonce.v1", "nonce": token,
                "context": dict(context), "context_digest": cdigest,
                "issued_at": issued, "expires_at": expires,
                "state": "issued", "consumed_at": None,
            }
            if existing is None:
                return True, "created", {}, candidate
            EtcdSignedReplayService._verify_nonce_record(token, existing)
            if all(existing[k] == candidate[k] for k in (
                "context", "context_digest", "issued_at", "expires_at"
            )):
                return False, "already-exists", {}, existing
            return False, "collision", {}, existing

        if operation not in {"nonce-consume", "nonce-inspect"}:
            raise ReplayProtocolError("unsupported replay operation")
        fields = {"nonce", "now"} | ({"context_digest"} if operation == "nonce-consume" else set())
        value = _require_exact_fields(payload, fields, "nonce operation")
        claimed_now = _require_integer(value["now"], "nonce now")
        if abs(claimed_now - trusted_now) > MAX_CLOCK_SKEW_MS:
            raise ReplayProtocolError("nonce timestamp differs from trusted service clock")
        at = trusted_now
        cdigest = (
            _require_digest(value["context_digest"], "nonce context digest")
            if operation == "nonce-consume" else None
        )
        if existing is None:
            return False, "unknown", {}, None
        EtcdSignedReplayService._verify_nonce_record(token, existing)
        record = EtcdSignedReplayService._nonce_export(token, existing)
        if operation == "nonce-inspect":
            if existing["state"] == "issued" and at >= existing["expires_at"]:
                changed = {**existing, "state": "expired"}
                record["state"] = "expired"
                return True, "found", {"record": record}, changed
            return True, "found", {"record": record}, existing
        if existing["state"] == "consumed":
            return False, "consumed", {"record": record}, existing
        if existing["state"] == "expired" or at >= existing["expires_at"]:
            changed = {**existing, "state": "expired"}
            record["state"] = "expired"
            return False, "expired", {"record": record}, changed
        if existing["context_digest"] != cdigest:
            return False, "wrong-context", {"record": record}, existing
        changed = {**existing, "state": "consumed", "consumed_at": at}
        record.update({"state": "consumed", "consumedAt": at})
        return True, "consumed-now", {"record": record}, changed

    @staticmethod
    def _verify_nonce_record(token: str, row: Mapping[str, Any]) -> None:
        if (
            set(row) != {
                "schema", "nonce", "context", "context_digest",
                "issued_at", "expires_at", "state", "consumed_at",
            }
            or row["schema"] != "eh.signed-replay-nonce.v1"
            or row["nonce"] != token
            or row["state"] not in {"issued", "expired", "consumed"}
            or type(row["issued_at"]) is not int
            or type(row["expires_at"]) is not int
            or (row["consumed_at"] is not None and type(row["consumed_at"]) is not int)
            or not isinstance(row["context"], dict)
            or digest(row["context"]) != row["context_digest"]
        ):
            raise ReplayStateError("etcd nonce record corrupted")
