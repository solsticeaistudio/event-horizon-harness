"""Strict supervisor-owned contract for evidence submitted by a gateway child.

The gateway is a trusted component, but possessing a private recorder RPC
descriptor is not permission to ask the supervisor to sign arbitrary claims.
This validates shape, exact request bindings and event order. It does NOT by
itself prove an effect committed: independent recipient/etcd observations do.
"""
from __future__ import annotations

import re
import threading

HEX = re.compile(r"^[0-9a-f]{64}$")

class GatewayEvidenceContractError(ValueError):
    pass


class GatewayEventContract:
    def __init__(self, *, gateway_pid: int, request_digest: str, request_id: str,
                 capability_id: str, fenced_recipient_id: str | None = None,
                 fenced_original_capability_id: str | None = None):
        if type(gateway_pid) is not int or gateway_pid <= 1:
            raise ValueError("gateway child identity not pinned")
        if not isinstance(request_digest, str) or not HEX.fullmatch(request_digest):
            raise ValueError("invalid pinned request digest")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("missing pinned request ID")
        if not isinstance(capability_id, str) or not capability_id:
            raise ValueError("missing pinned capability ID")
        if fenced_recipient_id is not None and (not isinstance(fenced_recipient_id, str)
                or not fenced_recipient_id or len(fenced_recipient_id) > 128):
            raise ValueError("invalid pinned fenced recipient ID")
        self.fenced_recipient_id = fenced_recipient_id
        if fenced_original_capability_id is not None and (
                fenced_recipient_id is None or not isinstance(fenced_original_capability_id, str)
                or not fenced_original_capability_id):
            raise ValueError("recovery source must have a pinned fenced original capability")
        self.original_capability_id = fenced_original_capability_id
        self.pid = gateway_pid
        self.digest = request_digest
        self.request_id = request_id
        self.capability_id = capability_id
        self.authorized = False
        self.dispatched = False
        self.finished = False
        self.current_capability = None
        self._lock = threading.RLock()

    def begin_request(self, message: object) -> None:
        with self._lock:
            if self.current_capability is not None:
                raise GatewayEvidenceContractError("concurrent gateway exchange")
            claim = None
            if isinstance(message, dict):
                token = message.get("capability")
                if isinstance(token, dict) and isinstance(token.get("claims"), dict):
                    claim = token["claims"].get("capability_id")
            self.current_capability = claim if isinstance(claim, str) else None

    def end_request(self) -> None:
        with self._lock:
            self.current_capability = None

    def check(self, event: dict) -> None:
        with self._lock:
            self._check(event)

    def _check(self, event: dict) -> None:
        if (not isinstance(event, dict)
                or set(event) != {"event_type", "payload", "source_id"}
                or event.get("source_id") != "host-effect-service"
                or not isinstance(event.get("payload"), dict)):
            raise GatewayEvidenceContractError("gateway evidence envelope invalid")
        kind, payload = event["event_type"], event["payload"]
        keys = set(payload)
        if kind == "execution.denied":
            boundary = (keys == {"source", "effect_state"}
                        and payload == {"source": "effect-boundary",
                                        "effect_state": "not-started"})
            gateway = (keys == {"request_id", "error_class", "effect_state"}
                       and payload.get("request_id") == self.request_id
                       and payload.get("error_class") in {
                           "authority-denied", "unsupported-operation",
                           "pre-dispatch-denied", "effect-journal-unavailable",
                       } and payload.get("effect_state") == "not-started")
            if not (boundary or gateway):
                raise GatewayEvidenceContractError("unrecognized denial evidence")
            return
        if kind == "fenced.authorized" and self.fenced_recipient_id is not None:
            if (keys != {"request_id", "request_digest", "capability_id"}
                    or (self.authorized and not self.finished)
                    or payload.get("request_id") != self.request_id
                    or payload.get("request_digest") != self.digest
                    or payload.get("capability_id") != self.current_capability
                    or (not self.authorized and payload.get("capability_id") != self.capability_id)):
                raise GatewayEvidenceContractError("invalid fenced authorization")
            self.authorized = True
            self.finished = False
            return
        if kind == "fenced.indeterminate" and self.fenced_recipient_id is not None:
            if (keys != {"request_id", "request_digest", "capability_id", "effect_state"}
                    or not self.authorized or self.finished
                    or payload.get("request_id") != self.request_id
                    or payload.get("request_digest") != self.digest
                    or payload.get("capability_id") != self.current_capability
                    or payload.get("effect_state") != "possibly-committed"):
                raise GatewayEvidenceContractError("unverifiable indeterminate recipient event")
            # A new signed capability may enter the same living gateway, but
            # the original durable fence cannot be released or rebound.
            self.finished = True
            return
        if kind == "fenced.recipient-confirmed" and self.fenced_recipient_id is not None:
            if (keys != {"request_id", "request_digest", "capability_id",
                         "original_capability_id", "receipt_digest", "recipient_id",
                         "commit_sequence", "recovery", "new_effect_commit"}
                    or not self.authorized or self.finished
                    or payload.get("request_id") != self.request_id
                    or payload.get("request_digest") != self.digest
                    or payload.get("capability_id") != self.current_capability
                    or payload.get("recipient_id") != self.fenced_recipient_id
                    or not isinstance(payload.get("receipt_digest"), str)
                    or not HEX.fullmatch(payload["receipt_digest"])
                    or type(payload.get("commit_sequence")) is not int
                    or payload["commit_sequence"] < 1
                    or type(payload.get("recovery")) is not bool
                    or type(payload.get("new_effect_commit")) is not bool):
                raise GatewayEvidenceContractError("unverified fenced completion envelope")
            if self.original_capability_id is None:
                if (payload["original_capability_id"] != self.capability_id
                        or payload["recovery"] or not payload["new_effect_commit"]):
                    raise GatewayEvidenceContractError("original fenced commit provenance mismatch")
                self.original_capability_id = self.capability_id
            elif (payload["original_capability_id"] != self.original_capability_id
                  or payload["recovery"] is not (
                      payload["capability_id"] != self.original_capability_id)):
                # A newly authorized recovery MAY commit the first effect if
                # the old gateway died before recipient commit, or replay an
                # already committed result. Independent durable observation
                # must corroborate either case before evidence is signed.
                raise GatewayEvidenceContractError("fenced recovery rewrote original authority")
            self.finished = True
            return
        if kind == "execution.authorized":
            if (keys != {"request_id", "request_digest", "capability_id"}
                    or (self.authorized and not self.finished)
                    or payload.get("request_id") != self.request_id
                    or payload.get("request_digest") != self.digest
                    or payload.get("capability_id") != self.current_capability
                    or (not self.authorized and
                        payload.get("capability_id") != self.capability_id)):
                raise GatewayEvidenceContractError("forged or repeated authorization evidence")
            self.authorized = True
            return
        if kind == "execution.dispatch":
            if (keys != {"request_digest", "dispatch_count", "gateway_pid"}
                    or not self.authorized or self.dispatched or self.finished
                    or payload.get("request_digest") != self.digest
                    or type(payload.get("dispatch_count")) is not int
                    or payload["dispatch_count"] != 1
                    or type(payload.get("gateway_pid")) is not int
                    or payload["gateway_pid"] != self.pid):
                raise GatewayEvidenceContractError("forged or out-of-order gateway dispatch")
            self.dispatched = True
            return
        if kind == "execution.completed":
            if (keys != {"request_id", "capability_id", "success",
                         "output_bytes", "effect_state"}
                    or not self.dispatched or self.finished
                    or payload["request_id"] != self.request_id
                    or payload["capability_id"] != self.capability_id
                    or payload["success"] is not True
                    or payload["effect_state"] != "completed"
                    or type(payload["output_bytes"]) is not int
                    or not 0 <= payload["output_bytes"] <= 512):
                raise GatewayEvidenceContractError("forged or out-of-order completion")
            self.finished = True
            return
        if kind == "execution.indeterminate":
            if (keys != {"request_id", "effect_state"}
                    or not self.dispatched or self.finished
                    or payload != {"request_id": self.request_id,
                                   "effect_state": "possibly-committed"}):
                raise GatewayEvidenceContractError("invalid ambiguous-effect evidence")
            self.finished = True
            return
        raise GatewayEvidenceContractError("gateway event type not on allowlist")
