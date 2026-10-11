"""Owned, effect-safe fuzz entrypoints for EHH's actual parsing/authority code.

Atheris provides coverage guidance in a SEPARATE process per target.
These entrypoints do not make network requests, run guest commands,
contact etcd, or execute any caller-selected code or external effects.

The gateway target uses the real DatasetEffectBoundary with a synthetic
read-only fixture and local temporary SQLite replay/decay state. Both
fully framed wire inputs and structured, signature-preserving mutations
are tested so deeper branches are reachable under coverage fuzzing.
"""
from __future__ import annotations

import copy
import io
import json
import struct
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

from event_horizon.broker import CapabilityBroker, CapabilityError, CapabilityVerifier
from event_horizon.canonical import (
    CanonicalizationError, canonical_bytes, strict_json_loads,
)
from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.models import ActionRequest, IssuedCapability, ValidationError
from event_horizon.protocol import ProtocolError, encode_frame, read_frame
from scripts.capability_fixture_support import authority_context, issue_options, verify_options

TARGETS = ("frame", "canonical", "capability", "gateway")
MAX_INPUT_BYTES = 65_540  # 4-byte prefix plus protocol's 65,536-byte body
_MUTATION = 0xF0
_FIXED_ID = b"fuzz-research-only"


class _Recorder:
    def __init__(self):
        self.counts: Counter[str] = Counter()

    def append(self, event_type: str, _payload: Any):
        self.counts[event_type] += 1
        return {"acknowledged": True}


def _changed(value: Any) -> Any:
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if isinstance(value, str):
        return value + "-tampered"
    if isinstance(value, dict):
        return {**value, "unexpected_fuzz_field": "tampered"}
    if isinstance(value, list):
        return value + ["tampered"]
    return "tampered"


def _mutated_capability(original: dict[str, Any], data: bytes) -> dict[str, Any]:
    """Always change a signed value, its signature, or its key binding."""
    altered = copy.deepcopy(original)
    mode = (data[1] if len(data) > 1 else 0) % 4
    if mode == 0:
        fields = sorted(altered["claims"])
        field = fields[(data[2] if len(data) > 2 else 0) % len(fields)]
        altered["claims"][field] = _changed(altered["claims"][field])
    elif mode == 1:
        altered["signature"] = "A" * 86
    elif mode == 2:
        altered["key_id"] = "ed25519:" + "0" * 32
    else:
        altered["algorithm"] = "None"
    return altered


def _mutated_gateway(original: dict[str, Any], data: bytes) -> tuple[dict[str, Any], int]:
    altered = copy.deepcopy(original)
    mode = (data[1] if len(data) > 1 else 0) % 9
    uid = 60000
    if mode == 0:
        altered["request"]["arguments"]["offset"] = 1
    elif mode == 1:
        altered["request"]["operation"] = "network.connect"
    elif mode == 2:
        altered["request"]["resource_id"] = "synthetic-credential"
    elif mode == 3:
        altered["request"]["executor_id"] = "different-executor"
    elif mode == 4:
        altered["request"]["session_id"] = "different-session"
    elif mode == 5:
        altered["capability"] = _mutated_capability(original["capability"], b"\xf0\x00\x00")
    elif mode == 6:
        altered["authority_backend"] = "memory"
    elif mode == 7:
        altered["request"]["arguments"]["length"] = 513
    else:
        uid = 60042
    return altered, uid


class FuzzTargets:
    """A single fuzz worker has its own disposable state and immutable key."""

    def __init__(self, target: str):
        if target not in TARGETS:
            raise ValueError("unknown fuzz target")
        self.target = target
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.boundary: DatasetEffectBoundary | None = None
        self.recorder: _Recorder | None = None
        self.valid_capability: bytes = b""
        self.valid_gateway: bytes = b""
        self._accepted_gateway = False
        self._verify_kwargs: dict[str, Any] = {}
        if target in {"capability", "gateway"}:
            self._make_fixture()

    def _make_fixture(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="ehh-fuzz-owned-")
        request = ActionRequest(
            "fuzz-test-read", "ehh-fuzz-session", "attacker-agent",
            "object.read", "synthetic-dataset", "exec-1",
            {"offset": 0, "length": 5}, "owned synthetic fuzz fixture",
        )
        context = authority_context(request, time.time())
        # This test-only seed has NO relationship to installed EHH authority.
        broker = CapabilityBroker(b"ehh-fuzz-local-only-key-32-bytes!!", ttl_seconds=300)
        capability = broker.issue(
            request, **issue_options(context), max_output_bytes=4096,
        )
        self.baseline_capability = capability.to_dict()
        self.baseline_gateway = {
            "request": request.canonical_payload(),
            "capability": capability.to_dict(),
        }
        self.valid_capability = canonical_bytes(self.baseline_capability)
        self.valid_gateway = canonical_bytes(self.baseline_gateway)
        self.request = request
        self.verifier = CapabilityVerifier(broker.public_key_pem, broker.key_id)
        self._verify_kwargs = verify_options(context)
        self.recorder = _Recorder()
        if self.target == "gateway":
            directory = Path(self._temporary.name)
            self.boundary = DatasetEffectBoundary({
                "verification_context": {
                    **{key: context[key] for key in (
                        "device_id", "executor_measurement",
                        "verifier_policy_digest", "policy_digest", "attestation",
                    )},
                    "tenant": "default", "environment": "synthetic",
                },
                "public_key_pem": broker.public_key_pem,
                "key_id": broker.key_id,
                "dataset": "hello-owned-only",
                "session_id": request.session_id,
                "resource_id": request.resource_id,
                "vm_uid": 60000,
                "replay_database": str(directory / "local-replay.sqlite"),
                "decay_database": str(directory / "local-decay.sqlite"),
            }, self.recorder)

    def close(self) -> None:
        if self.boundary is not None:
            self.boundary.close()
            self.boundary = None
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None

    def seeds(self) -> list[bytes]:
        if self.target == "frame":
            valid = encode_frame({"type": "ping", "request_id": "fuzz-1",
                                  "deadline_ms": 1_700_000_000_000, "body": {}})
            ambiguous = b'{"a":1,"a":2}'
            noncanonical = b'{"b":2, "a":1}'
            return [
                valid, valid[:-1], valid + b"trailing",
                struct.pack(">I", len(ambiguous)) + ambiguous,
                struct.pack(">I", len(noncanonical)) + noncanonical,
                struct.pack(">I", 65_537), b"\x00\x00\x00\x00",
                b"\xff\xff\xff\xff",
            ]
        if self.target == "canonical":
            return [
                b'{"a":1}', b'{"a":1,"a":2}', b'{"x":1.0}',
                b'{"x":"safe"}', b'["nested",{"a":true}]',
                b'{"x":-0}', b'{"x":"\xff"}',
            ]
        if self.target == "capability":
            return [self.valid_capability, b"\xf0\x00\x00", b"\xf0\x01",
                    b"\xf0\x02", b"\xf0\x03", b'{"claims":{}}']
        return [self.valid_gateway, *[bytes((_MUTATION, x)) for x in range(9)],
                b'{"request":{},"capability":{}}']

    def exercise(self, data: bytes) -> str:
        if not isinstance(data, bytes):
            raise TypeError("fuzz input must be raw bytes")
        if len(data) > MAX_INPUT_BYTES:
            return "bounded-rejection"

        if self.target == "frame":
            stream = io.BytesIO(data)
            try:
                parsed = read_frame(stream)
            except (ProtocolError, CanonicalizationError, EOFError):
                return "rejected"
            # A successful parse MUST bind exactly to the consumed bytes.
            consumed = stream.tell()
            if encode_frame(parsed) != data[:consumed]:
                raise AssertionError("frame accepted noncanonical or mismatched bytes")
            return "accepted"

        if self.target == "canonical":
            try:
                value = strict_json_loads(data, require_canonical=True)
            except CanonicalizationError:
                return "rejected"
            if canonical_bytes(value) != data:
                raise AssertionError("strict canonical parser accepted ambiguous bytes")
            return "accepted"

        if self.target == "capability":
            try:
                if data.startswith(bytes((_MUTATION,))):
                    parsed = _mutated_capability(self.baseline_capability, data)
                else:
                    parsed = strict_json_loads(data, require_canonical=True)
                capability = IssuedCapability.from_dict(parsed)
            except (CanonicalizationError, ValidationError, ValueError, TypeError, KeyError):
                return "rejected"
            try:
                self.verifier.verify_and_consume(
                    capability, self.request, **self._verify_kwargs,
                )
            except (CapabilityError, ValueError):
                return "rejected"
            if canonical_bytes(parsed) != self.valid_capability:
                raise AssertionError("altered signed capability was authorized")
            return "accepted"

        assert self.boundary is not None
        uid = 60000
        try:
            if data.startswith(bytes((_MUTATION,))):
                parsed, uid = _mutated_gateway(self.baseline_gateway, data)
            else:
                parsed = strict_json_loads(data, require_canonical=True)
        except CanonicalizationError:
            return "rejected"
        result = self.boundary.execute(parsed, peer_uid=uid)
        if type(result.get("success")) is not bool:
            raise AssertionError("host gate produced malformed success value")
        if result["success"]:
            if uid != 60000 or canonical_bytes(parsed) != self.valid_gateway:
                raise AssertionError("unauthorized host effect was dispatched")
            if self._accepted_gateway:
                raise AssertionError("same capability executed twice")
            self._accepted_gateway = True
            if self.recorder is None or self.recorder.counts["execution.completed"] != 1:
                raise AssertionError("effect succeeded without exactly one trusted completion")
        elif result.get("effect_state") != "not-started":
            raise AssertionError("gateway denial may have committed an effect")
        return "accepted" if result["success"] else "denied"


def run_case(target: str, data: bytes) -> str:
    harness = FuzzTargets(target)
    try:
        return harness.exercise(data)
    finally:
        harness.close()
