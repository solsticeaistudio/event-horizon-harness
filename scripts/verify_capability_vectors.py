#!/usr/bin/env python3
"""Independently verify the committed public capability test vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from event_horizon.broker import CapabilityError, CapabilityVerifier
from event_horizon.models import ActionRequest, IssuedCapability, ValidationError
from event_horizon.replay_state import InMemoryCapabilityConsumptionStore


VECTOR_FIELDS = {
    "schema", "description", "public_key_pem", "request", "capability",
    "context", "verification_time", "preconsume", "expected",
}
CONTEXT_FIELDS = {
    "device_id", "executor_measurement", "attestation",
    "verifier_policy_digest", "policy_digest", "tenant", "environment",
}


def verify_vector(payload: dict[str, Any]) -> tuple[bool, str]:
    try:
        if set(payload) != VECTOR_FIELDS or payload["schema"] != "event-horizon.capability-test-vector.v1":
            raise ValidationError("test vector schema fields are invalid")
        context = payload["context"]
        if not isinstance(context, dict) or set(context) != CONTEXT_FIELDS:
            raise ValidationError("test vector context fields are invalid")
        request = ActionRequest.from_dict(payload["request"])
        capability = IssuedCapability.from_dict(payload["capability"])
        verifier = CapabilityVerifier(
            payload["public_key_pem"], capability.key_id, InMemoryCapabilityConsumptionStore()
        )
        options = {**context, "now": payload["verification_time"]}
        if payload["preconsume"] is True:
            verifier.verify_and_consume(capability, request, **options)
        verifier.verify_and_consume(capability, request, **options)
        return True, "accepted"
    except (CapabilityError, ValidationError, TypeError, ValueError) as exc:
        return False, str(exc)


def main(argv: list[str] | None = None) -> int:
    paths = [Path(value) for value in (argv or sys.argv[1:])]
    if not paths:
        paths = sorted((Path(__file__).resolve().parents[1] / "test-vectors").glob("*.json"))
    failures = 0
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        actual_valid, actual_reason = verify_vector(payload)
        expected = payload.get("expected", {})
        passed = actual_valid is expected.get("valid") and str(expected.get("reason", "")) in actual_reason
        print(f"{path.name}: {'PASS' if passed else 'FAIL'} ({actual_reason})")
        failures += not passed
    return int(failures > 0)


if __name__ == "__main__":
    raise SystemExit(main())
