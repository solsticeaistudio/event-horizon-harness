from __future__ import annotations

import json
import os
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol

from .canonical import digest


class AttestationError(RuntimeError):
    pass


class AttestationProvider(Protocol):
    def verify_executor(
        self,
        executor_id: str,
        session_id: str,
        purpose: str,
    ) -> Mapping[str, Any]: ...


@dataclass
class StaticAttestationProvider:
    """Explicit development fallback for tests that do not run Executor Attestation."""

    measurements: Mapping[str, str]

    def verify_executor(
        self,
        executor_id: str,
        session_id: str,
        purpose: str,
    ) -> Mapping[str, Any]:
        measurement = self.measurements.get(executor_id)
        if not measurement:
            raise AttestationError("executor has no trusted measurement")
        result = {
            "valid": True,
            "deviceId": executor_id,
            "method": "static-development",
            "trustLevel": "software",
            "assuranceLevel": "development",
            "measurements": {"executor": measurement},
            "bundleDigest": digest({
                "provider": "static-development",
                "deviceId": executor_id,
                "executorMeasurement": measurement,
                "sessionId": session_id,
                "purpose": purpose,
            }),
            "keyId": "static-development:no-external-authority",
            "verifiedAt": "1970-01-01T00:00:00.000Z",
            "nonceContext": {
                "deviceId": executor_id,
                "executorId": executor_id,
                "sessionId": session_id,
                "purpose": purpose,
            },
            "nonceIssuedAt": "1970-01-01T00:00:00.000Z",
            "nonceExpiresAt": "1970-01-01T00:00:00.001Z",
        }
        result["verifierPolicyDigest"] = digest({
            "provider": "static-development",
            "deviceId": executor_id,
            "executorMeasurement": measurement,
        })
        result["resultDigest"] = digest(result)
        return result


@dataclass
class DevelopmentAttestationProvider:
    """Runs the rebuilt Executor Attestation verifier outside the hostile executor.

    This provider is intentionally a development bridge. The production trusted
    path will use a fixed local protocol and a separately administered verifier.
    No successful result is cached: every call creates and consumes a fresh,
    session-bound challenge before returning evidence for capability issuance.
    """

    attestation_root: Path
    device_seeds: Mapping[str, str]
    node_binary: str = "node"
    timeout_seconds: float = 10.0
    replay_database: Path | None = None
    replay_namespace: str = "event-horizon"
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)

    def verify_executor(
        self,
        executor_id: str,
        session_id: str,
        purpose: str,
    ) -> Mapping[str, Any]:
        seed = self.device_seeds.get(executor_id)
        if not seed:
            raise AttestationError("executor is not enrolled with Executor Attestation")
        with self._lock:
            script = self.attestation_root / "bridge" / "verify-executor.mjs"
            if not script.exists():
                raise AttestationError(f"Executor Attestation bridge missing: {script}")
            try:
                environment = os.environ.copy()
                if self.replay_database is not None:
                    environment["EH_ATTESTATION_REPLAY_DB"] = str(self.replay_database.resolve())
                    environment["EH_ATTESTATION_REPLAY_NAMESPACE"] = self.replay_namespace
                # The enrollment seed travels over stdin: process command
                # lines are world-readable via the OS process listing.
                completed = subprocess.run(
                    [self.node_binary, str(script), executor_id, session_id, purpose],
                    input=f"{seed}\n",
                    cwd=self.attestation_root,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    env=environment,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise AttestationError(f"Executor Attestation verifier unavailable: {exc}") from exc
            if completed.returncode != 0:
                detail = completed.stderr.strip() or completed.stdout.strip() or "unknown verifier failure"
                raise AttestationError(f"Executor Attestation verification failed: {detail}")
            try:
                result = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise AttestationError("Executor Attestation verifier returned malformed JSON") from exc
            if not isinstance(result, dict) or not result.get("valid"):
                raise AttestationError(str(result.get("failureReason", "attestation rejected")))
            if result.get("deviceId") != executor_id:
                raise AttestationError("Executor Attestation result device identity mismatch")
            expected_context = {
                "deviceId": executor_id,
                "executorId": executor_id,
                "sessionId": session_id,
                "purpose": purpose,
            }
            if result.get("nonceContext") != expected_context:
                raise AttestationError("Executor Attestation result nonce context mismatch")
            if not result.get("nonceIssuedAt") or not result.get("nonceExpiresAt"):
                raise AttestationError("Executor Attestation result omitted nonce lifetime")
            measurements = result.get("measurements")
            if not isinstance(measurements, dict) or not measurements.get("executor"):
                raise AttestationError("Executor Attestation result omitted executor measurement")
            if not result.get("bundleDigest") or not result.get("keyId"):
                raise AttestationError("Executor Attestation result omitted proof or key identity")
            result["verifierPolicyDigest"] = digest({
                "provider": "attestation-development-bridge",
                "deviceId": executor_id,
                "minimumTrust": "simulated",
                "expectedExecutorMeasurement": measurements["executor"],
            })
            result["resultDigest"] = digest(result)
            return result
