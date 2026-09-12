from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest
from .recorder import ExternalRecorder


@dataclass(frozen=True)
class DeviceEnrollment:
    device_id: str
    public_key_pem: str
    key_id: str
    enrolled_at: str
    revoked_at: str | None = None
    trust_level: str = "hardware"
    assurance_level: str = "hardware-rooted"
    measurements: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MeasurementPolicy:
    policy_id: str
    rules: Mapping[str, Mapping[str, Any]]
    created_at: str
    version: int
    signature: str = ""


class AttestationEnrollmentError(RuntimeError):
    pass


class AttestationRevocationError(RuntimeError):
    pass


class AttestationPolicyError(RuntimeError):
    pass


class ProductionAttestationManager:
    """Production attestation enrollment, provenance validation, measurement policy, revocation, updates."""

    def __init__(
        self,
        recorder: ExternalRecorder,
        enrollment_db_path: str | Path,
        policy_db_path: str | Path,
        signing_key: bytes | Ed25519PrivateKey | None = None,
    ) -> None:
        self.recorder = recorder
        self.enrollment_db_path = Path(enrollment_db_path)
        self.enrollment_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.policy_db_path = Path(policy_db_path)
        self.policy_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes):
            if len(signing_key) < 32:
                raise ValueError("signing seed must be at least 32 bytes")
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        elif signing_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            raise TypeError("unsupported signing key")
        self._public_key = self._private_key.public_key()
        raw_public = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"

        self._enrollment_db = sqlite3.connect(self.enrollment_db_path, check_same_thread=False)
        self._enrollment_db.execute("PRAGMA journal_mode = WAL")
        self._enrollment_db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_enrollments (
                device_id TEXT PRIMARY KEY,
                public_key_pem TEXT NOT NULL,
                key_id TEXT NOT NULL,
                enrolled_at TEXT NOT NULL,
                revoked_at TEXT,
                trust_level TEXT NOT NULL,
                assurance_level TEXT NOT NULL,
                measurements_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            )
            """
        )
        self._enrollment_db.execute(
            """
            CREATE TABLE IF NOT EXISTS enrollment_provenance (
                device_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                PRIMARY KEY (device_id, action, timestamp)
            )
            """
        )
        self._policy_db = sqlite3.connect(self.policy_db_path, check_same_thread=False)
        self._policy_db.execute("PRAGMA journal_mode = WAL")
        self._policy_db.execute(
            """
            CREATE TABLE IF NOT EXISTS measurement_policies (
                policy_id TEXT PRIMARY KEY,
                rules_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                version INTEGER NOT NULL,
                signature TEXT NOT NULL
            )
            """
        )
        self._policy_db.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_provenance (
                policy_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                PRIMARY KEY (policy_id, action, timestamp)
            )
            """
        )

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def close(self) -> None:
        with self._lock:
            if hasattr(self, "_enrollment_db"):
                self._enrollment_db.close()
            if hasattr(self, "_policy_db"):
                self._policy_db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def enroll_device(
        self,
        device_id: str,
        public_key_pem: str,
        *,
        trust_level: str = "hardware",
        assurance_level: str = "hardware-rooted",
        measurements: Mapping[str, str] | None = None,
        metadata: Mapping[str, Any] | None = None,
        actor: str = "operator",
    ) -> DeviceEnrollment:
        """Enroll a new device with its attestation public key."""
        if not device_id or len(device_id) > 256:
            raise AttestationEnrollmentError("invalid device_id")
        if not public_key_pem or len(public_key_pem) > 4096:
            raise AttestationEnrollmentError("invalid public_key_pem")

        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            if not isinstance(public_key, Ed25519PublicKey):
                raise AttestationEnrollmentError("public key must be Ed25519")
        except Exception as exc:
            raise AttestationEnrollmentError(f"invalid public key: {exc}") from exc

        raw_public = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        key_id = f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"

        with self._lock:
            existing = self._enrollment_db.execute(
                "SELECT device_id FROM device_enrollments WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if existing:
                raise AttestationEnrollmentError(f"device {device_id} already enrolled")

            existing_key = self._enrollment_db.execute(
                "SELECT device_id FROM device_enrollments WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            if existing_key:
                raise AttestationEnrollmentError(f"key {key_id} already enrolled to another device")

            enrolled_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            enrollment = DeviceEnrollment(
                device_id=device_id,
                public_key_pem=public_key_pem,
                key_id=key_id,
                enrolled_at=enrolled_at,
                trust_level=trust_level,
                assurance_level=assurance_level,
                measurements=measurements or {},
                metadata=metadata or {},
            )

            self._enrollment_db.execute(
                """
                INSERT INTO device_enrollments
                (device_id, public_key_pem, key_id, enrolled_at, revoked_at, trust_level, assurance_level, measurements_json, metadata_json)
                VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    public_key_pem,
                    key_id,
                    enrolled_at,
                    trust_level,
                    assurance_level,
                    json.dumps(dict(measurements or {})),
                    json.dumps(dict(metadata or {})),
                ),
            )
            self._enrollment_db.commit()

            self._record_provenance(device_id, "enroll", actor, {
                "key_id": key_id,
                "trust_level": trust_level,
                "assurance_level": assurance_level,
                "measurements": dict(measurements or {}),
                "metadata": dict(metadata or {}),
            })

            self.recorder.append("attestation.device_enrolled", {
                "device_id": device_id,
                "key_id": key_id,
                "actor": actor,
                "enrolled_at": enrolled_at,
            })

            return enrollment

    def revoke_device(
        self,
        device_id: str,
        *,
        reason: str,
        actor: str = "operator",
    ) -> DeviceEnrollment:
        """Revoke a device's attestation credentials."""
        revoked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            row = self._enrollment_db.execute(
                "SELECT * FROM device_enrollments WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if not row:
                raise AttestationRevocationError(f"device {device_id} not enrolled")
            if row[4] is not None:
                raise AttestationRevocationError(f"device {device_id} already revoked")

            self._enrollment_db.execute(
                "UPDATE device_enrollments SET revoked_at = ? WHERE device_id = ?",
                (revoked_at, device_id),
            )
            self._enrollment_db.commit()

            self._record_provenance(device_id, "revoke", actor, {
                "reason": reason,
                "revoked_at": revoked_at,
            })

            self.recorder.append("attestation.device_revoked", {
                "device_id": device_id,
                "reason": reason,
                "actor": actor,
                "revoked_at": revoked_at,
            })

            return self._row_to_enrollment(row, revoked_at=revoked_at)

    def get_enrollment(self, device_id: str) -> DeviceEnrollment | None:
        """Get device enrollment by ID."""
        row = self._enrollment_db.execute(
            "SELECT * FROM device_enrollments WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_enrollment(row)

    def is_device_active(self, device_id: str) -> bool:
        """Check if a device is enrolled and not revoked."""
        enrollment = self.get_enrollment(device_id)
        return enrollment is not None and enrollment.revoked_at is None

    def validate_provenance(self, device_id: str) -> list[Mapping[str, Any]]:
        """Get the provenance chain for a device."""
        rows = self._enrollment_db.execute(
            "SELECT action, actor, timestamp, details_json, signature FROM enrollment_provenance WHERE device_id = ? ORDER BY timestamp",
            (device_id,),
        ).fetchall()
        return [
            {
                "action": row[0],
                "actor": row[1],
                "timestamp": row[2],
                "details": json.loads(row[3]),
                "signature": row[4],
            }
            for row in rows
        ]

    def _record_provenance(
        self,
        device_id: str,
        action: str,
        actor: str,
        details: Mapping[str, Any],
    ) -> None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = {
            "device_id": device_id,
            "action": action,
            "actor": actor,
            "timestamp": timestamp,
            "details": details,
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(payload))
        ).rstrip(b"=").decode("ascii")
        self._enrollment_db.execute(
            """
            INSERT INTO enrollment_provenance
            (device_id, action, actor, timestamp, details_json, signature)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (device_id, action, actor, timestamp, json.dumps(details), signature),
        )
        self._enrollment_db.commit()

    def _row_to_enrollment(self, row, revoked_at: str | None = None) -> DeviceEnrollment:
        return DeviceEnrollment(
            device_id=row[0],
            public_key_pem=row[1],
            key_id=row[2],
            enrolled_at=row[3],
            revoked_at=revoked_at or row[4],
            trust_level=row[5],
            assurance_level=row[6],
            measurements=json.loads(row[7]),
            metadata=json.loads(row[8]),
        )

    def create_measurement_policy(
        self,
        policy_id: str,
        rules: Mapping[str, Mapping[str, Any]],
        *,
        actor: str = "operator",
    ) -> MeasurementPolicy:
        """Create a new measurement policy."""
        if not policy_id or len(policy_id) > 256:
            raise AttestationPolicyError("invalid policy_id")

        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            row = self._policy_db.execute(
                "SELECT version FROM measurement_policies WHERE policy_id = ?",
                (policy_id,),
            ).fetchone()
            version = (row[0] + 1) if row else 1

            payload = {
                "policy_id": policy_id,
                "rules": dict(rules),
                "created_at": created_at,
                "version": version,
            }
            signature = base64.urlsafe_b64encode(
                self._private_key.sign(canonical_bytes(payload))
            ).rstrip(b"=").decode("ascii")

            self._policy_db.execute(
                """
                INSERT OR REPLACE INTO measurement_policies
                (policy_id, rules_json, created_at, version, signature)
                VALUES (?, ?, ?, ?, ?)
                """,
                (policy_id, json.dumps(dict(rules)), created_at, version, signature),
            )
            self._policy_db.commit()

            self._record_policy_provenance(policy_id, "create" if not row else "update", actor, {
                "rules": dict(rules),
                "version": version,
            })

            self.recorder.append("attestation.policy_created" if not row else "attestation.policy_updated", {
                "policy_id": policy_id,
                "version": version,
                "actor": actor,
                "created_at": created_at,
            })

            return MeasurementPolicy(
                policy_id=policy_id,
                rules=rules,
                created_at=created_at,
                version=version,
                signature=signature,
            )

    def revoke_measurement_policy(
        self,
        policy_id: str,
        *,
        reason: str,
        actor: str = "operator",
    ) -> None:
        """Revoke a measurement policy."""
        with self._lock:
            row = self._policy_db.execute(
                "SELECT * FROM measurement_policies WHERE policy_id = ?",
                (policy_id,),
            ).fetchone()
            if not row:
                raise AttestationPolicyError(f"policy {policy_id} not found")

            self._policy_db.execute(
                "DELETE FROM measurement_policies WHERE policy_id = ?",
                (policy_id,),
            )
            self._policy_db.commit()

            self._record_policy_provenance(policy_id, "revoke", actor, {
                "reason": reason,
            })

            self.recorder.append("attestation.policy_revoked", {
                "policy_id": policy_id,
                "reason": reason,
                "actor": actor,
            })

    def get_measurement_policy(self, policy_id: str) -> MeasurementPolicy | None:
        """Get measurement policy by ID."""
        row = self._policy_db.execute(
            "SELECT * FROM measurement_policies WHERE policy_id = ?",
            (policy_id,),
        ).fetchone()
        if not row:
            return None
        return MeasurementPolicy(
            policy_id=row[0],
            rules=json.loads(row[1]),
            created_at=row[2],
            version=row[3],
            signature=row[4],
        )

    def verify_policy_signature(self, policy: MeasurementPolicy) -> bool:
        """Verify a measurement policy's signature."""
        try:
            payload = {
                "policy_id": policy.policy_id,
                "rules": dict(policy.rules),
                "created_at": policy.created_at,
                "version": policy.version,
            }
            public_key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
            sig = base64.urlsafe_b64decode(policy.signature + "=" * (-len(policy.signature) % 4))
            public_key.verify(sig, canonical_bytes(payload))
            return True
        except Exception:
            return False

    def _record_policy_provenance(
        self,
        policy_id: str,
        action: str,
        actor: str,
        details: Mapping[str, Any],
    ) -> None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = {
            "policy_id": policy_id,
            "action": action,
            "actor": actor,
            "timestamp": timestamp,
            "details": details,
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(payload))
        ).rstrip(b"=").decode("ascii")
        self._policy_db.execute(
            """
            INSERT INTO policy_provenance
            (policy_id, action, actor, timestamp, details_json, signature)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (policy_id, action, actor, timestamp, json.dumps(details), signature),
        )
        self._policy_db.commit()

    def verify_attestation_bundle(
        self,
        bundle: Mapping[str, Any],
        *,
        nonce: str,
        nonce_context: Mapping[str, Any],
        measurement_policy: MeasurementPolicy | None = None,
        max_proof_age_seconds: int = 300,
        max_future_skew_seconds: int = 10,
    ) -> Mapping[str, Any]:
        """Verify a production attestation bundle with provenance checks."""
        if bundle.get("version") != "eh-attestation-1":
            return {"valid": False, "reason": "unsupported bundle version", "code": "MALFORMED_BUNDLE"}

        if bundle.get("method") not in {"tpm2", "secure-enclave", "android-keystore"}:
            return {"valid": False, "reason": "unsupported attestation method", "code": "UNSUPPORTED_METHOD"}

        device_id = bundle.get("deviceId")
        if not device_id or not isinstance(device_id, str):
            return {"valid": False, "reason": "missing deviceId", "code": "MALFORMED_BUNDLE"}

        enrollment = self.get_enrollment(device_id)
        if not enrollment:
            return {"valid": False, "reason": "device not enrolled", "code": "UNKNOWN_DEVICE"}

        if enrollment.revoked_at is not None:
            return {"valid": False, "reason": "device credentials revoked", "code": "DEVICE_REVOKED"}

        if enrollment.key_id != bundle.get("keyId"):
            return {"valid": False, "reason": "key ID mismatch", "code": "KEY_ID_MISMATCH"}

        if bundle.get("nonce") != nonce:
            return {"valid": False, "reason": "nonce mismatch", "code": "NONCE_MISMATCH"}

        issued_at = bundle.get("issuedAt")
        expires_at = bundle.get("expiresAt")
        if not issued_at or not expires_at:
            return {"valid": False, "reason": "missing timestamps", "code": "MALFORMED_BUNDLE"}

        try:
            import calendar
            issued_ts = calendar.timegm(time.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ"))
            expires_ts = calendar.timegm(time.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ"))
            now_ts = time.time()
        except Exception:
            return {"valid": False, "reason": "invalid timestamp format", "code": "MALFORMED_BUNDLE"}

        if expires_ts <= issued_ts:
            return {"valid": False, "reason": "expiresAt before issuedAt", "code": "MALFORMED_BUNDLE"}

        if issued_ts > now_ts + max_future_skew_seconds:
            return {"valid": False, "reason": "attestation from future", "code": "PROOF_FROM_FUTURE"}

        if expires_ts < now_ts:
            return {"valid": False, "reason": "attestation expired", "code": "PROOF_EXPIRED"}

        if now_ts - issued_ts > max_proof_age_seconds:
            return {"valid": False, "reason": "attestation too old", "code": "PROOF_TOO_OLD"}

        if measurement_policy:
            measurements = bundle.get("measurements", {})
            for register, rule in measurement_policy.rules.items():
                actual = measurements.get(register)
                allowed = (rule.get("type") == "exact" and actual == rule.get("value")) or \
                          (rule.get("type") == "oneOf" and actual in rule.get("values", []))
                if not allowed:
                    return {"valid": False, "reason": f"measurement {register} failed policy", "code": "MEASUREMENT_POLICY_FAILED"}

        public_key_pem = enrollment.public_key_pem
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            if not isinstance(public_key, Ed25519PublicKey):
                return {"valid": False, "reason": "enrolled key not Ed25519", "code": "KEY_ID_MISMATCH"}
        except Exception:
            return {"valid": False, "reason": "enrolled public key invalid", "code": "KEY_ID_MISMATCH"}

        bundle_copy = dict(bundle)
        signature = bundle_copy.pop("signature", None)
        if not signature:
            return {"valid": False, "reason": "missing signature", "code": "MALFORMED_BUNDLE"}

        padding = "=" * (-len(signature) % 4)
        sig_bytes = base64.urlsafe_b64decode(signature + padding)
        try:
            public_key.verify(sig_bytes, canonical_bytes(bundle_copy))
        except InvalidSignature:
            return {"valid": False, "reason": "invalid signature", "code": "INVALID_SIGNATURE"}

        provenance = self.validate_provenance(device_id)
        has_enroll = any(p["action"] == "enroll" for p in provenance)
        if not has_enroll:
            return {"valid": False, "reason": "missing enrollment provenance", "code": "PROVENANCE_INCOMPLETE"}

        return {
            "valid": True,
            "device_id": device_id,
            "trust_level": enrollment.trust_level,
            "assurance_level": enrollment.assurance_level,
            "key_id": enrollment.key_id,
            "measurements": bundle.get("measurements", {}),
            "provenance": provenance,
        }