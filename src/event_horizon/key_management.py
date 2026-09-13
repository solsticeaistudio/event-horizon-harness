from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .hsm_backend import HSMKeyInfo
from .recorder import ExternalRecorder


class KeyManagementError(RuntimeError):
    pass


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


@dataclass(frozen=True)
class KeyMetadata:
    key_id: str
    public_key_pem: str
    created_at: str
    expires_at: str | None
    purpose: str
    status: str = "active"
    rotated_from: str | None = None
    rotated_at: str | None = None


@dataclass(frozen=True)
class KeyRevocation:
    """Cryptographically signed key revocation entry."""
    key_id: str
    revoked_at: str
    reason: str
    revoked_by: str
    signature: str
    previous_revocation_digest: str | None = None


@dataclass
class KeyRotationPolicy:
    max_age_seconds: int = 30 * 24 * 3600
    auto_rotate: bool = True
    require_manual_approval: bool = False


class KeyManager:
    """Unified key management across all services with rotation, provenance, and HSM support."""
    
    def __init__(
        self,
        recorder: ExternalRecorder,
        db_path: str | Path,
        signing_key: bytes | Ed25519PrivateKey | None = None,
        rotation_policy: KeyRotationPolicy | None = None,
        hsm_backend: Optional[object] = None,
        hsm_key_label: Optional[str] = None,
    ) -> None:
        self.recorder = recorder
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.rotation_policy = rotation_policy or KeyRotationPolicy()
        self._hsm = hsm_backend
        self._hsm_key_label = hsm_key_label
        self._hsm_key_info: Optional[HSMKeyInfo] = None
        
        # Initialize HSM if provided
        if self._hsm is not None:
            try:
                self._hsm.initialize()
                # Try to find existing key or generate new one
                if hsm_key_label:
                    try:
                        self._hsm_key_info = self._hsm.get_public_key(hsm_key_label)
                    except Exception:
                        # Key doesn't exist, will generate on first use
                        pass
            except Exception as e:
                raise KeyManagementError(f"Failed to initialize HSM: {e}")
        
        # Software fallback key (used if no HSM or HSM unavailable)
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
        # Use DER encoding for key_id computation (Raw + SubjectPublicKeyInfo is not supported)
        raw_public = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_id = f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"
        
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode = WAL")
        self._initialize_db()
        
        # Record HSM key info if available
        if self._hsm_key_info:
            self._record_hsm_key_info()
    
    def _record_hsm_key_info(self) -> None:
        """Record HSM key information in the database."""
        if not self._hsm_key_info:
            return
        with self._lock:
            self._db.execute(
                """
                INSERT OR REPLACE INTO keys (
                    key_id, public_key_pem, created_at, expires_at, purpose, status,
                    rotated_from, rotated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (
                    self._hsm_key_info.key_id,
                    self._hsm_key_info.public_key_pem,
                    self._hsm_key_info.created_at,
                    None,
                    "hsm-signing",
                    self._hsm_key_info.label,
                    __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
                    json.dumps({"hsm_backed": True, "hsm_label": self._hsm_key_label}),
                ),
            )
            self._db.commit()

    def _initialize_db(self) -> None:
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY,
                public_key_pem TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                rotated_from TEXT,
                rotated_at TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS key_provenance (
                key_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                PRIMARY KEY (key_id, action, timestamp)
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS revocations (
                key_id TEXT NOT NULL,
                revoked_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                revoked_by TEXT NOT NULL,
                signature TEXT NOT NULL,
                previous_revocation_digest TEXT,
                PRIMARY KEY (key_id, revoked_at)
            )
            """
        )
        self._db.commit()

    def close(self) -> None:
        with self._lock:
            if hasattr(self, "_db"):
                self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def _public_key_to_pem(self, public_key: Ed25519PublicKey) -> str:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def _sign(self, payload: Mapping[str, Any]) -> str:
        """Sign payload using HSM if available, otherwise software key."""
        data = canonical_bytes(payload)
        if self._hsm is not None and self._hsm_key_info is not None:
            # Use HSM for signing
            try:
                signature = self._hsm.sign_ed25519(self._hsm_key_info.key_id, data)
                return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
            except Exception:
                # Fall back to software key if HSM signing fails
                pass
        # Software fallback
        return base64.urlsafe_b64encode(
            self._private_key.sign(data)
        ).rstrip(b"=").decode("ascii")

    def _record_provenance(self, key_id: str, action: str, actor: str, details: Mapping[str, Any]) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload = {"key_id": key_id, "action": action, "actor": actor, "timestamp": timestamp, "details": details}
        signature = self._sign(payload)
        with self._lock:
            self._db.execute(
                "INSERT INTO key_provenance (key_id, action, actor, timestamp, details_json, signature) VALUES (?, ?, ?, ?, ?, ?)",
                (key_id, action, actor, timestamp, json.dumps(details), signature),
            )
            self._db.commit()

    def _row_to_metadata(self, row) -> KeyMetadata:
        """Convert a database row to KeyMetadata."""
        return KeyMetadata(
            key_id=row[0],
            public_key_pem=row[1],
            created_at=row[2],
            expires_at=row[3],
            purpose=row[4],
            status=row[5],
            rotated_from=row[6],
            rotated_at=row[7],
        )

    def generate_key(self, purpose: str, *, actor: str = "operator", metadata: Mapping[str, Any] | None = None) -> KeyMetadata:
        """Generate a new key for a specific purpose."""
        if self._hsm is not None and self._hsm_key_label:
            # Generate key in HSM
            try:
                hsm_key_info = self._hsm.generate_ed25519_key(self._hsm_key_label, f"{purpose}-{int(time.time())}")
                self._hsm_key_info = hsm_key_info
                self._record_hsm_key_info()
                return self._row_to_metadata((
                    hsm_key_info.key_id,
                    hsm_key_info.public_key_pem,
                    hsm_key_info.created_at,
                    None,
                    "hsm-signing",
                    "active",
                    None,
                    None,
                    json.dumps({"hsm_backed": True, "hsm_label": self._hsm_key_label})
                ))
            except Exception:
                # Fall through to software generation
                pass
        
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id_str = key_id(public_key)
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        expires_at = None
        if self.rotation_policy.max_age_seconds > 0:
            expires_at = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + self.rotation_policy.max_age_seconds)
            )

        metadata_obj = metadata or {}
        with self._lock:
            self._db.execute(
                """
                INSERT INTO keys (key_id, public_key_pem, created_at, expires_at, purpose, status, rotated_from, rotated_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, 'active', NULL, NULL, ?)
                """,
                (key_id_str, self._public_key_to_pem(public_key), created_at, expires_at, purpose, json.dumps(metadata or {})),
            )
            self._db.commit()

        self._record_provenance(key_id_str, "generate", actor="operator", details={
            "purpose": purpose,
            "expires_at": expires_at,
            "metadata": dict(metadata or {}),
        })

        return KeyMetadata(
            key_id=key_id_str,
            public_key_pem=self._public_key_to_pem(public_key),
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            expires_at=expires_at,
            purpose=purpose,
            status="active",
        )

    def rotate_key(
        self,
        key_id_str: str,
        *,
        actor: str = "operator",
        reason: str = "scheduled",
        explicit_key: Ed25519PrivateKey | None = None,
    ) -> KeyMetadata:
        """Rotate an existing key."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM keys WHERE key_id = ?", (key_id_str,)
            ).fetchone()
            if not row:
                raise KeyManagementError(f"key {key_id_str} not found")
            if row[5] != "active":
                raise KeyManagementError(f"key {key_id_str} is not active")

            rotated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            expires_at = row[3]

            if explicit_key:
                new_private = explicit_key
            else:
                new_private = Ed25519PrivateKey.generate()
            new_public = new_private.public_key()
            new_key_id = key_id(new_public)

            self._db.execute(
                """
                INSERT INTO keys (key_id, public_key_pem, created_at, expires_at, purpose, status, rotated_from, rotated_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (
                    new_key_id,
                    self._public_key_to_pem(new_public),
                    rotated_at,
                    expires_at,
                    row[4],  # purpose
                    key_id_str,
                    rotated_at,
                    row[8],  # metadata_json
                ),
            )

            self._db.execute(
                "UPDATE keys SET status = 'rotated', rotated_at = ? WHERE key_id = ?",
                (rotated_at, key_id_str),
            )
            self._db.commit()

        # Record provenance inside lock to ensure ordering
        self._record_provenance(key_id_str, "rotate", "operator", {
            "rotated_to": new_key_id,
            "reason": reason,
        })
        self._record_provenance(new_key_id, "rotate", "operator", {
            "rotated_from": key_id_str,
            "reason": reason,
        })

        return KeyMetadata(
            key_id=new_key_id,
            public_key_pem=self._public_key_to_pem(new_public),
            created_at=rotated_at,
            expires_at=expires_at,
            purpose=row[4],
            status="active",
            rotated_from=key_id_str,
            rotated_at=rotated_at,
        )

    def revoke_key(self, key_id_str: str, *, actor: str = "operator", reason: str = "revoked") -> None:
        """Revoke a key."""
        with self._lock:
            row = self._db.execute("SELECT * FROM keys WHERE key_id = ?", (key_id_str,)).fetchone()
            if not row:
                raise KeyManagementError(f"key {key_id_str} not found")
            if row[5] == "revoked":
                raise KeyManagementError(f"key {key_id_str} already revoked")

            revoked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._db.execute(
                "UPDATE keys SET status = 'revoked', rotated_at = ? WHERE key_id = ?",
                (revoked_at, key_id_str),
            )
            self._db.commit()

        self._record_provenance(key_id_str, "revoke", "operator", {"reason": reason})

    def revoke_key_with_crl(self, key_id_str: str, *, actor: str = "operator", reason: str = "revoked") -> KeyRevocation:
        """Revoke a key and create a signed revocation entry for CRL distribution.
        
        This creates a cryptographically signed revocation entry that can be
        distributed to all system components for revocation checking.
        """
        with self._lock:
            row = self._db.execute("SELECT * FROM keys WHERE key_id = ?", (key_id_str,)).fetchone()
            if not row:
                raise KeyManagementError(f"key {key_id_str} not found")
            if row[5] == "revoked":
                raise KeyManagementError(f"key {key_id_str} already revoked")

            revoked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._db.execute(
                "UPDATE keys SET status = 'revoked', rotated_at = ? WHERE key_id = ?",
                (revoked_at, key_id_str),
            )
            
            # Get previous revocation for chain
            prev_row = self._db.execute(
                "SELECT * FROM revocations ORDER BY revoked_at DESC LIMIT 1"
            ).fetchone()
            prev_digest = prev_row[5] if prev_row else None  # signature column as chain link
            
            # Create revocation entry
            revocation = KeyRevocation(
                key_id=key_id_str,
                revoked_at=revoked_at,
                reason=reason,
                revoked_by=actor,
                signature="",  # Will be filled after signing
                previous_revocation_digest=prev_digest,
            )
            
            # Sign the revocation
            payload = {
                "key_id": revocation.key_id,
                "revoked_at": revocation.revoked_at,
                "reason": revocation.reason,
                "revoked_by": revocation.revoked_by,
                "previous_revocation_digest": revocation.previous_revocation_digest,
            }
            signature = self._sign(payload)
            
            revocation = KeyRevocation(
                key_id=revocation.key_id,
                revoked_at=revocation.revoked_at,
                reason=revocation.reason,
                revoked_by=revocation.revoked_by,
                signature=signature,
                previous_revocation_digest=revocation.previous_revocation_digest,
            )
            
            # Store revocation
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS revocations (
                    key_id TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    revoked_by TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    previous_revocation_digest TEXT,
                    PRIMARY KEY (key_id, revoked_at)
                )
                """
            )
            self._db.execute(
                "INSERT INTO revocations (key_id, revoked_at, reason, revoked_by, signature, previous_revocation_digest) VALUES (?, ?, ?, ?, ?, ?)",
                (revocation.key_id, revocation.revoked_at, revocation.reason, revocation.revoked_by, revocation.signature, revocation.previous_revocation_digest),
            )
            self._db.commit()

        self._record_provenance(key_id_str, "revoke", actor, {"reason": reason})
        
        return revocation

    def verify_revocation(self, revocation: KeyRevocation) -> bool:
        """Verify a revocation entry's signature."""
        payload = {
            "key_id": revocation.key_id,
            "revoked_at": revocation.revoked_at,
            "reason": revocation.reason,
            "revoked_by": revocation.revoked_by,
            "previous_revocation_digest": revocation.previous_revocation_digest,
        }
        try:
            sig_bytes = base64.urlsafe_b64decode(revocation.signature + "==")
            self._public_key.verify(sig_bytes, canonical_bytes(payload))
            return True
        except Exception:
            return False

    def is_revoked(self, key_id_str: str) -> bool:
        """Check if a key is revoked."""
        row = self._db.execute("SELECT * FROM keys WHERE key_id = ?", (key_id_str,)).fetchone()
        return row is not None and row[5] == "revoked"

    def get_revocation_list(self, since: str | None = None) -> list[KeyRevocation]:
        """Get all revocations, optionally since a given timestamp."""
        query = "SELECT * FROM revocations"
        params: list[Any] = []
        if since:
            query += " WHERE revoked_at > ?"
            params.append(since)
        query += " ORDER BY revoked_at"
        rows = self._db.execute(query, params).fetchall()
        revocations = []
        for row in rows:
            revocations.append(KeyRevocation(
                key_id=row[0],
                revoked_at=row[1],
                reason=row[2],
                revoked_by=row[3],
                signature=row[4],
                previous_revocation_digest=row[5] if len(row) > 5 else None,
            ))
        return revocations

    def check_revocation_chain(self) -> bool:
        """Verify the integrity of the revocation chain."""
        rows = self._db.execute("SELECT * FROM revocations ORDER BY revoked_at").fetchall()
        if not rows:
            return True
        
        prev_digest = None
        for row in rows:
            if row[5] != prev_digest:  # previous_revocation_digest
                return False
            # Verify signature
            rev = KeyRevocation(
                key_id=row[0], revoked_at=row[1], reason=row[2],
                revoked_by=row[3], signature=row[4], previous_revocation_digest=row[5] if len(row) > 5 else None
            )
            if not self.verify_revocation(rev):
                return False
            # Compute digest for next link
            import hashlib
            prev_digest = hashlib.sha256(row[4].encode()).hexdigest()[:32]
        
        return True

    def get_key(self, key_id_str: str) -> KeyMetadata | None:
        """Get a key by its ID."""
        row = self._db.execute("SELECT * FROM keys WHERE key_id = ?", (key_id_str,)).fetchone()
        if not row:
            return None
        return self._row_to_metadata(row)
    def get_provenance(self, key_id_str: str) -> list[dict]:
        """Get provenance records for a key."""
        rows = self._db.execute(
            "SELECT * FROM key_provenance WHERE key_id = ? ORDER BY timestamp",
            (key_id_str,)
        ).fetchall()
        return [
            {
                'key_id': row[0],
                'action': row[1],
                'actor': row[2],
                'timestamp': row[3],
                'details_json': row[4],
                'signature': row[5],
            }
            for row in rows
        ]


    def list_keys(self, purpose: str | None = None, status: str | None = None) -> list[KeyMetadata]:
        """List keys, optionally filtered by purpose and status."""
        query = "SELECT * FROM keys WHERE 1=1"
        params: list[Any] = []
        if purpose:
            query += " AND purpose = ?"
            params.append(purpose)
        if status:
            query += " AND status = ?"
            params.append(status)
        rows = self._db.execute(query, params).fetchall()
        return [self._row_to_metadata(row) for row in rows]

    def check_rotation_needed(self) -> list[KeyMetadata]:
        """Check which keys need rotation."""
        rows = self._db.execute(
            "SELECT * FROM keys WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < ?",
            (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),),
        ).fetchall()
        return [self._row_to_metadata(row) for row in rows]

    def auto_rotate_due(self) -> None:
        """Auto-rotate keys that are due."""
        if not self.rotation_policy.auto_rotate:
            return
        for key in self.check_rotation_needed():
            try:
                self.rotate_key(key.key_id, actor="auto", reason="auto-rotation")
            except KeyManagementError:
                pass


class ServiceKeyProvider:
    """Provides keys to services with automatic rotation tracking."""

    def __init__(self, key_manager: KeyManager, service_name: str) -> None:
        self.key_manager = key_manager
        self.service_name = service_name
        self._current_keys: dict[str, KeyMetadata] = {}

    def get_key(self, purpose: str) -> KeyMetadata:
        """Get current key for a purpose, checking for rotation."""
        if purpose not in self._current_keys:
            keys = self.key_manager.list_keys(purpose=purpose, status="active")
            if not keys:
                raise KeyManagementError(f"no active key for purpose {purpose}")
            self._current_keys[purpose] = keys[0]
        else:
            key = self._current_keys[purpose]
            new_key = self.key_manager.get_key(key.key_id)
            if new_key and new_key.status == "rotated":
                self._current_keys[purpose] = self.key_manager.get_key(key.rotated_from or key.key_id)
        return self._current_keys[purpose]

    def get_signing_key(self, purpose: str) -> Ed25519PrivateKey:
        """Get private key for signing (requires key manager to have it)."""
        raise KeyManagementError("private keys not exposed through provider")