"""PKCS#11 HSM backend for hardware-backed key management."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class HSMError(RuntimeError):
    """HSM operation error."""
    pass


class HSMUnavailableError(HSMError):
    """HSM device unavailable."""
    pass


class HSMKeyNotFoundError(HSMError):
    """Key not found in HSM."""
    pass


@dataclass(frozen=True)
class HSMKeyInfo:
    """Information about a key stored in the HSM."""
    key_id: str
    label: str
    public_key_pem: str
    created_at: str
    key_type: str = "Ed25519"


class PKCS11Backend:
    """PKCS#11 HSM backend for hardware-backed key operations."""
    
    def __init__(
        self,
        library_path: str,
        slot: int = 0,
        pin: Optional[str] = None,
        token_label: Optional[str] = None,
    ) -> None:
        self.library_path = library_path
        self.slot = slot
        self.pin = pin
        self.token_label = token_label
        self._lib = None
        self._session = None
        self._lock = threading.RLock()
        self._initialized = False
    
    def initialize(self) -> None:
        """Initialize the PKCS#11 library and open a session."""
        with self._lock:
            if self._initialized:
                return
            
            try:
                import pkcs11
            except ImportError:
                raise HSMUnavailableError("python-pkcs11 not installed")
            
            self._lib = pkcs11.lib(self.library_path)
            
            # Find token
            token = None
            for t in self._lib.get_tokens():
                if self.token_label is None or t.label == self.token_label:
                    token = t
                    break
            
            if token is None:
                raise HSMUnavailableError(f"Token not found: {self.token_label}")
            
            self._session = token.open(user_pin=self.pin, rw=True)
            self._initialized = True
    
    def close(self) -> None:
        """Close the HSM session."""
        with self._lock:
            if self._session:
                self._session.close()
                self._session = None
            self._initialized = False
    
    def generate_ed25519_key(self, label: str, key_id: str) -> HSMKeyInfo:
        """Generate an Ed25519 key pair in the HSM."""
        with self._lock:
            if not self._initialized:
                self.initialize()
            
            # Generate key pair
            pub, priv = self._session.generate_key_pair(
                pkcs11.KeyType.ED25519,
                label=label,
                id=key_id.encode(),
                store=True,
            )
            
            # Export public key
            pub_pem = pub.export_public_key()
            
            # Compute key ID from public key
            raw_pub = pub_pem.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            derived_key_id = f"ed25519:{hashlib.sha256(raw_pub).hexdigest()[:32]}"
            
            return HSMKeyInfo(
                key_id=derived_key_id,
                label=label,
                public_key_pem=pub_pem.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("ascii"),
                created_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
            )
    
    def sign_ed25519(self, key_id: str, data: bytes) -> bytes:
        """Sign data with an Ed25519 key in the HSM."""
        with self._lock:
            if not self._initialized:
                self.initialize()
            
            # Find private key by ID
            priv_key = self._session.get_key(
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                key_type=pkcs11.KeyType.ED25519,
                label=key_id,
            )
            
            if not priv_key:
                raise HSMKeyNotFoundError(f"Private key not found: {key_id}")
            
            # Sign the data
            signature = priv_key.sign(data)
            return signature
    
    def get_public_key(self, key_id: str) -> Ed25519PublicKey:
        """Get public key from HSM."""
        with self._lock:
            if not self._initialized:
                self.initialize()
            
            pub_key = self._session.get_key(
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
                key_type=pkcs11.KeyType.ED25519,
                label=key_id,
            )
            
            if not pub_key:
                raise HSMKeyNotFoundError(f"Public key not found: {key_id}")
            
            pub_pem = pub_key.export_public_key()
            return serialization.load_pem_public_key(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
    
    def list_keys(self) -> list[HSMKeyInfo]:
        """List all Ed25519 keys in the HSM."""
        with self._lock:
            if not self._initialized:
                self.initialize()
            
            keys = []
            for pub_key in self._session.get_keys(
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
                key_type=pkcs11.KeyType.ED25519,
            ):
                label = pub_key.label or "unknown"
                pub_pem = pub_key.export_public_key()
                raw_pub = pub_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                key_id = f"ed25519:{hashlib.sha256(raw_pub).hexdigest()[:32]}"
                
                keys.append(HSMKeyInfo(
                    key_id=key_id,
                    label=label,
                    public_key_pem=pub_pem.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode("ascii"),
                    created_at="unknown",  # PKCS#11 doesn't standardize creation time
                ))
            
            return keys
    
    def delete_key(self, key_id: str) -> bool:
        """Delete a key pair from the HSM."""
        with self._lock:
            if not self._initialized:
                self.initialize()
            
            deleted = False
            # Delete private key
            for priv_key in self._session.get_keys(
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                key_type=pkcs11.KeyType.ED25519,
                label=key_id,
            ):
                priv_key.destroy()
                deleted = True
            
            # Delete public key
            for pub_key in self._session.get_keys(
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
                key_type=pkcs11.KeyType.ED25519,
                label=key_id,
            ):
                pub_key.destroy()
                deleted = True
            
            return deleted


class SoftHSM2Backend:
    """SoftHSM2 backend for development/testing without hardware HSM."""
    
    def __init__(
        self,
        token_dir: Path,
        token_label: str = "event-horizon",
        pin: str = "1234",
        so_pin: str = "5678",
    ) -> None:
        self.token_dir = Path(token_dir)
        self.token_label = token_label
        self.pin = pin
        self.so_pin = so_pin
        self._backend = None
        self._init_softhsm()
    
    def _init_softhsm(self) -> None:
        """Initialize SoftHSM2 token if needed."""
        self.token_dir.mkdir(parents=True, exist_ok=True)
        
        # Check if token already exists
        import subprocess
        try:
            result = subprocess.run(
                ["softhsm2-util", "--show-slots"],
                capture_output=True, text=True, check=False
            )
            if self.token_label in result.stdout:
                return  # Token already exists
        except FileNotFoundError:
            pass  # softhsm2-util not available
        
        # Initialize new token
        try:
            subprocess.run([
                "softhsm2-util", "--init-token",
                "--slot", "0",
                "--label", self.token_label,
                "--pin", self.pin,
                "--so-pin", self.so_pin,
            ], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass  # SoftHSM2 not available, will fail at runtime
    
    def get_backend(self) -> PKCS11Backend:
        """Get PKCS#11 backend for SoftHSM2."""
        if self._backend is None:
            # Find SoftHSM2 library
            lib_paths = [
                "/usr/lib/softhsm/libsofthsm2.so",
                "/usr/local/lib/softhsm/libsofthsm2.so",
                "/opt/homebrew/lib/softhsm/libsofthsm2.so",
            ]
            lib_path = None
            for path in lib_paths:
                if Path(path).exists():
                    lib_path = path
                    break
            
            if not lib_path:
                raise HSMUnavailableError("SoftHSM2 library not found")
            
            self._backend = PKCS11Backend(
                library_path=lib_path,
                slot=0,
                pin="1234",
                token_label="event-horizon",
            )
        
        return self._backend


def create_hsm_backend(
    backend_type: str = "auto",
    **kwargs,
) -> PKCS11Backend:
    """Factory function to create HSM backend."""
    if backend_type == "softhsm2" or (backend_type == "auto" and _softhsm2_available()):
        backend = SoftHSM2Backend(**kwargs)
        return backend.get_backend()
    elif backend_type == "pkcs11":
        return PKCS11Backend(**kwargs)
    else:
        raise HSMError(f"Unknown HSM backend type: {backend_type}")


def _softhsm2_available() -> bool:
    """Check if SoftHSM2 is available."""
    lib_paths = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    ]
    return any(Path(p).exists() for p in lib_paths)