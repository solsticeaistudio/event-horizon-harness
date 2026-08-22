"""Role-scoped signing key providers.

Raw seed files must not be baked into the architecture. This module defines
the seam between Event Horizon services and wherever private keys actually
live (local development files today; KMS/HSM/TPM backends tomorrow).

Two properties matter architecturally:

* **Role binding** — a provider instance hands out keys for exactly one
  declared role and purpose set. A service cannot ask for another actor's
  signing identity, so no API exists through which the coordinator could
  borrow independent actors' keys.
* **Narrow exposure** — callers receive an ``Ed25519PrivateKey`` only through
  :meth:`signing_key`, and providers may be replaced by backends that never
  export key material at all (they would override ``sign`` instead).
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .trust_manifest import PURPOSES, ROLES


class KeyProviderError(RuntimeError):
    pass


def load_private_seed(path: str | os.PathLike[str]) -> bytes:
    """Load a restricted 32-byte seed file (symlink/permission hardened)."""
    from .protected_boundary import load_private_seed as _load

    return _load(path)


class SigningKeyProvider(Protocol):
    """Backend contract for one role's signing identity."""

    role: str

    def purposes(self) -> frozenset[str]: ...

    def public_key_pem(self) -> str: ...

    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> bytes: ...


class LocalFileSigningKeyProvider:
    """Development backend: one restricted seed file bound to one role.

    Production backends implement :class:`SigningKeyProvider` against KMS,
    HSM, or TPM stores; only this class reads raw seeds from disk.
    """

    def __init__(
        self,
        seed_path: str | os.PathLike[str],
        *,
        role: str,
        purposes: set[str] | frozenset[str] | None = None,
    ) -> None:
        if role not in ROLES:
            raise KeyProviderError(f"unknown key provider role: {role!r}")
        allowed = PURPOSES.get(role, frozenset())
        resolved = frozenset(purposes) if purposes is not None else allowed
        if not resolved <= allowed:
            raise KeyProviderError(
                f"purposes {sorted(resolved - allowed)} are not valid for role {role!r}"
            )
        seed = load_private_seed(seed_path)
        self.role = role
        self._purposes = resolved
        self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self._public_key = self._private_key.public_key()
        self._public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        import hashlib

        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_id = f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"

    def purposes(self) -> frozenset[str]:
        return self._purposes

    def public_key_pem(self) -> str:
        return self._public_pem

    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes):
            raise KeyProviderError("signing payload must be bytes")
        return self._private_key.sign(payload)


def provision_dev_seed(path: str | os.PathLike[str], seed: bytes) -> Path:
    """Provision a development seed file (delegates to hardened helper)."""
    from .protected_boundary import provision_private_seed

    return provision_private_seed(path, seed)


__all__ = [
    "KeyProviderError",
    "LocalFileSigningKeyProvider",
    "SigningKeyProvider",
    "load_private_seed",
    "provision_dev_seed",
]
