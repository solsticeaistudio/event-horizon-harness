"""Trusted replay clients for the process-harness's authoritative RPC path.

The signer, verifier, recorder and certificate services use their OWN
Ed25519 client identities and scoped partitions. Client private seed files
and durable checkpoint witnesses must live outside the untrusted executor.
No network/plaintext fallback and no local SQLite fallback in remote mode.
"""
from __future__ import annotations

import os
import tempfile
import threading
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_bytes, strict_json_loads
from .protected_boundary import load_private_seed, provision_private_seed
from .remote_replay import (
    AuthenticatedReplayClient,
    HttpReplayTransport,
    ReplayClientPolicy,
    ReplayProtocolError,
    ReplayRequestSigner,
    RemoteAuthorizationReplayStore,
    RemoteCapabilityConsumptionStore,
)

ROLE_GRANTS = {
    "verifier": (
        frozenset({"nonce-create", "nonce-consume", "nonce-inspect"}),
        frozenset({"attestation.nonces"}),
    ),
    "signer": (
        frozenset({"capability-consume", "authorization-consume"}),
        frozenset({"capability.authority", "protected.signer"}),
    ),
    "recorder": (
        frozenset({"authorization-consume"}),
        frozenset({"protected.recorder"}),
    ),
    "certificate": (
        frozenset({"authorization-consume"}),
        frozenset({"protected.certificate"}),
    ),
}
REMOTE_FIELDS = frozenset({
    "url", "service_id", "epoch", "server_public_key_pem",
    "client_seed_path", "checkpoint_state_path",
    "ca_cert_path", "client_cert_path", "client_key_path",
})
_NODE_PRIVATE_KEY_FIELD = "client_private_key_pem_path"


def role_client_seed_path(workdir: str | Path, role: str) -> Path:
    if role not in ROLE_GRANTS:
        raise ValueError("untrusted role may not hold replay signing credentials")
    return Path(workdir) / "trusted-control" / f"replay-client-{role}.seed"


def _provision_seed(path: Path) -> bytes:
    import secrets
    try:
        provision_private_seed(path, secrets.token_bytes(32))
    except FileExistsError:
        pass
    return load_private_seed(path)


def provision_replay_client_policies(
    workdir: str | Path, service_id: str,
) -> dict[str, ReplayClientPolicy]:
    """Pre-provision scoped keys *before* starting external replay service.

    The caller registers the resulting public policies on a separately
    trusted authority. No signer/etcd server secret is returned.
    """
    result = {}
    for role, (operations, partitions) in ROLE_GRANTS.items():
        signer = ReplayRequestSigner(
            _provision_seed(role_client_seed_path(workdir, role)), service_id
        )
        result[role] = ReplayClientPolicy.create(
            signer.public_key_pem, operations=operations, partitions=partitions,
        )
    return result


def role_remote_settings(
    workdir: str | Path,
    role: str,
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Build host-owned config for one role. No guest ever receives it."""
    if role not in ROLE_GRANTS:
        raise ValueError("only trusted roles may hold replay client identity")
    names = {
        "url", "service_id", "epoch", "server_public_key_pem",
        "ca_cert_path", "client_cert_path", "client_key_path",
    }
    if not isinstance(authority, Mapping) or set(authority) != names:
        raise ValueError("remote authority configuration fields are invalid")
    _validate_endpoint(authority)
    seed = role_client_seed_path(workdir, role)
    _provision_seed(seed)
    remote = dict(authority)
    remote["client_seed_path"] = str(seed)
    remote["checkpoint_state_path"] = str(
        Path(workdir) / "trusted-control" / f"replay-checkpoint-{role}.json"
    )
    if role == "verifier":
        # Node bridge expects PKCS8 PEM, only in the trusted verifier config.
        pem_file = seed.with_suffix(".pem")
        pkcs8 = Ed25519PrivateKey.from_private_bytes(load_private_seed(seed)).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pem_file.parent.mkdir(parents=True, exist_ok=True)
        if pem_file.is_symlink():
            raise RuntimeError("remote nonce client PEM must not be a symlink")
        if pem_file.exists() and (not pem_file.is_file() or pem_file.read_bytes() != pkcs8):
            raise RuntimeError("remote nonce client PEM differs from pinned role seed")
        if not pem_file.exists():
            # Constrain private PEM creation and avoid symlink following.
            descriptor = os.open(pem_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as writer:
                writer.write(pkcs8)
                writer.flush()
                os.fsync(writer.fileno())
        if os.name != "nt" and pem_file.stat().st_mode & 0o077:
            raise RuntimeError("remote nonce client PEM permissions are unsafe")
        remote[_NODE_PRIVATE_KEY_FIELD] = str(pem_file)
    return remote


def _validate_endpoint(config: Mapping[str, Any]) -> None:
    url = config.get("url")
    if not isinstance(url, str):
        raise ValueError("trusted replay endpoint is invalid")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path != "/v1/transition" or not parsed.hostname
        or parsed.scheme not in {"http", "https"}
    ):
        raise ValueError("trusted replay endpoint must be exact /v1/transition")
    tls = [config.get(field) for field in (
        "ca_cert_path", "client_cert_path", "client_key_path",
    )]
    if parsed.scheme == "http":
        if parsed.hostname not in {"127.0.0.1", "::1", "localhost"} or any(tls):
            raise ValueError("plaintext replay only allowed on explicit loopback")
    elif not all(isinstance(v, str) and v for v in tls):
        raise ValueError("remote replay TLS requires CA, cert and client key")


def _atomic_checkpoint(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".replay-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as writer:
            writer.write(canonical_bytes(data) + b"\n")
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class DurableReplayClient(AuthenticatedReplayClient):
    """Persist a trusted high-water mark before returning accepted decisions."""

    def __init__(self, *args, checkpoint_path: Path, **kwargs):
        self.checkpoint_path = checkpoint_path
        super().__init__(*args, **kwargs)

    def call(self, operation: str, partition: str, payload: Mapping[str, Any]):
        with self._lock:
            result = super().call(operation, partition, payload)
            _atomic_checkpoint(self.checkpoint_path, {
                "service_id": self.signer.service_id,
                "epoch": self.epoch,
                "server_key_id": self.server_key_id,
                "checkpoint": self.checkpoint,
                "checkpoint_digest": self.checkpoint_digest,
            })
            return result


def remote_client(config: Mapping[str, Any]) -> DurableReplayClient:
    """Validate and instantiate a pinned client; rejects malformed stored witnesses."""
    if not isinstance(config, Mapping) or set(config) != REMOTE_FIELDS:
        raise ValueError("remote replay client config fields invalid")
    _validate_endpoint(config)
    path = Path(config["checkpoint_state_path"])
    signer = ReplayRequestSigner(
        load_private_seed(config["client_seed_path"]), config["service_id"],
    )
    checkpoint, checkpoint_digest = 0, None
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("replay checkpoint witness is unsafe")
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise RuntimeError("replay checkpoint witness permissions are unsafe")
        state = strict_json_loads(path.read_bytes())
        if not isinstance(state, dict) or set(state) != {
            "service_id", "epoch", "server_key_id",
            "checkpoint", "checkpoint_digest",
        }:
            raise RuntimeError("replay checkpoint witness malformed")
        from .remote_replay import _load_public_key, replay_key_id
        pinned = replay_key_id(_load_public_key(config["server_public_key_pem"]))
        if (
            state["service_id"] != config["service_id"]
            or state["epoch"] != config["epoch"]
            or state["server_key_id"] != pinned
        ):
            raise RuntimeError("replay checkpoint witness identity mismatch")
        checkpoint, checkpoint_digest = state["checkpoint"], state["checkpoint_digest"]
    return DurableReplayClient(
        signer,
        HttpReplayTransport(
            config["url"],
            ca_cert_path=config["ca_cert_path"],
            client_cert_path=config["client_cert_path"],
            client_key_path=config["client_key_path"],
        ),
        config["server_public_key_pem"],
        epoch=config["epoch"],
        checkpoint=checkpoint,
        checkpoint_digest=checkpoint_digest,
        checkpoint_path=path,
    )
