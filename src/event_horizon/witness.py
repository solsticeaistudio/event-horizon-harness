"""External checkpoint witness.

The recorder and its local anchor are no longer the strongest history
guarantee. A witness is a **separate trust principal** that independently
retains recorder checkpoints and produces its own authenticated
acknowledgments. Certificate generation can then distinguish:

* ``LOCAL`` — no external anchoring at all;
* ``WITNESSED`` — an independent witness has acknowledged the checkpointed
  history, and the recorder matches it (no rollback/fork detected).

Divergence classes detected here:

* ``recorder-behind-witness`` — the events file lost acknowledged history;
* ``fork`` — same sequence, different chain tip than witnessed;
* ``unrecognized-witness`` — acknowledgment from a non-pinned witness key;
* ``stale-witness`` — witness ack older than policy allows (in sequences);
* deployment/manifest mismatch — evidence from another trust root.

The default :class:`LocalCheckpointWitness` is a deterministic in-process
implementation suitable for tests; remote notaries/transparency logs implement
the same protocol.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest
from .statements import TYPE_WITNESS_ACKNOWLEDGMENT, StatementSigner, StatementVerifier

WITNESS_ACK_FIELDS = {
    "statement_type",
    "witness_id",
    "deployment_id",
    "manifest_digest",
    "recorder_key_id",
    "checkpoint_sequence",
    "chain_tip",
    "previous_checkpoint_digest",
    "checkpoint_digest",
    "witnessed_at_ms",
}


class WitnessError(RuntimeError):
    pass


@dataclass(frozen=True)
class WitnessVerdict:
    status: str          # ok | recorder-behind-witness | fork | unrecognized-witness | stale-witness | no-acknowledgment | manifest-mismatch | deployment-mismatch
    detail: str
    acknowledgment: Mapping[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _key_id_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


class LocalCheckpointWitness:
    """Deterministic witness retaining signed acknowledgments durably."""

    MAX_JOURNAL_BYTES = 1_048_576

    def __init__(
        self,
        journal_path: str | Path,
        *,
        witness_id: str,
        signing_key: bytes | Ed25519PrivateKey,
        deployment_id: str,
    ) -> None:
        self.path = Path(journal_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(signing_key, Ed25519PrivateKey):
            self._private_key = signing_key
        elif isinstance(signing_key, bytes) and len(signing_key) >= 32:
            self._private_key = Ed25519PrivateKey.from_private_bytes(signing_key[:32])
        else:
            raise WitnessError("witness signing key must be Ed25519")
        self.public_key_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.key_id = _key_id_for(self._private_key.public_key())
        if not isinstance(witness_id, str) or not witness_id or len(witness_id) > 128:
            raise WitnessError("witness identity is invalid")
        self.witness_id = witness_id
        if not isinstance(deployment_id, str) or not deployment_id:
            raise WitnessError("witness deployment binding is invalid")
        self.deployment_id = deployment_id

    # ------------------------------------------------------------------ API

    def publish_checkpoint(
        self,
        envelope: Mapping[str, Any],
        *,
        recorder_public_key_pem: str,
        manifest_digest: str,
    ) -> dict[str, Any]:
        """Verify a recorder checkpoint and acknowledge it independently."""
        payload = self._verify_checkpoint(envelope, recorder_public_key_pem)
        if payload["deployment_id"] != self.deployment_id:
            raise WitnessError("checkpoint belongs to a different deployment")
        if payload["manifest_digest"] != manifest_digest:
            raise WitnessError("checkpoint was issued under a different manifest")
        latest = self.latest_acknowledgment(payload["recorder_id"])
        if latest is not None:
            if payload["sequence"] < latest["checkpoint_sequence"]:
                raise WitnessError("witness refuses checkpoint rollback")
            if (
                payload["sequence"] == latest["checkpoint_sequence"]
                and payload["chain_tip"] != latest["chain_tip"]
            ):
                raise WitnessError("witness refuses conflicting checkpoint fork")
            if (
                payload["sequence"] == latest["checkpoint_sequence"]
                and payload["chain_tip"] == latest["chain_tip"]
            ):
                return latest  # idempotent republish
        acknowledgment = {
            "statement_type": TYPE_WITNESS_ACKNOWLEDGMENT,
            "witness_id": self.witness_id,
            "deployment_id": self.deployment_id,
            "manifest_digest": payload["manifest_digest"],
            "recorder_key_id": payload["recorder_id"],
            "checkpoint_sequence": payload["sequence"],
            "chain_tip": payload["chain_tip"],
            "previous_checkpoint_digest": payload["previous_checkpoint_digest"],
            "checkpoint_digest": digest(dict(payload)),
            "witnessed_at_ms": time.time_ns() // 1_000_000,
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(acknowledgment))
        ).rstrip(b"=").decode("ascii")
        record = {**acknowledgment, "signature": signature, "key_id": self.key_id}
        self._append(record)
        return record

    def latest_acknowledgment(self, recorder_key_id: str) -> Mapping[str, Any] | None:
        records = self._load_all()
        matching = [
            record for record in records
            if record.get("recorder_key_id") == recorder_key_id
        ]
        return matching[-1] if matching else None

    def all_acknowledgments(self) -> list[Mapping[str, Any]]:
        return self._load_all()

    # -------------------------------------------------------------- internal

    def _append(self, record: Mapping[str, Any]) -> None:
        encoded = canonical_bytes(record).decode("utf-8") + "\n"
        if self.path.exists() and self.path.stat().st_size + len(encoded) > self.MAX_JOURNAL_BYTES:
            raise WitnessError("witness journal capacity exceeded")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()

    def _load_all(self) -> list[Mapping[str, Any]]:
        if not self.path.exists():
            return []
        records = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records

    def _verify_checkpoint(
        self,
        envelope: Mapping[str, Any],
        recorder_public_key_pem: str,
    ) -> Mapping[str, Any]:
        expected_fields = {
            "schema", "deployment_id", "manifest_digest", "recorder_id",
            "sequence", "chain_tip", "previous_checkpoint_digest", "issued_at_ms",
        }
        if not isinstance(envelope, dict) or set(envelope) != {
            "checkpoint", "signature", "algorithm", "key_id"
        }:
            raise WitnessError("checkpoint envelope fields are invalid")
        payload = envelope["checkpoint"]
        if not isinstance(payload, dict) or set(payload) != expected_fields:
            raise WitnessError("checkpoint payload fields are invalid")
        if envelope["algorithm"] != "Ed25519":
            raise WitnessError("unsupported checkpoint algorithm")
        try:
            loaded = serialization.load_pem_public_key(recorder_public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeError) as exc:
            raise WitnessError("recorder public key is malformed") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise WitnessError("recorder public key must be Ed25519")
        recorder_key_id = _key_id_for(loaded)
        if envelope["key_id"] != recorder_key_id or payload["recorder_id"] != recorder_key_id:
            raise WitnessError("checkpoint identity does not match the pinned recorder")
        try:
            decoded = base64.urlsafe_b64decode(
                envelope["signature"] + "=" * (-len(envelope["signature"]) % 4)
            )
            if len(decoded) != 64:
                raise WitnessError("checkpoint signature length is invalid")
            loaded.verify(decoded, canonical_bytes(payload))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise WitnessError("checkpoint signature is invalid") from exc
        return payload


def verify_witness_acknowledgment_signature(
    acknowledgment: Mapping[str, Any],
    witness_public_key_pem: str,
) -> bool:
    try:
        if not isinstance(acknowledgment, dict):
            return False
        unsigned = {
            key: value for key, value in acknowledgment.items()
            if key in WITNESS_ACK_FIELDS
        }
        if set(unsigned) != WITNESS_ACK_FIELDS:
            return False
        loaded = serialization.load_pem_public_key(witness_public_key_pem.encode("ascii"))
        if not isinstance(loaded, Ed25519PublicKey):
            return False
        raw = loaded.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if acknowledgment.get("key_id") != _key_id_for(loaded):
            return False
        decoded = base64.urlsafe_b64decode(
            acknowledgment["signature"] + "=" * (-len(acknowledgment["signature"]) % 4)
        )
        if len(decoded) != 64:
            return False
        loaded.verify(decoded, canonical_bytes(unsigned))
        return True
    except (KeyError, InvalidSignature, ValueError, TypeError, UnicodeError):
        return False


@dataclass(frozen=True)
class WitnessPolicy:
    """Assurance configuration for certificate-time witness checks."""

    require_witness: bool = False
    max_sequences_behind: int = 0


def compare_recorder_with_witness(
    *,
    snapshot_event_count: int,
    snapshot_chain_tip: str,
    acknowledgment: Mapping[str, Any] | None,
    deployment_id: str,
    manifest_digest: str,
    policy: WitnessPolicy,
    max_sequences_behind: int | None = None,
) -> WitnessVerdict:
    """Classify the relationship between recorder state and witness state.

    Rules:
    * recorder at the witnessed sequence with an identical tip -> ``ok``;
    * recorder strictly ahead of the witnessed point -> ``ok`` (it extends
      witnessed history; the witnessed prefix remains intact);
    * recorder behind the witnessed sequence -> ``recorder-behind-witness``
      (acknowledged history was lost locally);
    * recorder at the witnessed sequence with a different tip -> ``fork``;
    * wrong deployment/manifest/witness key -> respective mismatch class.
    """
    del max_sequences_behind
    if acknowledgment is None:
        if policy.require_witness:
            return WitnessVerdict("no-acknowledgment", "witness has acknowledged nothing")
        return WitnessVerdict("ok", "witness not required by assurance policy")
    if not verify_witness_acknowledgment_signature(acknowledgment["ack"], acknowledgment["witness_public_key_pem"]):
        return WitnessVerdict("unrecognized-witness", "acknowledgment signature is invalid")
    ack = {key: value for key, value in acknowledgment["ack"].items() if key in WITNESS_ACK_FIELDS}
    if ack["deployment_id"] != deployment_id:
        return WitnessVerdict("deployment-mismatch", "witness ack belongs to another deployment")
    if ack["manifest_digest"] != manifest_digest:
        return WitnessVerdict("manifest-mismatch", "witness ack was issued under another manifest")
    if snapshot_event_count < ack["checkpoint_sequence"]:
        return WitnessVerdict(
            "recorder-behind-witness",
            f"recorder lost {ack['checkpoint_sequence'] - snapshot_event_count} acknowledged event(s)",
        )
    if snapshot_event_count == ack["checkpoint_sequence"]:
        if snapshot_chain_tip != ack["chain_tip"]:
            return WitnessVerdict("fork", "recorder diverged from witnessed history at the same sequence")
        return WitnessVerdict("ok", "recorder matches witnessed history exactly")
    return WitnessVerdict("ok", "recorder extends witnessed history")
