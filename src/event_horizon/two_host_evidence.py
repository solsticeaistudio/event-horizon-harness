"""Two-Linux-host network-loss evidence: individually signed observations.

This verifies signed evidence *consistency*, not physical identity or actual
cable removal. Operator independently controls the physical fault and must
retain an independent fault log. No machine shutdown or network manipulation.

A signed observation is bound to: one source SHA, run UUID, effect/request
digests, recipient ID, phase, role, self-reported host boot/machine identity,
and an independently readable journal / recipient record / TLS probe.
One signature per host, never a shared private key. The verifier takes
independently pinned public keys; it never trusts self-supplied signer keys.

This is NOT a certificate of physical power loss, genuine gateway failover,
three independent etcd fault domains, or arbitrary API exactly-once effects.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any, Mapping
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .canonical import canonical_bytes, strict_json_loads

OBS_SCHEMA = "event-horizon.two-host-signed-observation.v1"
RESULT_SCHEMA = "event-horizon.two-host-network-evidence-result.v1"
PHASES = ("before", "disconnected", "recovered")
ROLES = ("gateway", "recipient")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REV = re.compile(r"^[0-9a-f]{40}$")
BOOT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RESULTS = ("positive", "indeterminate", "absent")


def _hex64(value: Any, name: str) -> str:
    if type(value) is not str or not HEX64.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _uuid(value: Any) -> str:
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError("run ID must be a canonical UUID")
    return value


def _canonical_file(path: str | Path) -> dict:
    raw = Path(path).read_bytes()
    decoded = strict_json_loads(raw, require_canonical=True)
    if type(decoded) is not dict or canonical_bytes(decoded) != raw:
        raise ValueError("noncanonical evidence file")
    return decoded


def _key_id(key: Ed25519PublicKey) -> str:
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _pub(path: str | Path) -> Ed25519PublicKey:
    obj = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(obj, Ed25519PublicKey):
        raise ValueError("host witness key must be Ed25519")
    return obj


def _private(path: str | Path) -> Ed25519PrivateKey:
    # Called after CLI validates the immutable operator-owned 0600 file.
    obj = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(obj, Ed25519PrivateKey):
        raise ValueError("host witness private key must be Ed25519")
    return obj


def _check_snapshot(snapshot: Any, role: str) -> None:
    if type(snapshot) is not dict:
        raise ValueError("missing trusted host evidence snapshot")
    if role == "recipient":
        if set(snapshot) != {
            "status", "row_count", "receipt_digest", "sequence", "output_digest",
        } or snapshot["status"] != "positive":
            raise ValueError("recipient must positively observe original row")
        if (type(snapshot["row_count"]) is not int
                or snapshot["row_count"] != 1
                or type(snapshot["sequence"]) is not int
                or snapshot["sequence"] < 1):
            raise ValueError("recipient durable row count/sequence invalid")
        _hex64(snapshot["receipt_digest"], "recipient receipt")
        _hex64(snapshot["output_digest"], "recipient result")
    else:
        if set(snapshot) != {"journal", "transport"}:
            raise ValueError("gateway must independently read journal and TLS transport")
        journal, probe = snapshot["journal"], snapshot["transport"]
        if type(journal) is not dict or set(journal) != {
            "status", "original_capability_id", "state", "receipt_digest",
            "request_digest", "recipient_id", "output_digest",
        } or journal["status"] != "positive":
            raise ValueError("gateway reservation unreadable")
        if (type(journal["original_capability_id"]) is not str
                or not journal["original_capability_id"]
                or journal["state"] not in ("possibly-committed", "recipient-confirmed")):
            raise ValueError("gateway original reservation missing")
        _hex64(journal["request_digest"], "journal request")
        _hex64(journal["output_digest"], "journal output")
        if journal["receipt_digest"] is not None:
            _hex64(journal["receipt_digest"], "journal receipt")
        if (journal["state"] == "recipient-confirmed"
                and journal["receipt_digest"] is None):
            raise ValueError("confirmed gateway has no recipient receipt")
        if (type(probe) is not dict or set(probe) != {
            "status", "receipt_digest", "sequence", "output_digest",
        } or probe["status"] not in RESULTS):
            raise ValueError("gateway transport result malformed")
        if probe["status"] == "positive":
            _hex64(probe["receipt_digest"], "remote TLS receipt")
            _hex64(probe["output_digest"], "remote TLS output")
            if type(probe["sequence"]) is not int or probe["sequence"] < 1:
                raise ValueError("remote TLS commit sequence invalid")
        elif any(probe[k] is not None for k in (
            "receipt_digest", "sequence", "output_digest"
        )):
            raise ValueError("non-positive remote observation cannot contain receipt")


def make_payload(*, role: str, phase: str, run_id: str,
                 source_revision: str, effect_key: str,
                 request_digest: str, recipient_id: str,
                 machine_id_hash: str, boot_id: str,
                 kernel_release: str, environment_hint: str,
                 snapshot: dict) -> dict:
    if role not in ROLES or phase not in PHASES:
        raise ValueError("unsupported two-host evidence role or phase")
    _uuid(run_id)
    if type(source_revision) is not str or not REV.fullmatch(source_revision):
        raise ValueError("source revision must be a pinned 40-char Git SHA")
    for name, value in (
        ("effect key", effect_key), ("request", request_digest),
        ("host identity", machine_id_hash),
    ):
        _hex64(value, name)
    if (type(boot_id) is not str or not BOOT.fullmatch(boot_id)
            or type(recipient_id) is not str or not 1 <= len(recipient_id) <= 128
            or any(not c.isascii() or not (c.isalnum() or c in "-_.:")
                   for c in recipient_id)
            or type(kernel_release) is not str or not 1 <= len(kernel_release) <= 256
            or environment_hint not in ("wsl2", "linux", "virtualized-or-unknown")):
        raise ValueError("invalid host attestation fields")
    _check_snapshot(snapshot, role)
    return {
        "schema": OBS_SCHEMA, "run_id": run_id, "role": role, "phase": phase,
        "source_revision": source_revision, "effect_key": effect_key,
        "request_digest": request_digest, "recipient_id": recipient_id,
        "machine_id_hash": machine_id_hash, "boot_id": boot_id,
        "kernel_release": kernel_release, "environment_hint": environment_hint,
        "snapshot": snapshot,
        "host_identity_evidence": "self-reported-signed-not-hardware-attested",
    }


def sign_payload(payload: dict, private_key: Ed25519PrivateKey) -> dict:
    if type(payload) is not dict or payload.get("schema") != OBS_SCHEMA:
        raise ValueError("unsupported observation to sign")
    key = private_key.public_key()
    return {
        "payload": payload, "signer_key_id": _key_id(key),
        "signature_hex": private_key.sign(canonical_bytes(payload)).hex(),
    }


def verify_signed(envelope: dict, expected_public_key: Ed25519PublicKey) -> dict:
    if type(envelope) is not dict or set(envelope) != {
        "payload", "signer_key_id", "signature_hex",
    } or type(envelope["payload"]) is not dict:
        raise ValueError("invalid signed evidence envelope")
    payload = envelope["payload"]
    expected = make_payload(**{
        key: payload[key] for key in (
            "role", "phase", "run_id", "source_revision", "effect_key",
            "request_digest", "recipient_id", "machine_id_hash", "boot_id",
            "kernel_release", "environment_hint", "snapshot",
        ) if key in payload
    })
    if payload != expected or envelope["signer_key_id"] != _key_id(expected_public_key):
        raise ValueError("signed observation schema or pinned host key changed")
    sig = envelope["signature_hex"]
    if (type(sig) is not str or len(sig) != 128
            or any(c not in "0123456789abcdef" for c in sig)):
        raise ValueError("malformed Ed25519 witness signature")
    try:
        expected_public_key.verify(bytes.fromhex(sig), canonical_bytes(payload))
    except InvalidSignature as exc:
        raise ValueError("host witness signature invalid") from exc
    return payload


def verify_bundle(*, observations: Mapping[tuple[str, str], dict],
                  gateway_public: Ed25519PublicKey,
                  recipient_public: Ed25519PublicKey) -> dict:
    """Independently validate six phase/role snapshots.

    A PASS asserts only observed physical-*host identity contrast* as
    self-reported, communication loss seen by TLS client, and one preserved
    atomic SQLite business effect. Source/action and field provenance is
    signed by two independently PINNED host identities. No recovery token
    signature, network fault cause or physical host identity is certified.
    """
    required = {(role, phase) for role in ROLES for phase in PHASES}
    if set(observations) != required:
        raise ValueError("missing or unexpected two-host observations")
    if _key_id(gateway_public) == _key_id(recipient_public):
        raise ValueError("host signers must be distinct pinned identities")
    decoded = {}
    for (role, phase), record in observations.items():
        d = verify_signed(
            record, gateway_public if role == "gateway" else recipient_public,
        )
        if (d["role"], d["phase"]) != (role, phase):
            raise ValueError("mislabelled signed role or phase")
        decoded[(role, phase)] = d
    first = decoded[("gateway", "before")]
    for entry in decoded.values():
        for name in ("run_id", "source_revision", "effect_key",
                     "request_digest", "recipient_id"):
            if entry[name] != first[name]:
                raise ValueError("cross-host observation identity/binding mismatch")
    for role in ROLES:
        before = decoded[(role, "before")]
        for phase in PHASES:
            cur = decoded[(role, phase)]
            if (cur["machine_id_hash"] != before["machine_id_hash"]
                    or cur["boot_id"] != before["boot_id"]):
                raise ValueError("host identity/boot changed mid-campaign")
    if (decoded[("recipient", "before")]["machine_id_hash"]
            == first["machine_id_hash"]):
        raise ValueError("two-host evidence reports identical machine identities")

    r = [decoded[("recipient", phase)]["snapshot"] for phase in PHASES]
    original = r[0]
    if any(x != original for x in r):
        raise ValueError("recipient original receipt, result or row count changed")

    g = [decoded[("gateway", phase)]["snapshot"] for phase in PHASES]
    original_cap = g[0]["journal"]["original_capability_id"]
    for x in g:
        j = x["journal"]
        if (j["original_capability_id"] != original_cap
                or j["request_digest"] != first["request_digest"]
                or j["recipient_id"] != first["recipient_id"]
                or j["output_digest"] != original["output_digest"]):
            raise ValueError("gateway original reservation was rebound")
        if j["receipt_digest"] not in (None, original["receipt_digest"]):
            raise ValueError("gateway recipient receipt diverged")
    if (g[0]["transport"]["status"] != "positive"
            or g[1]["transport"]["status"] != "indeterminate"
            or g[2]["transport"]["status"] != "positive"):
        raise ValueError("expected connected/disconnected/restored TLS observations")
    if g[2]["journal"]["state"] != "recipient-confirmed":
        raise ValueError("gateway never positively confirmed recipient")
    for x in (g[0], g[2]):
        t = x["transport"]
        if (t["receipt_digest"] != original["receipt_digest"]
                or t["output_digest"] != original["output_digest"]
                or t["sequence"] != original["sequence"]):
            raise ValueError("gateway remote TLS observation disagrees with recipient")
    if g[2]["journal"]["receipt_digest"] != original["receipt_digest"]:
        raise ValueError("final gateway reservation has wrong receipt")

    return {
        "schema": RESULT_SCHEMA,
        "status": "PASS",
        "scope": "signed-two-host-transport-loss-and-preserved-atomic-sqlite-receipt",
        "run_id": first["run_id"],
        "source_revision": first["source_revision"],
        "effect_key": first["effect_key"],
        "original_capability_id": original_cap,
        "recipient_id": first["recipient_id"],
        "receipt_digest": original["receipt_digest"],
        "recipient_row_count": 1,
        "gateway_signer_key_id": _key_id(gateway_public),
        "recipient_signer_key_id": _key_id(recipient_public),
        "distinct_reported_machine_identities": True,
        "same_boot_across_phases": True,
        "signed_fresh_recovery_verified": False,
        "actual_network_disconnect_cause_verified": False,
        "physical_independence_hardware_attested": False,
        "physical_power_cut_proven": False,
        "cross_host_gateway_failover_proven": False,
    }


def load_and_verify_bundle(*, paths: Mapping[tuple[str, str], str | Path],
                           gateway_pub: str | Path,
                           recipient_pub: str | Path) -> dict:
    envelopes = {key: _canonical_file(path) for key, path in paths.items()}
    result = verify_bundle(
        observations=envelopes,
        gateway_public=_pub(gateway_pub),
        recipient_public=_pub(recipient_pub),
    )
    result["original_artifacts_sha256"] = {
        f"{role}.{phase}": hashlib.sha256(
            Path(path).read_bytes()
        ).hexdigest() for (role, phase), path in sorted(paths.items())
    }
    return result
