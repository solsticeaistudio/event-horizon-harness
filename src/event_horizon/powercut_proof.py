"""Boot-separated SQLite durability check bound to an external signed witness.

NO physical power-off is performed here. Operator must use a disposable VM
or host with externally controlled power and independent evidence retention.
A changed Linux boot ID alone CANNOT prove a power cut (normal reboot
also changes it). The verifier reports only operator-attested evidence with
a separately signed external power-control log, not hardware attestation.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import uuid

from cryptography import x509  # installed with EHH's cryptography dependency
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from .canonical import canonical_bytes, strict_json_loads
from .fenced_recipient import FencedSqliteRecipient


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_BOOT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SCHEMA = "event-horizon.powercut-preflight.v1"
_WITNESS = "event-horizon.externally-attested-powercut.v1"
_OUTPUT = {"durable_synthetic_effect": "committed"}
_CONTROL_METHOD = "external-power-controller-hard-off-on"


def _read_json(path: str | Path) -> dict:
    raw = Path(path).read_bytes()
    result = strict_json_loads(raw)
    if type(result) is not dict or canonical_bytes(result) != raw:
        raise ValueError("powercut evidence must be canonical JSON")
    return result


def _write_new(path: str | Path, payload: bytes) -> None:
    path = Path(path)
    if not path.parent.is_dir():
        raise ValueError("powercut output parent must already exist")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        # Preserve any partially written original for failure review.
        raise


def _boot_id() -> str:
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().lower()
    if not _BOOT.fullmatch(boot):
        raise RuntimeError("unavailable Linux boot identity")
    return boot


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare(*, database: str | Path, preflight_path: str | Path,
            recipient_id: str, boot_id: str | None = None) -> dict:
    """Create a one-time effect and fsync a preflight outside the ledger.

    Caller MUST export preflight off the target host before performing the
    externally controlled cutoff. No destructive operation is implemented.
    """
    database = Path(database)
    if (not database.is_absolute() or database.exists()
            or database.is_symlink()):
        raise ValueError("powercut requires a fresh absolute SQLite DB path")
    boot = _boot_id() if boot_id is None else boot_id
    if type(boot) is not str or not _BOOT.fullmatch(boot):
        raise ValueError("invalid boot ID")
    effect_key, request_digest = secrets.token_hex(32), secrets.token_hex(32)
    recipient = FencedSqliteRecipient(database, recipient_id=recipient_id)
    record = recipient.apply(
        effect_key=effect_key, request_digest=request_digest,
        output=_OUTPUT,
    )
    if not record.newly_committed or record.sequence != 1 or recipient.commit_count() != 1:
        raise RuntimeError("no unique first durable commit before power cut")
    # SQLite synchronous=FULL is used by FencedSqliteRecipient; flush the DB
    # inode and directory metadata. Real storage power-loss correctness still
    # depends on the disk/VM flush path honoring the request.
    fd = os.open(database, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    dir_fd = os.open(database.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    report = {
        "schema": _SCHEMA,
        "run_id": str(uuid.uuid4()),
        "boot_id_before": boot,
        "database": str(database),
        "recipient_id": recipient_id,
        "effect_key": effect_key,
        "request_digest": request_digest,
        "output_digest": record.output_digest,
        "receipt_digest": record.receipt_digest,
        "sequence": record.sequence,
        "durable_row_count_before": 1,
        "claimed_sync": "sqlite-synchronous-full-and-fsync-regular-file-and-directory",
        "attestation": "none-preflight-only",
    }
    _write_new(preflight_path, canonical_bytes(report))
    return report


def create_external_statement(
    *, preflight_path: str | Path, event_log_path: str | Path,
    controller_id: str, boot_id_after: str, private_key_path: str | Path,
    statement_path: str | Path,
) -> dict:
    """Run ONLY on the independent power controller AFTER an actual hard cut.

    The private Ed25519 witness key never belongs on the tested target host.
    The controller is responsible for event log authenticity; this script
    checks log byte integrity, not electrical power state.
    """
    preflight_raw = Path(preflight_path).read_bytes()
    preflight = _read_json(preflight_path)
    if preflight.get("schema") != _SCHEMA:
        raise ValueError("unrecognized powercut baseline")
    if (type(controller_id) is not str or not 1 <= len(controller_id) <= 128
            or not all(c.isascii() and (c.isalnum() or c in "-_.:")
                        for c in controller_id)):
        raise ValueError("invalid external controller identity")
    if (not _BOOT.fullmatch(boot_id_after)
            or boot_id_after == preflight["boot_id_before"]):
        raise ValueError("no changed measured boot ID")
    log_data = Path(event_log_path).read_bytes()
    if not (16 <= len(log_data) <= 1_000_000):
        raise ValueError("external controller event log must be meaningful and bounded")
    statement = {
        "schema": _WITNESS,
        "preflight_sha256": _sha(preflight_raw),
        "controller_id": controller_id,
        "control_method": _CONTROL_METHOD,
        "external_event_log_sha256": _sha(log_data),
        "boot_id_before": preflight["boot_id_before"],
        "boot_id_after": boot_id_after,
        "operator_claim": "out-of-band-power-removed-and-restored",
    }
    key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(), password=None,
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("external controller must use Ed25519 witness key")
    sig = key.sign(canonical_bytes(statement))
    record = {"statement": statement, "signature_hex": sig.hex()}
    _write_new(statement_path, canonical_bytes(record))
    return record


def verify(
    *, preflight_path: str | Path, statement_path: str | Path,
    event_log_path: str | Path, controller_public_key: str | Path,
    database: str | Path, report_path: str | Path | None = None,
    boot_id: str | None = None,
) -> dict:
    baseline_bytes = Path(preflight_path).read_bytes()
    baseline = _read_json(preflight_path)
    signed = _read_json(statement_path)
    if (baseline.get("schema") != _SCHEMA or set(signed) != {
            "statement", "signature_hex"
    } or type(signed["statement"]) is not dict):
        raise ValueError("unrecognized durability evidence")
    s = signed["statement"]
    if set(s) != {
        "schema", "preflight_sha256", "controller_id", "control_method",
        "external_event_log_sha256", "boot_id_before", "boot_id_after",
        "operator_claim",
    } or (s["schema"] != _WITNESS or s["preflight_sha256"] != _sha(baseline_bytes)
          or s["boot_id_before"] != baseline.get("boot_id_before")
          or s["control_method"] != _CONTROL_METHOD
          or s["operator_claim"] != "out-of-band-power-removed-and-restored"
          or s["external_event_log_sha256"] != _sha(Path(event_log_path).read_bytes())):
        raise ValueError("external powercut observation is not bound to preflight and log")
    public = serialization.load_pem_public_key(
        Path(controller_public_key).read_bytes(),
    )
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("external controller public key must be Ed25519")
    try:
        if (type(signed["signature_hex"]) is not str
                or len(signed["signature_hex"]) != 128):
            raise ValueError("external witness signature malformed")
        public.verify(
            bytes.fromhex(signed["signature_hex"]), canonical_bytes(s),
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid controller-signed statement") from exc
    # Invalid signatures also raise cryptography.exceptions.InvalidSignature;
    # let that fail closed rather than fabricating PASS.
    boot = _boot_id() if boot_id is None else boot_id
    if (type(boot) is not str or not _BOOT.fullmatch(boot)
            or boot == baseline["boot_id_before"] or boot != s["boot_id_after"]):
        raise ValueError("target has not proven a distinct post-cut boot")
    database = Path(database)
    if (not database.is_absolute() or database.is_symlink()
            or str(database) != baseline["database"]
            or not database.is_file()):
        raise ValueError("original durable recipient database unavailable or rebound")
    recipient = FencedSqliteRecipient(
        database, recipient_id=baseline["recipient_id"],
    )
    row = recipient.observe(
        effect_key=baseline["effect_key"],
        request_digest=baseline["request_digest"],
    )
    if (recipient.commit_count() != 1 or row is None or row.newly_committed
            or row.sequence != baseline["sequence"]
            or row.receipt_digest != baseline["receipt_digest"]
            or row.output_digest != baseline["output_digest"]
            or row.output != _OUTPUT):
        raise ValueError("original SQLite commit missing/corrupt/duplicated after boot")
    report = {
        "schema": "event-horizon.boot-separated-recipient-durability-result.v1",
        "status": "PASS",
        "scope": "operator-attested-external-hard-off-on-plus-durable-sqlite-row",
        "preflight_sha256": _sha(baseline_bytes),
        "witness_signature_verified": True,
        "witness_controller_id": s["controller_id"],
        "controller_event_log_sha256": s["external_event_log_sha256"],
        "boot_id_before": baseline["boot_id_before"],
        "boot_id_after": boot,
        "effect_key": baseline["effect_key"],
        "receipt_digest": row.receipt_digest,
        "final_durable_row_count": 1,
        "first_commit_preserved": True,
        "hardware_power_measurement": "not-verified-by-software",
    }
    if report_path is not None:
        _write_new(report_path, canonical_bytes(report))
    return report
