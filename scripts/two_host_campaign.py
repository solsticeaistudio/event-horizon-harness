"""Operator-controlled two-host evidence runner (NO fault injection).

Run separately on gateway MSI and recipient HP over real LAN. Each host
signs local observations with its OWN Ed25519 key. Copy original JSON and
.sha256 files to the controller for independent offline verification.
No SSH, firewall, routing, network link or power changes occur here.

Phase ordering is operator-controlled: before / disconnected / recovered.
For a real partition, an operator must deliberately disconnect ONLY the
disposable HP's lab network, keeping independent evidence of that action.
A detected TLS error does NOT, on its own, prove a physical link partition.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.authority_backends import EtcdGatewayConfig
from event_horizon.canonical import canonical_bytes, digest, strict_json_loads
from event_horizon.etcd_effect_journal import EtcdFencedEffectJournal
from event_horizon.fenced_recipient import FencedRecipientError
from event_horizon.fenced_recipient_tls import FencedTlsRecipientClient
from event_horizon.fenced_recipient_transport import _private_parent
from event_horizon.two_host_evidence import (
    PHASES, ROLES, _private, _uuid, _hex64,
    _check_snapshot, load_and_verify_bundle, make_payload, sign_payload,
)
from scripts.serve_fenced_tls_recipient import load_private_config

TLS_FIELDS = {
    "host", "port", "server_name", "ca_file", "client_cert_file",
    "client_key_file", "server_cert_sha256", "recipient_id", "auth_key_hex",
}
ETCD_FIELDS = {"etcd_gateway", "etcd_cluster_id", "etcd_namespace"}
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _write_exclusive(path: str | Path, data: bytes) -> None:
    p = Path(path)
    _private_parent(p)
    fd = os.open(
        p, os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        dirfd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except BaseException:
        raise


def _safe_key(path: Path) -> Ed25519PrivateKey:
    _private_parent(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError("host private witness key is not operator-owned mode 0600")
        with os.fdopen(fd, "rb", closefd=False) as f:
            raw = f.read(4097)
    finally:
        os.close(fd)
    if len(raw) > 4096:
        raise ValueError("host private key exceeded size ceiling")
    obj = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(obj, Ed25519PrivateKey):
        raise ValueError("host private witness must be Ed25519")
    return obj


def _read_config(path: Path, expected: set[str]) -> dict:
    return load_private_config(path, expected)


def keygen(private: Path, public: Path) -> None:
    if private == public:
        raise ValueError("private and public witness keys must be separate files")
    key = Ed25519PrivateKey.generate()
    _write_exclusive(
        private,
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write_exclusive(
        public,
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    print("CREATED distinct witness keypair; KEEP private key on its OWN host.")


def _host_facts(run_id: str) -> dict:
    if platform.system() != "Linux":
        raise RuntimeError("two-host evidence requires Linux on both machines")
    machine = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip().lower()
    if not machine or len(machine) > 128:
        raise RuntimeError("Linux machine identity unavailable")
    release = platform.release()
    if "microsoft" in release.lower() or "wsl" in release.lower():
        hint = "wsl2"
    elif "hypervisor" in Path("/proc/cpuinfo").read_text(
        encoding="utf-8", errors="ignore"
    ).lower():
        hint = "virtualized-or-unknown"
    else:
        hint = "linux"
    return {
        "machine_id_hash": hashlib.sha256(
            (run_id + ":" + machine).encode(),
        ).hexdigest(),
        "boot_id": boot, "kernel_release": release,
        "environment_hint": hint,
    }


def _sqlite_open_ro(database: Path):
    _private_parent(database)
    if not database.is_absolute() or database.is_symlink():
        raise ValueError("private evidence DB must be an absolute regular file")
    info = os.lstat(database)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise ValueError("evidence database is not a private trusted file")
    db = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=3)
    db.execute("PRAGMA query_only=ON")
    return db


def recipient_snapshot(*, database: Path, effect_key: str,
                       request_digest: str, recipient_id: str) -> dict:
    with _sqlite_open_ro(database) as db:
        rid = db.execute(
            "SELECT recipient_id FROM recipient_identity WHERE singleton=1"
        ).fetchone()
        count = db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
        row = db.execute(
            "SELECT sequence,request_digest,output_json,output_digest,receipt_digest "
            "FROM effects WHERE effect_key=?", (effect_key,),
        ).fetchone()
    if rid != (recipient_id,) or count != 1 or row is None:
        raise ValueError("recipient durable identity/row count not positively established")
    seq, req, raw, result_hash, receipt_hash = row
    output = strict_json_loads(raw, require_canonical=True)
    expected = digest({
        "schema": "event-horizon.fenced-recipient-receipt.v1",
        "recipient_id": recipient_id,
        "effect_key": effect_key,
        "request_digest": request_digest,
        "output_digest": result_hash,
        "sequence": seq,
    })
    if (req != request_digest or result_hash != digest(output)
            or receipt_hash != expected):
        raise ValueError("recipient original durable receipt or result is corrupted")
    snapshot = {
        "status": "positive", "row_count": count,
        "receipt_digest": receipt_hash, "sequence": seq,
        "output_digest": result_hash,
    }
    _check_snapshot(snapshot, "recipient")
    return snapshot


def journal_snapshot(*, effect_key: str, request_digest: str,
                     recipient_id: str, journal_db: Path | None = None,
                     consensus_config: Path | None = None) -> dict:
    if (journal_db is None) == (consensus_config is None):
        raise ValueError("select exactly one journal backend")
    if journal_db is not None:
        with _sqlite_open_ro(journal_db) as db:
            row = db.execute(
                "SELECT capability_id,request_digest,claims_digest,state,"
                "receipt_digest,fenced_protocol,fenced_recipient_id,"
                "fenced_output_digest FROM effects "
                "WHERE tenant=? AND environment=? AND effect_key=?",
                ("default", "synthetic", effect_key),
            ).fetchone()
        if row is None:
            raise ValueError("no original gateway effect reservation")
        record = dict(zip((
            "capability_id", "request_digest", "claims_digest", "state",
            "receipt_digest", "fenced_protocol", "fenced_recipient_id",
            "fenced_output_digest",
        ), row))
    else:
        c = _read_config(consensus_config, ETCD_FIELDS)  # no secret material in report
        if type(c["etcd_gateway"]) is not dict:
            raise ValueError("untrusted etcd transport configuration")
        journal = EtcdFencedEffectJournal.connect(
            EtcdGatewayConfig(**c["etcd_gateway"]),
            expected_cluster_id=c["etcd_cluster_id"],
            namespace=c["etcd_namespace"],
        )
        record = journal.observe_effect(
            tenant="default", environment="synthetic", effect_key=effect_key,
        )
        if record is None:
            raise ValueError("no consensus effect fence for requested key")
    if (record["request_digest"] != request_digest
            or record["fenced_recipient_id"] != recipient_id
            or record["fenced_protocol"] != "atomic-sqlite-v1"):
        raise ValueError("original gateway reservation differs from pinned effect")
    snapshot = {
        "status": "positive",
        "original_capability_id": record["capability_id"],
        "state": record["state"], "receipt_digest": record["receipt_digest"],
        "request_digest": record["request_digest"],
        "recipient_id": record["fenced_recipient_id"],
        "output_digest": record["fenced_output_digest"],
    }
    return snapshot


def gateway_snapshot(*, tls_config: Path, effect_key: str,
                     request_digest: str, recipient_id: str,
                     journal_db: Path | None, consensus_config: Path | None) -> dict:
    journal = journal_snapshot(
        effect_key=effect_key, request_digest=request_digest,
        recipient_id=recipient_id, journal_db=journal_db,
        consensus_config=consensus_config,
    )
    # Configuration/identity errors are NOT a substitute for network loss:
    # fully validate host-owned config, TLS cert paths and peer pin first.
    c = _read_config(tls_config, TLS_FIELDS)
    if c["recipient_id"] != recipient_id:
        raise ValueError("recipient TLS config changed recipient identity")
    client = FencedTlsRecipientClient(
        host=c["host"], port=c["port"], server_name=c["server_name"],
        ca_file=c["ca_file"], client_cert_file=c["client_cert_file"],
        client_key_file=c["client_key_file"],
        server_cert_sha256=c["server_cert_sha256"],
        recipient_id=recipient_id,
        auth_key=bytes.fromhex(c["auth_key_hex"]), timeout=2,
    )
    try:
        receipt = client.observe(
            effect_key=effect_key, request_digest=request_digest,
        )
        if receipt is None:
            probe = {
                "status": "absent", "receipt_digest": None,
                "sequence": None, "output_digest": None,
            }
        else:
            probe = {
                "status": "positive",
                "receipt_digest": receipt.receipt_digest,
                "sequence": receipt.sequence,
                "output_digest": receipt.output_digest,
            }
    except FencedRecipientError:
        probe = {
            "status": "indeterminate", "receipt_digest": None,
            "sequence": None, "output_digest": None,
        }
    snapshot = {"journal": journal, "transport": probe}
    _check_snapshot(snapshot, "gateway")
    return snapshot


def _revision() -> str:
    p = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True, timeout=5,
    )
    value = p.stdout.strip()
    if not HEX40.fullmatch(value):
        raise ValueError("cannot pin EHH source revision")
    return value


def capture(args) -> None:
    _uuid(args.run_id)
    _hex64(args.effect_key, "effect key")
    _hex64(args.request_digest, "request digest")
    if args.role == "recipient":
        if (args.database is None or args.tls_config is not None
                or args.journal_db is not None or args.consensus_config is not None):
            raise ValueError("recipient must use only its private SQLite evidence DB")
        snapshot = recipient_snapshot(
            database=args.database, effect_key=args.effect_key,
            request_digest=args.request_digest, recipient_id=args.recipient_id,
        )
    else:
        if args.database is not None or args.tls_config is None:
            raise ValueError("gateway needs its pinned recipient TLS config")
        snapshot = gateway_snapshot(
            tls_config=args.tls_config, effect_key=args.effect_key,
            request_digest=args.request_digest, recipient_id=args.recipient_id,
            journal_db=args.journal_db, consensus_config=args.consensus_config,
        )
    payload = make_payload(
        role=args.role, phase=args.phase, run_id=args.run_id,
        source_revision=_revision(), effect_key=args.effect_key,
        request_digest=args.request_digest, recipient_id=args.recipient_id,
        snapshot=snapshot, **_host_facts(args.run_id),
    )
    signed = sign_payload(payload, _safe_key(args.private_key))
    raw = canonical_bytes(signed)
    _write_exclusive(args.output, raw)
    _write_exclusive(
        Path(str(args.output) + ".sha256"),
        (hashlib.sha256(raw).hexdigest() + "  " + args.output.name + "\n").encode(),
    )
    print(json.dumps({
        "status": "SIGNED-OBSERVATION-ONLY", "role": args.role,
        "phase": args.phase,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "path": str(args.output),
    }, sort_keys=True))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("new-run-id")
    g = sub.add_parser("keygen", help="Run once separately on EACH trusted Linux host")
    g.add_argument("--private-key", required=True, type=Path)
    g.add_argument("--public-key", required=True, type=Path)
    a = sub.add_parser("capture", help="Signed READ-ONLY checkpoint on current host")
    a.add_argument("--role", choices=ROLES, required=True)
    a.add_argument("--phase", choices=PHASES, required=True)
    a.add_argument("--run-id", required=True)
    a.add_argument("--effect-key", required=True)
    a.add_argument("--request-digest", required=True)
    a.add_argument("--recipient-id", required=True)
    a.add_argument("--private-key", type=Path, required=True)
    a.add_argument("--output", type=Path, required=True)
    a.add_argument("--database", type=Path)
    a.add_argument("--journal-db", type=Path)
    a.add_argument("--consensus-config", type=Path)
    a.add_argument("--tls-config", type=Path)
    v = sub.add_parser("verify", help="Offline verification on controller")
    v.add_argument("--directory", required=True, type=Path)
    v.add_argument("--gateway-public-key", required=True, type=Path)
    v.add_argument("--recipient-public-key", required=True, type=Path)
    v.add_argument("--report", required=True, type=Path)
    args = p.parse_args()
    if args.command == "new-run-id":
        print(str(uuid4()))
    elif args.command == "keygen":
        keygen(args.private_key, args.public_key)
    elif args.command == "capture":
        capture(args)
    else:
        paths = {
            (role, phase): args.directory / f"{role}.{phase}.json"
            for role in ROLES for phase in PHASES
        }
        result = load_and_verify_bundle(
            paths=paths, gateway_pub=args.gateway_public_key,
            recipient_pub=args.recipient_public_key,
        )
        _write_exclusive(args.report, canonical_bytes(result))
        print(json.dumps({
            "status": result["status"], "scope": result["scope"],
            "report": str(args.report),
            "signed_fresh_recovery_verified": False,
        }, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"INCOMPLETE/FAIL CLOSED: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        raise SystemExit(1) from exc
