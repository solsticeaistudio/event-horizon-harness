"""Privileged operator entrypoint for opt-in remote cooperating TLS recipient.

Run on two trusted Linux hosts: one owns the SQLite recipient database and
the other owns the signed EHH execution gateway. Provision certificates and
the 256-bit HMAC key out-of-band; never include private values in Git or an
untrusted Firecracker guest. This command itself is only a transport smoke
probe, NOT proof of a multi-host failover.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from event_horizon.canonical import digest, strict_json_loads
from event_horizon.fenced_recipient_tls import (
    FencedTlsRecipientClient, serve_fenced_tls_recipient,
)


def load_private_config(path: Path, expected: set[str]) -> dict:
    info = os.lstat(path)
    parent = os.lstat(path.parent)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid() or parent.st_mode & 0o022):
        raise ValueError("TLS recipient config must be an operator-owned 0600 file")
    value = strict_json_loads(path.read_bytes())
    if type(value) is not dict or set(value) != expected:
        raise ValueError("unexpected remote TLS recipient config fields")
    if (type(value.get("auth_key_hex")) is not str
            or len(value["auth_key_hex"]) != 64):
        raise ValueError("expected exactly 32 bytes of hex private IPC key")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("serve", help="Recipient host: bound TLS server + atomic SQLite")
    a.add_argument("--config", required=True, type=Path)
    b = sub.add_parser("observe", help="Gateway host: read only a specified effect")
    b.add_argument("--config", required=True, type=Path)
    b.add_argument("--effect-key", required=True)
    b.add_argument("--request-digest", required=True)
    args = parser.parse_args()
    if args.command == "serve":
        keys = {"listen_host", "listen_port", "database", "recipient_id",
                "auth_key_hex", "ca_file", "server_cert_file", "server_key_file",
                "client_cert_sha256"}
        c = load_private_config(args.config, keys)
        serve_fenced_tls_recipient(
            host=c["listen_host"], port=c["listen_port"],
            database=c["database"], recipient_id=c["recipient_id"],
            auth_key=bytes.fromhex(c["auth_key_hex"]), ca_file=c["ca_file"],
            server_cert_file=c["server_cert_file"],
            server_key_file=c["server_key_file"],
            client_cert_sha256=c["client_cert_sha256"],
            ready=lambda port: print("READY: mTLS recipient listening on pinned port",
                                     flush=True),
        )
    else:
        keys = {"host", "port", "server_name", "ca_file",
                "client_cert_file", "client_key_file", "server_cert_sha256",
                "recipient_id", "auth_key_hex"}
        c = load_private_config(args.config, keys)
        client = FencedTlsRecipientClient(
            host=c["host"], port=c["port"], server_name=c["server_name"],
            ca_file=c["ca_file"], client_cert_file=c["client_cert_file"],
            client_key_file=c["client_key_file"],
            server_cert_sha256=c["server_cert_sha256"],
            recipient_id=c["recipient_id"],
            auth_key=bytes.fromhex(c["auth_key_hex"]),
        )
        response = client.observe(
            effect_key=args.effect_key, request_digest=args.request_digest,
        )
        # Do not print private key or entire receiver output to terminal.
        print(json.dumps({
            "transport": "mutually-verified-TLS-plus-HMAC",
            "found": response is not None,
            "receipt_digest": None if response is None else response.receipt_digest,
            "sequence": None if response is None else response.sequence,
        }, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL CLOSED: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
