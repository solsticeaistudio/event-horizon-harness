"""Serve EHH's atomic signed etcd replay authority in a TRUSTED process.

Usage: python scripts/serve_etcd_signed_replay.py --config trusted.json
       python scripts/serve_etcd_signed_replay.py --config trusted.json --bootstrap

Only --bootstrap permits initializing an empty authority. Production remote
listeners require mTLS; plaintext is opt-in for 127.0.0.1/::1 only.
Never run in an attacker-controlled worker or pass this configuration to a VM.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from event_horizon.authority_backends import EtcdGatewayConfig  # noqa: E402
from event_horizon.canonical import strict_json_loads  # noqa: E402
from event_horizon.etcd_signed_replay import EtcdSignedReplayService  # noqa: E402
from event_horizon.protected_boundary import load_private_seed  # noqa: E402
from event_horizon.remote_replay import ReplayClientPolicy, ReplayHttpServer  # noqa: E402


def configure(path: Path, *, bootstrap: bool = False):
    """Parse an exact-field config, return a constructed service + HTTP server."""
    config = strict_json_loads(path.read_bytes())
    expected = {
        "etcd", "cluster_id", "namespace", "service_id", "epoch",
        "signing_seed_path", "client_policies", "listen_host", "listen_port",
        "server_tls",
    }
    if not isinstance(config, dict) or set(config) != expected:
        raise ValueError("trusted replay server configuration fields are invalid")
    clients = {}
    policies = config["client_policies"]
    if not isinstance(policies, list) or not policies:
        raise ValueError("trusted replay requires explicit client key policies")
    for entry in policies:
        if not isinstance(entry, dict) or set(entry) != {
            "public_key_pem", "operations", "partitions",
        }:
            raise ValueError("client policy fields invalid")
        ops, partitions = entry["operations"], entry["partitions"]
        if not isinstance(ops, list) or not isinstance(partitions, list):
            raise ValueError("client ACLs must be arrays")
        if len(ops) != len(set(ops)) or len(partitions) != len(set(partitions)):
            raise ValueError("client ACLs cannot repeat operations or partitions")
        item = ReplayClientPolicy.create(
            entry["public_key_pem"], operations=set(ops), partitions=set(partitions)
        )
        if item.key_id in clients:
            raise ValueError("duplicate client identity")
        clients[item.key_id] = item
    etcd = config["etcd"]
    if not isinstance(etcd, dict):
        raise ValueError("etcd transport config invalid")
    etcd_config = EtcdGatewayConfig(**etcd)
    host = config["listen_host"]
    if not isinstance(host, str) or not host:
        raise ValueError("listener host invalid")
    server_tls = config["server_tls"]
    # Never serve unencrypted on a network interface. Even if clients sign
    # requests, authentication alone is not transport confidentiality.
    if server_tls is None:
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("non-loopback trusted replay listener requires mTLS")
        tls_kwargs = {}
    else:
        if not isinstance(server_tls, dict) or set(server_tls) != {
            "certfile", "keyfile", "cafile"
        }:
            raise ValueError("trusted replay TLS config invalid")
        tls_kwargs = {**server_tls, "require_client_cert": True}
    service = EtcdSignedReplayService.connect(
        etcd_config,
        expected_cluster_id=config["cluster_id"],
        namespace=config["namespace"],
        service_id=config["service_id"],
        epoch=config["epoch"],
        signing_key=load_private_seed(config["signing_seed_path"]),
        clients=clients,
        bootstrap=bootstrap,
    )
    http_server = ReplayHttpServer(
        service, host=host, port=config["listen_port"], **tls_kwargs
    )
    return service, http_server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--bootstrap", action="store_true",
        help="EXPLICIT operator action: initialize absent authority only",
    )
    args = parser.parse_args()
    _service, server = configure(args.config, bootstrap=args.bootstrap)
    print(json.dumps({
        "status": "ready",
        "url": server.url,
        "service_id": _service.service_id,
        "epoch": _service.epoch,
        "server_key_id": _service.server_key_id,
        "checkpoint": _service.checkpoint()[1],
    }), flush=True)
    try:
        server.start()
        import threading
        threading.Event().wait()
    except KeyboardInterrupt:
        return 0
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
