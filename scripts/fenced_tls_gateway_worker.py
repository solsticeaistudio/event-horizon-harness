"""Trusted gateway: one SIGNED EHH request to a pinned remote TLS recipient.

This is only a trusted operator-invoked worker. The guest never sees client
keys, replay state, journal, TLS certificate, or recipient endpoint.
A second gateway host MUST NOT run with an independent local journal and
pretend the original reservation was shared; clustered effect-fence state is
future work. The recipient atomically deduplicates its own SQLite effect.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from event_horizon.broker import CapabilityVerifier
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.etcd_effect_journal import EtcdFencedEffectJournal
from event_horizon.authority_backends import EtcdGatewayConfig
from event_horizon.fenced_effect_recovery import FencedEffectRecoveryGateway
from event_horizon.fenced_recipient_tls import FencedTlsRecipientClient
from event_horizon.models import ActionRequest, IssuedCapability
from event_horizon.recorder import ExternalRecorder
from event_horizon.trusted_effect_gateway import select_consumption_store
from scripts.fenced_remote_gateway_worker import load_gateway_config

_TLS_KEYS = {
    "host", "port", "server_name", "ca_file", "client_cert_file",
    "client_key_file", "server_cert_sha256", "recipient_id", "auth_key_hex",
}
_REQUIRED = {
    "public_key_pem", "key_id", "request", "capability",
    "verification_context", "tls_recipient", "journal_path",
    "replay_path", "recorder_path", "output",
}
_CONSENSUS_REQUIRED = (_REQUIRED - {"journal_path", "replay_path"}) | {
    "etcd_gateway", "etcd_cluster_id", "etcd_namespace",
}


def run(config: dict) -> dict:
    if type(config) is not dict or set(config) not in (
        _REQUIRED, _CONSENSUS_REQUIRED,
    ):
        raise ValueError("exact signed remote gateway configuration required")
    distributed = set(config) == _CONSENSUS_REQUIRED
    tls = config["tls_recipient"]
    if type(tls) is not dict or set(tls) != _TLS_KEYS:
        raise ValueError("remote recipient TLS config not host-pinned")
    request = ActionRequest.from_dict(config["request"])
    cap = IssuedCapability.from_dict(config["capability"])
    v = config["verification_context"]
    if type(v) is not dict or set(v) != {
        "attestation", "executor_measurement", "device_id",
        "verifier_policy_digest", "policy_digest", "tenant", "environment",
    }:
        raise ValueError("signed verification context must be explicit")
    if distributed:
        # No local journal/replay fallback in the distributed mode. Every
        # gateway must pin the exact same consensus cluster and namespaces.
        if type(config["etcd_gateway"]) is not dict:
            raise ValueError("consensus authority transport must be explicit")
        etcd_config = EtcdGatewayConfig(**config["etcd_gateway"])
        cluster_id = config["etcd_cluster_id"]
        namespace = config["etcd_namespace"]
        journal = EtcdFencedEffectJournal.connect(
            etcd_config, expected_cluster_id=cluster_id,
            namespace=namespace, domain="effect-fence",
        )
        store = select_consumption_store(
            backend="etcd", namespace=namespace,
            domain="external-effect", etcd_config=etcd_config,
            expected_cluster_id=cluster_id,
        )
    else:
        journal = DurableEffectJournal(config["journal_path"])
        store = select_consumption_store(
            backend="sqlite", namespace=request.session_id,
            domain="external-effect", sqlite_path=config["replay_path"],
        )
    try:
        client = FencedTlsRecipientClient(
            host=tls["host"], port=tls["port"],
            server_name=tls["server_name"], ca_file=tls["ca_file"],
            client_cert_file=tls["client_cert_file"],
            client_key_file=tls["client_key_file"],
            server_cert_sha256=tls["server_cert_sha256"],
            recipient_id=tls["recipient_id"],
            auth_key=bytes.fromhex(tls["auth_key_hex"]), timeout=3,
        )
        gate = FencedEffectRecoveryGateway(
            CapabilityVerifier(
                config["public_key_pem"], config["key_id"], store,
            ),
            ExternalRecorder(config["recorder_path"]),
            journal,
            client, output_factory=lambda _: config["output"],
            tenant=v["tenant"], environment=v["environment"],
        )
        result = gate.execute(
            request, cap, v["attestation"],
            executor_measurement=v["executor_measurement"],
            device_id=v["device_id"],
            verifier_policy_digest=v["verifier_policy_digest"],
            policy_digest=v["policy_digest"],
        )
        return {
            "accepted": result.accepted, "effect_state": result.effect_state,
            "error_class": result.error_class, "output": result.output,
        }
    finally:
        close = getattr(store, "close", None)
        if callable(close):
            close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    c = load_gateway_config(args.config)
    print("RESULT:" + json.dumps(run(c), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
