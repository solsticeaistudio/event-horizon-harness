#!/usr/bin/env python3
"""Independent structural/signature verifier for an internally signed crash report.

A matching embedded key proves consistency only, NOT an external witness.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from event_horizon.canonical import canonical_bytes, strict_json_loads
from scripts.run_effect_crash_campaign import SCHEMA, PHASES, check_scenario


class CrashEvidenceError(ValueError):
    pass


def verify_report(document: dict) -> dict:
    if not isinstance(document, dict) or set(document) != {
        "payload", "signer_public_key", "signature",
    }:
        raise CrashEvidenceError("invalid signed report envelope")
    payload = document["payload"]
    if not isinstance(payload, dict):
        raise CrashEvidenceError("signed payload is not an object")
    try:
        key = serialization.load_pem_public_key(document["signer_public_key"].encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise CrashEvidenceError("report public key is not Ed25519")
        signature = document["signature"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature):
            raise CrashEvidenceError("invalid report signature encoding")
        decoded = base64.urlsafe_b64decode(signature + "==")
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != signature:
            raise CrashEvidenceError("noncanonical report signature")
        key.verify(decoded, canonical_bytes(payload))
    except (ValueError, TypeError, AttributeError, UnicodeError) as exc:
        raise CrashEvidenceError("invalid signed report") from exc
    except Exception as exc:
        raise CrashEvidenceError("report Ed25519 signature verification failed") from exc
    expected_keys = {
        "schema", "status", "experiment_mode", "source_commit", "authority_backend",
        "etcd_cluster_id", "host_kernel", "attestation", "provenance",
        "kvm_exercised", "guardian_quorum_exercised", "scenarios",
    }
    if set(payload) != expected_keys:
        raise CrashEvidenceError("report schema contains unexpected or missing fields")
    if (payload["schema"] != SCHEMA or payload["status"] != "PASS"
            or payload["experiment_mode"] != "linux-host-process-sigkill"
            or not isinstance(payload["source_commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", payload["source_commit"])
            or payload["attestation"] != "synthetic-fixture"
            or payload["provenance"] != "internal ephemeral signing key; embedded public key; no witness"
            or payload["kvm_exercised"] is not False
            or payload["guardian_quorum_exercised"] is not False):
        raise CrashEvidenceError("unexpected evidence claim or status")
    backend = payload["authority_backend"]
    cluster = payload["etcd_cluster_id"]
    if backend not in {"sqlite", "etcd"}:
        raise CrashEvidenceError("unknown replay backend")
    if backend == "sqlite" and cluster is not None:
        raise CrashEvidenceError("local replay cannot claim etcd consensus")
    if backend == "etcd" and (not isinstance(cluster, str)
                              or not cluster.isdecimal() or int(cluster) <= 0):
        raise CrashEvidenceError("missing real etcd cluster ID")
    if not isinstance(payload["scenarios"], list) or len(payload["scenarios"]) != len(PHASES):
        raise CrashEvidenceError("incomplete fault campaign")
    ids = set()
    for actual, name in zip(payload["scenarios"], PHASES):
        expected_row = {
            "scenario", "session_id", "request_digest", "capability_id",
            "replacement_capability_id", "killed_worker", "recipient_before",
            "recipient_after_kill", "recipient_after_recovery",
            "journal_state_after_kill", "original_replay", "replacement_replay",
            "consumed_capabilities", "etcd_oracle",
        }
        if not isinstance(actual, dict) or set(actual) != expected_row:
            raise CrashEvidenceError("unrecognized scenario record schema")
        if actual["scenario"] != name or not check_scenario(actual):
            raise CrashEvidenceError(f"fault campaign assertion failed: {name}")
        if (actual["session_id"] in ids
                or not isinstance(actual["session_id"], str)
                or not re.fullmatch(r"ehk-crash-[0-9a-f]{14}", actual["session_id"])):
            raise CrashEvidenceError("duplicate or malformed session identity")
        ids.add(actual["session_id"])
        if not isinstance(actual["request_digest"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", actual["request_digest"]
        ):
            raise CrashEvidenceError("invalid request binding")
        for keyname in ("capability_id", "replacement_capability_id"):
            if not isinstance(actual[keyname], str) or not re.fullmatch(
                r"cap_[0-9a-f]{24}", actual[keyname]
            ):
                raise CrashEvidenceError("invalid signed capability identity")
        if actual["capability_id"] == actual["replacement_capability_id"]:
            raise CrashEvidenceError("replacement token was not fresh")
        for state in ("recipient_before", "recipient_after_kill", "recipient_after_recovery"):
            observation = actual[state]
            if (not isinstance(observation, dict)
                    or set(observation) != {"count", "rows_digest"}
                    or type(observation["count"]) is not int
                    or not isinstance(observation["rows_digest"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", observation["rows_digest"])):
                raise CrashEvidenceError("invalid recipient-side observation")
        oracle = actual["etcd_oracle"]
        if (backend == "etcd") != (oracle is not None):
            raise CrashEvidenceError("missing or misrepresented etcd read")
        if oracle and (oracle["cluster_id"] != cluster or oracle["backend"] != "etcd"
                       or oracle["source"] != "host-supervisor-linearizable-etcd-read"):
            raise CrashEvidenceError("etcd oracle cluster/source mismatch")
    return payload


def verify_file(path: Path) -> dict:
    raw = path.read_bytes()
    sidecar = Path(str(path) + ".sha256")
    if sidecar.is_file():
        expected = hashlib.sha256(raw).hexdigest() + "  " + path.name + "\n"
        if sidecar.read_text() != expected:
            raise CrashEvidenceError("original report SHA256 sidecar mismatch")
    try:
        document = strict_json_loads(raw)
    except (TypeError, ValueError) as exc:
        raise CrashEvidenceError("invalid or ambiguous report JSON") from exc
    return verify_report(document)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    payload = verify_file(args.report)
    print(f"VERIFIED: {len(payload['scenarios'])} real SIGKILL subprocess "
          f"scenarios; {payload['authority_backend']} replay; internal signatures only; "
          "no KVM or external witness")


if __name__ == "__main__":
    main()
