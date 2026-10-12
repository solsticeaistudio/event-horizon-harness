#!/usr/bin/env python3
"""Opt-in real SIGKILL effect campaign with an independent recipient process.

Portable Linux mode: private SQLite capability state.
Owned etcd mode: real three-node etcd compare-and-put capability state.
NO Firecracker, hardware attestation, four-guardian quorum or power-loss claim.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.authority_backends import EtcdGatewayConfig, EtcdV3TransactionTransport
from event_horizon.broker import CapabilityBroker, CapabilityVerifier
from event_horizon.canonical import canonical_bytes, digest
from event_horizon.effect_outcome_journal import DurableEffectJournal
from event_horizon.models import ActionRequest, IssuedCapability
from event_horizon.trusted_effect_gateway import TrustedEffectGateway, select_consumption_store
from scripts.capability_fixture_support import authority_context, issue_options
from scripts.package_authority_oracle import inspect_committed_consumption, owned_etcd_config
from scripts.effect_crash_process_supervisor import kill_at_checkpoint
from scripts.effect_crash_recipient import observed_recipient, recipient_main

SCHEMA = "event-horizon.effect-process-crash.v1"
PHASES = (
    "before_reservation",
    "after_reservation_before_dispatch",
    "after_recipient_commit_before_gateway_ack",
    "after_handler_return_before_completion",
    "after_completion_before_client_ack",
)
EXPECTED = (0, 0, 1, 1, 1)


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    os.chmod(path, 0o600)



def mark(phase: str) -> None:
    print("PHASE:" + phase, flush=True)
    # The supervisor must send SIGKILL. Never continue or dispatch on timeout.
    while True:
        signal.pause()


def _worker_config(config: dict):
    request = ActionRequest.from_dict(config["request"])
    context = authority_context(request, config["reference_time"], max_output_bytes=512)
    cap = IssuedCapability.from_dict(config["capability"])
    backend = config["backend"]
    store = select_consumption_store(
        backend=backend, namespace=request.session_id, domain="external-effect",
        sqlite_path=config["consumption_database"] if backend == "sqlite" else None,
        etcd_config=EtcdGatewayConfig(
            endpoint=config["etcd_endpoint"], allow_insecure_loopback=True
        ) if backend == "etcd" else None,
        expected_cluster_id=config["etcd_cluster_id"] if backend == "etcd" else None,
    )
    verifier = CapabilityVerifier(config["public_key"], config["key_id"],
                                  consumption_store=store)
    return request, context, cap, verifier


class DurableRecorder:
    def __init__(self, path: Path, phase: str):
        self.path = path
        self.phase = phase

    def append(self, event_type, payload):
        if (self.phase == "after_handler_return_before_completion"
                and event_type == "gateway.completed"):
            mark(self.phase)
        line = json.dumps({"event": event_type, "payload": payload},
                          sort_keys=True, default=str) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)


def worker_main(config: dict, phase: str, token: str) -> int:
    request, context, capability, verifier = _worker_config(
        {**config, "capability": config["capabilities"][token]}
    )
    def rule(_request, _claims):
        if phase == "before_reservation":
            mark(phase)
        return True

    def effect(_request):
        if phase == "after_reservation_before_dispatch":
            mark(phase)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as recipient:
            recipient.settimeout(3)
            recipient.connect(config["recipient_socket"])
            recipient.sendall(json.dumps({
                "effect_key": config["effect_key"],
                "request_digest": request.request_digest,
            }).encode("utf-8"))
            response = recipient.recv(4096)
        if json.loads(response).get("committed") is not True:
            raise RuntimeError("recipient did not confirm commit")
        if phase == "after_recipient_commit_before_gateway_ack":
            mark(phase)
        return {"recipient": "committed"}

    gateway = TrustedEffectGateway(
        verifier, {"object.read": effect},
        DurableRecorder(Path(config["recorder"]), phase),
        outcome_journal=DurableEffectJournal(config["journal"]),
        pre_dispatch_rules={"object.read": rule},
    )
    decision = gateway.execute(
        request, capability, context["attestation"],
        executor_measurement=context["executor_measurement"],
        device_id=context["device_id"],
        verifier_policy_digest=context["verifier_policy_digest"],
        policy_digest=context["policy_digest"],
    )
    if phase == "after_completion_before_client_ack":
        mark(phase)
    print("RESULT:" + json.dumps({
        "accepted": decision.accepted,
        "effect_state": decision.effect_state,
        "error_class": decision.error_class,
    }, sort_keys=True), flush=True)
    return 0


def _start_process(args: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), *args],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1,
    )


def _read_line(process: subprocess.Popen, prefix: str, deadline: float = 20.0) -> str:
    if process.stdout is None:
        raise RuntimeError("child stdout unavailable")
    ready, _, _ = select.select([process.stdout], [], [], deadline)
    if not ready:
        process.kill()
        process.communicate(timeout=4)
        raise TimeoutError(f"child never reached required {prefix} checkpoint")
    line = process.stdout.readline().strip()
    if not line.startswith(prefix):
        try:
            _, errors = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            _, errors = process.communicate(timeout=4)
        raise RuntimeError(f"child exited before {prefix}: {line}; {errors[-500:]}")
    return line[len(prefix):]


def _stop(process: subprocess.Popen):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
    if process.stdout:
        process.stdout.close()
    if process.stderr:
        process.stderr.close()


def _request(session_id: str) -> ActionRequest:
    return ActionRequest("read-one", session_id, "attacker-agent", "object.read",
                         "synthetic-dataset", "exec-1",
                         {"offset": 0, "length": 5}, "bounded crash experiment")


def _execute_once(path: Path, phase: str, token: str, *, expect_crash: bool):
    proc = _start_process(["--role", "worker", "--config", str(path),
                           "--phase", phase, "--token", token])
    try:
        if expect_crash:
            observation = kill_at_checkpoint(proc, phase)
            return {"marker": observation.marker, "signal": observation.signal,
                    "exit_code": observation.exit_code}
        response = _read_line(proc, "RESULT:")
        stdout, stderr = proc.communicate(timeout=6)
        if proc.returncode != 0:
            raise RuntimeError(f"recovery failed unexpectedly: {stderr[-500:]}")
        return json.loads(response)
    finally:
        _stop(proc)


def run_scenario(root: Path, scenario: str, backend: str, endpoint: str | None,
                 cluster: str | None) -> dict:
    folder = root / scenario
    folder.mkdir(mode=0o700)
    session = "ehk-crash-" + uuid.uuid4().hex[:14]
    req = _request(session)
    now = time.time()
    ctx = authority_context(req, now, max_output_bytes=512)
    broker = CapabilityBroker(ttl_seconds=120)
    original = broker.issue(req, **issue_options(ctx), max_output_bytes=512)
    replacement = broker.issue(req, **issue_options(ctx), max_output_bytes=512)
    config = {
        "backend": backend,
        "etcd_endpoint": endpoint,
        "etcd_cluster_id": cluster,
        "consumption_database": str(folder / "replay.sqlite"),
        "recipient_database": str(folder / "recipient.sqlite"),
        "recipient_socket": str(folder / "recipient.sock"),
        "journal": str(folder / "effects.sqlite"),
        "recorder": str(folder / "events.jsonl"),
        "effect_key": digest({"session_id": session, "request_id": req.request_id}),
        "request_digest": req.request_digest,
        "reference_time": now,
        "request": req.canonical_payload(),
        "public_key": broker.public_key_pem,
        "key_id": broker.key_id,
        "capabilities": {"original": original.to_dict(), "replacement": replacement.to_dict()},
    }
    cfg_path = folder / "config.json"
    _write_json(cfg_path, config)
    recipient = _start_process(["--role", "recipient", "--config", str(cfg_path)])
    try:
        if _read_line(recipient, "") != "READY":
            raise RuntimeError("recipient failed startup")
        before = observed_recipient(Path(config["recipient_database"]))
        crash = _execute_once(cfg_path, scenario, "original", expect_crash=True)
        after = observed_recipient(Path(config["recipient_database"]))
        journal = DurableEffectJournal(config["journal"])
        state = journal.observe(tenant="default", environment="synthetic",
                                capability_id=original.claims.capability_id)
        old = _execute_once(cfg_path, "recovery", "original", expect_crash=False)
        new = None
        if scenario != "before_reservation":
            new = _execute_once(cfg_path, "recovery", "replacement", expect_crash=False)
        final = observed_recipient(Path(config["recipient_database"]))
        oracle = None
        if backend == "etcd":
            bindings = {replacement.claims.capability_id: (
                digest(replacement.claims.to_dict()), replacement.claims.expires_at,
            )} if new is not None else None
            oracle = inspect_committed_consumption(
                EtcdV3TransactionTransport(EtcdGatewayConfig(
                    endpoint=endpoint, allow_insecure_loopback=True)),
                cluster_id=cluster, session_id=session,
                capability_id=original.claims.capability_id,
                claims_digest=digest(original.claims.to_dict()),
                expires_at=original.claims.expires_at, extra_bindings=bindings,
            )
        outcome = {
            "scenario": scenario,
            "session_id": session,
            "request_digest": req.request_digest,
            "capability_id": original.claims.capability_id,
            "replacement_capability_id": replacement.claims.capability_id,
            "killed_worker": crash,
            "recipient_before": before,
            "recipient_after_kill": after,
            "recipient_after_recovery": final,
            "journal_state_after_kill": state["state"] if state else None,
            "original_replay": old,
            "replacement_replay": new,
            "consumed_capabilities": 1 + (new is not None),
            "etcd_oracle": oracle,
        }
        if not check_scenario(outcome):
            raise AssertionError(f"unsafe scenario outcome: {scenario}")
        return outcome
    finally:
        _stop(recipient)


def check_scenario(row: dict) -> bool:
    try:
        index = PHASES.index(row["scenario"])
        expected_count = EXPECTED[index]
        original = row["original_replay"]
        renewed = row["replacement_replay"]
        killed = row["killed_worker"]
        oracle = row["etcd_oracle"]
        return (
            killed["marker"] == row["scenario"]
            and killed["signal"] == signal.SIGKILL
            and killed["exit_code"] == -signal.SIGKILL
            and row["recipient_before"]["count"] == 0
            and row["recipient_after_kill"]["count"] == expected_count
            and row["recipient_after_recovery"] == row["recipient_after_kill"]
            and row["journal_state_after_kill"] == (
                None if index == 0 else "possibly-committed"
            )
            and original == {"accepted": False, "effect_state": "not-started",
                            "error_class": "authority-denied"}
            and (
                renewed is None if index == 0 else renewed == {
                    "accepted": False, "effect_state": "possibly-committed",
                    "error_class": "prior-effect-unknown",
                }
            )
            and row["consumed_capabilities"] == (1 if index == 0 else 2)
            and (oracle is None or (
                oracle["record_count"] == row["consumed_capabilities"]
                and oracle["cluster_id"].isdecimal()
                and oracle["capability_id"] == row["capability_id"]
                and oracle["record_integrity_checked"] is True
            ))
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def supervisor_main(args) -> None:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise RuntimeError("real SIGKILL campaign is Linux-only")
    if args.report.exists() or Path(str(args.report) + ".sha256").exists():
        raise FileExistsError("never overwrite signed experiment evidence")
    if args.backend == "etcd":
        if not args.etcd_endpoint or not args.etcd_cluster_id:
            raise ValueError("etcd mode requires pinned endpoint and cluster ID")
        owned_etcd_config(args.etcd_endpoint, args.etcd_cluster_id)
    source = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                     cwd=ROOT, text=True).strip()
    if subprocess.check_output(["git", "diff", "HEAD", "--name-only"],
                               cwd=ROOT).strip():
        raise RuntimeError("commit all implementation files before evidence run")
    report = {
        "schema": SCHEMA, "status": "INCOMPLETE",
        "experiment_mode": "linux-host-process-sigkill",
        "source_commit": source,
        "authority_backend": args.backend,
        "etcd_cluster_id": args.etcd_cluster_id if args.backend == "etcd" else None,
        "host_kernel": platform.release(),
        "attestation": "synthetic-fixture",
        "provenance": "internal ephemeral signing key; embedded public key; no witness",
        "kvm_exercised": False, "guardian_quorum_exercised": False, "scenarios": [],
    }
    try:
        with tempfile.TemporaryDirectory(prefix="ehh-crash-campaign-") as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            for scenario in PHASES:
                report["scenarios"].append(
                    run_scenario(root, scenario, args.backend,
                                 args.etcd_endpoint, args.etcd_cluster_id)
                )
        report["status"] = "PASS"
    except BaseException as exc:
        report["failure_class"] = type(exc).__name__
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        private = Ed25519PrivateKey.generate()
        pem = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        signed = {
            "payload": report,
            "signer_public_key": pem,
            "signature": base64.urlsafe_b64encode(
                private.sign(canonical_bytes(report))
            ).rstrip(b"=").decode("ascii"),
        }
        data = (json.dumps(signed, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        with args.report.open("xb") as stream:
            stream.write(data)
        with Path(str(args.report) + ".sha256").open("x") as sidecar:
            sidecar.write(hashlib.sha256(data).hexdigest() + "  " + args.report.name + "\n")
        print("Original report:", args.report, "SHA256:", hashlib.sha256(data).hexdigest(),
              "status:", report["status"], flush=True)
    if report["status"] != "PASS":
        raise AssertionError("effect campaign incomplete")
    print("PASS: real SIGKILL, independent recipient ledger, durable journal, signed capabilities",
          f"and {args.backend} replay storage; NO KVM or independent witness", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("supervisor", "recipient", "worker"),
                        default="supervisor")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--phase", default="recovery")
    parser.add_argument("--token", choices=("original", "replacement"), default="original")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--backend", choices=("sqlite", "etcd"), default="sqlite")
    parser.add_argument("--etcd-endpoint")
    parser.add_argument("--etcd-cluster-id")
    args = parser.parse_args()
    if args.role == "supervisor":
        if args.report is None:
            parser.error("--report is required")
        supervisor_main(args)
    else:
        if args.config is None:
            parser.error("--config is required in child process")
        config = json.loads(args.config.read_text())
        if args.role == "recipient":
            raise SystemExit(recipient_main(config))
        raise SystemExit(worker_main(config, args.phase, args.token))


if __name__ == "__main__":
    main()
