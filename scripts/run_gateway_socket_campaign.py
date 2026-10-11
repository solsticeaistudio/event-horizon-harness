"""Owned real-process adversarial test of the Linux KVM trusted effect service.

This invokes the ACTUAL linux_effect_service.py across inherited Unix
sockets, exercising framing, SO_PEERCRED, capability consumption and external
recorder acknowledgements. No Firecracker, Docker, root, network listener,
external write connector or production authority is used. A temporary
SQLite replay database is independently inspected by the test supervisor.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from event_horizon.broker import CapabilityBroker
from event_horizon.canonical import canonical_bytes
from event_horizon.models import ActionRequest
from event_horizon.protocol import MAX_FRAME_BYTES, encode_frame, read_frame
from scripts.capability_fixture_support import authority_context, issue_options

SCENARIOS = (
    "positive_and_replay",
    "argument_tamper",
    "signature_tamper",
    "injected_backend",
    "duplicate_json_key",
    "oversized_header",
    "truncated_payload",
    "incorrect_unix_peer",
    "recorder_refuses_authorization",
)
SYNTHETIC_DATA = "hello-owned-guest-effect-fixture"
SERVICE = ROOT / "scripts/linux_effect_service.py"


class SupervisorRecorder:
    def __init__(self, channel: socket.socket, *, refuse_authorization: bool = False):
        self.channel = channel
        self.refuse_authorization = refuse_authorization
        self.events: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self._thread = threading.Thread(target=self._run, name="owned-evidence-oracle", daemon=True)

    def start(self):
        self._thread.start()

    def _run(self):
        try:
            with self.channel:
                with self.channel.makefile("rb") as stream:
                    while True:
                        try:
                            event = read_frame(stream)
                        except EOFError:
                            return
                        if not isinstance(event.get("event_type"), str):
                            raise ValueError("malformed trusted service recorder event")
                        self.events.append(event)
                        accept = not (
                            self.refuse_authorization
                            and event["event_type"] == "execution.authorized"
                        )
                        self.channel.sendall(encode_frame({"recorded": accept}))
        except (OSError, ValueError, RuntimeError) as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")

    def join(self):
        self._thread.join(timeout=3)
        if self._thread.is_alive():
            raise AssertionError("recorder thread did not terminate")
        if self.errors:
            raise AssertionError(f"recorder oracle malfunction: {self.errors}")


def _fixture(directory: Path, *, bad_peer: bool):
    request = ActionRequest(
        "attack-lab-request", "attack-lab-session", "attacker-agent",
        "object.read", "synthetic-dataset", "exec-1",
        {"offset": 0, "length": 5}, "inert owned attack range",
    )
    context = authority_context(request, time.time())
    broker = CapabilityBroker(ttl_seconds=60)
    capability = broker.issue(
        request, **issue_options(context), max_output_bytes=512,
    )
    uid = os.getuid()
    config = {
        "verification_context": {
            **{key: context[key] for key in (
                "device_id", "executor_measurement",
                "verifier_policy_digest", "policy_digest", "attestation",
            )},
            "tenant": "default", "environment": "synthetic",
        },
        "public_key_pem": broker.public_key_pem,
        "key_id": broker.key_id,
        "dataset": SYNTHETIC_DATA,
        "session_id": request.session_id,
        "resource_id": request.resource_id,
        "vm_uid": uid + 100_000 if bad_peer else uid,
        "replay_database": str(directory / "trusted-replay.sqlite"),
        "decay_database": str(directory / "trusted-decay.sqlite"),
    }
    return {
        "request": request.canonical_payload(),
        "capability": capability.to_dict(),
    }, config


def _wire(scenario: str, baseline: dict[str, Any]) -> bytes:
    message = copy.deepcopy(baseline)
    if scenario == "argument_tamper":
        message["request"]["arguments"]["offset"] = 1
    elif scenario == "signature_tamper":
        message["capability"]["signature"] = "A" * 86
    elif scenario == "injected_backend":
        message["authority_backend"] = "etcd"
    elif scenario == "duplicate_json_key":
        first = canonical_bytes(message)
        return struct.pack(">I", len(first) + len(b',"request":null')) + (
            first[:-1] + b',"request":null}'
        )
    elif scenario == "oversized_header":
        return struct.pack(">I", MAX_FRAME_BYTES + 1)
    elif scenario == "truncated_payload":
        return struct.pack(">I", 30) + b'{"x":1}'
    return encode_frame(message)


def _client(path: Path, data: bytes, *, allow_no_reply: bool = False) -> dict | None:
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    channel.settimeout(2)
    try:
        for attempt in range(30):
            try:
                channel.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if attempt == 29:
                    raise
                time.sleep(0.03)
        channel.sendall(data)
        channel.shutdown(socket.SHUT_WR)
        try:
            with channel.makefile("rb") as stream:
                return read_frame(stream)
        except (EOFError, ConnectionResetError, BrokenPipeError, TimeoutError):
            if allow_no_reply:
                return None
            raise
    finally:
        channel.close()


def run_scenario(scenario: str) -> dict[str, Any]:
    if scenario not in SCENARIOS:
        raise ValueError("only predefined synthetic gateway probes are allowed")
    if not hasattr(socket, "SO_PEERCRED") or os.name != "posix":
        raise RuntimeError("this owned gate transport exercise needs Linux Unix credentials")
    with tempfile.TemporaryDirectory(prefix="ehh-owned-gate-") as temp:
        directory = Path(temp)
        baseline, config = _fixture(
            directory, bad_peer=scenario == "incorrect_unix_peer",
        )
        configuration = directory / "trusted-config.json"
        configuration.write_bytes(canonical_bytes(config))
        configuration.chmod(0o600)
        listen_path = directory / "listener.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(listen_path))
        listener.listen(12)
        recorder_parent, recorder_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        observer = SupervisorRecorder(
            recorder_parent,
            refuse_authorization=scenario == "recorder_refuses_authorization",
        )
        process = None
        actual: list[dict | None] = []
        try:
            process = subprocess.Popen(
                [
                    sys.executable, "-u", str(SERVICE),
                    "--listener-fd", str(listener.fileno()),
                    "--recorder-fd", str(recorder_child.fileno()),
                    "--config", str(configuration),
                ],
                cwd=ROOT,
                pass_fds=(listener.fileno(), recorder_child.fileno()),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            recorder_child.close()
            listener.close()
            observer.start()
            sent = _wire(scenario, baseline)
            bad_framing = scenario in {
                "duplicate_json_key", "oversized_header", "truncated_payload",
                "incorrect_unix_peer",
            }
            actual.append(_client(listen_path, sent, allow_no_reply=bad_framing))
            if scenario in {
                "positive_and_replay", "argument_tamper",
                "signature_tamper", "injected_backend",
                "recorder_refuses_authorization",
            }:
                actual.append(_client(listen_path, encode_frame(baseline)))
            # Stop only our owned process. Never touch real KVM or the host gate.
            if process.poll() is None:
                process.terminate()
            _out, stderr = process.communicate(timeout=5)
            if process.returncode not in {-15, 0, 1}:
                raise AssertionError(
                    "owned gateway service crashed unexpectedly: "
                    + stderr.decode("utf-8", errors="replace")[-1500:]
                )
            observer.join()
            count = 0
            if Path(config["replay_database"]).exists():
                with sqlite3.connect(config["replay_database"]) as database:
                    count = database.execute(
                        "SELECT COUNT(*) FROM capability_consumptions"
                    ).fetchone()[0]
            types = [event["event_type"] for event in observer.events]
            completed = types.count("execution.completed")
            authorized = types.count("execution.authorized")
            def denied(result):
                return (result is not None
                        and result.get("success") is False
                        and result.get("effect_state") == "not-started")
            if scenario == "positive_and_replay":
                valid = (
                    len(actual) == 2 and actual[0] is not None
                    and actual[0].get("success") is True
                    and actual[0].get("output") == SYNTHETIC_DATA[:5]
                    and denied(actual[1]) and count == 1
                    and completed == 1 and authorized == 1
                )
            elif scenario in {"argument_tamper", "signature_tamper", "injected_backend"}:
                valid = (
                    len(actual) == 2 and denied(actual[0])
                    and actual[1] is not None and actual[1].get("success") is True
                    and actual[1].get("output") == SYNTHETIC_DATA[:5]
                    and count == 1 and completed == 1 and authorized == 1
                )
            elif scenario == "recorder_refuses_authorization":
                valid = (
                    len(actual) == 2 and denied(actual[0]) and denied(actual[1])
                    and count == 1 and completed == 0 and authorized == 1
                    and "execution.denied" in types
                )
            else:
                valid = count == 0 and completed == 0 and authorized == 0
            report = {
                "scenario": scenario,
                "status": "PASS" if valid else "FAIL",
                "effect_count": completed,
                "authorized_events": authorized,
                "replay_consumptions": count,
                "response_states": [
                    None if item is None else {
                        "success": item.get("success"),
                        "effect_state": item.get("effect_state"),
                        "output_digest": hashlib.sha256(
                            str(item.get("output")).encode()
                        ).hexdigest() if item.get("success") else None,
                    }
                    for item in actual
                ],
                "host_recorder_events": types,
                "source": "real-unprivileged-linux-effect-service-unix-process",
            }
            if not valid:
                raise AssertionError(json.dumps(report, sort_keys=True))
            return report
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            try:
                listener.close()
            except OSError:
                pass
            recorder_child.close()
            recorder_parent.close()


def run_campaign() -> dict:
    outcomes = [run_scenario(scenario) for scenario in SCENARIOS]
    return {
        "schema": "event-horizon.gateway-socket-campaign.v1",
        "status": "PASS",
        "host": "owned-local-linux-without-kvm",
        "real_gate_process": True,
        "socket_credential_check": True,
        "synthetic_read_only": True,
        "external_effects": False,
        "cases": outcomes,
        "limits": (
            "not Firecracker/vsock, not independent evidence trust, "
            "not proof against kernel/host compromise"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    options = parser.parse_args()
    report = run_campaign()
    options.report.parent.mkdir(parents=True, exist_ok=True)
    options.report.write_bytes(canonical_bytes(report))
    print(f"PASS: {len(report['cases'])} actual Unix-socket gateway attack scenarios; "
          f"report: {options.report}")


if __name__ == "__main__":
    main()
