"""Opt-in actual DatasetEffectBoundary running as a separate host process.

A private inherited socket is its only request channel. For the integrated KVM
bridge a *second* private descriptor proxies evidence to the supervisor's signed
recorder. The guest never receives these descriptors, signer secrets or etcd config.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.protocol import encode_frame, read_frame
from event_horizon.recorder import ExternalRecorder
from scripts.real_gateway_crash_checkpoints import PHASES, GatewayCrashProbe, ReservationProbe, RecorderProbe


class HostRecorderProxy:
    """Append events synchronously to the host supervisor's recorder."""

    def __init__(self, fd: int):
        self.channel = socket.socket(fileno=fd)
        self.stream = self.channel.makefile("rb")

    def append(self, event_type, payload, *, source_id="host-effect-service"):
        self.channel.sendall(encode_frame({
            "event_type": event_type,
            "payload": payload,
            "source_id": source_id,
        }))
        if read_frame(self.stream) != {"recorded": True}:
            raise RuntimeError("host recorder failed to confirm durable append")
        return None

    def close(self):
        self.stream.close()
        self.channel.close()


def start_effect_gateway(config_path: Path, *, recorder_bridge: bool = False,
                         crash_phase: str | None = None,
                         ready_stdout: bool = False):
    """Return a child and request socket; optionally a supervisor recorder socket."""
    if not config_path.is_file():
        raise FileNotFoundError(config_path)
    if crash_phase is not None and crash_phase not in PHASES:
        raise ValueError("untrusted gateway crash phase")
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    record_parent, record_child = (
        socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        if recorder_bridge else (None, None)
    )
    try:
        command = [
            sys.executable, "-m", "scripts.isolated_effect_gateway_worker",
            "--fd", str(child.fileno()), "--config", str(config_path),
        ]
        if crash_phase is not None:
            command += ["--crash-phase", crash_phase]
        if ready_stdout:
            command.append("--ready-stdout")
        fds = [child.fileno()]
        if record_child is not None:
            command += ["--recorder-fd", str(record_child.fileno())]
            fds.append(record_child.fileno())
        proc = subprocess.Popen(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if (crash_phase is not None or ready_stdout)
            else subprocess.DEVNULL,
            stderr=subprocess.PIPE, close_fds=True, pass_fds=tuple(fds),
            start_new_session=True,
        )
        return (proc, parent, record_parent) if recorder_bridge else (proc, parent)
    except BaseException:
        parent.close()
        if record_parent is not None:
            record_parent.close()
        raise
    finally:
        child.close()
        if record_child is not None:
            record_child.close()


def run_gateway(fd: int, config_path: Path, *, recorder_fd: int | None = None,
                crash_phase: str | None = None, ready_stdout: bool = False) -> None:
    """Serve up to 24 guest-shaped requests via the genuine trusted boundary."""
    config = json.loads(config_path.read_text())
    if not isinstance(config, dict) or set(config) != {"boundary", "recorder_path"}:
        raise ValueError("invalid trusted gateway configuration")
    boundary_config = config["boundary"]
    if not isinstance(boundary_config, dict):
        raise ValueError("invalid boundary configuration")
    recorder = (HostRecorderProxy(recorder_fd) if recorder_fd is not None
                else ExternalRecorder(config["recorder_path"]))
    boundary = None
    try:
        boundary = DatasetEffectBoundary(boundary_config, recorder)
        if crash_phase is not None:
            # Test instrumentation stays outside TrustedEffectGateway itself.
            if boundary.gateway.outcome_journal is None or not boundary_config.get("recipient_socket"):
                raise ValueError("crash hooks require durable external recipient and journal")
            probe = GatewayCrashProbe(crash_phase)

            existing_rule = boundary.gateway.pre_dispatch_rules.get("object.read")

            def before_reserve(_request, _claims):
                if existing_rule is not None and existing_rule(_request, _claims) is not True:
                    return False
                probe.mark("before_reservation")
                return True

            boundary.gateway.pre_dispatch_rules["object.read"] = before_reserve
            boundary.gateway.outcome_journal = ReservationProbe(
                boundary.gateway.outcome_journal, probe,
            )
            original_handler = boundary.gateway.effects["object.read"]

            def commit_then_pause(request):
                output = original_handler(request)
                probe.mark("after_recipient_commit_before_gateway_ack")
                return output

            boundary.gateway.effects["object.read"] = commit_then_pause
            boundary.gateway.recorder = RecorderProbe(boundary.gateway.recorder, probe)
        if recorder_fd is not None and boundary_config.get("observe_integrated_dispatch"):
            original = boundary.gateway.effects["object.read"]

            dispatch_count = 0

            def observed_dispatch(request):
                nonlocal dispatch_count
                dispatch_count += 1
                recorder.append("execution.dispatch", {
                    "request_digest": request.request_digest,
                    "dispatch_count": dispatch_count,
                    "gateway_pid": os.getpid(),
                })
                return original(request)

            boundary.gateway.effects["object.read"] = observed_dispatch
        if ready_stdout:
            # Unforgeable readiness from the actual trusted child AFTER
            # constructing its authority and recorder, BEFORE accepting work.
            print("READY", flush=True)
        with socket.socket(fileno=fd) as channel:
            with channel.makefile("rb") as stream:
                for _ in range(24):
                    try:
                        message = read_frame(stream)
                    except EOFError:
                        break
                    # The supervisor authenticates its upstream effect-service
                    # transport and owns this private FD; no caller-set peer UID.
                    response = boundary.execute(
                        message, peer_uid=boundary_config["vm_uid"],
                    )
                    if crash_phase == "after_completion_before_client_ack" and response.get("success"):
                        probe.mark("after_completion_before_client_ack")
                    channel.sendall(encode_frame(response))
    finally:
        if boundary is not None:
            boundary.close()
        if recorder_fd is not None:
            recorder.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--recorder-fd", type=int)
    parser.add_argument("--crash-phase", choices=PHASES)
    parser.add_argument("--ready-stdout", action="store_true")
    args = parser.parse_args()
    run_gateway(args.fd, args.config, recorder_fd=args.recorder_fd,
                crash_phase=args.crash_phase, ready_stdout=args.ready_stdout)


if __name__ == "__main__":
    main()
