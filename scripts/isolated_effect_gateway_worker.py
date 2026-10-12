"""Opt-in actual DatasetEffectBoundary running as a separate host process.

A private inherited socket is its only request channel. For the integrated KVM
bridge a *second* private descriptor proxies evidence to the supervisor's signed
recorder. The guest never receives these descriptors, signer secrets or etcd config.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys

from event_horizon.effect_boundary import DatasetEffectBoundary
from event_horizon.protocol import encode_frame, read_frame
from event_horizon.recorder import ExternalRecorder


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


def start_effect_gateway(config_path: Path, *, recorder_bridge: bool = False):
    """Return a child and request socket; optionally a supervisor recorder socket."""
    if not config_path.is_file():
        raise FileNotFoundError(config_path)
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
        fds = [child.fileno()]
        if record_child is not None:
            command += ["--recorder-fd", str(record_child.fileno())]
            fds.append(record_child.fileno())
        proc = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
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


def run_gateway(fd: int, config_path: Path, *, recorder_fd: int | None = None) -> None:
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
        if recorder_fd is not None and boundary_config.get("observe_integrated_dispatch"):
            original = boundary.gateway.effects["object.read"]

            def observed_dispatch(request):
                recorder.append("execution.dispatch", {
                    "request_digest": request.request_digest,
                })
                return original(request)

            boundary.gateway.effects["object.read"] = observed_dispatch
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
    args = parser.parse_args()
    run_gateway(args.fd, args.config, recorder_fd=args.recorder_fd)


if __name__ == "__main__":
    main()
