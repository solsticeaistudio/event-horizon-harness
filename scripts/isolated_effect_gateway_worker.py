"""Opt-in, real DatasetEffectBoundary in a distinct host process.

Transport bridge for later Firecracker/vsock integration. The supervisor must
protect the host-owned config and evidence paths. NOT KVM evidence by itself.
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


def start_effect_gateway(config_path: Path) -> tuple[subprocess.Popen, socket.socket]:
    """Start the real, authorized gateway; never pass config in guest messages."""
    if not config_path.is_file():
        raise FileNotFoundError(config_path)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "scripts.isolated_effect_gateway_worker",
             "--fd", str(child.fileno()), "--config", str(config_path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            close_fds=True, pass_fds=(child.fileno(),), start_new_session=True,
        )
        return proc, parent
    except BaseException:
        parent.close()
        raise
    finally:
        child.close()


def run_gateway(fd: int, config_path: Path) -> None:
    """Serve exactly one guest-shaped request via the actual trusted boundary."""
    config = json.loads(config_path.read_text())
    if not isinstance(config, dict) or set(config) != {"boundary", "recorder_path"}:
        raise ValueError("invalid trusted host gateway configuration")
    boundary_config = config["boundary"]
    if not isinstance(boundary_config, dict):
        raise ValueError("invalid boundary configuration")
    recorder = ExternalRecorder(config["recorder_path"])
    boundary = DatasetEffectBoundary(boundary_config, recorder)
    try:
        with socket.socket(fileno=fd) as channel:
            with channel.makefile("rb") as stream:
                message = read_frame(stream)
                # A fixed, trusted transport UID: future vsock bridge must
                # independently enforce the peer principal before forwarding.
                result = boundary.execute(message, peer_uid=boundary_config["vm_uid"])
                channel.sendall(encode_frame(result))
    finally:
        boundary.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    run_gateway(args.fd, args.config)


if __name__ == "__main__":
    main()
